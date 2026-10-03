package main

// harden.go is the security boundary shared by every compiler service.
//
// It is deliberately identical across all eight services so a fix lands
// everywhere at once. The threat model is one sentence: the request body is
// fully attacker-controlled and anonymous, so the source code, the language
// runtime, and the compiler driver must all be treated as hostile.

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// sandboxUIDBase and sandboxPoolSize define the per-job uid pool.
	//
	// Giving every job the *same* unprivileged uid is not isolation: with a
	// shared uid, a 0700 job directory is still readable by every other job,
	// because they are all the same principal. Handing each concurrent job its
	// own uid makes 0700 mean what it says. The pool is larger than
	// maxConcurrentJobs, so two jobs can never hold the same uid at once.
	sandboxUIDBase  = 2000
	sandboxPoolSize = 32

	// maxBodyBytes caps the request body *before* decoding.
	//
	// The existing maxSourceSize check runs after json.Decode, by which point
	// the whole body has already been buffered into memory. An oversized POST is
	// therefore an OOM primitive against the service itself. ReadTimeout limits
	// the rate, not the size.
	maxBodyBytes = 256 * 1024

	// childPath is the PATH handed to compilers and runtimes. It is fixed so
	// behaviour does not depend on the service's own environment.
	childPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// sandboxExecFlag makes the service re-exec itself as a trampoline that applies
// rlimits before execve'ing the compiler or runtime. See harden_unix.go.
const sandboxExecFlag = "--codhoot-sandbox-exec"

// uidPool hands out one sandbox uid per in-flight job.
type uidPool struct {
	mu     sync.Mutex
	inUse  map[uint32]bool
	cursor int
}

func newUIDPool() *uidPool {
	return &uidPool{inUse: make(map[uint32]bool)}
}

// acquire returns a uid not currently held by any other job.
func (p *uidPool) acquire() uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := 0; i < sandboxPoolSize; i++ {
		uid := uint32(sandboxUIDBase + ((p.cursor + i) % sandboxPoolSize))
		if !p.inUse[uid] {
			p.inUse[uid] = true
			p.cursor = (p.cursor + i + 1) % sandboxPoolSize
			return uid
		}
	}
	// Unreachable while the pool is larger than the concurrency limit; fall back
	// to the base uid rather than blocking a request.
	return uint32(sandboxUIDBase)
}

// release returns a uid to the pool once its job has finished.
func (p *uidPool) release(uid uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.inUse, uid)
}

// cappedWriter accumulates at most max bytes and discards the rest.
//
// The previous code used cmd.CombinedOutput(), which buffers the program's
// entire output before any limit is applied. The 512KB cap therefore bounded
// what the *user* saw but not what the *service* consumed, so a program writing
// continuously for the full timeout could still push hundreds of megabytes into
// a 512MB container. Capping at the point of production fixes that.
type cappedWriter struct {
	buf     bytes.Buffer
	max     int
	dropped bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) <= room {
			c.buf.Write(p)
			return len(p), nil
		}
		c.buf.Write(p[:room])
		c.dropped = true
		return len(p), nil
	}
	c.dropped = true
	return len(p), nil
}

// Bytes returns the captured output, which is never longer than max.
func (c *cappedWriter) Bytes() []byte { return c.buf.Bytes() }

// sanitizeOutput strips terminal control sequences and rewrites the service's
// internal paths before anything is returned to the client.
//
// Two distinct problems:
//
//  1. Control bytes. A program can emit ESC[2J ESC[H to clear the screen and
//     repaint arbitrary text ("your session expired, re-enter password"), which
//     is a convincing phishing primitive in any viewer that honours escapes, and
//     CR to overwrite a line so the visible output differs from the real output.
//     Newline and tab are preserved because program output legitimately uses them.
//
//  2. Internal paths. The runtime's stderr is merged into the response, so a raw
//     Python traceback hands the user /tmp/codhoot-job-<rand>/main.py along with
//     the exact interpreter build.
func sanitizeOutput(s, jobDir string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if jobDir != "" {
		out = strings.ReplaceAll(out, jobDir+"/", "")
	}
	return out
}

// limitBody caps the request body before it is decoded.
func limitBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
}

// hostPath is the PATH handed to compilers and runtimes.
//
// It deliberately starts from the service's own PATH, which the base image sets
// correctly, rather than a hardcoded list. A fixed list silently broke three
// services: javac lives in /opt/java/openjdk/bin, go in /usr/local/go/bin and
// rustc in /usr/local/cargo/bin, none of which are on a conventional PATH. The
// fallback exists only for the impossible case of an empty PATH.
func hostPath() string {
	if p := os.Getenv("PATH"); p != "" {
		return p
	}
	return childPath
}

// toolchainEnvKeys are the environment variables copied from the service into the
// child. PATH alone is not enough: rustup refuses to pick a toolchain without
// RUSTUP_HOME and CARGO_HOME, and the JVM and Go toolchains resolve their own
// roots through JAVA_HOME and GOROOT. Stripping these broke the rust service with
// "rustup could not choose a version of rustc to run".
//
// The list is an allowlist rather than a full copy on purpose. The child is
// attacker-controlled, so the point is to hand it only what the toolchain needs,
// never the deployment's own variables (internal IP, service id, git branch) or
// any secret added later.
var toolchainEnvKeys = []string{
	"JAVA_HOME",
	"GOROOT",
	"GOPATH",
	"RUSTUP_HOME",
	"CARGO_HOME",
	"RUSTUP_TOOLCHAIN",
	"NODE_PATH",
	"NODE_OPTIONS",
	"PYTHONHOME",
}

// hostEnvAllowlist returns the toolchain variables this service actually has.
func hostEnvAllowlist() []string {
	out := make([]string, 0, len(toolchainEnvKeys))
	for _, k := range toolchainEnvKeys {
		if v := os.Getenv(k); v != "" {
			out = append(out, k+"="+v)
		}
	}
	return out
}

// childEnv returns the complete environment for a compiler or runtime process.
//
// The child used to inherit the service's entire environment, which exposed the
// Render deployment variables (internal IP, service ID, git branch, Kubernetes
// API host) to every anonymous user who could read /proc. An explicit list keeps
// the toolchain variables the compiler genuinely needs while dropping everything
// else, so a future secret is not leaked by default.
func childEnv(jobDir string, extra ...string) []string {
	env := []string{
		"HOME=" + jobDir,
		"TMPDIR=" + jobDir,
		"PATH=" + hostPath(),
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"TZ=UTC",
	}
	env = append(env, hostEnvAllowlist()...)
	return append(env, extra...)
}

// cacheSecret authenticates cached compilation artifacts.
//
// Compiled languages cache the produced binary on disk and later EXECUTE it. All
// jobs share one uid pool and one cache directory, so any user could drop a file
// at the path derived from another user's source hash and have the service
// execute it. That is remote code execution, and it persists, because the planted
// file survives across requests. Matching by sha256(source) alone does not help:
// the attacker only has to write the file, not collide a hash.
//
// Sealing each artifact with an HMAC over (source || artifact), keyed by a secret
// that exists only in this process's memory, makes a planted or transplanted file
// fail verification and be recompiled instead. The key is generated per boot with
// crypto/rand and is never written to disk or placed in the environment, so no
// job can read it. Binding the source as well as the artifact is what prevents
// transplanting a legitimately sealed binary from one cache entry to another.
//
// This keeps the cache, which is where nearly all of the speed comes from.
var cacheSecret = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// A predictable key would silently defeat the whole mechanism.
		panic("crypto/rand unavailable: " + err.Error())
	}
	return b
}()

func artifactMAC(source string, artifact []byte) []byte {
	m := hmac.New(sha256.New, cacheSecret)
	m.Write([]byte(source))
	m.Write([]byte{0}) // separator so ("ab","c") and ("a","bc") differ
	m.Write(artifact)
	return m.Sum(nil)
}

// writeArtifact stores a freshly compiled artifact together with its
// authentication tag.
func writeArtifact(path, source string, artifact []byte) error {
	if err := os.WriteFile(path, artifact, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path+".mac", artifactMAC(source, artifact), 0o644)
}

// verifyArtifact reports whether path holds an artifact this process produced
// from exactly this source. Anything else is treated as a cache miss, so a
// planted or transplanted binary is recompiled rather than executed.
func verifyArtifact(path, source string) bool {
	got := mustReadFile(path + ".mac")
	if len(got) == 0 {
		return false
	}
	return hmac.Equal(got, artifactMAC(source, mustReadFile(path)))
}

func mustReadFile(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

// --- multi-file request handling ---------------------------------------------
//
// A request may arrive either as a single `source` string (the original
// contract, still sent by older callers) or as a `files` map plus an
// `entry_file`. Both must work because the service is reachable directly.
//
// Everything here is attacker controlled and reachable without authentication,
// so the file set is validated in this layer as well as in the backend. A
// validation bug in one layer must not become a sandbox escape in the other.

const (
	maxFiles      = 20
	maxFileBytes  = 512 * 1024
	maxTotalBytes = 2 * 1024 * 1024
)

// File mirrors the backend's wire format exactly: codhoot-backend's
// execution.File is `{name, content}` and Files is a *list*, not a map.
// Accepting a map here would silently never match what the backend sends, so
// the shape has to be identical.
type File struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// entryPoint is a validated request: the files to materialise, and the one that
// actually runs.
type entryPoint struct {
	files []File
	entry string
}

// validFileName rejects anything that is not a plain single-segment file name.
//
// The name becomes a path inside a private job directory, so separators, parent
// references, NUL bytes, control characters and over-long names are refused
// outright rather than sanitised: no legitimate editor buffer contains them.
func validFileName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	if name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// resolveEntry validates a request into a set of files plus a single entry.
//
// Falling back to "the first file" when entry_file is absent would run a program
// the caller did not ask for, which breaks the entry-point guarantee the
// multi-file feature depends on, so it is refused instead.
func resolveEntry(source string, files []File, entryFile, defaultName string) (entryPoint, error) {
	if len(files) == 0 {
		if entryFile != "" {
			return entryPoint{}, errors.New("entry_file given without files")
		}
		if len(source) > maxFileBytes {
			return entryPoint{}, fmt.Errorf("source exceeds %d bytes", maxFileBytes)
		}
		return entryPoint{files: []File{{Name: defaultName, Content: source}}, entry: defaultName}, nil
	}

	if len(files) > maxFiles {
		return entryPoint{}, fmt.Errorf("too many files (max %d)", maxFiles)
	}
	total := 0
	seen := make(map[string]bool, len(files))
	for _, f := range files {
		if !validFileName(f.Name) {
			return entryPoint{}, errors.New("invalid file name")
		}
		// A duplicate name would let a later file silently overwrite an earlier
		// one, so the set the caller asked for is not the set that gets run.
		if seen[f.Name] {
			return entryPoint{}, fmt.Errorf("duplicate file name %q", f.Name)
		}
		seen[f.Name] = true
		if len(f.Content) > maxFileBytes {
			return entryPoint{}, fmt.Errorf("file %q exceeds %d bytes", f.Name, maxFileBytes)
		}
		total += len(f.Content)
	}
	if total > maxTotalBytes {
		return entryPoint{}, fmt.Errorf("total source exceeds %d bytes", maxTotalBytes)
	}

	entry := entryFile
	if entry == "" {
		if len(files) != 1 {
			return entryPoint{}, errors.New("entry_file is required when files has more than one entry")
		}
		entry = files[0].Name
	}
	if !validFileName(entry) {
		return entryPoint{}, errors.New("invalid entry_file")
	}
	found := false
	for _, f := range files {
		if f.Name == entry {
			found = true
			break
		}
	}
	if !found {
		return entryPoint{}, errors.New("entry_file is not present in files")
	}
	return entryPoint{files: files, entry: entry}, nil
}

// writeEntry materialises validated files into dir and returns the entry path.
// dir must already be private to this job's uid. Files are chowned to the
// sandbox uid because the service creates them as root.
func writeEntry(dir string, ep entryPoint, uid uint32) (string, error) {
	for _, f := range ep.files {
		path := filepath.Join(dir, f.Name)
		if err := os.WriteFile(path, []byte(f.Content), 0o644); err != nil {
			return "", err
		}
		if err := chownToSandbox(path, uid); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, ep.entry), nil
}
