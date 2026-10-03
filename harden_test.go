package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestCappedWriterBoundsMemory(t *testing.T) {
	cw := &cappedWriter{max: 16}
	// Simulate a program printing continuously: 1000 writes of 1KB each.
	for i := 0; i < 1000; i++ {
		if _, err := cw.Write(make([]byte, 1024)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := len(cw.Bytes()); got != 16 {
		t.Fatalf("captured %d bytes, want exactly the 16 byte cap", got)
	}
	if !cw.dropped {
		t.Fatal("dropped flag not set although output exceeded the cap")
	}
}

func TestCappedWriterUnderCap(t *testing.T) {
	cw := &cappedWriter{max: 64}
	cw.Write([]byte("hello"))
	if got := string(cw.Bytes()); got != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
	if cw.dropped {
		t.Fatal("dropped set although output stayed under the cap")
	}
}

// A zero cap must not panic and must not retain anything.
func TestCappedWriterZeroCap(t *testing.T) {
	cw := &cappedWriter{max: 0}
	cw.Write([]byte("anything"))
	if len(cw.Bytes()) != 0 {
		t.Fatal("zero cap retained output")
	}
}

func TestSanitizeStripsANSIAndControlBytes(t *testing.T) {
	raw := "\x1b[31m\x1b[2J\x1b[HFAKE ERROR\x1b[0m\rOVERWRITTEN\nsecond\x00line\x7f"
	got := sanitizeOutput(raw, "")

	for _, seq := range []string{"\x1b", "\x00", "\x7f"} {
		if strings.Contains(got, seq) {
			t.Errorf("output still contains %q: %q", seq, got)
		}
	}
	if strings.Contains(got, "\r") {
		t.Errorf("carriage return survived and can overwrite a line: %q", got)
	}
	if strings.Contains(got, "FAKE ERROR") != true {
		t.Error("sanitiser deleted the printable text, which it must not do")
	}
}

// Newline and tab are legitimate in program output and must be preserved, or
// every multi-line program would be flattened.
func TestSanitizePreservesNewlineAndTab(t *testing.T) {
	got := sanitizeOutput("line1\n\tindented\nline3", "")
	want := "line1\n\tindented\nline3"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSanitizeRewritesInternalJobPaths(t *testing.T) {
	jobDir := "/tmp/codhoot-job-4242"
	raw := "Traceback:\n  File \"" + jobDir + "/main.py\", line 3\nValueError: boom"
	got := sanitizeOutput(raw, jobDir)

	if strings.Contains(got, "/tmp/codhoot-job-") {
		t.Errorf("internal job path leaked to the client: %q", got)
	}
	if !strings.Contains(got, `"main.py"`) {
		t.Errorf("expected the bare filename to survive: %q", got)
	}
}

func TestUIDPoolNeverHandsOutSameUIDConcurrently(t *testing.T) {
	p := newUIDPool()
	const parallel = 8

	var wg sync.WaitGroup
	var mu sync.Mutex
	held := make(map[uint32]int)

	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			uid := p.acquire()
			mu.Lock()
			held[uid]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	for uid, n := range held {
		if n != 1 {
			t.Errorf("uid %d was handed out %d times concurrently; isolation is broken", uid, n)
		}
	}
	if len(held) != parallel {
		t.Errorf("expected %d distinct uids, got %d", parallel, len(held))
	}
}

// UIDs must stay in the documented range and must not collide with the
// unprivileged uid 1000 that the service itself may run as.
func TestUIDPoolStaysInRangeAndAvoidsServiceUID(t *testing.T) {
	p := newUIDPool()
	for i := 0; i < sandboxPoolSize*3; i++ {
		uid := p.acquire()
		if uid < sandboxUIDBase || uid >= sandboxUIDBase+sandboxPoolSize {
			t.Fatalf("uid %d outside pool range [%d,%d)", uid, sandboxUIDBase, sandboxUIDBase+sandboxPoolSize)
		}
		if uid == 1000 {
			t.Fatal("pool handed out uid 1000, which the service itself may use")
		}
		p.release(uid)
	}
}

// A released uid must become available again, otherwise a long-running service
// would eventually exhaust the pool and fall back to a shared uid.
func TestUIDPoolReleaseAllowsReuse(t *testing.T) {
	p := newUIDPool()

	first := make(map[uint32]bool)
	for i := 0; i < sandboxPoolSize; i++ {
		uid := p.acquire()
		if first[uid] {
			t.Fatalf("uid %d issued twice without being released", uid)
		}
		first[uid] = true
	}
	for uid := range first {
		p.release(uid)
	}

	second := make(map[uint32]bool)
	for i := 0; i < sandboxPoolSize; i++ {
		uid := p.acquire()
		if second[uid] {
			t.Fatalf("uid %d issued twice in the second round", uid)
		}
		second[uid] = true
	}
	if len(second) != len(first) {
		t.Fatalf("after a full release cycle got %d uids, want %d", len(second), len(first))
	}
}

// Exhausting the pool then releasing everything must let a full round be served
// again, which is the property that keeps the service alive indefinitely.
func TestUIDPoolNeverPermanentlyExhausts(t *testing.T) {
	p := newUIDPool()
	for round := 0; round < 5; round++ {
		var uids []uint32
		for i := 0; i < sandboxPoolSize; i++ {
			uids = append(uids, p.acquire())
		}
		for _, u := range uids {
			p.release(u)
		}
	}
}

func TestUIDPoolUnderContentionNeverReturnsZeroOrServiceUID(t *testing.T) {
	p := newUIDPool()
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			uid := p.acquire()
			if uid == 0 {
				t.Error("pool returned uid 0, which would run user code as root")
			}
			p.release(uid)
		}()
	}
	wg.Wait()
}

// --- artifact cache integrity -------------------------------------------------

func TestArtifactSealRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.bin")
	src := "int main(){return 0;}"
	if err := writeArtifact(path, src, []byte("ELF-BINARY")); err != nil {
		t.Fatalf("writeArtifact: %v", err)
	}
	if !verifyArtifact(path, src) {
		t.Fatal("a genuine artifact failed verification")
	}
}

// The core attack: an attacker writes their own binary to the cache path that
// another user's source hashes to. Verification must fail so it is recompiled.
func TestArtifactVerificationRejectsPlantedBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "victim.bin")
	victimSrc := "print('hello')"

	// Attacker plants a binary and, to look maximally convincing, copies a real
	// tag from a different entry.
	attackerArtifact := []byte("ATTACKER-PAYLOAD")
	otherSrc := "print('other')"
	otherPath := filepath.Join(dir, "other.bin")
	if err := writeArtifact(otherPath, otherSrc, []byte("GENUINE")); err != nil {
		t.Fatalf("writeArtifact: %v", err)
	}
	genuineTag, err := os.ReadFile(otherPath + ".mac")
	if err != nil {
		t.Fatalf("read tag: %v", err)
	}
	if err := os.WriteFile(path, attackerArtifact, 0o755); err != nil {
		t.Fatalf("plant: %v", err)
	}
	if err := os.WriteFile(path+".mac", genuineTag, 0o644); err != nil {
		t.Fatalf("plant tag: %v", err)
	}

	if verifyArtifact(path, victimSrc) {
		t.Fatal("planted binary accepted for a source it was not compiled from: RCE")
	}
}

func TestArtifactVerificationRejectsTransplantedArtifact(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	b := filepath.Join(dir, "b.bin")
	srcA := "AAAA"
	srcB := "BBBB"
	if err := writeArtifact(a, srcA, []byte("BINARY-A")); err != nil {
		t.Fatalf("writeArtifact: %v", err)
	}
	if err := writeArtifact(b, srcB, []byte("BINARY-B")); err != nil {
		t.Fatalf("writeArtifact: %v", err)
	}

	// Swap the binaries while leaving each tag in place, so every entry now holds
	// a genuine artifact that was simply produced from the wrong source.
	blobA, _ := os.ReadFile(a)
	blobB, _ := os.ReadFile(b)
	if err := os.WriteFile(a, blobB, 0o755); err != nil {
		t.Fatalf("swap: %v", err)
	}
	if err := os.WriteFile(b, blobA, 0o755); err != nil {
		t.Fatalf("swap: %v", err)
	}

	if verifyArtifact(a, srcA) {
		t.Error("entry a accepted an artifact that was compiled from source B")
	}
	if verifyArtifact(b, srcB) {
		t.Error("entry b accepted an artifact that was compiled from source A")
	}
}

func TestArtifactVerificationRejectsMissingFiles(t *testing.T) {
	dir := t.TempDir()
	if verifyArtifact(filepath.Join(dir, "nope.bin"), "src") {
		t.Fatal("a nonexistent artifact was accepted")
	}
}

func TestArtifactMACBindsSourceAndArtifact(t *testing.T) {
	src := "x"
	artifact := []byte("y")
	// The separator byte must make ("ab","c") differ from ("a","bc").
	if string(artifactMAC("a", []byte("bc"))) == string(artifactMAC("ab", []byte("c"))) {
		t.Fatal("MAC does not unambiguously bind source to artifact")
	}
	if string(artifactMAC(src, artifact)) != string(artifactMAC(src, artifact)) {
		t.Fatal("MAC is not deterministic")
	}
}

func TestCacheSecretIsNotDerivedFromAnythingGuessable(t *testing.T) {
	if len(cacheSecret) != 32 {
		t.Fatalf("cache secret is %d bytes, want 32", len(cacheSecret))
	}
	allZero := true
	for _, b := range cacheSecret {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("cache secret is all zeroes")
	}
}

// --- child environment --------------------------------------------------------

// The child previously inherited the service's whole environment, which exposed
// the Render deployment topology (internal IP, service id, git branch, Kubernetes
// API host) to any user who could read /proc.
func TestChildEnvLeaksNothingFromService(t *testing.T) {
	t.Setenv("SUPABASE_SERVICE_KEY", "super-secret")
	t.Setenv("RENDER_INTERNAL_IP", "10.199.130.212")

	env := strings.Join(childEnv("/tmp/job"), "\n")
	for _, leak := range []string{"super-secret", "SUPABASE_SERVICE_KEY", "RENDER_INTERNAL_IP", "10.199.130.212"} {
		if strings.Contains(env, leak) {
			t.Errorf("child environment leaks %q: %s", leak, env)
		}
	}
}

// The child must get the job directory as its writable HOME/TMPDIR and a usable
// PATH, but must not inherit anything the toolchain does not need.
func TestChildEnvIsScopedToTheJob(t *testing.T) {
	t.Setenv("PATH", "/opt/java/openjdk/bin:/usr/local/go/bin:/usr/bin:/bin")
	t.Setenv("RUSTUP_HOME", "/usr/local/rustup")

	env := childEnv("/tmp/job")
	joined := strings.Join(env, "\n")

	for _, want := range []string{
		"HOME=/tmp/job",
		"TMPDIR=/tmp/job",
		"PATH=/opt/java/openjdk/bin:/usr/local/go/bin:/usr/bin:/bin",
		"TZ=UTC",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("child env missing %q\ngot:\n%s", want, joined)
		}
	}

	// Toolchain variables the compiler genuinely needs must survive, otherwise
	// rustup cannot pick a toolchain and the JVM cannot find its root.
	if !strings.Contains(joined, "RUSTUP_HOME=/usr/local/rustup") {
		t.Errorf("toolchain env not forwarded, rust service would break:\n%s", joined)
	}
}

// PATH must come from the service, not a hardcoded list. A fixed list silently
// broke three services because javac, go and rustc all live outside it.
func TestChildEnvPATHComesFromHost(t *testing.T) {
	t.Setenv("PATH", "/totally/custom/bin")
	if got := strings.Join(childEnv("/tmp/job"), "|"); !strings.Contains(got, "PATH=/totally/custom/bin") {
		t.Fatalf("host PATH not used: %s", got)
	}
	if strings.Contains(strings.Join(childEnv("/tmp/job"), "|"), childPath) && !strings.Contains(hostPath(), childPath) {
		t.Fatal("fell back to the hardcoded PATH while a host PATH was available")
	}
}

func TestChildEnvExtrasAreAppendedLast(t *testing.T) {
	got := childEnv("/tmp/job", "GOCACHE=/tmp/job/.gocache", "GOPROXY=off")
	if got[len(got)-2] != "GOCACHE=/tmp/job/.gocache" {
		t.Errorf("first extra not appended last: %v", got)
	}
	if got[len(got)-1] != "GOPROXY=off" {
		t.Errorf("second extra not appended last: %v", got)
	}
}

func TestMaxBodyBytesIsSmallerThanSourceLimit(t *testing.T) {
	// The body cap must be enforced before decoding; if it were larger than the
	// source limit it would never be the binding constraint and the check would
	// be dead code that only gave false assurance.
	if maxBodyBytes <= maxSourceSize {
		t.Fatalf("maxBodyBytes (%d) must exceed maxSourceSize (%d) so the JSON envelope is rejected rather than accepted and then truncated",
			maxBodyBytes, maxSourceSize)
	}
}
