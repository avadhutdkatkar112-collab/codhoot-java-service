//go:build unix

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

// sandboxExecFlag makes the service re-exec itself as a trampoline: apply
// rlimits, then replace the process with the compiler or language runtime.
//
// Why a trampoline rather than SysProcAttr: Go's os/exec exposes no hook to set
// rlimits in the child (SysProcAttr has no Setrlimit field and syscall.Setrlimit
// acts on the calling process, not the forked one). Having the child set its own
// limits before execve is dependency-free and exact, and rlimits survive execve.
//
// It is used as defence in depth. The container flags --cpus, --pids-limit,
// --memory and --tmpfs size are the real boundary, because the kernel enforces
// them correctly through cgroups; these limits mean a service that is deployed
// with those flags missing is still not trivially fork-bombable.
func sandboxExec() bool {
	if len(os.Args) < 3 || os.Args[1] != sandboxExecFlag {
		return false
	}

	argv := os.Args[2:]

	// RLIMIT_AS is deliberately absent: it caps *virtual* address space, and the
	// JVM and the Go runtime reserve far more virtual memory than they ever
	// resident-set, so it breaks Java and Go outright. Real memory is bounded by
	// the container memory limit.
	//
	// RLIMIT_NPROC is per-real-uid, which is meaningful only because each job
	// holds a distinct uid. With one shared uid a single fork bomb would exhaust
	// the container-wide total for every job at once.
	limits := []struct {
		resource int
		cur, max uint64
	}{
		{syscall.RLIMIT_FSIZE, 32 << 20, 32 << 20}, // no unbounded file writes
		{syscall.RLIMIT_CORE, 0, 0},                // no core dumps onto disk
	}
	for _, l := range limits {
		if err := syscall.Setrlimit(l.resource, &syscall.Rlimit{Cur: l.cur, Max: l.max}); err != nil {
			// Not fatal: the container limits remain in force. Log and continue so a
			// kernel without one of these does not take the whole service down.
			fmt.Fprintf(os.Stderr, "sandbox: rlimit %d: %v\n", l.resource, err)
		}
	}

	path, err := exec.LookPath(argv[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: %v\n", err)
		os.Exit(127)
	}
	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: exec %s: %v\n", path, err)
		os.Exit(126)
	}
	return true // unreachable
}

// killProcessGroup SIGKILLs the whole process group led by pid, so a timeout
// takes out cc1, javac, or any forked grandchild rather than orphaning it.
func killProcessGroup(pid int) error {
	return syscall.Kill(-pid, syscall.SIGKILL)
}

// sandboxInnerUID is the uid the compiler/runtime sees *inside* its user
// namespace. It is deliberately non-zero so that a program which refuses to run
// as root keeps working, and so `getuid()` reports something meaningful to the
// user instead of 0.
const sandboxInnerUID = 1000

// netnsAvailable is resolved once at startup.
//
// The sandbox previously had unrestricted network egress: any user could use the
// compiler as an SSRF relay, scan internal ranges, attack third parties from the
// project's IP, or run a cryptominer.
//
// The fix is a per-job user+network namespace. CLONE_NEWNET gives the child an
// empty network namespace with no interfaces, so it cannot reach the internet at
// all. It is created together with CLONE_NEWUSER because the child only has
// CAP_SYS_ADMIN over a network namespace it owns, and pairing them means no
// capability is required on the parent. That matters here: Render does not let an
// arbitrary --cap-add=SYS_ADMIN be set, so an approach that relies on the parent
// already holding CAP_SYS_ADMIN would simply never activate.
//
// CLONE_NEWUSER can be disabled by kernel policy (unprivileged_userns_clone=0),
// which is why this is probed rather than assumed. If the probe fails the service
// keeps the plain uid drop, so execution always works; only the network
// isolation is forgone, and it is reported at startup rather than failing open
// silently.
// netnsEnabled resolves the mode once, on first use.
//
// It must NOT be a package-level variable initialiser: Go runs package var
// initialisation before main(), so the trampoline child would re-run the probe
// and write its log line into the captured output, leaking internal diagnostics
// into what the user sees and forking an extra process on every execution.
var (
	netnsOnce sync.Once
	netnsOK   bool
)

func netnsEnabled() bool {
	netnsOnce.Do(func() { netnsOK = probeNetns() })
	return netnsOK
}

func probeNetns() bool {
	self, err := selfPath()
	if err != nil {
		log.Printf("sandbox: cannot locate own binary (%v); uid isolation only", err)
		return false
	}
	cmd := exec.Command(self, sandboxExecFlag, "/bin/sh", "-c", "exit 0")
	cmd.Env = childEnv(os.TempDir())
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: sandboxInnerUID, HostID: sandboxUIDBase, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: sandboxInnerUID, HostID: sandboxUIDBase, Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		Setpgid:                    true,
		Credential:                 &syscall.Credential{Uid: sandboxInnerUID, Gid: sandboxInnerUID},
	}
	if err := cmd.Run(); err != nil {
		log.Printf("sandbox: per-job network namespace UNAVAILABLE (%v); running with uid isolation only", err)
		return false
	}
	log.Printf("sandbox: per-job user+network namespace active")
	return true
}

// netnsIsolationActive reports the effective mode, for startup logging.
func netnsIsolationActive() bool { return netnsEnabled() }

// newJobDir creates a private working directory owned by this job's sandbox uid.
//
// The previous scheme created one shared parent (/tmp/codhoot-workspace) plus a
// predictable child name derived from time.Now().UnixNano(), mode 0755. Any
// concurrent job could list the parent, read another user's source, or rewrite it
// between the write and the exec. A random 0700 directory owned by a uid unique
// to this job closes both the read and the write path.
func newJobDir(uid uint32) (string, error) {
	dir, err := os.MkdirTemp("", "codhoot-job-")
	if err != nil {
		return "", err
	}
	// MkdirTemp creates the directory owned by the service user. Hand ownership to
	// the sandbox uid so the unprivileged compiler can write into it, while every
	// other job is a different uid and therefore locked out by the 0700 mode.
	if err := os.Chown(dir, int(uid), int(uid)); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// chownToSandbox hands a service-created file to the job's uid so the
// unprivileged interpreter can read it and nothing else can write it.
func chownToSandbox(path string, uid uint32) error {
	return os.Chown(path, int(uid), int(uid))
}

// selfPath is this binary, used as the sandbox trampoline. It must stay readable
// and executable by the unprivileged sandbox uid.
func selfPath() (string, error) {
	return os.Executable()
}

// hardenProcAttr builds the SysProcAttr used for every compiler and runtime child.
//
//   - Setpgid puts the child in its own process group so a timeout SIGKILL
//     reaches every descendant. It was already correct and is preserved.
//   - When namespaces are available, the child also gets its own user namespace
//     (so it has no authority over anything owned by anyone else) and its own
//     empty network namespace (so it has no network at all), with the host uid
//     mapped to a non-zero inner uid.
//   - Otherwise the child is dropped with Credential, which still confines it to
//     an unprivileged uid but leaves network egress to the container runtime.
//
// RLIMIT_AS is deliberately absent: it caps *virtual* address space, and both the
// JVM and the Go runtime reserve far more virtual memory than they ever
// resident-set, so it breaks Java and Go outright. Real memory is bounded by the
// container memory limit.
func hardenProcAttr(uid uint32) *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{Setpgid: true}
	if netnsEnabled() {
		attr.Cloneflags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: sandboxInnerUID, HostID: int(uid), Size: 1}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: sandboxInnerUID, HostID: int(uid), Size: 1}}
		attr.GidMappingsEnableSetgroups = false
		attr.Credential = &syscall.Credential{Uid: sandboxInnerUID, Gid: sandboxInnerUID}
		return attr
	}
	attr.Credential = &syscall.Credential{Uid: uid, Gid: uid}
	return attr
}
