//go:build linux

package isolatedexec

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxCapabilityGateRequiresOwnedImmutableRegularSingleLinkExecutor(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "executor")
	if err := os.WriteFile(executable, []byte("fixture"), 0o500); err != nil {
		t.Fatalf("write executor fixture: %v", err)
	}
	if supervisor, err := newSupervisor(executable, defaultSettings()); err != nil || supervisor == nil {
		t.Fatalf("newSupervisor(secure executable) = %#v, %v", supervisor, err)
	}

	writable := filepath.Join(directory, "writable")
	if err := os.WriteFile(writable, []byte("fixture"), 0o720); err != nil {
		t.Fatalf("write writable fixture: %v", err)
	}
	if err := os.Chmod(writable, 0o720); err != nil {
		t.Fatalf("chmod writable fixture: %v", err)
	}
	if supervisor, err := newSupervisor(writable, defaultSettings()); supervisor != nil || !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("newSupervisor(group-writable) = %#v, %v", supervisor, err)
	}

	symlink := filepath.Join(directory, "executor-link")
	if err := os.Symlink(executable, symlink); err != nil {
		t.Fatalf("create executor symlink: %v", err)
	}
	if supervisor, err := newSupervisor(symlink, defaultSettings()); supervisor != nil || !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("newSupervisor(symlink) = %#v, %v", supervisor, err)
	}

	hardlink := filepath.Join(directory, "executor-hardlink")
	if err := os.Link(executable, hardlink); err != nil {
		t.Fatalf("create executor hard link: %v", err)
	}
	if supervisor, err := newSupervisor(executable, defaultSettings()); supervisor != nil || !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("newSupervisor(multiple links) = %#v, %v", supervisor, err)
	}

	xattrExecutable := filepath.Join(t.TempDir(), "executor-xattr")
	if err := os.WriteFile(xattrExecutable, []byte("fixture"), 0o700); err != nil {
		t.Fatalf("write xattr executor fixture: %v", err)
	}
	if err := unix.Setxattr(xattrExecutable, "user.aiops-executor-test", []byte("present"), 0); err != nil {
		t.Fatalf("set executor xattr: %v", err)
	}
	if err := os.Chmod(xattrExecutable, 0o500); err != nil {
		t.Fatalf("chmod xattr executor fixture: %v", err)
	}
	if supervisor, err := newSupervisor(xattrExecutable, defaultSettings()); supervisor != nil || !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("newSupervisor(xattr) = %#v, %v", supervisor, err)
	}
}

func TestLinuxCommandBoundaryCreatesOwnGroupAndParentDeathSignal(t *testing.T) {
	command := exec.Command("/does/not/run")
	configureProcess(command)
	if command.SysProcAttr == nil || !command.SysProcAttr.Setpgid || command.SysProcAttr.Pdeathsig != syscall.SIGKILL ||
		command.SysProcAttr.PidFD == nil || *command.SysProcAttr.PidFD != -1 {
		t.Fatalf("SysProcAttr = %#v", command.SysProcAttr)
	}
}

func TestLinuxProcessGroupScanAllowsPIDOneWithoutRelaxingSignals(t *testing.T) {
	procRoot := t.TempDir()
	for pid, stat := range map[string]string{
		"1": "1 (write-runner) S 0 1 1 0\n",
		"2": "2 (executor child) S 1 1 1 0\n",
	} {
		directory := filepath.Join(procRoot, pid)
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("mkdir fake proc entry: %v", err)
		}
		if err := os.WriteFile(filepath.Join(directory, "stat"), []byte(stat), 0o600); err != nil {
			t.Fatalf("write fake proc stat: %v", err)
		}
	}

	hasMembers, err := processGroupHasMembersExceptLeaderAt(1, procRoot)
	if err != nil || !hasMembers {
		t.Fatalf("processGroupHasMembersExceptLeaderAt(1) = %t, %v", hasMembers, err)
	}
	if err := signalProcessGroup(1, syscall.SIGKILL); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("signalProcessGroup(1) error = %v, want invalid request", err)
	}
	if _, err := processGroupHasMembersExceptLeaderAt(0, procRoot); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("processGroupHasMembersExceptLeaderAt(0) error = %v, want invalid request", err)
	}
	members, err := processGroupMembersExceptLeaderAt(1, procRoot)
	if err != nil || len(members) != 1 || members[0] != (processGroupMember{pid: 2, ppid: 1, state: 'S'}) {
		t.Fatalf("processGroupMembersExceptLeaderAt(1) = %#v, %v", members, err)
	}
}

func TestLinuxSecureTempRootMountInfoRequiresOneExactSafeTmpfs(t *testing.T) {
	root := "25 1 0:1 / / ro,relatime - overlay overlay rw\n"
	temp := "36 25 0:32 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=16384k,mode=700,uid=65532,gid=65532\n"
	valid := root + temp
	tests := map[string]string{
		"valid":            valid,
		"parent-only":      root,
		"writable-root":    strings.Replace(valid, "ro,relatime", "rw,relatime", 1),
		"propagating-root": strings.Replace(valid, "ro,relatime -", "ro,relatime shared:7 -", 1),
		"missing-noexec":   root + strings.Replace(temp, ",noexec", "", 1),
		"missing-nodev":    root + strings.Replace(temp, ",nodev", "", 1),
		"missing-nosuid":   root + strings.Replace(temp, ",nosuid", "", 1),
		"read-only":        root + strings.Replace(temp, "rw,nosuid", "ro,nosuid", 1),
		"contradictory":    root + strings.Replace(temp, "rw,nosuid", "rw,ro,nosuid", 1),
		"wrong-filesystem": root + strings.Replace(temp, "- tmpfs", "- ext4", 1),
		"subtree-bind":     root + strings.Replace(temp, "0:32 / /tmp", "0:32 /nested /tmp", 1),
		"propagating":      root + strings.Replace(temp, "relatime -", "relatime shared:7 -", 1),
		"child-mount":      valid + "37 36 0:33 / /tmp/nested rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n",
		"duplicate-overmount": valid +
			"37 25 0:33 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=16384k\n",
		"malformed": "not mountinfo\n",
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			got := mountInfoHasSecureRuntimeRoots([]byte(contents), "/tmp", 36, 25)
			if got != (name == "valid") {
				t.Fatalf("mountInfoHasSecureTempRoot() = %t for %q", got, contents)
			}
		})
	}
	if mountInfoHasSecureRuntimeRoots([]byte(valid), "/tmp", 37, 25) {
		t.Fatal("mountInfoHasSecureRuntimeRoots(wrong temp mount ID) = true")
	}
	if mountInfoHasSecureRuntimeRoots([]byte(valid), "/tmp", 36, 24) {
		t.Fatal("mountInfoHasSecureRuntimeRoots(wrong root mount ID) = true")
	}
}

func TestLinuxFDInfoMountIDIsStrictAndBounded(t *testing.T) {
	tests := map[string]struct {
		contents string
		wantID   uint64
		wantOK   bool
	}{
		"valid":     {contents: "pos:\t0\nflags:\t012000000\nmnt_id:\t36\nino:\t1\n", wantID: 36, wantOK: true},
		"missing":   {contents: "pos:\t0\nflags:\t012000000\n"},
		"zero":      {contents: "mnt_id:\t0\n"},
		"negative":  {contents: "mnt_id:\t-1\n"},
		"duplicate": {contents: "mnt_id:\t36\nmnt_id:\t37\n"},
		"extra":     {contents: "mnt_id:\t36 extra\n"},
		"nul":       {contents: "mnt_id:\t36\x00\n"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotID, gotOK := parseFDInfoMountID([]byte(test.contents))
			if gotID != test.wantID || gotOK != test.wantOK {
				t.Fatalf("parseFDInfoMountID() = %d, %t; want %d, %t", gotID, gotOK, test.wantID, test.wantOK)
			}
		})
	}
}

func TestLinuxSecureTempRootStatfsRequiresBoundedWritableTmpfs(t *testing.T) {
	valid := unix.Statfs_t{
		Type:   unix.TMPFS_MAGIC,
		Bsize:  4096,
		Frsize: 4096,
		Blocks: (16 << 20) / 4096,
		Flags:  unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC,
	}
	if !statfsHasSecureTempRoot(valid) {
		t.Fatal("statfsHasSecureTempRoot(valid) = false")
	}
	for name, mutate := range map[string]func(*unix.Statfs_t){
		"not-tmpfs":      func(value *unix.Statfs_t) { value.Type = unix.EXT4_SUPER_MAGIC },
		"missing-noexec": func(value *unix.Statfs_t) { value.Flags &^= unix.ST_NOEXEC },
		"missing-nodev":  func(value *unix.Statfs_t) { value.Flags &^= unix.ST_NODEV },
		"missing-nosuid": func(value *unix.Statfs_t) { value.Flags &^= unix.ST_NOSUID },
		"read-only":      func(value *unix.Statfs_t) { value.Flags |= unix.ST_RDONLY },
		"zero-capacity":  func(value *unix.Statfs_t) { value.Blocks = 0 },
		"oversized":      func(value *unix.Statfs_t) { value.Blocks++ },
		"overflow":       func(value *unix.Statfs_t) { value.Blocks = ^value.Blocks },
		"invalid-unit":   func(value *unix.Statfs_t) { value.Frsize, value.Bsize = 0, 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if statfsHasSecureTempRoot(candidate) {
				t.Fatalf("statfsHasSecureTempRoot(%s) = true", name)
			}
		})
	}
	frsizeWins := valid
	frsizeWins.Bsize = 1 << 20
	if !statfsHasSecureTempRoot(frsizeWins) {
		t.Fatal("statfsHasSecureTempRoot() ignored valid Frsize")
	}
	fallback := valid
	fallback.Frsize = 0
	if !statfsHasSecureTempRoot(fallback) {
		t.Fatal("statfsHasSecureTempRoot() did not fall back to Bsize")
	}
	if statfsReadOnly(valid) {
		t.Fatal("statfsReadOnly(writable) = true")
	}
	readOnly := valid
	readOnly.Flags |= unix.ST_RDONLY
	if !statfsReadOnly(readOnly) {
		t.Fatal("statfsReadOnly(read-only) = false")
	}
}

func TestLinuxSecureTempRootMetadataRequiresPrivateOwnedDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("chmod temp root: %v", err)
	}
	descriptor, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open temp root: %v", err)
	}
	defer unix.Close(descriptor)
	var metadata unix.Stat_t
	if err := unix.Fstat(descriptor, &metadata); err != nil {
		t.Fatalf("fstat temp root: %v", err)
	}
	if !tempRootMetadataSecure(metadata, uint32(os.Geteuid()), uint32(os.Getegid())) {
		t.Fatal("tempRootMetadataSecure(private owned directory) = false")
	}
	if tempRootMetadataSecure(metadata, uint32(os.Geteuid())+1, uint32(os.Getegid())) {
		t.Fatal("tempRootMetadataSecure(wrong owner) = true")
	}
	permissive := metadata
	permissive.Mode = permissive.Mode&^0o7777 | 0o750
	if tempRootMetadataSecure(permissive, uint32(os.Geteuid()), uint32(os.Getegid())) {
		t.Fatal("tempRootMetadataSecure(permissive mode) = true")
	}
	notDirectory := metadata
	notDirectory.Mode = notDirectory.Mode&^unix.S_IFMT | unix.S_IFLNK
	if tempRootMetadataSecure(notDirectory, uint32(os.Geteuid()), uint32(os.Getegid())) {
		t.Fatal("tempRootMetadataSecure(non-directory) = true")
	}
}

func TestLinuxPrivateJobDirectoryStaysBoundToRetainedDescriptor(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	relocated := filepath.Join(parent, "relocated")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	descriptor, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer unix.Close(descriptor)
	if err := os.Rename(root, relocated); err != nil {
		t.Fatalf("relocate root after open: %v", err)
	}
	name, err := createPrivateDirectoryAt(descriptor, "job-", uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		t.Fatalf("createPrivateDirectoryAt() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(relocated, name)); err != nil {
		t.Fatalf("retained descriptor did not create in original inode: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path replacement unexpectedly selected: %v", err)
	}
	if err := unix.Unlinkat(descriptor, name, unix.AT_REMOVEDIR); err != nil {
		t.Fatalf("unlink private directory: %v", err)
	}
}

func TestLinuxRuntimeJobPathIsRecheckedAndCleanupIsDescriptorAnchored(t *testing.T) {
	root, err := os.Open("/tmp")
	if err != nil {
		t.Fatalf("open /tmp: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	mountID, ok := descriptorMountID(int(root.Fd()))
	if !ok {
		t.Fatal("descriptorMountID(/tmp) failed")
	}
	name, err := createPrivateDirectoryAt(int(root.Fd()), "aiops-executor-test-", uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		t.Fatalf("create private runtime directory: %v", err)
	}
	jobDirectory := filepath.Join("/tmp", name)
	t.Cleanup(func() { _ = removeRuntimeJobDirectory(root, jobDirectory) })
	if !validateRuntimeJobDirectoryForIdentity(
		"/tmp", root, mountID, jobDirectory, uint32(os.Geteuid()), uint32(os.Getegid()),
	) {
		t.Fatal("validateRuntimeJobDirectoryForIdentity(valid) = false")
	}
	if validateRuntimeJobDirectoryForIdentity(
		"/tmp", root, mountID+1, jobDirectory, uint32(os.Geteuid()), uint32(os.Getegid()),
	) {
		t.Fatal("validateRuntimeJobDirectoryForIdentity(wrong mount ID) = true")
	}
	if err := os.Mkdir(filepath.Join(jobDirectory, "nested"), 0o700); err != nil {
		t.Fatalf("mkdir nested runtime data: %v", err)
	}
	if err := os.WriteFile(filepath.Join(jobDirectory, "nested", "data"), []byte("non-secret fixture"), 0o600); err != nil {
		t.Fatalf("write nested runtime data: %v", err)
	}
	if err := removeRuntimeJobDirectory(root, jobDirectory); err != nil {
		t.Fatalf("removeRuntimeJobDirectory() error = %v", err)
	}
	if _, err := os.Stat(jobDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime job directory still exists: %v", err)
	}
}
