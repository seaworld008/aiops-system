//go:build linux

package isolatedexec

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	isolatedRuntimeUID = 65532
	isolatedRuntimeGID = 65532
	tempRootMaxBytes   = 16 << 20
	mountInfoMaxBytes  = 1 << 20
	fdInfoMaxBytes     = 16 << 10
)

func validatePlatform(executablePath string, allowCurrentOwner bool) error {
	if executablePath == "" || len(executablePath) > 4096 || !filepath.IsAbs(executablePath) ||
		filepath.Clean(executablePath) != executablePath || strings.TrimSpace(executablePath) != executablePath {
		return ErrInvalidConfiguration
	}
	for _, character := range executablePath {
		if character < 0x20 || character == 0x7f {
			return ErrInvalidConfiguration
		}
	}
	info, err := os.Lstat(executablePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || executableHasUnsafeMetadata(executablePath) {
		return ErrInvalidConfiguration
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || (stat.Uid != 0 && (!allowCurrentOwner || stat.Uid != uint32(os.Geteuid()))) {
		return ErrInvalidConfiguration
	}
	parentInfo, err := os.Lstat(filepath.Dir(executablePath))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o022 != 0 {
		return ErrInvalidConfiguration
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || (parentStat.Uid != 0 && (!allowCurrentOwner || parentStat.Uid != uint32(os.Geteuid()))) {
		return ErrInvalidConfiguration
	}
	for _, required := range []string{"/proc/self/status", "/proc/self/fd"} {
		if _, err := os.Stat(required); err != nil {
			return ErrUnsupportedPlatform
		}
	}
	if _, err := processGroupHasMembersExceptLeader(os.Getpid()); err != nil {
		return ErrUnsupportedPlatform
	}
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return ErrUnsupportedPlatform
	}
	defer unix.Close(pidfd)
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return ErrUnsupportedPlatform
	}
	return nil
}

// validateRuntimeBoundary is part of the non-production startup capability
// probe. It intentionally rejects a host directory, an inherited root mount,
// or an unbounded tmpfs before the runner can wait for work.
func openRuntimeBoundary(tempRoot string) (*os.File, error) {
	if tempRoot != "/tmp" || os.Geteuid() != isolatedRuntimeUID || os.Getegid() != isolatedRuntimeGID {
		return nil, ErrUnsupportedPlatform
	}
	descriptor, err := unix.Open(tempRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsupportedPlatform
	}
	fail := func() (*os.File, error) {
		_ = unix.Close(descriptor)
		return nil, ErrUnsupportedPlatform
	}
	var metadata unix.Stat_t
	if err := unix.Fstat(descriptor, &metadata); err != nil ||
		!tempRootMetadataSecure(metadata, isolatedRuntimeUID, isolatedRuntimeGID) {
		return fail()
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(descriptor, &filesystem); err != nil || !statfsHasSecureTempRoot(filesystem) {
		return fail()
	}
	tempMountID, ok := descriptorMountID(descriptor)
	if !ok {
		return fail()
	}
	rootDescriptor, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail()
	}
	defer unix.Close(rootDescriptor)
	var rootFilesystem unix.Statfs_t
	rootMountID, rootMountOK := descriptorMountID(rootDescriptor)
	if err := unix.Fstatfs(rootDescriptor, &rootFilesystem); err != nil || !statfsReadOnly(rootFilesystem) || !rootMountOK {
		return fail()
	}
	mountInfo, err := readMountInfo()
	if err != nil || !mountInfoHasSecureRuntimeRoots(mountInfo, tempRoot, tempMountID, rootMountID) {
		return fail()
	}
	canary, err := createPrivateDirectoryAt(descriptor, "aiops-capability-", isolatedRuntimeUID, isolatedRuntimeGID)
	if err != nil || unix.Unlinkat(descriptor, canary, unix.AT_REMOVEDIR) != nil {
		return fail()
	}
	file := os.NewFile(uintptr(descriptor), "aiops-isolated-temp-root")
	if file == nil {
		return fail()
	}
	return file, nil
}

func createRuntimeJobDirectory(root string, handle *os.File) (string, error) {
	if root != "/tmp" || handle == nil {
		return "", ErrInvalidConfiguration
	}
	descriptor := int(handle.Fd())
	if descriptor < 0 {
		return "", ErrInvalidConfiguration
	}
	name, err := createPrivateDirectoryAt(descriptor, "aiops-executor-", isolatedRuntimeUID, isolatedRuntimeGID)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, name), nil
}

func createPrivateDirectoryAt(descriptor int, prefix string, expectedUID, expectedGID uint32) (string, error) {
	if descriptor < 0 || prefix == "" || strings.ContainsAny(prefix, "/\\\x00") {
		return "", ErrInvalidConfiguration
	}
	for attempt := 0; attempt < 8; attempt++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", ErrUnsupportedPlatform
		}
		name := prefix + hex.EncodeToString(random)
		if err := unix.Mkdirat(descriptor, name, 0o700); errors.Is(err, syscall.EEXIST) {
			continue
		} else if err != nil {
			return "", ErrUnsupportedPlatform
		}
		var metadata unix.Stat_t
		if err := unix.Fstatat(descriptor, name, &metadata, unix.AT_SYMLINK_NOFOLLOW); err == nil &&
			tempRootMetadataSecure(metadata, expectedUID, expectedGID) {
			return name, nil
		}
		_ = unix.Unlinkat(descriptor, name, unix.AT_REMOVEDIR)
		return "", ErrUnsupportedPlatform
	}
	return "", ErrUnsupportedPlatform
}

func tempRootMetadataSecure(value unix.Stat_t, expectedUID, expectedGID uint32) bool {
	return value.Mode&unix.S_IFMT == unix.S_IFDIR && value.Mode&0o7777 == 0o700 &&
		value.Uid == expectedUID && value.Gid == expectedGID
}

func readMountInfo() ([]byte, error) {
	return readBoundedProcFile("/proc/self/mountinfo", mountInfoMaxBytes)
}

func readBoundedProcFile(path string, maximum int64) ([]byte, error) {
	if path == "" || maximum < 1 || maximum > mountInfoMaxBytes {
		return nil, ErrUnsupportedPlatform
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(contents) == 0 || int64(len(contents)) > maximum {
		return nil, ErrUnsupportedPlatform
	}
	return contents, nil
}

func parseFDInfoMountID(contents []byte) (uint64, bool) {
	if len(contents) == 0 || len(contents) > fdInfoMaxBytes || bytes.IndexByte(contents, 0) >= 0 {
		return 0, false
	}
	found := false
	var mountID uint64
	for _, line := range bytes.Split(contents, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) == 0 || !bytes.Equal(fields[0], []byte("mnt_id:")) {
			continue
		}
		if found || len(fields) != 2 {
			return 0, false
		}
		parsed, err := strconv.ParseUint(string(fields[1]), 10, 64)
		if err != nil || parsed == 0 {
			return 0, false
		}
		mountID = parsed
		found = true
	}
	return mountID, found
}

func descriptorMountID(descriptor int) (uint64, bool) {
	if descriptor < 0 {
		return 0, false
	}
	fdInfo, err := readBoundedProcFile(filepath.Join("/proc/self/fdinfo", strconv.Itoa(descriptor)), fdInfoMaxBytes)
	if err != nil {
		return 0, false
	}
	return parseFDInfoMountID(fdInfo)
}

func mountInfoHasSecureRuntimeRoots(contents []byte, tempRoot string, expectedTempMountID, expectedRootMountID uint64) bool {
	if tempRoot != "/tmp" || expectedTempMountID == 0 || expectedRootMountID == 0 ||
		expectedTempMountID == expectedRootMountID || len(contents) == 0 || len(contents) > mountInfoMaxBytes ||
		bytes.IndexByte(contents, 0) >= 0 {
		return false
	}
	matches := 0
	rootMatches := 0
	var rootMountID uint64
	for _, line := range bytes.Split(contents, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		fields := bytes.Fields(line)
		if len(fields) < 10 {
			return false
		}
		separator := -1
		for index := 6; index < len(fields); index++ {
			if bytes.Equal(fields[index], []byte{'-'}) {
				separator = index
				break
			}
		}
		if separator < 6 || separator+3 >= len(fields) {
			return false
		}
		mountPoint := string(fields[4])
		if mountPoint == "/" {
			rootMatches++
			parsed, err := strconv.ParseUint(string(fields[0]), 10, 64)
			if err != nil || parsed != expectedRootMountID || rootMatches != 1 ||
				!mountOptionsContainAll(string(fields[5]), "ro") || mountOptionsContainAny(string(fields[5]), "rw") {
				return false
			}
			rootMountID = parsed
		}
		if strings.HasPrefix(mountPoint, tempRoot+"/") {
			return false
		}
		if mountPoint != tempRoot {
			continue
		}
		matches++
		mountID, err := strconv.ParseUint(string(fields[0]), 10, 64)
		if matches != 1 || err != nil || mountID != expectedTempMountID || separator != 6 ||
			!bytes.Equal(fields[3], []byte{'/'}) ||
			!bytes.Equal(fields[separator+1], []byte("tmpfs")) ||
			!mountOptionsContainAll(string(fields[5]), "rw", "nosuid", "nodev", "noexec") ||
			mountOptionsContainAny(string(fields[5]), "ro", "suid", "dev", "exec") {
			return false
		}
	}
	return matches == 1 && rootMatches == 1 && rootMountID == expectedRootMountID
}

func mountOptionsContainAny(value string, candidates ...string) bool {
	options := make(map[string]struct{}, len(candidates))
	for _, option := range strings.Split(value, ",") {
		options[option] = struct{}{}
	}
	for _, candidate := range candidates {
		if _, ok := options[candidate]; ok {
			return true
		}
	}
	return false
}

func mountOptionsContainAll(value string, required ...string) bool {
	options := make(map[string]struct{}, len(required))
	for _, option := range strings.Split(value, ",") {
		if option == "" {
			return false
		}
		options[option] = struct{}{}
	}
	for _, option := range required {
		if _, ok := options[option]; !ok {
			return false
		}
	}
	return true
}

func statfsHasSecureTempRoot(value unix.Statfs_t) bool {
	flags := uint64(value.Flags)
	required := uint64(unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC)
	fragmentSize := int64(value.Frsize)
	if fragmentSize <= 0 {
		fragmentSize = int64(value.Bsize)
	}
	blocks := uint64(value.Blocks)
	if value.Type != unix.TMPFS_MAGIC || flags&required != required || flags&uint64(unix.ST_RDONLY) != 0 ||
		fragmentSize <= 0 || blocks == 0 {
		return false
	}
	unit := uint64(fragmentSize)
	return unit <= tempRootMaxBytes && blocks <= uint64(tempRootMaxBytes)/unit
}

func statfsReadOnly(value unix.Statfs_t) bool {
	return uint64(value.Flags)&uint64(unix.ST_RDONLY) != 0
}

func executableHasUnsafeMetadata(path string) bool {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return true
	}
	defer unix.Close(descriptor)
	size, err := unix.Flistxattr(descriptor, nil)
	if err != nil || size < 0 || size > 1<<20 {
		return true
	}
	if size == 0 {
		return false
	}
	names := make([]byte, size)
	read, err := unix.Flistxattr(descriptor, names)
	if err != nil || read != size {
		return true
	}
	for len(names) > 0 {
		end := bytes.IndexByte(names, 0)
		if end <= 0 || !allowedExecutorExtendedAttribute(string(names[:end])) {
			return true
		}
		names = names[end+1:]
	}
	return false
}

func allowedExecutorExtendedAttribute(name string) bool {
	return name == "security.selinux" || name == "security.ima" || name == "security.evm"
}

func configureProcess(command *exec.Cmd) {
	if command == nil {
		return
	}
	pidfd := -1
	command.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
		PidFD:     &pidfd,
	}
}

func stableProcessHandle(command *exec.Cmd) int {
	if command == nil || command.SysProcAttr == nil || command.SysProcAttr.PidFD == nil {
		return -1
	}
	return *command.SysProcAttr.PidFD
}

func waitStableProcessExit(handle int) error {
	if handle < 0 {
		return ErrTerminationUnconfirmed
	}
	descriptors := []unix.PollFd{{Fd: int32(handle), Events: unix.POLLIN}}
	for {
		count, err := unix.Poll(descriptors, -1)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil || count != 1 || descriptors[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 ||
			descriptors[0].Revents&(unix.POLLNVAL|unix.POLLERR) != 0 {
			return ErrTerminationUnconfirmed
		}
		return nil
	}
}

func closeStableProcessHandle(handle int) error {
	if handle < 0 {
		return ErrTerminationUnconfirmed
	}
	return unix.Close(handle)
}

func signalProcessGroup(pid int, signal syscall.Signal) error {
	if pid <= 1 {
		return ErrInvalidRequest
	}
	err := syscall.Kill(-pid, signal)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func processGroupGone(pid int) (bool, error) {
	if pid <= 1 {
		return false, ErrInvalidRequest
	}
	err := syscall.Kill(-pid, 0)
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, syscall.ESRCH):
		return true, nil
	default:
		return false, err
	}
}

func processGroupHasMembersExceptLeader(pid int) (bool, error) {
	return processGroupHasMembersExceptLeaderAt(pid, "/proc")
}

func processGroupHasMembersExceptLeaderAt(pid int, procRoot string) (bool, error) {
	if pid < 1 || procRoot == "" {
		return false, ErrInvalidRequest
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil || len(entries) > 1<<20 {
		return false, ErrTerminationUnconfirmed
	}
	for _, entry := range entries {
		candidate, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || candidate < 1 || candidate == pid {
			continue
		}
		contents, readErr := os.ReadFile(filepath.Join(procRoot, entry.Name(), "stat"))
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil || len(contents) == 0 || len(contents) > 4096 {
			return false, ErrTerminationUnconfirmed
		}
		closing := bytes.LastIndexByte(contents, ')')
		if closing < 1 || closing+2 >= len(contents) || contents[closing+1] != ' ' {
			return false, ErrTerminationUnconfirmed
		}
		fields := bytes.Fields(contents[closing+2:])
		if len(fields) < 3 {
			return false, ErrTerminationUnconfirmed
		}
		group, groupErr := strconv.Atoi(string(fields[2]))
		if groupErr != nil {
			return false, ErrTerminationUnconfirmed
		}
		if group == pid {
			return true, nil
		}
	}
	return false, nil
}
