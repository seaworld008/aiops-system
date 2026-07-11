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
	"unsafe"

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
	if err := ensureChildSubreaper(); err != nil {
		return ErrUnsupportedPlatform
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

func ensureChildSubreaper() error {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return err
	}
	var enabled int32
	if err := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&enabled)), 0, 0, 0); err != nil {
		return err
	}
	if enabled != 1 {
		return ErrUnsupportedPlatform
	}
	return nil
}

// validateRuntimeBoundary is part of the non-production startup capability
// probe. It intentionally rejects a host directory, an inherited root mount,
// or an unbounded tmpfs before the runner can wait for work.
func openRuntimeBoundary(tempRoot string) (*os.File, uint64, error) {
	if tempRoot != "/tmp" || os.Geteuid() != isolatedRuntimeUID || os.Getegid() != isolatedRuntimeGID {
		return nil, 0, ErrUnsupportedPlatform
	}
	descriptor, err := unix.Open(tempRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, ErrUnsupportedPlatform
	}
	fail := func() (*os.File, uint64, error) {
		_ = unix.Close(descriptor)
		return nil, 0, ErrUnsupportedPlatform
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
	return file, tempMountID, nil
}

func createRuntimeJobDirectory(
	root string,
	handle *os.File,
	expectedMountID uint64,
) (string, *runtimeJobDirectory, error) {
	if root != "/tmp" || handle == nil || expectedMountID == 0 ||
		!runtimeRootPathMatches(root, handle, expectedMountID) {
		return "", nil, ErrInvalidConfiguration
	}
	descriptor := int(handle.Fd())
	if descriptor < 0 {
		return "", nil, ErrInvalidConfiguration
	}
	name, err := createPrivateDirectoryAt(descriptor, "aiops-executor-", isolatedRuntimeUID, isolatedRuntimeGID)
	if err != nil {
		return "", nil, err
	}
	jobDirectory := filepath.Join(root, name)
	job, err := captureRuntimeJobDirectory(jobDirectory)
	if err != nil || !validateRuntimeJobDirectory(root, handle, expectedMountID, jobDirectory, job) {
		if job != nil && job.file != nil {
			_ = job.file.Close()
		}
		_ = unix.Unlinkat(descriptor, name, unix.AT_REMOVEDIR)
		return "", nil, ErrUnsupportedPlatform
	}
	return jobDirectory, job, nil
}

func captureRuntimeJobDirectory(jobDirectory string) (*runtimeJobDirectory, error) {
	descriptor, err := unix.Open(jobDirectory, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsupportedPlatform
	}
	var metadata unix.Stat_t
	if err := unix.Fstat(descriptor, &metadata); err != nil {
		_ = unix.Close(descriptor)
		return nil, ErrUnsupportedPlatform
	}
	file := os.NewFile(uintptr(descriptor), "aiops-isolated-job-directory")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, ErrUnsupportedPlatform
	}
	return &runtimeJobDirectory{file: file, device: uint64(metadata.Dev), inode: metadata.Ino}, nil
}

func runtimeRootPathMatches(root string, handle *os.File, expectedMountID uint64) bool {
	if root != "/tmp" || handle == nil || expectedMountID == 0 {
		return false
	}
	retainedDescriptor := int(handle.Fd())
	if retainedDescriptor < 0 {
		return false
	}
	pathDescriptor, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(pathDescriptor)
	retainedMountID, retainedOK := descriptorMountID(retainedDescriptor)
	pathMountID, pathOK := descriptorMountID(pathDescriptor)
	var retained, observed unix.Stat_t
	var retainedFilesystem, observedFilesystem unix.Statfs_t
	return retainedOK && pathOK && retainedMountID == expectedMountID && pathMountID == expectedMountID &&
		unix.Fstat(retainedDescriptor, &retained) == nil && unix.Fstat(pathDescriptor, &observed) == nil &&
		unix.Fstatfs(retainedDescriptor, &retainedFilesystem) == nil &&
		unix.Fstatfs(pathDescriptor, &observedFilesystem) == nil &&
		runtimeRootDescriptorsSecure(
			retained, observed, retainedFilesystem, observedFilesystem, isolatedRuntimeUID, isolatedRuntimeGID,
		)
}

func runtimeRootDescriptorsSecure(
	retained, observed unix.Stat_t,
	retainedFilesystem, observedFilesystem unix.Statfs_t,
	expectedUID, expectedGID uint32,
) bool {
	return retained.Dev == observed.Dev && retained.Ino == observed.Ino &&
		tempRootMetadataSecure(retained, expectedUID, expectedGID) &&
		tempRootMetadataSecure(observed, expectedUID, expectedGID) &&
		statfsHasSecureTempRoot(retainedFilesystem) && statfsHasSecureTempRoot(observedFilesystem)
}

func validateRuntimeJobDirectory(
	root string,
	handle *os.File,
	expectedMountID uint64,
	jobDirectory string,
	job *runtimeJobDirectory,
) bool {
	return runtimeRootPathMatches(root, handle, expectedMountID) && filepath.Dir(jobDirectory) == root &&
		runtimeJobPathMatches(handle, expectedMountID, jobDirectory, job, isolatedRuntimeUID, isolatedRuntimeGID)
}

func runtimeJobPathMatches(
	handle *os.File,
	expectedMountID uint64,
	jobDirectory string,
	job *runtimeJobDirectory,
	expectedUID, expectedGID uint32,
) bool {
	if handle == nil || job == nil || job.file == nil || expectedMountID == 0 {
		return false
	}
	name := filepath.Base(jobDirectory)
	if !strings.HasPrefix(name, "aiops-executor-") || strings.ContainsAny(name, "/\\\x00") {
		return false
	}
	retainedDescriptor := int(handle.Fd())
	pathDescriptor, err := unix.Open(jobDirectory, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(pathDescriptor)
	pathMountID, pathOK := descriptorMountID(pathDescriptor)
	jobMountID, jobOK := descriptorMountID(int(job.file.Fd()))
	var expected, observed, retained unix.Stat_t
	return pathOK && jobOK && pathMountID == expectedMountID && jobMountID == expectedMountID &&
		unix.Fstatat(retainedDescriptor, name, &expected, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		unix.Fstat(pathDescriptor, &observed) == nil && unix.Fstat(int(job.file.Fd()), &retained) == nil &&
		uint64(expected.Dev) == job.device && expected.Ino == job.inode &&
		uint64(observed.Dev) == job.device && observed.Ino == job.inode &&
		uint64(retained.Dev) == job.device && retained.Ino == job.inode && retained.Nlink > 0 &&
		tempRootMetadataSecure(observed, expectedUID, expectedGID) &&
		tempRootMetadataSecure(retained, expectedUID, expectedGID)
}

func removeRuntimeJobDirectory(handle *os.File, jobDirectory string, job *runtimeJobDirectory) error {
	return removeRuntimeJobDirectoryForIdentity(
		"/tmp", handle, jobDirectory, job, isolatedRuntimeUID, isolatedRuntimeGID, true,
	)
}

func removeRuntimeJobDirectoryForIdentity(
	root string,
	handle *os.File,
	jobDirectory string,
	job *runtimeJobDirectory,
	expectedUID, expectedGID uint32,
	requireSecureRoot bool,
) error {
	if handle == nil || job == nil || job.file == nil || filepath.Dir(jobDirectory) != root {
		return ErrInvalidConfiguration
	}
	name := filepath.Base(jobDirectory)
	if !strings.HasPrefix(name, "aiops-executor-") || strings.ContainsAny(name, "/\\\x00") {
		return ErrInvalidConfiguration
	}
	descriptor := int(handle.Fd())
	if descriptor < 0 {
		return ErrInvalidConfiguration
	}
	mountID, ok := descriptorMountID(descriptor)
	if !ok || (requireSecureRoot && !runtimeRootPathMatches(root, handle, mountID)) ||
		!runtimeJobPathMatches(handle, mountID, jobDirectory, job, expectedUID, expectedGID) {
		return ErrTerminationUnconfirmed
	}
	anchored := filepath.Join("/proc/self/fd", strconv.Itoa(descriptor), name)
	if err := os.RemoveAll(anchored); err != nil {
		return ErrTerminationUnconfirmed
	}
	var retained, named unix.Stat_t
	nameErr := unix.Fstatat(descriptor, name, &named, unix.AT_SYMLINK_NOFOLLOW)
	if err := unix.Fstat(int(job.file.Fd()), &retained); err != nil || uint64(retained.Dev) != job.device ||
		retained.Ino != job.inode || retained.Nlink != 0 || !errors.Is(nameErr, syscall.ENOENT) ||
		(requireSecureRoot && !runtimeRootPathMatches(root, handle, mountID)) {
		return ErrTerminationUnconfirmed
	}
	if err := job.file.Close(); err != nil {
		return ErrTerminationUnconfirmed
	}
	job.file = nil
	return nil
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
			if err != nil || parsed != expectedRootMountID || rootMatches != 1 || separator != 6 ||
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
	members, err := processGroupMembersExceptLeaderAt(pid, "/proc")
	return len(members) != 0, err
}

func processGroupHasMembersExceptLeaderAt(pid int, procRoot string) (bool, error) {
	members, err := processGroupMembersExceptLeaderAt(pid, procRoot)
	return len(members) != 0, err
}

type processGroupMember struct {
	pid   int
	ppid  int
	state byte
}

func processGroupMembersExceptLeaderAt(pid int, procRoot string) ([]processGroupMember, error) {
	if pid < 1 || procRoot == "" {
		return nil, ErrInvalidRequest
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil || len(entries) > 1<<20 {
		return nil, ErrTerminationUnconfirmed
	}
	members := make([]processGroupMember, 0, 4)
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
			return nil, ErrTerminationUnconfirmed
		}
		closing := bytes.LastIndexByte(contents, ')')
		if closing < 1 || closing+2 >= len(contents) || contents[closing+1] != ' ' {
			return nil, ErrTerminationUnconfirmed
		}
		fields := bytes.Fields(contents[closing+2:])
		if len(fields) < 3 || len(fields[0]) != 1 {
			return nil, ErrTerminationUnconfirmed
		}
		parent, parentErr := strconv.Atoi(string(fields[1]))
		group, groupErr := strconv.Atoi(string(fields[2]))
		if parentErr != nil || groupErr != nil || parent < 0 {
			return nil, ErrTerminationUnconfirmed
		}
		if group == pid {
			members = append(members, processGroupMember{pid: candidate, ppid: parent, state: fields[0][0]})
			if len(members) > 1<<16 {
				return nil, ErrTerminationUnconfirmed
			}
		}
	}
	return members, nil
}

func reapAdoptedProcessGroupZombies(groupID, parentPID int) error {
	if groupID <= 1 || parentPID < 1 {
		return ErrInvalidRequest
	}
	members, err := processGroupMembersExceptLeaderAt(groupID, "/proc")
	if err != nil {
		return err
	}
	for _, member := range members {
		if member.state != 'Z' || member.ppid != parentPID {
			continue
		}
		var status syscall.WaitStatus
		waited, waitErr := syscall.Wait4(member.pid, &status, syscall.WNOHANG, nil)
		switch {
		case waitErr == nil && (waited == 0 || waited == member.pid):
			continue
		case errors.Is(waitErr, syscall.ECHILD), errors.Is(waitErr, syscall.ESRCH):
			if _, statErr := os.Stat(filepath.Join("/proc", strconv.Itoa(member.pid))); errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			return ErrTerminationUnconfirmed
		default:
			return ErrTerminationUnconfirmed
		}
	}
	return nil
}
