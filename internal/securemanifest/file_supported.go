//go:build darwin || linux

package securemanifest

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func readStableFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrFile
	}
	file := os.NewFile(uintptr(fd), "secure-manifest")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrFile
	}
	info, err := file.Stat()
	if err != nil || !validFileInfo(info) || fileHasAccessExpandingMetadata(file) {
		_ = file.Close()
		return nil, ErrFile
	}
	first, err := readPass(file)
	if err != nil {
		_ = file.Close()
		return nil, ErrFile
	}
	second, secondErr := readPass(file)
	after, statErr := file.Stat()
	metadataRejected := statErr != nil || !validFileInfo(after) || fileHasAccessExpandingMetadata(file)
	closeErr := file.Close()
	defer clear(second)
	if secondErr != nil || metadataRejected || closeErr != nil {
		clear(first)
		return nil, ErrFile
	}
	if !os.SameFile(info, after) ||
		after.Size() != info.Size() || after.Size() != int64(len(first)) ||
		after.Mode() != info.Mode() || !after.ModTime().Equal(info.ModTime()) || !bytes.Equal(first, second) {
		clear(first)
		return nil, ErrFile
	}
	return first, nil
}

func validFileInfo(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximumFileSize ||
		info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

func readPass(file *os.File) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, ErrFile
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumFileSize+1))
	if err != nil || len(contents) > maximumFileSize {
		clear(contents)
		return nil, ErrFile
	}
	return contents, nil
}

func fileHasAccessExpandingMetadata(file *os.File) bool {
	if file == nil {
		return true
	}
	if runtime.GOOS == "darwin" && darwinFileHasACL(file) {
		return true
	}
	size, _, errno := syscall.Syscall6(syscall.SYS_FLISTXATTR, file.Fd(), 0, 0, 0, 0, 0)
	if errno != 0 || size > maximumFileSize {
		return true
	}
	if size == 0 {
		return false
	}
	names := make([]byte, size)
	read, _, errno := syscall.Syscall6(
		syscall.SYS_FLISTXATTR,
		file.Fd(),
		uintptr(unsafe.Pointer(&names[0])),
		uintptr(len(names)),
		0,
		0,
		0,
	)
	if errno != 0 || read != size {
		return true
	}
	for len(names) > 0 {
		end := bytes.IndexByte(names, 0)
		if end <= 0 || !allowedExtendedAttribute(runtime.GOOS, string(names[:end])) {
			return true
		}
		names = names[end+1:]
	}
	return false
}

func allowedExtendedAttribute(goos, name string) bool {
	switch goos {
	case "darwin":
		return name == "com.apple.provenance"
	case "linux":
		return name == "security.selinux" || name == "security.ima" || name == "security.evm"
	default:
		return false
	}
}

func darwinFileHasACL(file *os.File) bool {
	const (
		darwinFgetattrlistSyscall  = 228
		darwinAttrBitMapCount      = 5
		darwinExtendedSecurityAttr = 0x00400000
		darwinNoACLEntryCount      = uint32(0xffffffff)
	)
	type attrList struct {
		bitmapCount uint16
		reserved    uint16
		commonAttr  uint32
		volumeAttr  uint32
		directory   uint32
		fileAttr    uint32
		forkAttr    uint32
	}
	attributes := attrList{bitmapCount: darwinAttrBitMapCount, commonAttr: darwinExtendedSecurityAttr}
	buffer := make([]byte, 4096)
	_, _, errno := syscall.Syscall6(
		darwinFgetattrlistSyscall,
		file.Fd(),
		uintptr(unsafe.Pointer(&attributes)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		0,
		0,
	)
	if errno != 0 {
		return true
	}
	total := int(binary.LittleEndian.Uint32(buffer[:4]))
	if total < 12 || total > len(buffer) {
		return true
	}
	referenceOffset := int(int32(binary.LittleEndian.Uint32(buffer[4:8])))
	referenceLength := int(binary.LittleEndian.Uint32(buffer[8:12]))
	dataStart := 4 + referenceOffset
	if referenceLength == 0 {
		return false
	}
	if dataStart < 12 || referenceLength < 44 || dataStart > total-referenceLength {
		return true
	}
	entryCount := binary.LittleEndian.Uint32(buffer[dataStart+36 : dataStart+40])
	return entryCount != darwinNoACLEntryCount
}
