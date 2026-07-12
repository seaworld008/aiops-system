package readrunnerclient

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	maximumTrustFileSize = 1 << 20
	maximumTrustPathSize = 4096
)

type openedTrustFile struct {
	file       *os.File
	info       os.FileInfo
	privateKey bool
}

func loadTrustFiles(options Options) (rootCA, certificate, privateKey []byte, err error) {
	candidates := []struct {
		path       string
		privateKey bool
	}{
		{options.RootCAFile, false},
		{options.ClientCertificateFile, false},
		{options.ClientPrivateKeyFile, true},
	}
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if !validTrustPath(candidate.path) {
			return nil, nil, nil, ErrInvalidConfiguration
		}
		if _, duplicate := seen[candidate.path]; duplicate {
			return nil, nil, nil, ErrInvalidConfiguration
		}
		seen[candidate.path] = struct{}{}
	}

	opened := make([]*openedTrustFile, 0, len(candidates))
	defer func() {
		for _, file := range opened {
			_ = file.file.Close()
		}
	}()
	for _, candidate := range candidates {
		file, openErr := openTrustFile(candidate.path, candidate.privateKey)
		if openErr != nil {
			return nil, nil, nil, ErrInvalidConfiguration
		}
		for _, existing := range opened {
			if os.SameFile(existing.info, file.info) {
				_ = file.file.Close()
				return nil, nil, nil, ErrInvalidConfiguration
			}
		}
		opened = append(opened, file)
	}
	contents := make([][]byte, len(opened))
	for index, file := range opened {
		contents[index], err = file.readStable()
		if err != nil {
			for _, value := range contents {
				clear(value)
			}
			return nil, nil, nil, ErrInvalidConfiguration
		}
	}
	return contents[0], contents[1], contents[2], nil
}

func validTrustPath(path string) bool {
	if path == "" || len(path) > maximumTrustPathSize || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		strings.TrimSpace(path) != path {
		return false
	}
	for _, character := range path {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func openTrustFile(path string, privateKey bool) (*openedTrustFile, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	file := os.NewFile(uintptr(fd), "read-runner-client-trust-file")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrInvalidConfiguration
	}
	info, err := file.Stat()
	if err != nil || !validTrustFileInfo(info, privateKey) || trustFileHasExtendedMetadata(file) {
		_ = file.Close()
		return nil, ErrInvalidConfiguration
	}
	return &openedTrustFile{file: file, info: info, privateKey: privateKey}, nil
}

func validTrustFileInfo(info os.FileInfo, privateKey bool) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumTrustFileSize {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return false
	}
	if privateKey {
		return info.Mode().Perm()&0o077 == 0
	}
	return info.Mode().Perm()&0o022 == 0
}

func (opened *openedTrustFile) readStable() ([]byte, error) {
	if opened == nil || opened.file == nil || opened.info == nil {
		return nil, ErrInvalidConfiguration
	}
	first, err := readTrustFile(opened.file)
	if err != nil {
		return nil, err
	}
	second, err := readTrustFile(opened.file)
	if err != nil {
		clear(first)
		return nil, err
	}
	defer clear(second)
	after, err := opened.file.Stat()
	if err != nil || !validTrustFileInfo(after, opened.privateKey) || trustFileHasExtendedMetadata(opened.file) ||
		!os.SameFile(opened.info, after) || after.Size() != opened.info.Size() ||
		after.Size() != int64(len(first)) || !after.ModTime().Equal(opened.info.ModTime()) || !bytes.Equal(first, second) {
		clear(first)
		return nil, ErrInvalidConfiguration
	}
	return first, nil
}

// Access-control metadata can grant permissions beyond POSIX mode bits. The
// check is bound to the opened descriptor and fails closed if enumeration is
// unavailable. Only non-access-expanding provenance/integrity labels pass.
func trustFileHasExtendedMetadata(file *os.File) bool {
	if file == nil {
		return true
	}
	if runtime.GOOS == "darwin" && darwinTrustFileHasACL(file) {
		return true
	}
	size, _, errno := syscall.Syscall6(syscall.SYS_FLISTXATTR, file.Fd(), 0, 0, 0, 0, 0)
	if errno != 0 {
		return true
	}
	if size == 0 {
		return false
	}
	if size > maximumTrustFileSize {
		return true
	}
	names := make([]byte, size)
	read, _, errno := syscall.Syscall6(
		syscall.SYS_FLISTXATTR, file.Fd(), uintptr(unsafe.Pointer(&names[0])), uintptr(len(names)), 0, 0, 0,
	)
	if errno != 0 || read != size {
		return true
	}
	for len(names) > 0 {
		end := bytes.IndexByte(names, 0)
		if end <= 0 || !allowedTrustFileExtendedAttributeForOS(runtime.GOOS, string(names[:end])) {
			return true
		}
		names = names[end+1:]
	}
	return false
}

func allowedTrustFileExtendedAttributeForOS(goos, name string) bool {
	switch goos {
	case "darwin":
		return name == "com.apple.provenance"
	case "linux":
		return name == "security.selinux" || name == "security.ima" || name == "security.evm"
	default:
		return false
	}
}

func darwinTrustFileHasACL(file *os.File) bool {
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
		darwinFgetattrlistSyscall, file.Fd(), uintptr(unsafe.Pointer(&attributes)),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0, 0,
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

func readTrustFile(file *os.File) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, ErrInvalidConfiguration
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumTrustFileSize+1))
	if err != nil || len(contents) == 0 || len(contents) > maximumTrustFileSize {
		clear(contents)
		return nil, fmt.Errorf("%w", ErrInvalidConfiguration)
	}
	return contents, nil
}
