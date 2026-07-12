package readconnector

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	manifestSchemaVersion = "read-connector-registry.v1"
	maximumManifestSize   = 1 << 20
	maximumManifestPath   = 4096
	maximumManifestDepth  = 16
)

var (
	// These sentinels intentionally carry only a low-sensitivity category.
	// Callers must never receive an operating-system, path, query, or target
	// error through this configuration boundary.
	ErrManifestPath       = errors.New("read connector manifest path rejected")
	ErrManifestFile       = errors.New("read connector manifest file rejected")
	ErrManifestJSON       = errors.New("read connector manifest JSON rejected")
	ErrManifestDefinition = errors.New("read connector manifest definition rejected")
)

type manifestDocument struct {
	SchemaVersion string       `json:"schema_version"`
	Definitions   []Definition `json:"definitions"`
}

// LoadFile securely loads an immutable, server-owned READ connector registry.
// It accepts neither inline configuration nor environment expansion: the
// already-admitted file is the sole source of definitions.
func LoadFile(path string) (*Registry, error) {
	if !validManifestPath(path) {
		return nil, ErrManifestPath
	}
	opened, err := openManifestFile(path)
	if err != nil {
		return nil, ErrManifestFile
	}
	contents, readErr := opened.readStable()
	closeErr := opened.file.Close()
	if readErr != nil || closeErr != nil {
		clear(contents)
		return nil, ErrManifestFile
	}
	defer clear(contents)

	document, err := decodeManifest(contents)
	if err != nil || document.SchemaVersion != manifestSchemaVersion {
		return nil, ErrManifestJSON
	}
	if len(document.Definitions) == 0 || len(document.Definitions) > maxDefinitions {
		return nil, manifestDefinitionError()
	}
	registry, err := New(document.Definitions)
	if err != nil {
		return nil, manifestDefinitionError()
	}
	return registry, nil
}

func manifestDefinitionError() error {
	return errors.Join(ErrManifestDefinition, ErrInvalidDefinition)
}

func validManifestPath(path string) bool {
	if path == "" || len(path) > maximumManifestPath || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path || strings.TrimSpace(path) != path {
		return false
	}
	for _, character := range path {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

type openedManifestFile struct {
	file *os.File
	info os.FileInfo
}

func openManifestFile(path string) (*openedManifestFile, error) {
	// O_NONBLOCK prevents an attacker-controlled FIFO from stalling admission;
	// regular files are unaffected. Metadata is checked only after the no-follow
	// descriptor has been acquired.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrManifestFile
	}
	file := os.NewFile(uintptr(fd), "read-connector-manifest")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrManifestFile
	}
	info, err := file.Stat()
	if err != nil || !validManifestFileInfo(info) || manifestFileHasExtendedMetadata(file) {
		_ = file.Close()
		return nil, ErrManifestFile
	}
	return &openedManifestFile{file: file, info: info}, nil
}

func validManifestFileInfo(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximumManifestSize ||
		info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

func (opened *openedManifestFile) readStable() ([]byte, error) {
	if opened == nil || opened.file == nil || opened.info == nil {
		return nil, ErrManifestFile
	}
	first, err := readManifestPass(opened.file)
	if err != nil {
		return nil, ErrManifestFile
	}
	second, err := readManifestPass(opened.file)
	if err != nil {
		clear(first)
		return nil, ErrManifestFile
	}
	defer clear(second)
	after, err := opened.file.Stat()
	if err != nil || !validManifestFileInfo(after) || manifestFileHasExtendedMetadata(opened.file) ||
		!os.SameFile(opened.info, after) ||
		after.Size() != opened.info.Size() || after.Size() != int64(len(first)) ||
		after.Mode() != opened.info.Mode() || !after.ModTime().Equal(opened.info.ModTime()) ||
		!bytes.Equal(first, second) {
		clear(first)
		return nil, ErrManifestFile
	}
	return first, nil
}

// ACLs and unknown extended attributes can silently widen access beyond the
// mode bits. Enumeration stays descriptor-bound so it cannot be redirected by
// a path replacement. Only integrity/provenance labels that do not grant file
// access are accepted.
func manifestFileHasExtendedMetadata(file *os.File) bool {
	if file == nil {
		return true
	}
	if runtime.GOOS == "darwin" && darwinManifestFileHasACL(file) {
		return true
	}
	size, _, errno := syscall.Syscall6(syscall.SYS_FLISTXATTR, file.Fd(), 0, 0, 0, 0, 0)
	if errno != 0 {
		return true
	}
	if size == 0 {
		return false
	}
	if size > maximumManifestSize {
		return true
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
		if end <= 0 || !allowedManifestFileExtendedAttribute(runtime.GOOS, string(names[:end])) {
			return true
		}
		names = names[end+1:]
	}
	return false
}

func allowedManifestFileExtendedAttribute(goos, name string) bool {
	switch goos {
	case "darwin":
		return name == "com.apple.provenance"
	case "linux":
		return name == "security.selinux" || name == "security.ima" || name == "security.evm"
	default:
		return false
	}
}

func darwinManifestFileHasACL(file *os.File) bool {
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

func readManifestPass(file *os.File) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, ErrManifestFile
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumManifestSize+1))
	if err != nil || len(contents) > maximumManifestSize {
		clear(contents)
		return nil, ErrManifestFile
	}
	return contents, nil
}

func decodeManifest(encoded []byte) (manifestDocument, error) {
	if len(encoded) == 0 || !utf8.Valid(encoded) || !validManifestJSON(encoded) {
		return manifestDocument{}, ErrManifestJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var document manifestDocument
	if err := decoder.Decode(&document); err != nil {
		return manifestDocument{}, ErrManifestJSON
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return manifestDocument{}, ErrManifestJSON
	}
	return document, nil
}

func validManifestJSON(encoded []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if !walkManifestJSONValue(decoder, 0) {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}

func walkManifestJSONValue(decoder *json.Decoder, depth int) bool {
	if decoder == nil || depth > maximumManifestDepth {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		switch token.(type) {
		case nil, bool, string, json.Number:
			return true
		default:
			return false
		}
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, ok := keyToken.(string)
			if keyErr != nil || !ok || !canonicalManifestFieldName(key) {
				return false
			}
			if _, duplicate := seen[key]; duplicate {
				return false
			}
			seen[key] = struct{}{}
			if !walkManifestJSONValue(decoder, depth+1) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		return closeErr == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			if !walkManifestJSONValue(decoder, depth+1) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		return closeErr == nil && closing == json.Delim(']')
	default:
		return false
	}
}

func canonicalManifestFieldName(value string) bool {
	if value == "" || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}
