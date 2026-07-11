package runneridentity

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	maximumIdentityFileSize = 1 << 20
	maximumIdentityPathSize = 4096
)

// FileOptions identifies the immutable files used to terminate the Runner
// Gateway's TLS connection. The server certificate file contains the complete
// leaf-first chain; the two client CA files define disjoint READ and WRITE
// trust roots.
type FileOptions struct {
	ServerCertFile    string
	ServerKeyFile     string
	ReadClientCAFile  string
	WriteClientCAFile string
	TrustDomain       string
	Clock             func() time.Time
}

// LoadFiles securely loads Runner Gateway identity files, constructs the
// client-certificate verifier, and returns its fail-closed TLS configuration.
// File contents and parser errors are intentionally excluded from returned
// errors because they may contain private key material.
func LoadFiles(options FileOptions) (*Verifier, *tls.Config, error) {
	files := []struct {
		path       string
		component  string
		privateKey bool
	}{
		{options.ServerCertFile, "server certificate file", false},
		{options.ServerKeyFile, "server private key file", true},
		{options.ReadClientCAFile, "READ client CA file", false},
		{options.WriteClientCAFile, "WRITE client CA file", false},
	}
	seenPaths := make(map[string]struct{}, len(files))
	for _, candidate := range files {
		if !validIdentityFilePath(candidate.path) {
			return nil, nil, fileConfigurationError("file path")
		}
		if _, duplicate := seenPaths[candidate.path]; duplicate {
			return nil, nil, fileConfigurationError("distinct file paths")
		}
		seenPaths[candidate.path] = struct{}{}
	}

	opened := make([]*openedIdentityFile, 0, len(files))
	defer func() {
		for _, file := range opened {
			_ = file.file.Close()
		}
	}()
	for _, candidate := range files {
		file, err := openIdentityFile(candidate.path, candidate.privateKey)
		if err != nil {
			return nil, nil, fileConfigurationError(candidate.component)
		}
		for _, existing := range opened {
			if os.SameFile(existing.info, file.info) {
				_ = file.file.Close()
				return nil, nil, fileConfigurationError("distinct file identities")
			}
		}
		opened = append(opened, file)
	}

	serverCertificatePEM, err := opened[0].readStable()
	if err != nil {
		return nil, nil, fileConfigurationError(files[0].component)
	}
	serverKeyPEM, err := opened[1].readStable()
	if err != nil {
		return nil, nil, fileConfigurationError(files[1].component)
	}
	defer clear(serverKeyPEM)
	readCAPEM, err := opened[2].readStable()
	if err != nil {
		return nil, nil, fileConfigurationError(files[2].component)
	}
	writeCAPEM, err := opened[3].readStable()
	if err != nil {
		return nil, nil, fileConfigurationError(files[3].component)
	}

	if err := validateCertificatePEM(serverCertificatePEM); err != nil {
		return nil, nil, fileConfigurationError("server certificate PEM")
	}
	if err := validatePrivateKeyPEM(serverKeyPEM); err != nil {
		return nil, nil, fileConfigurationError("server private key PEM")
	}
	serverCertificate, err := tls.X509KeyPair(serverCertificatePEM, serverKeyPEM)
	if err != nil {
		return nil, nil, fileConfigurationError("server certificate key pair")
	}
	readRoots, err := parseClientRoots(readCAPEM)
	if err != nil {
		return nil, nil, fileConfigurationError("READ client CA PEM")
	}
	writeRoots, err := parseClientRoots(writeCAPEM)
	if err != nil {
		return nil, nil, fileConfigurationError("WRITE client CA PEM")
	}

	verifier, err := NewVerifier(Options{
		TrustDomain: options.TrustDomain,
		ReadRoots:   readRoots,
		WriteRoots:  writeRoots,
		Clock:       options.Clock,
	})
	if err != nil {
		return nil, nil, fileConfigurationError("client trust roots")
	}
	configuration, err := verifier.ServerTLSConfig(serverCertificate)
	if err != nil {
		return nil, nil, fileConfigurationError("server certificate chain")
	}
	return verifier, configuration, nil
}

func validIdentityFilePath(path string) bool {
	if path == "" || len(path) > maximumIdentityPathSize || !filepath.IsAbs(path) ||
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

type openedIdentityFile struct {
	file       *os.File
	info       os.FileInfo
	privateKey bool
}

func openIdentityFile(path string, privateKey bool) (*openedIdentityFile, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	file := os.NewFile(uintptr(fd), "runner-identity-file")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrInvalidConfiguration
	}
	info, err := file.Stat()
	if err != nil || !validIdentityFileInfo(info, privateKey) || identityFileHasExtendedMetadata(file) {
		_ = file.Close()
		return nil, ErrInvalidConfiguration
	}
	return &openedIdentityFile{file: file, info: info, privateKey: privateKey}, nil
}

func (opened *openedIdentityFile) readStable() ([]byte, error) {
	if opened == nil || opened.file == nil || opened.info == nil {
		return nil, ErrInvalidConfiguration
	}
	first, err := readIdentityFilePass(opened.file)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	second, err := readIdentityFilePass(opened.file)
	if err != nil {
		clear(first)
		return nil, ErrInvalidConfiguration
	}
	defer clear(second)
	afterRead, err := opened.file.Stat()
	if err != nil || !validIdentityFileInfo(afterRead, opened.privateKey) || identityFileHasExtendedMetadata(opened.file) ||
		!os.SameFile(opened.info, afterRead) || afterRead.Size() != int64(len(first)) ||
		afterRead.Size() != opened.info.Size() || !afterRead.ModTime().Equal(opened.info.ModTime()) ||
		!bytes.Equal(first, second) {
		clear(first)
		return nil, ErrInvalidConfiguration
	}
	return first, nil
}

func readIdentityFilePass(file *os.File) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, ErrInvalidConfiguration
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumIdentityFileSize+1))
	if err != nil || len(contents) == 0 || len(contents) > maximumIdentityFileSize {
		return nil, ErrInvalidConfiguration
	}
	return contents, nil
}

func validIdentityFileInfo(info os.FileInfo, privateKey bool) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumIdentityFileSize {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return false
	}
	if privateKey {
		return info.Mode().Perm()&0o077 == 0
	}
	return info.Mode().Perm()&0o022 == 0
}

// ACLs can grant access beyond the POSIX mode bits. Linux exposes POSIX ACLs
// and macOS exposes security metadata through fd-scoped extended attributes.
// Only platform provenance/integrity labels that cannot expand DAC access are
// allowed. Every unknown or access-control attribute—and any inability to
// enumerate attributes from the already-open fd—fails closed.
func identityFileHasExtendedMetadata(file *os.File) bool {
	if file == nil {
		return true
	}
	if runtime.GOOS == "darwin" && darwinIdentityFileHasACL(file) {
		return true
	}
	size, _, errno := syscall.Syscall6(syscall.SYS_FLISTXATTR, file.Fd(), 0, 0, 0, 0, 0)
	if errno != 0 {
		return true
	}
	if size == 0 {
		return false
	}
	if size > maximumIdentityFileSize {
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
		if end <= 0 || !allowedIdentityFileExtendedAttribute(string(names[:end])) {
			return true
		}
		names = names[end+1:]
	}
	return false
}

func allowedIdentityFileExtendedAttribute(name string) bool {
	return allowedIdentityFileExtendedAttributeForOS(runtime.GOOS, name)
}

func allowedIdentityFileExtendedAttributeForOS(goos, name string) bool {
	switch goos {
	case "darwin":
		return name == "com.apple.provenance"
	case "linux":
		// These kernel-managed labels can only further restrict access after
		// normal DAC checks; unlike POSIX ACLs, they cannot grant around the
		// owner/mode requirements enforced above.
		return name == "security.selinux" || name == "security.ima" || name == "security.evm"
	default:
		return false
	}
}

// macOS keeps NFSv4-style ACLs in ATTR_CMN_EXTENDED_SECURITY rather than in
// the normal xattr namespace. fgetattrlist syscall 228 is used directly so the
// check remains bound to the already-open descriptor. A missing/invalid ACL is
// encoded as KAUTH_FILESEC_NOACL; every other value is an extended ACL.
func darwinIdentityFileHasACL(file *os.File) bool {
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

func validateCertificatePEM(contents []byte) error {
	blocks, err := decodeStrictPEM(contents)
	if err != nil || len(blocks) == 0 {
		return ErrInvalidConfiguration
	}
	for _, block := range blocks {
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return ErrInvalidConfiguration
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return ErrInvalidConfiguration
		}
	}
	return nil
}

func parseClientRoots(contents []byte) ([]*x509.Certificate, error) {
	blocks, err := decodeStrictPEM(contents)
	if err != nil || len(blocks) == 0 {
		return nil, ErrInvalidConfiguration
	}
	roots := make([]*x509.Certificate, 0, len(blocks))
	for _, block := range blocks {
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrInvalidConfiguration
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrInvalidConfiguration
		}
		roots = append(roots, certificate)
	}
	return roots, nil
}

func validatePrivateKeyPEM(contents []byte) error {
	blocks, err := decodeStrictPEM(contents)
	if err != nil || len(blocks) != 1 || len(blocks[0].Headers) != 0 {
		return ErrInvalidConfiguration
	}
	switch blocks[0].Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		return nil
	default:
		return ErrInvalidConfiguration
	}
}

func decodeStrictPEM(contents []byte) ([]*pem.Block, error) {
	remaining := contents
	blocks := make([]*pem.Block, 0, 1)
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN ")) {
			return nil, ErrInvalidConfiguration
		}
		block, rest := pem.Decode(remaining)
		if block == nil || len(rest) >= len(remaining) || !strictPEMBoundary(remaining[:len(remaining)-len(rest)], block.Type) {
			return nil, ErrInvalidConfiguration
		}
		blocks = append(blocks, block)
		remaining = rest
	}
	return blocks, nil
}

func strictPEMBoundary(consumed []byte, blockType string) bool {
	beginLine := []byte("-----BEGIN " + blockType + "-----")
	if !bytes.HasPrefix(consumed, beginLine) || len(consumed) <= len(beginLine) {
		return false
	}
	beginEnd := len(beginLine)
	if consumed[beginEnd] == '\r' {
		beginEnd++
	}
	if beginEnd >= len(consumed) || consumed[beginEnd] != '\n' {
		return false
	}
	endLine := []byte("-----END " + blockType + "-----")
	endStart := bytes.LastIndex(consumed, endLine)
	if endStart < beginEnd+1 {
		return false
	}
	end := endStart + len(endLine)
	if end < len(consumed) && consumed[end] == '\r' {
		end++
	}
	if end < len(consumed) && consumed[end] == '\n' {
		end++
	}
	return end == len(consumed)
}

func fileConfigurationError(component string) error {
	return fmt.Errorf("load Runner identity %s: %w", component, ErrInvalidConfiguration)
}
