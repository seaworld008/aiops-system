package credential

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	credentialKeyringSchema      = "credential-protection-keyring.v1"
	maximumCredentialKeyringSize = 64 << 10
	maximumCredentialKeyringKeys = 32
	maximumCredentialKeyringPath = 4096
)

type credentialKeyringDocument struct {
	SchemaVersion string                         `json:"schema_version"`
	ActiveKeyID   string                         `json:"active_key_id"`
	Keys          []credentialKeyringDocumentKey `json:"keys"`
}

func (document *credentialKeyringDocument) UnmarshalJSON(encoded []byte) error {
	if document == nil {
		return ErrReferenceProtection
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil || len(fields) != 3 {
		clearCredentialKeyringRawFields(fields)
		return ErrReferenceProtection
	}
	defer clearCredentialKeyringRawFields(fields)
	for _, required := range []string{"schema_version", "active_key_id", "keys"} {
		if _, found := fields[required]; !found {
			return ErrReferenceProtection
		}
	}
	var candidate credentialKeyringDocument
	if err := json.Unmarshal(fields["schema_version"], &candidate.SchemaVersion); err != nil {
		return ErrReferenceProtection
	}
	if err := json.Unmarshal(fields["active_key_id"], &candidate.ActiveKeyID); err != nil {
		return ErrReferenceProtection
	}
	if err := json.Unmarshal(fields["keys"], &candidate.Keys); err != nil {
		destroyCredentialKeyringDocument(&candidate)
		return ErrReferenceProtection
	}
	destroyCredentialKeyringDocument(document)
	*document = candidate
	return nil
}

type credentialKeyringDocumentKey struct {
	ID            string                    `json:"id"`
	EncryptionKey credentialKeyringMaterial `json:"encryption_key_b64u"`
	HMACKey       credentialKeyringMaterial `json:"hmac_key_b64u"`
}

func (key *credentialKeyringDocumentKey) UnmarshalJSON(encoded []byte) error {
	if key == nil {
		return ErrReferenceProtection
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil || len(fields) != 3 {
		clearCredentialKeyringRawFields(fields)
		return ErrReferenceProtection
	}
	defer clearCredentialKeyringRawFields(fields)
	for _, required := range []string{"id", "encryption_key_b64u", "hmac_key_b64u"} {
		if _, found := fields[required]; !found {
			return ErrReferenceProtection
		}
	}
	var candidate credentialKeyringDocumentKey
	if err := json.Unmarshal(fields["id"], &candidate.ID); err != nil {
		return ErrReferenceProtection
	}
	if err := json.Unmarshal(fields["encryption_key_b64u"], &candidate.EncryptionKey); err != nil {
		clear(candidate.EncryptionKey)
		return ErrReferenceProtection
	}
	if err := json.Unmarshal(fields["hmac_key_b64u"], &candidate.HMACKey); err != nil {
		clear(candidate.EncryptionKey)
		clear(candidate.HMACKey)
		return ErrReferenceProtection
	}
	clear(key.EncryptionKey)
	clear(key.HMACKey)
	*key = candidate
	return nil
}

type credentialKeyringMaterial []byte

// UnmarshalJSON accepts only the canonical, unpadded base64url encoding of a
// 256-bit key. Rejecting JSON escapes also avoids creating immutable Go
// strings containing decoded key material.
func (material *credentialKeyringMaterial) UnmarshalJSON(encoded []byte) error {
	if material == nil || len(encoded) != 2+base64.RawURLEncoding.EncodedLen(refEncryptionKeySize) ||
		encoded[0] != '"' || encoded[len(encoded)-1] != '"' || bytes.IndexByte(encoded, '\\') >= 0 {
		return ErrReferenceProtection
	}
	decoded := make([]byte, refEncryptionKeySize)
	count, err := base64.RawURLEncoding.Decode(decoded, encoded[1:len(encoded)-1])
	if err != nil || count != refEncryptionKeySize {
		clear(decoded)
		return ErrReferenceProtection
	}
	canonical := make([]byte, base64.RawURLEncoding.EncodedLen(len(decoded)))
	base64.RawURLEncoding.Encode(canonical, decoded)
	valid := bytes.Equal(canonical, encoded[1:len(encoded)-1])
	clear(canonical)
	if !valid {
		clear(decoded)
		return ErrReferenceProtection
	}
	clear(*material)
	*material = decoded
	return nil
}

// LoadAESGCMProtectorFile securely loads a private, app-owned keyring file and
// constructs a protector without exposing the decoded keyring to callers.
// Returned errors never contain a path, parser detail, or keyring contents.
func LoadAESGCMProtectorFile(path string) (*AESGCMProtector, error) {
	opened, err := openCredentialKeyringFile(path)
	if err != nil {
		return nil, credentialKeyringLoadError()
	}
	contents, readErr := opened.readStable()
	closeErr := opened.file.Close()
	if readErr != nil || closeErr != nil {
		clear(contents)
		return nil, credentialKeyringLoadError()
	}
	defer clear(contents)

	if err := rejectCredentialKeyringDuplicateJSON(contents); err != nil {
		return nil, credentialKeyringLoadError()
	}
	var document credentialKeyringDocument
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(&document); err != nil || requireCredentialKeyringJSONEOF(decoder) != nil {
		destroyCredentialKeyringDocument(&document)
		return nil, credentialKeyringLoadError()
	}
	defer destroyCredentialKeyringDocument(&document)
	if document.SchemaVersion != credentialKeyringSchema || !ValidIdentifier(document.ActiveKeyID, 128) ||
		len(document.Keys) == 0 || len(document.Keys) > maximumCredentialKeyringKeys {
		return nil, credentialKeyringLoadError()
	}

	ring := KeyRing{ActiveKeyID: document.ActiveKeyID, Keys: make(map[string]ProtectionKey, len(document.Keys))}
	for index := range document.Keys {
		key := &document.Keys[index]
		if !ValidIdentifier(key.ID, 128) || len(key.EncryptionKey) != refEncryptionKeySize ||
			len(key.HMACKey) != minRefHMACKeySize || bytes.Equal(key.EncryptionKey, key.HMACKey) {
			return nil, credentialKeyringLoadError()
		}
		if _, duplicate := ring.Keys[key.ID]; duplicate {
			return nil, credentialKeyringLoadError()
		}
		ring.Keys[key.ID] = ProtectionKey{EncryptionKey: key.EncryptionKey, HMACKey: key.HMACKey}
	}
	if _, found := ring.Keys[ring.ActiveKeyID]; !found {
		return nil, credentialKeyringLoadError()
	}
	protector, err := NewAESGCMProtector(ring)
	if err != nil {
		return nil, credentialKeyringLoadError()
	}
	return protector, nil
}

func credentialKeyringLoadError() error {
	return errors.Join(ErrReferenceProtection, errors.New("credential protection keyring rejected"))
}

func clearCredentialKeyringRawFields(fields map[string]json.RawMessage) {
	for name, raw := range fields {
		clear(raw)
		delete(fields, name)
	}
}

func destroyCredentialKeyringDocument(document *credentialKeyringDocument) {
	if document == nil {
		return
	}
	for index := range document.Keys {
		clear(document.Keys[index].EncryptionKey)
		clear(document.Keys[index].HMACKey)
		document.Keys[index].EncryptionKey = nil
		document.Keys[index].HMACKey = nil
	}
	clear(document.Keys)
	document.Keys = nil
	document.ActiveKeyID = ""
	document.SchemaVersion = ""
}

type openedCredentialKeyringFile struct {
	file *os.File
	info os.FileInfo
}

func openCredentialKeyringFile(path string) (*openedCredentialKeyringFile, error) {
	if !validCredentialKeyringPath(path) {
		return nil, ErrReferenceProtection
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrReferenceProtection
	}
	file := os.NewFile(uintptr(fd), "credential-protection-keyring")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrReferenceProtection
	}
	info, err := file.Stat()
	if err != nil || !validCredentialKeyringFileInfo(info) || credentialKeyringFileHasExtendedMetadata(file) {
		_ = file.Close()
		return nil, ErrReferenceProtection
	}
	return &openedCredentialKeyringFile{file: file, info: info}, nil
}

func validCredentialKeyringPath(path string) bool {
	if path == "" || len(path) > maximumCredentialKeyringPath || !filepath.IsAbs(path) ||
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

func validCredentialKeyringFileInfo(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumCredentialKeyringSize ||
		(info.Mode().Perm() != 0o400 && info.Mode().Perm() != 0o600) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

func (opened *openedCredentialKeyringFile) readStable() ([]byte, error) {
	if opened == nil || opened.file == nil || opened.info == nil {
		return nil, ErrReferenceProtection
	}
	first, err := readCredentialKeyringPass(opened.file)
	if err != nil {
		return nil, ErrReferenceProtection
	}
	second, err := readCredentialKeyringPass(opened.file)
	if err != nil {
		clear(first)
		return nil, ErrReferenceProtection
	}
	defer clear(second)
	afterRead, err := opened.file.Stat()
	if err != nil || !validCredentialKeyringFileInfo(afterRead) || credentialKeyringFileHasExtendedMetadata(opened.file) ||
		!os.SameFile(opened.info, afterRead) || afterRead.Size() != int64(len(first)) ||
		afterRead.Size() != opened.info.Size() || !afterRead.ModTime().Equal(opened.info.ModTime()) ||
		!bytes.Equal(first, second) {
		clear(first)
		return nil, ErrReferenceProtection
	}
	return first, nil
}

func readCredentialKeyringPass(file *os.File) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, ErrReferenceProtection
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumCredentialKeyringSize+1))
	if err != nil || len(contents) == 0 || len(contents) > maximumCredentialKeyringSize {
		clear(contents)
		return nil, ErrReferenceProtection
	}
	return contents, nil
}

// Access-control metadata is checked on the already-open descriptor. Unknown
// xattrs and ACLs fail closed; kernel integrity labels may only restrict DAC.
func credentialKeyringFileHasExtendedMetadata(file *os.File) bool {
	if file == nil {
		return true
	}
	if runtime.GOOS == "darwin" && darwinCredentialKeyringFileHasACL(file) {
		return true
	}
	size, _, errno := syscall.Syscall6(syscall.SYS_FLISTXATTR, file.Fd(), 0, 0, 0, 0, 0)
	if errno != 0 {
		return true
	}
	if size == 0 {
		return false
	}
	if size > maximumCredentialKeyringSize {
		return true
	}
	names := make([]byte, size)
	read, _, errno := syscall.Syscall6(
		syscall.SYS_FLISTXATTR,
		file.Fd(), uintptr(unsafe.Pointer(&names[0])), uintptr(len(names)), 0, 0, 0,
	)
	if errno != 0 || read != size {
		return true
	}
	for len(names) > 0 {
		end := bytes.IndexByte(names, 0)
		if end <= 0 || !allowedCredentialKeyringExtendedAttribute(string(names[:end])) {
			return true
		}
		names = names[end+1:]
	}
	return false
}

func allowedCredentialKeyringExtendedAttribute(name string) bool {
	switch runtime.GOOS {
	case "darwin":
		return name == "com.apple.provenance"
	case "linux":
		return name == "security.selinux" || name == "security.ima" || name == "security.evm"
	default:
		return false
	}
}

func darwinCredentialKeyringFileHasACL(file *os.File) bool {
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

func rejectCredentialKeyringDuplicateJSON(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := walkCredentialKeyringJSONValue(decoder, first, 0); err != nil {
		return err
	}
	return requireCredentialKeyringJSONEOF(decoder)
}

func walkCredentialKeyringJSONValue(decoder *json.Decoder, token json.Token, depth int) error {
	if depth > 8 {
		return ErrReferenceProtection
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrReferenceProtection
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrReferenceProtection
			}
			seen[key] = struct{}{}
			child, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := walkCredentialKeyringJSONValue(decoder, child, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrReferenceProtection
		}
		return nil
	case '[':
		for decoder.More() {
			child, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := walkCredentialKeyringJSONValue(decoder, child, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrReferenceProtection
		}
		return nil
	default:
		return ErrReferenceProtection
	}
}

func requireCredentialKeyringJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return ErrReferenceProtection
}
