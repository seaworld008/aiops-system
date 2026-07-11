package credential_test

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/seaworld008/aiops-system/internal/credential"
)

func TestLoadAESGCMProtectorFileLoadsPrivateCanonicalKeyring(t *testing.T) {
	path := writeKeyringFixture(t, validKeyringJSON(), 0o400)

	protector, err := credential.LoadAESGCMProtectorFile(path)
	if err != nil {
		t.Fatalf("LoadAESGCMProtectorFile() error = %v", err)
	}
	t.Cleanup(protector.Destroy)

	reference, err := credential.NewSensitiveReference([]byte("revoke-accessor-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveReference() error = %v", err)
	}
	defer reference.Destroy()
	context := credential.ReferenceContext{
		RevocationID: "11111111-1111-4111-8111-111111111111",
		ActionID:     "action-keyring-loader", ActionEpoch: 7,
		Issuer: "vault-non-production", IssuerRevision: "revision-1",
	}
	protected, err := protector.Protect(context, reference)
	if err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	opened, err := protector.Unprotect(context, protected)
	if err != nil {
		t.Fatalf("Unprotect() error = %v", err)
	}
	defer opened.Destroy()
	if got := string(opened.Bytes()); got != "revoke-accessor-canary" {
		t.Fatalf("Unprotect() = %q", got)
	}
}

func TestLoadAESGCMProtectorFileAcceptsOnlyAppOwnedPrivateRegularFile(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, path string) string
	}{
		{name: "relative path", mutate: func(_ *testing.T, path string) string { return filepath.Base(path) }},
		{name: "unclean path", mutate: func(_ *testing.T, path string) string {
			return filepath.Dir(path) + string(os.PathSeparator) + "ignored" + string(os.PathSeparator) + ".." +
				string(os.PathSeparator) + filepath.Base(path)
		}},
		{name: "symlink", mutate: func(t *testing.T, path string) string {
			link := filepath.Join(filepath.Dir(path), "keyring-link.json")
			if err := os.Symlink(path, link); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
			return link
		}},
		{name: "hardlink", mutate: func(t *testing.T, path string) string {
			link := filepath.Join(filepath.Dir(path), "keyring-hardlink.json")
			if err := os.Link(path, link); err != nil {
				t.Fatalf("Link() error = %v", err)
			}
			return path
		}},
		{name: "directory", mutate: func(t *testing.T, path string) string {
			directory := filepath.Join(filepath.Dir(path), "keyring-directory")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatalf("Mkdir() error = %v", err)
			}
			return directory
		}},
		{name: "group readable", mutate: chmodKeyring(0o440)},
		{name: "world readable", mutate: chmodKeyring(0o404)},
		{name: "executable", mutate: chmodKeyring(0o500)},
		{name: "owner write only", mutate: chmodKeyring(0o200)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeKeyringFixture(t, validKeyringJSON(), 0o400)
			path = test.mutate(t, path)
			assertKeyringFileRejected(t, path)
		})
	}

	t.Run("mode 0600", func(t *testing.T) {
		path := writeKeyringFixture(t, validKeyringJSON(), 0o600)
		protector, err := credential.LoadAESGCMProtectorFile(path)
		if err != nil {
			t.Fatalf("LoadAESGCMProtectorFile(mode 0600) error = %v", err)
		}
		protector.Destroy()
	})
}

func TestLoadAESGCMProtectorFileRejectsNonOwnerFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires a privileged test process")
	}
	path := writeKeyringFixture(t, validKeyringJSON(), 0o400)
	if err := os.Chown(path, 1, -1); err != nil {
		t.Fatalf("Chown() error = %v", err)
	}
	assertKeyringFileRejected(t, path)
}

func TestLoadAESGCMProtectorFileRejectsExtendedAccessMetadata(t *testing.T) {
	t.Run("extended attribute", func(t *testing.T) {
		path := writeKeyringFixture(t, validKeyringJSON(), 0o600)
		setKeyringExtendedAttribute(t, path)
		assertKeyringFileRejected(t, path)
	})

	if runtime.GOOS == "darwin" {
		t.Run("macOS extended ACL", func(t *testing.T) {
			path := writeKeyringFixture(t, validKeyringJSON(), 0o400)
			command := exec.Command("/bin/chmod", "+a", "everyone allow read", path)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("chmod +a error = %v: %s", err, output)
			}
			assertKeyringFileRejected(t, path)
		})
	}
}

func TestLoadAESGCMProtectorFileRejectsMalformedOrAmbiguousJSONWithoutLeak(t *testing.T) {
	const canary = "CREDENTIAL-KEYRING-PRIVATE-CANARY"
	valid := validKeyringJSON()
	tests := map[string]string{
		"empty":                "",
		"trailing value":       valid + `{}`,
		"unknown field":        strings.Replace(valid, `"active_key_id"`, `"unknown":"`+canary+`","active_key_id"`, 1),
		"wrong field case":     strings.Replace(valid, `"active_key_id"`, `"ACTIVE_KEY_ID"`, 1),
		"nested unknown field": strings.Replace(valid, `"id":"key-1"`, `"id":"key-1","unknown":true`, 1),
		"duplicate field":      strings.Replace(valid, `"active_key_id":"key-1"`, `"active_key_id":"key-1","active_key_id":"key-1"`, 1),
		"escaped duplicate":    strings.Replace(valid, `"active_key_id":"key-1"`, `"active_key_id":"key-1","active_key_\u0069d":"key-1"`, 1),
		"missing active key":   strings.Replace(valid, `"active_key_id":"key-1"`, `"active_key_id":"missing"`, 1),
		"duplicate key id":     strings.Replace(valid, `]}`, `,{"id":"key-1","encryption_key_b64u":"`+keyringEncodedByte(0x33)+`","hmac_key_b64u":"`+keyringEncodedByte(0x44)+`"}]}`, 1),
		"padded base64":        strings.Replace(valid, keyringEncodedByte(0x11), keyringEncodedByte(0x11)+"=", 1),
		"short encryption key": strings.Replace(valid, keyringEncodedByte(0x11), base64.RawURLEncoding.EncodeToString(make([]byte, 31)), 1),
		"same key material":    strings.Replace(valid, keyringEncodedByte(0x22), keyringEncodedByte(0x11), 1),
		"wrong schema":         strings.Replace(valid, "credential-protection-keyring.v1", "credential-protection-keyring.v2", 1),
		"secret canary":        canary,
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			path := writeKeyringFixture(t, contents, 0o400)
			_, err := credential.LoadAESGCMProtectorFile(path)
			if !errors.Is(err, credential.ErrReferenceProtection) {
				t.Fatalf("LoadAESGCMProtectorFile() error = %v", err)
			}
			if err != nil && strings.Contains(err.Error(), canary) {
				t.Fatalf("LoadAESGCMProtectorFile() leaked keyring material: %v", err)
			}
		})
	}
}

func TestLoadAESGCMProtectorFileRejectsOversizedFile(t *testing.T) {
	path := writeKeyringFixture(t, strings.Repeat("x", (64<<10)+1), 0o400)
	assertKeyringFileRejected(t, path)
}

func chmodKeyring(mode os.FileMode) func(*testing.T, string) string {
	return func(t *testing.T, path string) string {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("Chmod(%#o) error = %v", mode, err)
		}
		return path
	}
}

func assertKeyringFileRejected(t *testing.T, path string) {
	t.Helper()
	protector, err := credential.LoadAESGCMProtectorFile(path)
	if protector != nil {
		protector.Destroy()
		t.Fatal("LoadAESGCMProtectorFile() returned a protector for an unsafe file")
	}
	if !errors.Is(err, credential.ErrReferenceProtection) {
		t.Fatalf("LoadAESGCMProtectorFile() error = %v", err)
	}
}

func writeKeyringFixture(t *testing.T, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential-keyring.json")
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil {
			t.Fatalf("Stat() error = %v", err)
		} else if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
			t.Fatalf("fixture is not owned by effective user: %#v", info.Sys())
		}
	}
	return path
}

func setKeyringExtendedAttribute(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(xattr fixture) error = %v", err)
	}
	defer file.Close()
	name, err := syscall.BytePtrFromString("user.aiops-credential-keyring-test")
	if err != nil {
		t.Fatalf("BytePtrFromString(xattr) error = %v", err)
	}
	value := []byte("present")
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FSETXATTR,
		file.Fd(), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&value[0])), uintptr(len(value)), 0, 0,
	)
	runtime.KeepAlive(name)
	runtime.KeepAlive(value)
	if errno != 0 {
		t.Fatalf("fsetxattr() error = %v", errno)
	}
}

func validKeyringJSON() string {
	return `{"schema_version":"credential-protection-keyring.v1","active_key_id":"key-1","keys":[` +
		`{"id":"key-1","encryption_key_b64u":"` + keyringEncodedByte(0x11) +
		`","hmac_key_b64u":"` + keyringEncodedByte(0x22) + `"}]}`
}

func keyringEncodedByte(value byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{value}), 32)))
}
