package runneridentity

import "testing"

func TestAllowedIdentityFileExtendedAttributesNeverIncludeAccessACLs(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"darwin", "linux", "freebsd"} {
		for _, name := range []string{
			"system.posix_acl_access", "system.posix_acl_default", "com.apple.system.Security", "user.injected",
		} {
			if allowedIdentityFileExtendedAttributeForOS(goos, name) {
				t.Fatalf("%s access-affecting or unknown xattr %q was allowlisted", goos, name)
			}
		}
	}
	if !allowedIdentityFileExtendedAttributeForOS("darwin", "com.apple.provenance") {
		t.Fatal("macOS provenance metadata was rejected")
	}
	for _, name := range []string{"security.selinux", "security.ima", "security.evm"} {
		if !allowedIdentityFileExtendedAttributeForOS("linux", name) {
			t.Fatalf("restrictive Linux security label %q was rejected", name)
		}
	}
	for _, test := range []struct{ goos, name string }{
		{goos: "darwin", name: "security.selinux"},
		{goos: "linux", name: "com.apple.provenance"},
		{goos: "freebsd", name: "com.apple.provenance"},
	} {
		if allowedIdentityFileExtendedAttributeForOS(test.goos, test.name) {
			t.Fatalf("%s foreign xattr %q was allowlisted", test.goos, test.name)
		}
	}
}
