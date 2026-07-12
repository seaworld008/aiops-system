// Package readtarget defines immutable, process-owned READ data-source targets.
package readtarget

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/seaworld008/aiops-system/internal/readconnector"
)

const ManifestSchemaVersion = "read-target-manifest.v1"

var (
	ErrInvalidDefinition  = errors.New("invalid READ target definition")
	ErrTargetRejected     = errors.New("READ target rejected")
	ErrManifestPath       = errors.New("READ target manifest path rejected")
	ErrManifestFile       = errors.New("READ target manifest file rejected")
	ErrManifestJSON       = errors.New("READ target manifest JSON rejected")
	ErrManifestDefinition = errors.New("READ target manifest definition rejected")
)

type Scope struct {
	TenantID      string `json:"tenant_id"`
	WorkspaceID   string `json:"workspace_id"`
	EnvironmentID string `json:"environment_id"`
}

type Endpoint struct {
	Origin       string `json:"origin"`
	ServerName   string `json:"server_name"`
	CABundleFile string `json:"ca_bundle_file"`
}

type Definition struct {
	Scope             Scope              `json:"scope"`
	TargetRef         string             `json:"target_ref"`
	Kind              readconnector.Kind `json:"kind"`
	Endpoint          Endpoint           `json:"endpoint"`
	CredentialRoleRef string             `json:"credential_role_ref"`
	NetworkPolicyRef  string             `json:"network_policy_ref"`
}

// Target is a detached, immutable runtime capability. Its security-sensitive
// configuration is deliberately private and redacted at every wire boundary.
type Target struct {
	targetRef         string
	digest            string
	kind              readconnector.Kind
	origin            url.URL
	serverName        string
	credentialRoleRef string
	networkPolicyRef  string
	tlsConfiguration  *tls.Config
}

func (target Target) Digest() string            { return target.digest }
func (target Target) Kind() readconnector.Kind  { return target.kind }
func (target Target) TargetRef() string         { return target.targetRef }
func (target Target) CredentialRoleRef() string { return target.credentialRoleRef }
func (target Target) NetworkPolicyRef() string  { return target.networkPolicyRef }

func (target Target) OriginURL() *url.URL {
	copy := target.origin
	return &copy
}

func (target Target) TLSConfig() *tls.Config {
	if target.tlsConfiguration == nil {
		return nil
	}
	copy := target.tlsConfiguration.Clone()
	if target.tlsConfiguration.RootCAs != nil {
		copy.RootCAs = target.tlsConfiguration.RootCAs.Clone()
	}
	copy.NextProtos = append([]string(nil), target.tlsConfiguration.NextProtos...)
	return copy
}

func (Target) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Target) UnmarshalJSON([]byte) error  { return ErrTargetRejected }

func (target Target) String() string {
	return fmt.Sprintf("ReadTarget{Kind:%q Digest:%q Security:[REDACTED]}", target.kind, target.digest)
}
func (target Target) GoString() string { return target.String() }
func (target Target) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, target.String())
}

var _ json.Marshaler = Target{}
