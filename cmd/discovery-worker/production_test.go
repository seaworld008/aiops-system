package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/discoveryruntime"
	"github.com/seaworld008/aiops-system/internal/discoveryworker"
)

func TestSecureBootstrapFileBoundaryIsAbsoluteOwnerOnlyAndSymlinkSafe(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Fatalf("secure file boundary is unsupported on %s", runtime.GOOS)
	}
	root := t.TempDir()
	ownerOnly := filepath.Join(root, "owner-only")
	if err := os.WriteFile(ownerOnly, []byte("safe"), 0o600); err != nil {
		t.Fatalf("write owner-only file: %v", err)
	}
	var loaded string
	if err := loadSecureFile(ownerOnly, true, func(contents []byte) error {
		loaded = string(contents)
		return nil
	}); err != nil || loaded != "safe" {
		t.Fatalf("loadSecureFile(owner-only) = %q,%v", loaded, err)
	}

	shared := filepath.Join(root, "shared")
	if err := os.WriteFile(shared, []byte("unsafe"), 0o640); err != nil {
		t.Fatalf("write shared file: %v", err)
	}
	if err := os.Chmod(shared, 0o640); err != nil {
		t.Fatalf("chmod shared file: %v", err)
	}
	if err := loadSecureFile(shared, true, func([]byte) error { return nil }); !errors.Is(
		err, errBootstrapUnavailable,
	) {
		t.Fatalf("loadSecureFile(shared secret) error = %v", err)
	}
	if err := loadSecureFile(shared, false, func([]byte) error { return nil }); err != nil {
		t.Fatalf("loadSecureFile(shared public) error = %v", err)
	}

	symlink := filepath.Join(root, "symlink")
	if err := os.Symlink(ownerOnly, symlink); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	hardlink := filepath.Join(root, "hardlink")
	if err := os.Link(ownerOnly, hardlink); err != nil {
		t.Fatalf("create hardlink: %v", err)
	}
	for name, path := range map[string]string{
		"relative": "owner-only",
		"unclean":  root + "/../" + filepath.Base(root) + "/owner-only",
		"symlink":  symlink,
		"hardlink": hardlink,
	} {
		t.Run(name, func(t *testing.T) {
			if err := loadSecureFile(path, true, func([]byte) error { return nil }); !errors.Is(
				err, errBootstrapUnavailable,
			) {
				t.Fatalf("loadSecureFile(%q) error = %v", path, err)
			}
		})
	}
}

func TestSignedSourceProfileManifestAdmitsOnlyExactMergedExternalCMDB(t *testing.T) {
	root := t.TempDir()
	keyID := "source-profile-signing-v1"
	key := [sha256.Size]byte{1, 2, 3, 4}
	declaration := discoveryworker.ExternalCMDBDeclaration()
	payload := sourceProfilePayload{
		SchemaVersion: sourceProfilePayloadSchemaVersion,
		Providers: []sourceProfileProvider{{
			SourceKind:                      string(declaration.SourceKind),
			ProviderKind:                    declaration.ProviderKind,
			ProfileCode:                     string(declaration.ProfileCode),
			CanonicalDescriptorDigest:       declaration.CanonicalDescriptorDigest,
			RuntimeRecoveryCapabilityDigest: declaration.RuntimeRecoveryCapabilityDigest,
			IntegrationID:                   "11111111-1111-4111-8111-111111111111",
			CredentialReferenceID:           "external-cmdb-read-v1",
			TrustReferenceID:                "external-cmdb-trust-v1",
			NetworkPolicyReferenceID:        "external-cmdb-network-v1",
		}},
	}
	validPath := filepath.Join(root, "source-profile.json")
	writeSignedSourceProfileManifest(t, validPath, keyID, key, payload)
	registry, profiles, err := loadSourceProfileManifest(validPath, keyID, key)
	if err != nil {
		t.Fatalf("loadSourceProfileManifest(valid) error = %v", err)
	}
	if !registry.Registered(declaration.ProviderKind, declaration.ProfileCode) {
		t.Fatal("signed exact External CMDB declaration was not registered")
	}
	profile, err := profiles.ResolveProfileAdmission(t.Context(), declaration.ProfileCode)
	if err != nil || profile.ProviderKind != declaration.ProviderKind ||
		profile.IntegrationID != payload.Providers[0].IntegrationID ||
		string(profile.CredentialReferenceID) != payload.Providers[0].CredentialReferenceID {
		t.Fatalf("profile admission = %#v,%v", profile, err)
	}

	tamperedPath := filepath.Join(root, "tampered.json")
	writeSignedSourceProfileManifest(t, tamperedPath, keyID, key, payload)
	encoded, err := os.ReadFile(tamperedPath)
	if err != nil {
		t.Fatalf("read signed manifest: %v", err)
	}
	encoded[len(encoded)-3] ^= 1
	if err := os.WriteFile(tamperedPath, encoded, 0o640); err != nil {
		t.Fatalf("tamper signed manifest: %v", err)
	}
	if registry, profiles, err := loadSourceProfileManifest(
		tamperedPath, keyID, key,
	); !errors.Is(err, errBootstrapUnavailable) || registry != nil || profiles != nil {
		t.Fatalf("tampered manifest = %#v,%#v,%v", registry, profiles, err)
	}

	for name, mutate := range map[string]func(*sourceProfilePayload){
		"signed unavailable provider": func(value *sourceProfilePayload) {
			value.Providers[0].SourceKind = "KUBERNETES_OPERATOR"
			value.Providers[0].ProviderKind = "KUBERNETES_OPERATOR"
			value.Providers[0].ProfileCode = "KUBERNETES_OPERATOR"
		},
		"signed descriptor drift": func(value *sourceProfilePayload) {
			value.Providers[0].CanonicalDescriptorDigest = strings.Repeat("0", 64)
		},
		"duplicate": func(value *sourceProfilePayload) {
			value.Providers = append(value.Providers, value.Providers[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneSourceProfilePayload(payload)
			mutate(&candidate)
			path := filepath.Join(root, strings.ReplaceAll(name, " ", "-")+".json")
			writeSignedSourceProfileManifest(t, path, keyID, key, candidate)
			if registry, profiles, err := loadSourceProfileManifest(
				path, keyID, key,
			); !errors.Is(err, errBootstrapUnavailable) ||
				registry != nil || profiles != nil {
				t.Fatalf("load signed drift = %#v,%#v,%v", registry, profiles, err)
			}
		})
	}
}

func TestSecretKeyManifestsProofAuthorityAndCheckpointKeyringFailClosed(t *testing.T) {
	root := t.TempDir()
	keyHex := strings.Repeat("12", sha256.Size)
	keyPath := filepath.Join(root, "profile-key.json")
	writeJSONFile(t, keyPath, hmacKeyDocument{
		SchemaVersion: sourceProfileKeySchemaVersion,
		KeyID:         "profile-signing-v1",
		KeyHex:        keyHex,
	}, 0o600)
	keyID, key, err := loadHMACKey(keyPath, sourceProfileKeySchemaVersion)
	if err != nil || keyID != "profile-signing-v1" ||
		hex.EncodeToString(key[:]) != keyHex {
		t.Fatalf("loadHMACKey() = %q,%x,%v", keyID, key, err)
	}

	sharedPath := filepath.Join(root, "shared-key.json")
	writeJSONFile(t, sharedPath, hmacKeyDocument{
		SchemaVersion: sourceProfileKeySchemaVersion,
		KeyID:         "profile-signing-v1",
		KeyHex:        keyHex,
	}, 0o640)
	if _, _, err := loadHMACKey(
		sharedPath, sourceProfileKeySchemaVersion,
	); !errors.Is(err, errBootstrapUnavailable) {
		t.Fatalf("group-readable secret key error = %v", err)
	}

	keyringPath := filepath.Join(root, "checkpoint-keyring.json")
	writeJSONFile(t, keyringPath, checkpointKeyringDocument{
		SchemaVersion: checkpointKeyringSchemaVersion,
		ActiveKeyID:   "checkpoint-active-v1",
		Keys: []checkpointKeyDocument{
			{KeyID: "checkpoint-active-v1", KeyHex: strings.Repeat("34", sha256.Size)},
			{KeyID: "checkpoint-retained-v1", KeyHex: strings.Repeat("56", sha256.Size)},
		},
	}, 0o600)
	keyring, err := loadCheckpointKeyring(keyringPath)
	if err != nil {
		t.Fatalf("loadCheckpointKeyring() error = %v", err)
	}
	if active, err := keyring.ActiveKeyID(); err != nil || active != "checkpoint-active-v1" {
		t.Fatalf("ActiveKeyID() = %q,%v", active, err)
	}
	keyring.Destroy()

	authority, err := newHMACProofAuthority(key)
	clear(key[:])
	if err != nil {
		t.Fatalf("newHMACProofAuthority() error = %v", err)
	}
	digest := sha256.Sum256([]byte("cleanup-proof-test"))
	signature, err := authority.SignCleanupProof(t.Context(), digest[:])
	if err != nil || authority.VerifyCleanupProof(t.Context(), digest[:], signature) != nil {
		t.Fatalf("proof sign/verify = %x,%v", signature, err)
	}
	tampered := bytes.Clone(signature)
	tampered[0] ^= 1
	if authority.VerifyCleanupProof(t.Context(), digest[:], tampered) == nil {
		t.Fatal("proof authority accepted a tampered signature")
	}
	authority.Destroy()
	if _, err := authority.SignCleanupProof(
		context.Background(), digest[:],
	); !errors.Is(err, errBootstrapUnavailable) {
		t.Fatalf("destroyed proof authority error = %v", err)
	}
	clear(signature)
	clear(tampered)
}

func TestProductionGraphUsesMergedExternalCMDBRuntimeAuthority(t *testing.T) {
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, "production.go", nil, 0)
	if err != nil {
		t.Fatalf("parse production graph: %v", err)
	}

	imports := map[string]bool{}
	for _, imported := range parsed.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote production import: %v", err)
		}
		imports[path] = true
	}
	const runtimePackage = "github.com/seaworld008/aiops-system/internal/discoveryruntime"
	if !imports[runtimePackage] {
		t.Fatalf("production graph does not import merged runtime authority %q", runtimePackage)
	}

	calls := map[string]int{}
	var attemptFactoryArgument string
	forbiddenDeclarations := map[string]bool{}
	ast.Inspect(parsed, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.CallExpr:
			selector, ok := value.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			qualifier, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			name := qualifier.Name + "." + selector.Sel.Name
			calls[name]++
			if name == "discoveryworker.NewAttemptSessionAuthority" &&
				len(value.Args) == 3 {
				if argument, ok := value.Args[2].(*ast.Ident); ok {
					attemptFactoryArgument = argument.Name
				}
			}
		case *ast.TypeSpec:
			forbiddenDeclarations[value.Name.Name] = true
		case *ast.ValueSpec:
			for _, name := range value.Names {
				forbiddenDeclarations[name.Name] = true
			}
		}
		return true
	})

	for name, count := range map[string]int{
		"discoveryruntime.NewPostgres":               1,
		"discoveryruntime.NewExternalCMDBAuthority":  1,
		"discoveryworker.NewAttemptSessionAuthority": 1,
	} {
		if calls[name] != count {
			t.Fatalf("production graph call count %s = %d, want %d", name, calls[name], count)
		}
	}
	if attemptFactoryArgument != "runtimeAuthority" {
		t.Fatalf(
			"Task 28B attempt authority runtime factory = %q, want sole runtimeAuthority",
			attemptFactoryArgument,
		)
	}
	for _, forbidden := range []string{
		"closedExternalCMDBRuntimeFactory",
		"resolveRuntimeBindingSQL",
	} {
		if forbiddenDeclarations[forbidden] {
			t.Fatalf("production graph retains obsolete runtime implementation %q", forbidden)
		}
	}
}

func TestProductionRuntimeDependenciesRequireServerMaterialResolver(t *testing.T) {
	valid := productionRuntimeDependencies{
		observer:              discoveryworker.NewClosedWorkerObserver(),
		externalCMDBMaterials: &productionMaterialResolverStub{},
	}
	if !valid.valid() {
		t.Fatal("exact production runtime dependencies were rejected")
	}

	var typedNil *productionMaterialResolverStub
	for name, mutate := range map[string]func(*productionRuntimeDependencies){
		"missing observer": func(value *productionRuntimeDependencies) {
			value.observer = nil
		},
		"missing resolver": func(value *productionRuntimeDependencies) {
			value.externalCMDBMaterials = nil
		},
		"typed nil resolver": func(value *productionRuntimeDependencies) {
			value.externalCMDBMaterials = typedNil
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if candidate.valid() {
				t.Fatal("production runtime dependencies accepted a missing dependency")
			}
		})
	}
}

func TestDefaultProductionRuntimeDependenciesInstallExplicitClosedResolver(
	t *testing.T,
) {
	dependencies := defaultProductionRuntimeDependencies()
	if !dependencies.valid() {
		t.Fatal("default production runtime dependencies cannot assemble the binary")
	}
	material, err := dependencies.externalCMDBMaterials.ResolveExternalCMDB(
		t.Context(),
		nil,
	)
	if material != nil ||
		!errors.Is(err, discoveryruntime.ErrExternalCMDBRuntimeAuthority) {
		t.Fatalf("closed material resolver = %#v,%v", material, err)
	}
}

func TestNewProductionFailsBeforeReadyForMissingOrUnsafeBootstrap(t *testing.T) {
	valid, err := loadConfig(nil, validConfigEnvironment())
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if runtime, err := newProduction(valid); !errors.Is(err, errProductionUnavailable) || runtime != nil {
		t.Fatalf("newProduction(missing files) = %#v,%v", runtime, err)
	}

	for name, mutate := range map[string]func(*Config){
		"missing mTLS":       func(value *Config) { value.WorkloadPrivateKeyFile = "" },
		"missing manifest":   func(value *Config) { value.SourceProfileManifestFile = "" },
		"missing authority":  func(value *Config) { value.SessionAuthorityEndpoint = "" },
		"missing checkpoint": func(value *Config) { value.CheckpointKeyringFile = "" },
		"missing metrics":    func(value *Config) { value.MetricsBindAddress = "" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if runtime, err := newProduction(candidate); !errors.Is(
				err, errProductionUnavailable,
			) || runtime != nil {
				t.Fatalf("newProduction(%s) = %#v,%v", name, runtime, err)
			}
		})
	}
}

type productionMaterialResolverStub struct{}

func (*productionMaterialResolverStub) ResolveExternalCMDB(
	context.Context,
	*discoveryruntime.ExternalCMDBMaterialRequest,
) (*discoveryruntime.ExternalCMDBRuntimeMaterial, error) {
	return nil, discoveryruntime.ErrExternalCMDBRuntimeAuthority
}

func writeSignedSourceProfileManifest(
	t *testing.T,
	path, keyID string,
	key [sha256.Size]byte,
	payload sourceProfilePayload,
) {
	t.Helper()
	canonical, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal source profile payload: %v", err)
	}
	digest := sha256.Sum256(canonical)
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(sourceProfileSignatureDomain))
	_, _ = mac.Write(digest[:])
	writeJSONFile(t, path, sourceProfileManifestEnvelope{
		SchemaVersion:   sourceProfileManifestSchemaVersion,
		SigningKeyID:    keyID,
		Payload:         payload,
		PayloadSHA256:   hex.EncodeToString(digest[:]),
		SignatureSHA256: hex.EncodeToString(mac.Sum(nil)),
	}, 0o640)
	clear(canonical)
}

func cloneSourceProfilePayload(input sourceProfilePayload) sourceProfilePayload {
	input.Providers = slices.Clone(input.Providers)
	return input
}

func writeJSONFile(t *testing.T, path string, value any, mode os.FileMode) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s: %v", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, encoded, mode); err != nil {
		t.Fatalf("write %s: %v", filepath.Base(path), err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", filepath.Base(path), err)
	}
	clear(encoded)
}

func TestProductionGraphIsolatedFromControlPlaneFakesAndUnavailableProviders(t *testing.T) {
	root := repositoryRoot(t)
	discoveryGraph := localImportGraph(t, root, "cmd/discovery-worker")
	for _, required := range []string{
		"github.com/seaworld008/aiops-system/internal/assetsource/externalcmdb",
		"github.com/seaworld008/aiops-system/internal/discoverycleanup",
		"github.com/seaworld008/aiops-system/internal/discoveryruntime",
		"github.com/seaworld008/aiops-system/internal/discoveryworker",
	} {
		if !discoveryGraph[required] {
			t.Fatalf("Discovery Worker production graph does not reach %q", required)
		}
	}
	for path := range discoveryGraph {
		for _, forbidden := range []string{
			"/memory", "/testdata", "/msw", "/model", "/llm",
			"internal/httpapi", "internal/assetsource/vsphere",
			"internal/assetsource/proxmox",
			"internal/connectors/kubernetes", "internal/connectors/awx",
			"github.com/vmware/govmomi",
		} {
			if strings.Contains(path, forbidden) {
				t.Fatalf("Discovery Worker production graph reaches forbidden %q through %q", forbidden, path)
			}
		}
	}

	controlPlaneGraph := localImportGraph(t, root, "cmd/control-plane")
	for path := range controlPlaneGraph {
		for _, forbidden := range []string{
			"internal/assetsource/externalcmdb",
			"internal/assetsource/vsphere",
			"internal/assetsource/proxmox",
			"internal/discoveryworker",
			"internal/discoverycleanup",
			"github.com/vmware/govmomi",
		} {
			if strings.Contains(path, forbidden) {
				t.Fatalf("Control Plane production graph reaches forbidden %q through %q", forbidden, path)
			}
		}
	}
}

func TestProductionFilesAreTheExactTask28CWhitelist(t *testing.T) {
	root := repositoryRoot(t)
	var got []string
	for _, directory := range []string{"internal/discoveryworker", "cmd/discovery-worker"} {
		entries, err := os.ReadDir(filepath.Join(root, directory))
		if err != nil {
			t.Fatalf("ReadDir(%s): %v", directory, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := filepath.ToSlash(filepath.Join(directory, entry.Name()))
			if strings.HasPrefix(name, "cmd/discovery-worker/") ||
				slices.Contains([]string{
					"internal/discoveryworker/registry.go",
					"internal/discoveryworker/registry_test.go",
					"internal/discoveryworker/production.go",
					"internal/discoveryworker/production_test.go",
				}, name) {
				got = append(got, name)
			}
		}
	}
	slices.Sort(got)
	want := []string{
		"cmd/discovery-worker/config.go",
		"cmd/discovery-worker/config_test.go",
		"cmd/discovery-worker/main.go",
		"cmd/discovery-worker/main_test.go",
		"cmd/discovery-worker/production.go",
		"cmd/discovery-worker/production_test.go",
		"internal/discoveryworker/production.go",
		"internal/discoveryworker/production_test.go",
		"internal/discoveryworker/registry.go",
		"internal/discoveryworker/registry_test.go",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Task 28C file set = %#v, want %#v", got, want)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}

func localImportGraph(t *testing.T, root, start string) map[string]bool {
	t.Helper()
	const module = "github.com/seaworld008/aiops-system"
	graph := map[string]bool{}
	queue := []string{module + "/" + filepath.ToSlash(start)}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if graph[current] {
			continue
		}
		graph[current] = true
		if !strings.HasPrefix(current, module+"/") {
			continue
		}
		directory := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(current, module+"/")))
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatalf("read import graph directory %s: %v", directory, err)
		}
		files := token.NewFileSet()
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
				strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(directory, entry.Name())
			parsed, err := parser.ParseFile(files, path, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			for _, imported := range parsed.Imports {
				value, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					t.Fatalf("unquote import in %s: %v", path, err)
				}
				graph[value] = graph[value]
				if strings.HasPrefix(value, module+"/") && !slices.Contains(queue, value) &&
					!graph[value] {
					queue = append(queue, value)
				}
			}
			ast.Inspect(parsed, func(ast.Node) bool { return true })
		}
	}
	return graph
}
