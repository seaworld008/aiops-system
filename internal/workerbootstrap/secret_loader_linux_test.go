//go:build linux

package workerbootstrap

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWriteSecretFramesFromFixedRoot(t *testing.T) {
	fixture := newLinuxSecretLoaderFixture(t)
	frames, err := fixture.writeFrames()
	if err != nil {
		t.Fatalf("writeSecretFramesFromAnchor() error = %v", err)
	}

	postgres, err := decodeSecretFrame(secretFramePostgres, frames[0])
	if err != nil {
		t.Fatalf("decode postgres frame: %v", err)
	}
	defer postgres.close()
	starter, err := decodeSecretFrame(secretFrameTemporalStarter, frames[1])
	if err != nil {
		t.Fatalf("decode Temporal Starter frame: %v", err)
	}
	defer starter.close()
	control, err := decodeSecretFrame(secretFrameTemporalControl, frames[2])
	if err != nil {
		t.Fatalf("decode Temporal Control frame: %v", err)
	}
	defer control.close()

	if !bytes.Equal(postgres.password, fixture.password) ||
		!bytes.Equal(postgres.privateKeyPKCS8, fixture.keys[0]) ||
		!bytes.Equal(starter.privateKeyPKCS8, fixture.keys[1]) ||
		!bytes.Equal(control.privateKeyPKCS8, fixture.keys[2]) {
		t.Fatal("fixed-root loader changed secret material or role mapping")
	}
	for index, frame := range frames {
		if len(frame) == 0 || len(frame) > maximumSecretFrameBytes {
			t.Fatalf("frame %d length = %d", index, len(frame))
		}
		if bytes.HasPrefix(frame, []byte("{")) {
			t.Fatalf("frame %d unexpectedly uses JSON", index)
		}
	}
}

func TestWriteSecretFramesRejectsFilesystemAndMaterialSubstitution(t *testing.T) {
	tests := map[string]func(*testing.T, *linuxSecretLoaderFixture){
		"missing secret": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			if err := os.Remove(filepath.Join(fixture.rootPath, postgresPasswordFilename)); err != nil {
				t.Fatal(err)
			}
		},
		"empty secret": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			fixture.rewrite(t, postgresPasswordFilename, nil)
		},
		"oversized password": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			fixture.rewrite(t, postgresPasswordFilename, bytes.Repeat([]byte{'p'}, maximumSecretPasswordBytes+1))
		},
		"oversized private key": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			fixture.rewrite(t, postgresPrivateKeyFilename, bytes.Repeat([]byte{'k'}, maximumSecretPayloadBytes+1))
		},
		"writable ancestor": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			if err := os.Chmod(filepath.Join(fixture.anchorPath, fixture.components[0]), 0o770); err != nil {
				t.Fatal(err)
			}
		},
		"final directory mode": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			if err := os.Chmod(fixture.rootPath, 0o750); err != nil {
				t.Fatal(err)
			}
		},
		"secret mode": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			if err := os.Chmod(filepath.Join(fixture.rootPath, postgresPasswordFilename), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"secret symlink": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			path := filepath.Join(fixture.rootPath, postgresPasswordFilename)
			if err := os.Rename(path, path+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".real", path); err != nil {
				t.Fatal(err)
			}
		},
		"secret hardlink": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			path := filepath.Join(fixture.rootPath, postgresPasswordFilename)
			if err := os.Link(path, path+".link"); err != nil {
				t.Fatal(err)
			}
		},
		"secret fifo": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			path := filepath.Join(fixture.rootPath, postgresPasswordFilename)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(path, 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"secret xattr": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			path := filepath.Join(fixture.rootPath, postgresPasswordFilename)
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := unix.Setxattr(path, "user.aiops_canary", []byte("x"), 0); err != nil {
				t.Skipf("user xattr unavailable: %v", err)
			}
			if err := os.Chmod(path, 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"password newline": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			fixture.rewrite(t, postgresPasswordFilename, []byte("secret-canary\n"))
		},
		"invalid private key": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			fixture.rewrite(t, temporalStarterPrivateKeyFilename, []byte("secret-key-canary"))
		},
		"duplicate postgres and starter private keys": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			fixture.rewrite(t, temporalStarterPrivateKeyFilename, fixture.keys[0])
		},
		"duplicate postgres and control private keys": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			fixture.rewrite(t, temporalControlPrivateKeyFilename, fixture.keys[0])
		},
		"duplicate temporal private key roles": func(t *testing.T, fixture *linuxSecretLoaderFixture) {
			t.Helper()
			fixture.rewrite(t, temporalControlPrivateKeyFilename, fixture.keys[1])
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newLinuxSecretLoaderFixture(t)
			mutate(t, fixture)
			frames, err := fixture.writeFrames()
			if !errors.Is(err, ErrBootstrapRejected) {
				t.Fatalf("writeSecretFramesFromAnchor() error = %v; want rejection", err)
			}
			for index, frame := range frames {
				if len(frame) != 0 {
					t.Fatalf("rejected load wrote frame %d: %x", index, frame)
				}
			}
			for _, canary := range []string{fixture.rootPath, string(fixture.password), "secret-key-canary"} {
				if err != nil && strings.Contains(err.Error(), canary) {
					t.Fatalf("error leaked canary %q: %v", canary, err)
				}
			}
		})
	}
}

func TestWriteSecretFramesRequiresTMPFSRoot(t *testing.T) {
	fixture := newOrdinaryFilesystemSecretLoaderFixture(t)
	frames, err := fixture.writeFrames()
	if !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("ordinary-filesystem load error = %v; want rejection", err)
	}
	for index, frame := range frames {
		if len(frame) != 0 {
			t.Fatalf("ordinary-filesystem load wrote frame %d: %x", index, frame)
		}
	}
}

func TestWriteSecretFramesKeepsFixedFilenameRoleMapping(t *testing.T) {
	fixture := newLinuxSecretLoaderFixture(t)
	starterKey := bytes.Clone(fixture.keys[1])
	controlKey := bytes.Clone(fixture.keys[2])
	defer clear(starterKey)
	defer clear(controlKey)
	fixture.rewrite(t, temporalStarterPrivateKeyFilename, controlKey)
	fixture.rewrite(t, temporalControlPrivateKeyFilename, starterKey)

	frames, err := fixture.writeFrames()
	if err != nil {
		t.Fatalf("write swapped fixed files: %v", err)
	}
	starter, err := decodeSecretFrame(secretFrameTemporalStarter, frames[1])
	if err != nil {
		t.Fatalf("decode Temporal Starter frame: %v", err)
	}
	defer starter.close()
	control, err := decodeSecretFrame(secretFrameTemporalControl, frames[2])
	if err != nil {
		t.Fatalf("decode Temporal Control frame: %v", err)
	}
	defer control.close()
	if !bytes.Equal(starter.privateKeyPKCS8, controlKey) || !bytes.Equal(control.privateKeyPKCS8, starterKey) {
		t.Fatal("secret loader inferred roles from key contents instead of fixed filenames")
	}
}

func TestWriteSecretFramesRejectsInvalidOutputBeforeReadingRoot(t *testing.T) {
	fixture := newLinuxSecretLoaderFixture(t)
	ordinary, err := os.CreateTemp(t.TempDir(), "ordinary-output")
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	readers, writers := openSecretLoaderTestPipes(t)
	defer closeSecretLoaderTestFiles(readers[:])
	defer closeSecretLoaderTestFiles(writers[:])
	_ = writers[1].Close()
	writers[1] = ordinary

	anchor, err := unix.Open(fixture.anchorPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(anchor)
	if err := writeSecretFramesFromAnchor(anchor, fixture.rootPath, fixture.components, writers); !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("invalid output error = %v, want rejection", err)
	}
	for index, reader := range readers {
		_ = writers[index].Close()
		contents, readErr := io.ReadAll(reader)
		if readErr != nil || len(contents) != 0 {
			t.Fatalf("invalid-output pipe %d = %x, %v; want empty EOF", index, contents, readErr)
		}
	}
}

func TestWriteSecretFramesRejectsAliasedOutputPipes(t *testing.T) {
	fixture := newLinuxSecretLoaderFixture(t)
	readers, writers := openSecretLoaderTestPipes(t)
	defer closeSecretLoaderTestFiles(readers[:])
	defer closeSecretLoaderTestFiles(writers[:])

	aliasFD, err := unix.FcntlInt(writers[0].Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := writers[1].Close(); err != nil {
		_ = unix.Close(aliasFD)
		t.Fatal(err)
	}
	writers[1] = os.NewFile(uintptr(aliasFD), "aliased-secret-loader-output")
	if writers[1] == nil {
		_ = unix.Close(aliasFD)
		t.Fatal("os.NewFile(aliased output) returned nil")
	}

	anchor := fixture.openAnchor()
	defer unix.Close(anchor)
	if err := writeSecretFramesFromAnchor(anchor, fixture.rootPath, fixture.components, writers); !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("aliased outputs error = %v; want rejection", err)
	}
	closeSecretLoaderTestFiles(writers[:])
	for index, reader := range readers {
		contents, readErr := io.ReadAll(reader)
		if readErr != nil || len(contents) != 0 {
			t.Fatalf("aliased-output pipe %d = %x, %v; want empty EOF", index, contents, readErr)
		}
	}
}

func TestWriteFileAllRejectsPartialPipeWriteWithoutLeakingGoroutines(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	drained := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, readErr := reader.Read(buffer)
		closeErr := reader.Close()
		if readErr != nil {
			drained <- readErr
			return
		}
		drained <- closeErr
	}()
	contents := bytes.Repeat([]byte{'x'}, 1<<20)
	writeErr := writeFileAll(writer, contents)
	clear(contents)
	closeErr := writer.Close()
	if drainErr := <-drained; drainErr != nil {
		t.Fatalf("drain one byte and close read end: %v", drainErr)
	}
	if !errors.Is(writeErr, ErrBootstrapRejected) {
		t.Fatalf("writeFileAll(partial pipe) error = %v; want rejection", writeErr)
	}
	if closeErr != nil {
		t.Fatalf("close partial-write output: %v", closeErr)
	}
}

func TestSecretLoaderRejectsDirectoryReplacementAndFileMutation(t *testing.T) {
	t.Run("directory replacement", func(t *testing.T) {
		fixture := newLinuxSecretLoaderFixture(t)
		anchor := fixture.openAnchor()
		defer unix.Close(anchor)
		root, err := traverseTrustedDirectories(anchor, fixture.components)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(root)
		replacedPath := fixture.rootPath + ".replaced"
		if err := os.Rename(fixture.rootPath, replacedPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(fixture.rootPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if revalidateSecretDirectoryChain(anchor, root, fixture.components) {
			t.Fatal("revalidation accepted a replacement secret root")
		}
	})

	t.Run("opened file mutation", func(t *testing.T) {
		fixture := newLinuxSecretLoaderFixture(t)
		anchor := fixture.openAnchor()
		defer unix.Close(anchor)
		root, err := traverseTrustedDirectories(anchor, fixture.components)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(root)
		fd, err := openStableSecretAt(root, postgresPasswordFilename, maximumSecretPasswordBytes)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		contents, err := readStableDescriptor(fd, maximumSecretPasswordBytes, func() {
			fixture.rewrite(t, postgresPasswordFilename, []byte("mutated-secret-canary"))
		})
		clear(contents)
		if !errors.Is(err, ErrBootstrapRejected) {
			t.Fatalf("readStableDescriptor(mutated secret) error = %v; want rejection", err)
		}
	})

	t.Run("pathname replacement keeps opened inode", func(t *testing.T) {
		fixture := newLinuxSecretLoaderFixture(t)
		anchor := fixture.openAnchor()
		defer unix.Close(anchor)
		root, err := traverseTrustedDirectories(anchor, fixture.components)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(root)
		fd, err := openStableSecretAt(root, postgresPasswordFilename, maximumSecretPasswordBytes)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		path := filepath.Join(fixture.rootPath, postgresPasswordFilename)
		if err := os.Rename(path, path+".replaced"); err != nil {
			t.Fatal(err)
		}
		fixture.rewrite(t, postgresPasswordFilename, []byte("replacement-secret-canary"))
		contents, err := readStableDescriptor(fd, maximumSecretPasswordBytes, nil)
		defer clear(contents)
		if err != nil {
			t.Fatalf("read pinned secret descriptor: %v", err)
		}
		if !bytes.Equal(contents, fixture.password) {
			t.Fatal("opened secret descriptor followed a replacement pathname")
		}
	})
}

type linuxSecretLoaderFixture struct {
	t          *testing.T
	anchorPath string
	rootPath   string
	components []string
	password   []byte
	keys       [3][]byte
}

func newLinuxSecretLoaderFixture(t *testing.T) *linuxSecretLoaderFixture {
	t.Helper()
	anchorPath, err := os.MkdirTemp("/dev/shm", "aiops-secret-loader-test-")
	if err != nil {
		t.Skipf("tmpfs fixture unavailable: %v", err)
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(anchorPath, &filesystem); err != nil || filesystem.Type != unix.TMPFS_MAGIC {
		_ = os.RemoveAll(anchorPath)
		t.Skipf("tmpfs fixture unavailable: statfs=%#v, error=%v", filesystem, err)
	}
	return buildLinuxSecretLoaderFixture(t, anchorPath)
}

func newOrdinaryFilesystemSecretLoaderFixture(t *testing.T) *linuxSecretLoaderFixture {
	t.Helper()
	candidates := []string{t.TempDir(), "."}
	for _, candidate := range candidates {
		anchorPath, err := os.MkdirTemp(candidate, ".aiops-secret-loader-ordinary-")
		if err != nil {
			continue
		}
		absolute, absoluteErr := filepath.Abs(anchorPath)
		if absoluteErr != nil {
			_ = os.RemoveAll(anchorPath)
			continue
		}
		var filesystem unix.Statfs_t
		statErr := unix.Statfs(absolute, &filesystem)
		if statErr == nil && filesystem.Type != unix.TMPFS_MAGIC {
			return buildLinuxSecretLoaderFixture(t, absolute)
		}
		_ = os.RemoveAll(anchorPath)
	}
	t.Skip("writable ordinary filesystem unavailable")
	return nil
}

func buildLinuxSecretLoaderFixture(t *testing.T, anchorPath string) *linuxSecretLoaderFixture {
	t.Helper()
	t.Cleanup(func() { _ = os.RemoveAll(anchorPath) })
	if err := os.Chmod(anchorPath, 0o700); err != nil {
		t.Fatal(err)
	}
	components := []string{"control-worker-secrets", "v1"}
	rootPath := filepath.Join(append([]string{anchorPath}, components...)...)
	if err := os.Mkdir(filepath.Join(anchorPath, components[0]), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := &linuxSecretLoaderFixture{
		t:          t,
		anchorPath: anchorPath,
		rootPath:   rootPath,
		components: components,
		password:   []byte("postgres-secret-canary"),
		keys: [3][]byte{
			testPKCS8PrivateKey(t, elliptic.P256()),
			testPKCS8PrivateKey(t, elliptic.P256()),
			testPKCS8PrivateKey(t, elliptic.P256()),
		},
	}
	fixture.rewrite(t, postgresPasswordFilename, fixture.password)
	fixture.rewrite(t, postgresPrivateKeyFilename, fixture.keys[0])
	fixture.rewrite(t, temporalStarterPrivateKeyFilename, fixture.keys[1])
	fixture.rewrite(t, temporalControlPrivateKeyFilename, fixture.keys[2])
	return fixture
}

func (fixture *linuxSecretLoaderFixture) openAnchor() int {
	fixture.t.Helper()
	anchor, err := unix.Open(fixture.anchorPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return anchor
}

func (fixture *linuxSecretLoaderFixture) rewrite(t *testing.T, name string, contents []byte) {
	t.Helper()
	path := filepath.Join(fixture.rootPath, name)
	_ = os.Chmod(path, 0o600)
	if err := os.WriteFile(path, contents, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
}

func (fixture *linuxSecretLoaderFixture) writeFrames() ([3][]byte, error) {
	fixture.t.Helper()
	readers, writers := openSecretLoaderTestPipes(fixture.t)
	anchor := fixture.openAnchor()
	var err error
	writeErr := writeSecretFramesFromAnchor(anchor, fixture.rootPath, fixture.components, writers)
	closeErr := unix.Close(anchor)
	closeSecretLoaderTestFiles(writers[:])
	var frames [3][]byte
	for index, reader := range readers {
		frames[index], err = io.ReadAll(reader)
		_ = reader.Close()
		if err != nil && writeErr == nil {
			writeErr = err
		}
	}
	if writeErr == nil && closeErr != nil {
		writeErr = closeErr
	}
	return frames, writeErr
}

func openSecretLoaderTestPipes(t interface {
	Helper()
	Fatal(...any)
}) (readers [3]*os.File, writers [3]*os.File) {
	t.Helper()
	for index := range readers {
		var err error
		readers[index], writers[index], err = os.Pipe()
		if err != nil {
			closeSecretLoaderTestFiles(readers[:])
			closeSecretLoaderTestFiles(writers[:])
			t.Fatal(err)
		}
	}
	return readers, writers
}

func closeSecretLoaderTestFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}
