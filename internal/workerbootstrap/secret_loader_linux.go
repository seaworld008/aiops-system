//go:build linux

package workerbootstrap

import (
	"bytes"
	"os"

	"golang.org/x/sys/unix"
)

const (
	productionSecretRoot = "/run/aiops/control-worker-secrets/v1"

	postgresPasswordFilename          = "postgres-password"
	postgresPrivateKeyFilename        = "postgres-client-private-key.pkcs8"
	temporalStarterPrivateKeyFilename = "temporal-starter-private-key.pkcs8"
	temporalControlPrivateKeyFilename = "temporal-control-private-key.pkcs8"
	productionSecretLoaderPostgresFD  = 3
	productionSecretLoaderStarterFD   = 4
	productionSecretLoaderControlFD   = 5
	productionSecretLoaderOutputCount = 3
)

type fixedSecretSpec struct {
	name    string
	maximum int
	fd      int
	owned   []byte
}

// WriteProductionSecretsToLoaderFDs reads the independent, compile-time
// production secret root and writes exactly three role-bound frames to fixed
// anonymous FD3-FD5 pipes. It accepts no paths, environment, roles, bytes, or
// descriptors from its caller.
func WriteProductionSecretsToLoaderFDs() error {
	outputs, err := acceptProductionSecretLoaderOutputs()
	if err != nil {
		return ErrBootstrapRejected
	}
	defer closeSecretLoaderOutputs(outputs)
	anchor, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrBootstrapRejected
	}
	defer unix.Close(anchor)
	return writeSecretFramesFromAnchor(
		anchor,
		productionSecretRoot,
		[]string{"run", "aiops", "control-worker-secrets", "v1"},
		outputs,
	)
}

func acceptProductionSecretLoaderOutputs() (outputs [productionSecretLoaderOutputCount]*os.File, returnedErr error) {
	defer func() {
		if returnedErr != nil {
			closeSecretLoaderOutputs(outputs)
			outputs = [productionSecretLoaderOutputCount]*os.File{}
		}
	}()
	fds := [...]int{
		productionSecretLoaderPostgresFD,
		productionSecretLoaderStarterFD,
		productionSecretLoaderControlFD,
	}
	for index, fd := range fds {
		file, err := acceptLoaderPipe(fd, unix.O_WRONLY)
		if err != nil {
			return outputs, ErrBootstrapRejected
		}
		outputs[index] = file
	}
	if !secretLoaderOutputsDistinct(outputs) {
		return outputs, ErrBootstrapRejected
	}
	return outputs, nil
}

func writeSecretFramesFromAnchor(
	anchor int,
	rootPath string,
	components []string,
	outputs [productionSecretLoaderOutputCount]*os.File,
) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = ErrBootstrapRejected
		}
	}()
	if anchor < 0 || !validRootShape(rootPath, components) || !validTrustedDirectory(anchor, false) ||
		!validSecretLoaderOutputs(outputs) {
		return ErrBootstrapRejected
	}
	root, err := traverseTrustedDirectories(anchor, components)
	if err != nil {
		return ErrBootstrapRejected
	}
	defer unix.Close(root)
	if !validSecretFilesystem(root) {
		return ErrBootstrapRejected
	}

	specifications := []fixedSecretSpec{
		{name: postgresPasswordFilename, maximum: maximumSecretPasswordBytes, fd: -1},
		{name: postgresPrivateKeyFilename, maximum: maximumSecretPayloadBytes, fd: -1},
		{name: temporalStarterPrivateKeyFilename, maximum: maximumSecretPayloadBytes, fd: -1},
		{name: temporalControlPrivateKeyFilename, maximum: maximumSecretPayloadBytes, fd: -1},
	}
	defer closeAndClearFixedSecrets(specifications)
	// Open and validate every fixed file before reading or encoding any output.
	for index := range specifications {
		fd, openErr := openStableSecretAt(root, specifications[index].name, specifications[index].maximum)
		if openErr != nil {
			return ErrBootstrapRejected
		}
		specifications[index].fd = fd
	}
	for index := range specifications {
		contents, readErr := readStableDescriptor(
			specifications[index].fd,
			specifications[index].maximum,
			nil,
		)
		if readErr != nil {
			clear(contents)
			return ErrBootstrapRejected
		}
		specifications[index].owned = contents
	}
	if !revalidateSecretDirectoryChain(anchor, root, components) {
		return ErrBootstrapRejected
	}

	spkis := [3][]byte{}
	defer func() {
		for index := range spkis {
			clear(spkis[index])
			spkis[index] = nil
		}
	}()
	for index := range spkis {
		spki, keyErr := validateP256PKCS8PrivateKey(specifications[index+1].owned)
		if keyErr != nil {
			clear(spki)
			return ErrBootstrapRejected
		}
		spkis[index] = spki
	}
	if bytes.Equal(spkis[0], spkis[1]) || bytes.Equal(spkis[0], spkis[2]) || bytes.Equal(spkis[1], spkis[2]) {
		return ErrBootstrapRejected
	}

	frames := [productionSecretLoaderOutputCount][]byte{}
	defer func() {
		for index := range frames {
			clear(frames[index])
			frames[index] = nil
		}
	}()
	frames[0], err = encodePostgresSecretFrame(specifications[0].owned, specifications[1].owned)
	if err == nil {
		frames[1], err = encodeTemporalSecretFrame(secretFrameTemporalStarter, specifications[2].owned)
	}
	if err == nil {
		frames[2], err = encodeTemporalSecretFrame(secretFrameTemporalControl, specifications[3].owned)
	}
	if err != nil {
		return ErrBootstrapRejected
	}
	for index := range frames {
		if len(frames[index]) == 0 || len(frames[index]) > maximumSecretFrameBytes ||
			writeFileAll(outputs[index], frames[index]) != nil {
			return ErrBootstrapRejected
		}
	}
	return nil
}

func openStableSecretAt(parent int, name string, maximum int) (int, error) {
	if parent < 0 || !validBasename(name) || maximum <= 0 {
		return -1, ErrBootstrapRejected
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil || !validStableSecretDescriptor(fd, maximum) {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		return -1, ErrBootstrapRejected
	}
	return fd, nil
}

func validStableSecretDescriptor(fd int, maximum int) bool {
	if fd < 0 || maximum <= 0 {
		return false
	}
	var stat unix.Stat_t
	return unix.Fstat(fd, &stat) == nil && validArtifactStat(stat, maximum) &&
		validSecretFilesystem(fd) && !hasAccessExpandingMetadata(fd)
}

func validSecretFilesystem(fd int) bool {
	if fd < 0 {
		return false
	}
	var filesystem unix.Statfs_t
	return unix.Fstatfs(fd, &filesystem) == nil && filesystem.Type == unix.TMPFS_MAGIC
}

func validSecretLoaderOutputs(outputs [productionSecretLoaderOutputCount]*os.File) bool {
	for _, output := range outputs {
		if !validLoaderPipe(output, unix.O_WRONLY) {
			return false
		}
	}
	return secretLoaderOutputsDistinct(outputs)
}

func secretLoaderOutputsDistinct(outputs [productionSecretLoaderOutputCount]*os.File) bool {
	seen := make(map[[2]uint64]struct{}, len(outputs))
	for _, output := range outputs {
		if output == nil {
			return false
		}
		var stat unix.Stat_t
		if unix.Fstat(int(output.Fd()), &stat) != nil {
			return false
		}
		identity := [2]uint64{uint64(stat.Dev), stat.Ino}
		if _, duplicate := seen[identity]; duplicate {
			return false
		}
		seen[identity] = struct{}{}
	}
	return true
}

func revalidateSecretDirectoryChain(anchor, root int, components []string) bool {
	if !validTrustedDirectory(anchor, false) || !validTrustedDirectory(root, true) ||
		!validSecretFilesystem(root) {
		return false
	}
	reopened, err := traverseTrustedDirectories(anchor, components)
	if err != nil {
		return false
	}
	defer unix.Close(reopened)
	return validSecretFilesystem(reopened) && sameDirectoryIdentity(root, reopened)
}

func closeAndClearFixedSecrets(specifications []fixedSecretSpec) {
	for index := range specifications {
		if specifications[index].fd >= 0 {
			_ = unix.Close(specifications[index].fd)
			specifications[index].fd = -1
		}
		clear(specifications[index].owned)
		specifications[index].owned = nil
	}
}

func closeSecretLoaderOutputs(outputs [productionSecretLoaderOutputCount]*os.File) {
	for index := range outputs {
		if outputs[index] != nil {
			_ = outputs[index].Close()
			outputs[index] = nil
		}
	}
}
