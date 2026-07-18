package vsphere

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"github.com/google/uuid"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const (
	fullInventoryMode             = "FULL"
	fullInventoryCheckpointRedact = "[REDACTED_VSPHERE_FULL_INVENTORY_CHECKPOINT]"
)

var errInventoryCheckpoint = errors.New("vsphere full inventory checkpoint rejected")

type fullInventoryCheckpoint struct {
	instanceUUID     string
	mode             string
	collectorVersion string
	fullSnapshotID   string
	pageTokenHash    string
}

type fullInventoryCheckpointDocument struct {
	InstanceUUID     string `json:"instance_uuid"`
	Mode             string `json:"mode"`
	CollectorVersion string `json:"collector_version"`
	FullSnapshotID   string `json:"full_snapshot_id"`
	PageTokenHash    string `json:"page_token_hash"`
}

func newFullInventoryCheckpoint(
	instanceUUID string,
	collectorSequence int64,
	fullSnapshotID string,
	pageToken []byte,
) (discoverysource.Checkpoint, fullInventoryCheckpoint, error) {
	value := fullInventoryCheckpoint{
		instanceUUID:     instanceUUID,
		mode:             fullInventoryMode,
		collectorVersion: strconv.FormatInt(collectorSequence, 10),
		fullSnapshotID:   fullSnapshotID,
		pageTokenHash:    inventoryPageTokenHash(fullSnapshotID, pageToken),
	}
	canonical, err := value.canonicalBytes()
	if err != nil {
		return discoverysource.Checkpoint{}, fullInventoryCheckpoint{}, err
	}
	checkpoint, err := discoverysource.NewCheckpoint(profileCode, canonical)
	clear(canonical)
	if err != nil {
		return discoverysource.Checkpoint{}, fullInventoryCheckpoint{}, errInventoryCheckpoint
	}
	return checkpoint, value, nil
}

func openFullInventoryCheckpoint(
	checkpoint discoverysource.Checkpoint,
) (fullInventoryCheckpoint, bool, error) {
	if checkpoint.ProfileCode() != profileCode {
		return fullInventoryCheckpoint{}, false, errInventoryCheckpoint
	}
	if checkpoint.IsEmpty() {
		return fullInventoryCheckpoint{}, true, nil
	}
	var canonical []byte
	err := discoverysource.WithCheckpointBytes(
		checkpoint,
		profileCode,
		func(value []byte) error {
			canonical = append([]byte(nil), value...)
			return nil
		},
	)
	if err != nil {
		clear(canonical)
		return fullInventoryCheckpoint{}, false, errInventoryCheckpoint
	}
	defer clear(canonical)

	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	var document fullInventoryCheckpointDocument
	if err := decoder.Decode(&document); err != nil {
		return fullInventoryCheckpoint{}, false, errInventoryCheckpoint
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fullInventoryCheckpoint{}, false, errInventoryCheckpoint
	}
	value := fullInventoryCheckpoint{
		instanceUUID:     document.InstanceUUID,
		mode:             document.Mode,
		collectorVersion: document.CollectorVersion,
		fullSnapshotID:   document.FullSnapshotID,
		pageTokenHash:    document.PageTokenHash,
	}
	if !value.valid() {
		return fullInventoryCheckpoint{}, false, errInventoryCheckpoint
	}
	expected, err := value.canonicalBytes()
	if err != nil {
		return fullInventoryCheckpoint{}, false, errInventoryCheckpoint
	}
	defer clear(expected)
	if !bytes.Equal(canonical, expected) {
		return fullInventoryCheckpoint{}, false, errInventoryCheckpoint
	}
	return value, false, nil
}

func (value fullInventoryCheckpoint) valid() bool {
	sequence, err := value.sequence()
	parsedSnapshotID, snapshotErr := uuid.Parse(value.fullSnapshotID)
	return instanceUUIDPattern.MatchString(value.instanceUUID) &&
		value.mode == fullInventoryMode &&
		err == nil &&
		sequence > 0 &&
		snapshotErr == nil &&
		parsedSnapshotID.String() == value.fullSnapshotID &&
		(value.pageTokenHash == "" || lowercaseDigestPattern.MatchString(value.pageTokenHash))
}

func (value fullInventoryCheckpoint) sequence() (int64, error) {
	sequence, err := strconv.ParseInt(value.collectorVersion, 10, 64)
	if err != nil || sequence <= 0 || strconv.FormatInt(sequence, 10) != value.collectorVersion {
		return 0, errInventoryCheckpoint
	}
	return sequence, nil
}

func (value fullInventoryCheckpoint) canonicalBytes() ([]byte, error) {
	if !value.valid() {
		return nil, errInventoryCheckpoint
	}
	canonical, err := json.Marshal(fullInventoryCheckpointDocument{
		InstanceUUID:     value.instanceUUID,
		Mode:             value.mode,
		CollectorVersion: value.collectorVersion,
		FullSnapshotID:   value.fullSnapshotID,
		PageTokenHash:    value.pageTokenHash,
	})
	if err != nil || len(canonical) == 0 ||
		len(canonical) > discoverysource.MaxCheckpointCanonicalBytes {
		clear(canonical)
		return nil, errInventoryCheckpoint
	}
	return canonical, nil
}

func inventoryPageTokenHash(fullSnapshotID string, pageToken []byte) string {
	if len(pageToken) == 0 {
		return ""
	}
	return digestFramedStrings(
		"vsphere-page-token.v1",
		fullSnapshotID,
		string(pageToken),
	)
}

func (fullInventoryCheckpoint) MarshalJSON() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}

func (*fullInventoryCheckpoint) UnmarshalJSON([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}

func (fullInventoryCheckpoint) MarshalText() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}

func (*fullInventoryCheckpoint) UnmarshalText([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}

func (fullInventoryCheckpoint) MarshalBinary() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}

func (*fullInventoryCheckpoint) UnmarshalBinary([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}

func (fullInventoryCheckpoint) String() string   { return fullInventoryCheckpointRedact }
func (fullInventoryCheckpoint) GoString() string { return fullInventoryCheckpointRedact }
func (fullInventoryCheckpoint) LogValue() slog.Value {
	return slog.StringValue(fullInventoryCheckpointRedact)
}
func (fullInventoryCheckpoint) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, fullInventoryCheckpointRedact)
}
