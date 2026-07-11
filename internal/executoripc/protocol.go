// Package executoripc defines the bounded protocol between a write Runner and
// its single-job executor child process.
package executoripc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/execution"
)

const (
	// ExtraFiles are inherited in this exact order by cmd/executor.
	PrepareFD  = 3
	GoFD       = 4
	ResponseFD = 5

	PrepareSchemaVersionV1 = "executor-prepare.v1"
	ReadySchemaVersionV1   = "executor-ready.v1"
	ResultSchemaVersionV1  = "executor-result.v1"

	prepareBodyLimit = 256 << 10
	secretBodyLimit  = 64 << 10
	resultBodyLimit  = 16 << 10
	maxJSONDepth     = 32

	protocolVersion byte = 1
	headerSize           = len(frameMagic) + 1 + 1 + 4
)

var (
	frameMagic = [...]byte{'A', 'I', 'O', 'P', 'S', 'I', 'P', 'C'}

	ErrInvalidInput  = errors.New("invalid executor IPC input")
	ErrProtocol      = errors.New("invalid executor IPC protocol")
	ErrFrameTooLarge = errors.New("executor IPC frame exceeds its limit")

	hashPattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)
)

type frameType byte

const (
	framePrepare frameType = 1
	frameGo      frameType = 2
	frameReady   frameType = 3
	frameResult  frameType = 4
)

type PrepareRequest struct {
	SchemaVersion       string          `json:"schema_version"`
	JobID               string          `json:"job_id"`
	PlanHash            string          `json:"plan_hash"`
	EnvironmentRevision string          `json:"environment_revision"`
	Production          bool            `json:"production"`
	Payload             action.Envelope `json:"payload"`
}

type Ready struct {
	SchemaVersion       string `json:"schema_version"`
	JobID               string `json:"job_id"`
	PlanHash            string `json:"plan_hash"`
	EnvironmentRevision string `json:"environment_revision"`
}

type resultFrame struct {
	SchemaVersion       string                   `json:"schema_version"`
	JobID               string                   `json:"job_id"`
	PlanHash            string                   `json:"plan_hash"`
	EnvironmentRevision string                   `json:"environment_revision"`
	Result              execution.ExecutorResult `json:"result"`
}

type Handler interface {
	Validate(action.Envelope) error
	Execute(context.Context, action.Envelope, credential.SensitiveValue) (execution.ExecutorResult, error)
}

func WritePrepare(writer io.Writer, request PrepareRequest) error {
	if writer == nil || !request.validStructure() {
		return ErrInvalidInput
	}
	return writeJSONFrame(writer, framePrepare, request, prepareBodyLimit)
}

func ReadReady(reader io.Reader, expected PrepareRequest) (Ready, error) {
	if reader == nil || !expected.validStructure() {
		return Ready{}, ErrInvalidInput
	}
	encoded, err := readFrame(reader, frameReady, resultBodyLimit)
	if err != nil {
		return Ready{}, err
	}
	var ready Ready
	if err := decodeStrictJSON(encoded, &ready); err != nil || !ready.matches(expected) {
		return Ready{}, ErrProtocol
	}
	return ready, nil
}

func WriteGo(writer io.Writer, secret credential.SensitiveValue) error {
	if writer == nil {
		return ErrInvalidInput
	}
	material := secret.Bytes()
	defer clear(material)
	if len(material) == 0 || len(material) > secretBodyLimit {
		return ErrInvalidInput
	}
	return writeFrame(writer, frameGo, material, secretBodyLimit)
}

func ReadResult(reader io.Reader, expected PrepareRequest) (execution.ExecutorResult, error) {
	if reader == nil || !expected.validStructure() {
		return execution.ExecutorResult{}, ErrInvalidInput
	}
	encoded, err := readFrame(reader, frameResult, resultBodyLimit)
	if err != nil {
		return execution.ExecutorResult{}, err
	}
	var response resultFrame
	if err := decodeStrictJSON(encoded, &response); err != nil || !response.matches(expected) {
		return execution.ExecutorResult{}, ErrProtocol
	}
	if _, err := execution.ResultSummaryStatus(response.Result); err != nil {
		return execution.ExecutorResult{}, ErrProtocol
	}
	return response.Result, nil
}

func Serve(
	ctx context.Context,
	prepareReader io.Reader,
	goReader io.Reader,
	responseWriter io.Writer,
	handler Handler,
	clock func() time.Time,
) error {
	if ctx == nil || prepareReader == nil || goReader == nil || responseWriter == nil || handler == nil || clock == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := readFrame(prepareReader, framePrepare, prepareBodyLimit)
	if err != nil {
		return err
	}
	var request PrepareRequest
	if err := decodeStrictJSON(encoded, &request); err != nil {
		return ErrProtocol
	}
	now := clock()
	if now.IsZero() || !request.validAt(now) {
		return ErrInvalidInput
	}
	if !validateSafely(handler, request.Payload) {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ready := Ready{
		SchemaVersion: ReadySchemaVersionV1, JobID: request.JobID, PlanHash: request.PlanHash,
		EnvironmentRevision: request.EnvironmentRevision,
	}
	if err := writeJSONFrame(responseWriter, frameReady, ready, resultBodyLimit); err != nil {
		return err
	}

	material, err := readFrame(goReader, frameGo, secretBodyLimit)
	if err != nil {
		clear(material)
		return err
	}
	secret, err := credential.NewSensitiveValue(material)
	clear(material)
	if err != nil {
		return ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		secret.Destroy()
		return err
	}
	result, executionUnknown := executeSafely(ctx, handler, request.Payload, secret)
	secret.Destroy()
	if ctx.Err() != nil {
		executionUnknown = true
	}
	if executionUnknown {
		result = uncertainResult()
	}
	if _, err := execution.ResultSummaryStatus(result); err != nil {
		result = uncertainResult()
	}
	response := resultFrame{
		SchemaVersion: ResultSchemaVersionV1, JobID: request.JobID, PlanHash: request.PlanHash,
		EnvironmentRevision: request.EnvironmentRevision, Result: result,
	}
	return writeJSONFrame(responseWriter, frameResult, response, resultBodyLimit)
}

func validateSafely(handler Handler, envelope action.Envelope) (accepted bool) {
	defer func() {
		if recover() != nil {
			accepted = false
		}
	}()
	return handler.Validate(envelope) == nil
}

func uncertainResult() execution.ExecutorResult {
	return execution.ExecutorResult{
		Outcome: execution.ExecutorUncertain, Code: "EXECUTOR_OUTCOME_UNKNOWN",
		Verification: execution.VerificationUnknown,
	}
}

func executeSafely(
	ctx context.Context,
	handler Handler,
	envelope action.Envelope,
	secret credential.SensitiveValue,
) (result execution.ExecutorResult, unknown bool) {
	defer func() {
		if recover() != nil {
			result = execution.ExecutorResult{}
			unknown = true
		}
	}()
	result, err := handler.Execute(ctx, envelope, secret)
	return result, err != nil
}

func (request PrepareRequest) validStructure() bool {
	return request.SchemaVersion == PrepareSchemaVersionV1 && !request.Production &&
		identifierPattern.MatchString(request.JobID) && identifierPattern.MatchString(request.EnvironmentRevision) &&
		hashPattern.MatchString(request.PlanHash) && request.JobID == request.Payload.ActionID &&
		request.PlanHash == request.Payload.PlanHash && request.Payload.Signature != (action.Signature{}) &&
		request.Payload.Validate() == nil
}

func (request PrepareRequest) validAt(now time.Time) bool {
	return request.validStructure() && request.Payload.ValidateAt(now) == nil
}

func (ready Ready) matches(expected PrepareRequest) bool {
	return ready.SchemaVersion == ReadySchemaVersionV1 && ready.JobID == expected.JobID &&
		ready.PlanHash == expected.PlanHash && ready.EnvironmentRevision == expected.EnvironmentRevision
}

func (response resultFrame) matches(expected PrepareRequest) bool {
	return response.SchemaVersion == ResultSchemaVersionV1 && response.JobID == expected.JobID &&
		response.PlanHash == expected.PlanHash && response.EnvironmentRevision == expected.EnvironmentRevision
}

func writeJSONFrame(writer io.Writer, kind frameType, value any, limit int) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ErrInvalidInput
	}
	return writeFrame(writer, kind, encoded, limit)
}

func writeFrame(writer io.Writer, kind frameType, body []byte, limit int) error {
	if len(body) == 0 {
		return ErrInvalidInput
	}
	if len(body) > limit {
		return ErrFrameTooLarge
	}
	header := make([]byte, headerSize)
	copy(header, frameMagic[:])
	header[len(frameMagic)] = protocolVersion
	header[len(frameMagic)+1] = byte(kind)
	binary.BigEndian.PutUint32(header[len(frameMagic)+2:], uint32(len(body)))
	if err := writeFull(writer, header); err != nil {
		return ErrProtocol
	}
	if err := writeFull(writer, body); err != nil {
		return ErrProtocol
	}
	return nil
}

func readFrame(reader io.Reader, expected frameType, limit int) ([]byte, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, ErrProtocol
	}
	if !bytes.Equal(header[:len(frameMagic)], frameMagic[:]) || header[len(frameMagic)] != protocolVersion ||
		frameType(header[len(frameMagic)+1]) != expected {
		return nil, ErrProtocol
	}
	length := int(binary.BigEndian.Uint32(header[len(frameMagic)+2:]))
	if length <= 0 {
		return nil, ErrProtocol
	}
	if length > limit {
		return nil, ErrFrameTooLarge
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		clear(body)
		return nil, ErrProtocol
	}
	return body, nil
}

func writeFull(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := writer.Write(value)
		if err != nil {
			return err
		}
		if count <= 0 || count > len(value) {
			return io.ErrShortWrite
		}
		value = value[count:]
	}
	return nil
}

func decodeStrictJSON(encoded []byte, target any) error {
	if len(encoded) == 0 || !utf8.Valid(encoded) {
		return ErrProtocol
	}
	if err := rejectDuplicateJSONNames(encoded); err != nil {
		return ErrProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrProtocol
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return ErrProtocol
	}
	return nil
}

func rejectDuplicateJSONNames(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := inspectJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrProtocol
	}
	return nil
}

func inspectJSONValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxJSONDepth {
		return ErrProtocol
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
			if !ok || !canonicalJSONName(key) {
				return ErrProtocol
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrProtocol
			}
			seen[key] = struct{}{}
			if err := inspectJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrProtocol
		}
	case '[':
		for decoder.More() {
			if err := inspectJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrProtocol
		}
	default:
		return ErrProtocol
	}
	return nil
}

func canonicalJSONName(value string) bool {
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
