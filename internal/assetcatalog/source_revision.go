package assetcatalog

import (
	"context"
	"errors"
	"slices"
)

var ErrSourceRevisionNotValidated = errors.New("source revision not validated")

type SourceRevisionRepository interface {
	CreateRevision(context.Context, CreateSourceRevisionCommand) (SourceRevisionMutation, error)
	RequestValidation(context.Context, ValidateSourceRevisionCommand) (SourceRunMutation, error)
	Publish(context.Context, PublishSourceRevisionCommand) (SourceRevisionMutation, error)
	Disable(context.Context, DisableSourceCommand) (SourceMutation, error)
	RequestSync(context.Context, RequestSyncCommand) (SourceRunMutation, error)
}

type CreateSourceRevisionCommand struct {
	Context                 MutationContext
	SourceID                string
	ProfileCode             ProfileCode
	AuthorityEnvironmentIDs []string
	ChangeReasonCode        string
	ExpectedSourceVersion   int64
}

func (command CreateSourceRevisionCommand) Clone() CreateSourceRevisionCommand {
	command.AuthorityEnvironmentIDs = slices.Clone(command.AuthorityEnvironmentIDs)
	return command
}

type ValidateSourceRevisionCommand struct {
	Context                 MutationContext
	SourceID                string
	Revision                int64
	ExpectedSourceVersion   int64
	ExpectedRevisionVersion int64
	ExpectedRevisionDigest  string
}

type PublishSourceRevisionCommand struct {
	Context                  MutationContext
	SourceID                 string
	Revision                 int64
	ReasonCode               string
	ExpectedSourceVersion    int64
	ExpectedRevisionVersion  int64
	ExpectedRevisionDigest   string
	ExpectedValidationRunID  string
	ExpectedValidationDigest string
}

type DisableSourceCommand struct {
	Context               MutationContext
	SourceID              string
	ReasonCode            string
	ExpectedSourceVersion int64
}

type RequestSyncCommand struct {
	Context                   MutationContext
	SourceID                  string
	ExpectedSourceVersion     int64
	ExpectedRevision          int64
	ExpectedRevisionDigest    string
	ExpectedCheckpointVersion int64
	ExpectedCheckpointSHA256  string
}

type SourceRevisionMutation struct {
	Source   Source
	Revision SourceRevision
	Receipt  MutationReceipt
}

func (mutation SourceRevisionMutation) Clone() SourceRevisionMutation {
	mutation.Source = mutation.Source.Clone()
	mutation.Revision = mutation.Revision.Clone()
	return mutation
}

type SourceMutation struct {
	Source  Source
	Receipt MutationReceipt
}

func (mutation SourceMutation) Clone() SourceMutation {
	mutation.Source = mutation.Source.Clone()
	return mutation
}

type SourceRunMutation struct {
	Source   Source
	Revision SourceRevision
	Run      SourceRun
	Receipt  MutationReceipt
}

func (mutation SourceRunMutation) Clone() SourceRunMutation {
	mutation.Source = mutation.Source.Clone()
	mutation.Revision = mutation.Revision.Clone()
	mutation.Run = mutation.Run.Clone()
	return mutation
}
