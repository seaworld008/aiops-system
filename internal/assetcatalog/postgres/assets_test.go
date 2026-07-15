package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

func TestNewAssetRepositoryFailsClosed(t *testing.T) {
	t.Parallel()

	if repository, err := New(nil, time.Now, func() string { return "unused" }); err == nil || repository != nil {
		t.Fatalf("New(nil, clock, newID) = (%#v, %v), want fail closed", repository, err)
	}
	if repository, err := New(nil, time.Now, nil); err == nil || repository != nil {
		t.Fatalf("New(nil, clock, nil) = (%#v, %v), want fail closed", repository, err)
	}
}

func TestAssetRepositoryErrorsAreStableAndRedacted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code string
		want error
	}{
		{code: "23503", want: assetcatalog.ErrScopeViolation},
		{code: "23505", want: assetcatalog.ErrIdempotency},
		{code: "23514", want: assetcatalog.ErrInvalidRequest},
		{code: "22P02", want: assetcatalog.ErrInvalidRequest},
		{code: "40001", want: assetcatalog.ErrStateConflict},
		{code: "40P01", want: assetcatalog.ErrStateConflict},
		{code: "42P01", want: assetcatalog.ErrStateConflict},
	}
	for _, test := range tests {
		test := test
		t.Run(test.code, func(t *testing.T) {
			t.Parallel()
			mapped := mapPGError(&pgconn.PgError{Code: test.code, Message: "sensitive database detail"})
			if !errors.Is(mapped, test.want) || mapped.Error() == "sensitive database detail" {
				t.Fatalf("mapPGError(%s) = %v, want redacted %v", test.code, mapped, test.want)
			}
		})
	}
}

func TestAssetRepositoryRejectsInvalidGeneratedIdentity(t *testing.T) {
	t.Parallel()

	repository := &Repository{newID: func() string { return "not-a-uuid" }}
	if _, err := repository.allocateIDs(1); !errors.Is(err, assetcatalog.ErrStateConflict) {
		t.Fatalf("allocateIDs(invalid) error = %v, want ErrStateConflict", err)
	}
}
