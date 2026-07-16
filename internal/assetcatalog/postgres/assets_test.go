package postgres

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/puddle/v2"
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
		code        string
		want        error
		unavailable bool
	}{
		{code: "23503", want: assetcatalog.ErrScopeViolation},
		{code: "23505", want: assetcatalog.ErrIdempotency},
		{code: "23514", want: assetcatalog.ErrInvalidRequest},
		{code: "22P02", want: assetcatalog.ErrInvalidRequest},
		{code: "22001", want: assetcatalog.ErrInvalidRequest},
		{code: "22023", want: assetcatalog.ErrInvalidRequest},
		{code: "40001", want: assetcatalog.ErrStateConflict},
		{code: "40P01", want: assetcatalog.ErrStateConflict},
		{code: "08006", want: assetcatalog.ErrUnavailable, unavailable: true},
		{code: "53300", want: assetcatalog.ErrUnavailable, unavailable: true},
		{code: "57P01", want: assetcatalog.ErrUnavailable, unavailable: true},
		{code: "58030", want: assetcatalog.ErrUnavailable, unavailable: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.code, func(t *testing.T) {
			t.Parallel()
			mapped := mapPGError(&pgconn.PgError{Code: test.code, Message: "sensitive database detail"})
			if !errors.Is(mapped, test.want) || mapped.Error() == "sensitive database detail" {
				t.Fatalf("mapPGError(%s) = %v, want redacted %v", test.code, mapped, test.want)
			}
			if errors.Is(mapped, assetcatalog.ErrUnavailable) != test.unavailable {
				t.Fatalf("mapPGError(%s) availability = %t, want %t", test.code, errors.Is(mapped, assetcatalog.ErrUnavailable), test.unavailable)
			}
		})
	}
}

func TestAssetRepositoryUnavailableSQLStateFamiliesAreExact(t *testing.T) {
	t.Parallel()

	for _, code := range []string{
		"08000", "08001", "08003", "08004", "08006", "08007", "08P01",
		"53000", "53100", "53200", "53300", "53400",
		"57P01", "57P02", "57P03", "57P04",
		"58000", "58030",
	} {
		mapped := mapPGError(&pgconn.PgError{Code: code, Message: "sensitive database detail"})
		if !errors.Is(mapped, assetcatalog.ErrUnavailable) || mapped.Error() != assetcatalog.ErrUnavailable.Error() {
			t.Errorf("mapPGError(%s) = %v, want exact redacted ErrUnavailable", code, mapped)
		}
	}
}

func TestAssetRepositoryUnknownErrorsRemainInternalFailures(t *testing.T) {
	t.Parallel()

	for name, input := range map[string]error{
		"unknown SQLSTATE": &pgconn.PgError{Code: "42P01", Message: "sensitive database detail"},
		"query canceled":   &pgconn.PgError{Code: "57014", Message: "sensitive database detail"},
		"program error":    errors.New("sensitive program detail"),
	} {
		mapped := mapPGError(input)
		if !errors.Is(mapped, errAssetCatalogRepositoryFailure) {
			t.Errorf("%s mapped error = %v, want internal repository failure", name, mapped)
		}
		for _, semantic := range []error{
			assetcatalog.ErrInvalidRequest,
			assetcatalog.ErrNotFound,
			assetcatalog.ErrScopeViolation,
			assetcatalog.ErrVersionConflict,
			assetcatalog.ErrStateConflict,
			assetcatalog.ErrIdempotency,
			assetcatalog.ErrUnavailable,
		} {
			if errors.Is(mapped, semantic) {
				t.Errorf("%s mapped error = %v, unexpectedly matches %v", name, mapped, semantic)
			}
		}
		if mapped.Error() == input.Error() {
			t.Errorf("%s mapped error leaked underlying detail: %v", name, mapped)
		}
	}
}

func TestAssetRepositoryConnectionErrorsAreUnavailable(t *testing.T) {
	t.Parallel()

	for name, input := range map[string]error{
		"closed connection": pgconn.ErrConnClosed,
		"eof":               io.EOF,
		"unexpected eof":    io.ErrUnexpectedEOF,
		"closed pool":       puddle.ErrClosedPool,
		"pool unavailable":  puddle.ErrNotAvailable,
		"network": &net.OpError{
			Op: "read", Net: "tcp", Err: errors.New("sensitive network detail"),
		},
	} {
		mapped := mapPGError(input)
		if !errors.Is(mapped, assetcatalog.ErrUnavailable) || mapped.Error() != assetcatalog.ErrUnavailable.Error() {
			t.Errorf("%s mapped error = %v, want exact redacted ErrUnavailable", name, mapped)
		}
	}
}

func TestAssetRepositoryBeginTxErrorsAreUnavailable(t *testing.T) {
	t.Parallel()

	database := &assetCatalogPool{
		beginTx: func(context.Context, pgx.TxOptions) (pgx.Tx, error) {
			return nil, &net.OpError{
				Op: "dial", Net: "tcp", Err: errors.New("sensitive dial failure"),
			}
		},
	}
	if _, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable}); !errors.Is(err, assetcatalog.ErrUnavailable) {
		t.Fatalf("BeginTx(network error) = %v, want ErrUnavailable", err)
	} else if err.Error() != assetcatalog.ErrUnavailable.Error() {
		t.Fatalf("BeginTx(network error) leaked underlying detail: %v", err)
	}

	for _, contextErr := range []error{context.Canceled, context.DeadlineExceeded} {
		database.beginTx = func(context.Context, pgx.TxOptions) (pgx.Tx, error) {
			return nil, contextErr
		}
		if _, err := database.BeginTx(context.Background(), pgx.TxOptions{}); !errors.Is(err, contextErr) {
			t.Errorf("BeginTx(%v) = %v, want context error preserved", contextErr, err)
		}
	}

	database.beginTx = func(context.Context, pgx.TxOptions) (pgx.Tx, error) {
		return nil, &pgconn.PgError{Code: "42P01", Message: "sensitive database detail"}
	}
	if _, err := database.BeginTx(context.Background(), pgx.TxOptions{}); !errors.Is(err, errAssetCatalogRepositoryFailure) {
		t.Fatalf("BeginTx(unknown SQLSTATE) = %v, want internal repository failure", err)
	} else if errors.Is(err, assetcatalog.ErrUnavailable) {
		t.Fatalf("BeginTx(unknown SQLSTATE) = %v, must not masquerade as unavailable", err)
	}

	database.beginTx = func(context.Context, pgx.TxOptions) (pgx.Tx, error) {
		return nil, errors.New("sensitive program bug")
	}
	if _, err := database.BeginTx(context.Background(), pgx.TxOptions{}); !errors.Is(err, errAssetCatalogRepositoryFailure) {
		t.Fatalf("BeginTx(program error) = %v, want internal repository failure", err)
	} else if errors.Is(err, assetcatalog.ErrUnavailable) {
		t.Fatalf("BeginTx(program error) = %v, must not masquerade as unavailable", err)
	}
}

func TestAssetRepositoryRejectsInvalidGeneratedIdentity(t *testing.T) {
	t.Parallel()

	repository := &Repository{newID: func() string { return "not-a-uuid" }}
	if _, err := repository.allocateIDs(1); !errors.Is(err, assetcatalog.ErrStateConflict) {
		t.Fatalf("allocateIDs(invalid) error = %v, want ErrStateConflict", err)
	}
}
