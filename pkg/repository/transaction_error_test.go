package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"grantsupport/ent"
	"grantsupport/pkg/repository"
	_ "modernc.org/sqlite"
)

// TestTransaction_SuccessCommit verifies that a successful transaction callback commits without error.
func TestTransaction_SuccessCommit(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:tx_success_test?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	repo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := repo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Schema.Create failed: %v", err)
	}

	executed := false
	err = repo.Transaction(ctx, func(tx *ent.Tx) error {
		executed = true
		return nil
	})

	if err != nil {
		t.Fatalf("Expected nil error on successful transaction, got: %v", err)
	}
	if !executed {
		t.Fatal("Expected callback to execute")
	}
}

// TestTransaction_CallbackErrorRollback verifies that when a callback returns an error, the transaction is rolled back and the original error is returned.
func TestTransaction_CallbackErrorRollback(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:tx_rollback_test?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	repo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := repo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Schema.Create failed: %v", err)
	}

	sentinelErr := errors.New("custom domain violation")
	err = repo.Transaction(ctx, func(tx *ent.Tx) error {
		return sentinelErr
	})

	if !errors.Is(err, sentinelErr) {
		t.Fatalf("Expected sentinel error '%v', got '%v'", sentinelErr, err)
	}
}

// TestTransaction_PanicRecoveryAndRollback verifies that a panic inside a transaction callback safely triggers a rollback and re-panics.
func TestTransaction_PanicRecoveryAndRollback(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:tx_panic_test?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	repo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := repo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Schema.Create failed: %v", err)
	}

	panicked := false
	defer func() {
		if rec := recover(); rec != nil {
			panicked = true
			if rec != "deliberate test panic" {
				t.Errorf("Unexpected panic value: %v", rec)
			}
		}
	}()

	_ = repo.Transaction(ctx, func(tx *ent.Tx) error {
		panic("deliberate test panic")
	})

	if !panicked {
		t.Fatal("Expected Transaction to re-panic after rolling back")
	}
}

// TestTransaction_ContextCancellation verifies that an already-cancelled context returns an error and does not execute.
func TestTransaction_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	db, err := sql.Open("sqlite", "file:tx_cancel_test?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	repo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	_ = repo.MasterClient.Schema.Create(context.Background())

	err = repo.Transaction(ctx, func(tx *ent.Tx) error {
		t.Fatal("Callback must not be executed with a cancelled context")
		return nil
	})

	if err == nil {
		t.Fatal("Expected error when starting transaction with cancelled context, got nil")
	}
}

// TestTransaction_TimeoutDeadline verifies that a transaction timeout deadline is enforced within 10 seconds.
func TestTransaction_TimeoutDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	db, err := sql.Open("sqlite", "file:tx_timeout_test?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	repo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	_ = repo.MasterClient.Schema.Create(context.Background())

	err = repo.Transaction(ctx, func(tx *ent.Tx) error {
		time.Sleep(100 * time.Millisecond) // Exceed deadline
		return nil
	})

	if err == nil {
		t.Fatal("Expected error on transaction exceeding context deadline, got nil")
	}
}
