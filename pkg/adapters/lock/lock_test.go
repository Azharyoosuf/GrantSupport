package lock_test

import (
	"context"
	"testing"
	"time"

	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/ports"
)

func TestMemoryLockStore(t *testing.T) {
	store := lock.NewMemoryLockStore()
	ctx := context.Background()
	lockKey := "test:lock:123"

	// 1. First acquire succeeds
	token1, err := store.Acquire(ctx, lockKey, 1*time.Second)
	if err != nil {
		t.Fatalf("Expected successful acquire, got error: %v", err)
	}
	if token1 == "" {
		t.Fatal("Expected non-empty owner token")
	}

	// 2. Second concurrent acquire on same key fails with ErrLockBusy
	_, err = store.Acquire(ctx, lockKey, 1*time.Second)
	if err != ports.ErrLockBusy {
		t.Fatalf("Expected ErrLockBusy, got: %v", err)
	}

	// 3. Release with invalid token does not release the lock
	_ = store.Release(ctx, lockKey, "wrong_token")
	_, err = store.Acquire(ctx, lockKey, 1*time.Second)
	if err != ports.ErrLockBusy {
		t.Fatalf("Expected lock to still be held, got: %v", err)
	}

	// 4. Release with valid token allows subsequent acquire
	err = store.Release(ctx, lockKey, token1)
	if err != nil {
		t.Fatalf("Release failed: %v", err)
	}

	token2, err := store.Acquire(ctx, lockKey, 1*time.Second)
	if err != nil {
		t.Fatalf("Expected successful acquire after release, got: %v", err)
	}
	if token2 == "" {
		t.Fatal("Expected valid token")
	}
}

func TestMemoryLockStoreWithLock(t *testing.T) {
	store := lock.NewMemoryLockStore()
	ctx := context.Background()
	lockKey := "test:withlock"

	executed := false
	err := store.WithLock(ctx, lockKey, 1*time.Second, func(txCtx context.Context) error {
		executed = true
		// Verify lock is held during execution
		_, err := store.Acquire(txCtx, lockKey, 1*time.Second)
		if err != ports.ErrLockBusy {
			t.Errorf("Expected lock to be busy inside WithLock callback")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("WithLock failed: %v", err)
	}
	if !executed {
		t.Fatal("Expected callback to be executed")
	}

	// Verify lock is automatically released after WithLock finishes
	_, err = store.Acquire(ctx, lockKey, 1*time.Second)
	if err != nil {
		t.Fatalf("Expected lock to be released after WithLock: %v", err)
	}
}
