package replay_test

import (
	"context"
	"testing"
	"time"

	"grantsupport/pkg/adapters/replay"
	"grantsupport/pkg/ports"
)

func TestMemoryReplayStore(t *testing.T) {
	store := replay.NewMemoryReplayStore(100 * time.Millisecond)
	defer store.Close()

	ctx := context.Background()
	keyID := "key_test_1"
	nonce := "nonce_abc_123"

	// 1. First presentation of nonce succeeds
	ok, err := store.CheckAndSet(ctx, keyID, nonce, 500*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("Expected first CheckAndSet to succeed, got ok=%v, err=%v", ok, err)
	}

	// 2. Duplicate nonce presentation within TTL is rejected
	ok, err = store.CheckAndSet(ctx, keyID, nonce, 500*time.Millisecond)
	if ok || err != ports.ErrReplayDetected {
		t.Fatalf("Expected duplicate nonce to be rejected with ErrReplayDetected, got ok=%v, err=%v", ok, err)
	}

	// 3. Different nonce for same key succeeds
	ok, err = store.CheckAndSet(ctx, keyID, "nonce_different_456", 500*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("Expected different nonce to succeed, got ok=%v, err=%v", ok, err)
	}

	// 4. Same nonce for different key succeeds
	ok, err = store.CheckAndSet(ctx, "key_different_2", nonce, 500*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("Expected same nonce on different key to succeed, got ok=%v, err=%v", ok, err)
	}
}
