package domain_test

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"grantsupport/pkg/domain"
)

// TestUUIDv7_FormatAndVersion verifies that generated IDs are valid RFC 9562 UUIDv7 with correct version and variant bits.
func TestUUIDv7_FormatAndVersion(t *testing.T) {
	id := domain.NewUUID()

	if id == uuid.Nil {
		t.Fatal("Expected non-nil UUID")
	}

	// Verify UUID Version 7
	if version := id.Version(); version != 7 {
		t.Fatalf("Expected UUID version 7, got version %d", version)
	}

	// Verify RFC 4122 / RFC 9562 Variant (0b10 in high bits of octet 8)
	if variant := id.Variant(); variant != uuid.RFC4122 {
		t.Fatalf("Expected RFC 4122/9562 variant, got %v", variant)
	}

	// Verify string representation length (36 chars: 8-4-4-4-12)
	str := id.String()
	if len(str) != 36 {
		t.Fatalf("Expected 36-character UUID string, got %d chars: %s", len(str), str)
	}

	// Verify parsing back
	parsed, err := uuid.Parse(str)
	if err != nil {
		t.Fatalf("Failed to parse UUIDv7 string: %v", err)
	}
	if parsed != id {
		t.Fatalf("Parsed UUID %v does not match original %v", parsed, id)
	}
}

// TestUUIDv7_TimeOrdering verifies that UUIDv7 identifiers generated over time have time-ordered timestamp prefixes.
func TestUUIDv7_TimeOrdering(t *testing.T) {
	const count = 100
	ids := make([]uuid.UUID, count)

	for i := 0; i < count; i++ {
		ids[i] = domain.NewUUID()
		time.Sleep(1 * time.Millisecond) // Small delay to observe time progression
	}

	for i := 1; i < count; i++ {
		// Compare byte sequences: UUIDv7 is designed so standard byte comparison follows chronological generation order
		if string(ids[i-1][:]) >= string(ids[i][:]) {
			t.Fatalf("Expected id[%d] (%s) < id[%d] (%s)", i-1, ids[i-1], i, ids[i])
		}
	}
}

// TestUUIDv7_UniquenessAndConcurrency verifies that concurrent generation across multiple goroutines generates 0 collisions.
func TestUUIDv7_UniquenessAndConcurrency(t *testing.T) {
	const totalGenerations = 10000
	const concurrency = 50

	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[uuid.UUID]struct{}, totalGenerations)
	perWorker := totalGenerations / concurrency

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localIDs := make([]uuid.UUID, perWorker)
			for i := 0; i < perWorker; i++ {
				localIDs[i] = domain.NewUUID()
				if localIDs[i].Version() != 7 {
					t.Errorf("Generated UUID has invalid version: %d", localIDs[i].Version())
				}
			}

			mu.Lock()
			for _, id := range localIDs {
				if _, exists := seen[id]; exists {
					t.Errorf("Duplicate UUIDv7 detected: %s", id)
				}
				seen[id] = struct{}{}
			}
			mu.Unlock()
		}()
	}

	wg.Wait()
	if len(seen) != totalGenerations {
		t.Fatalf("Expected %d unique UUIDs, got %d", totalGenerations, len(seen))
	}
}
