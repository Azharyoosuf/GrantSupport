package security_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"grantsupport/pkg/security"
)

func TestMerkleTreeProofs(t *testing.T) {
	h1 := hex.EncodeToString(sha256.New().Sum([]byte("event_1")))
	h2 := hex.EncodeToString(sha256.New().Sum([]byte("event_2")))
	h3 := hex.EncodeToString(sha256.New().Sum([]byte("event_3")))
	hashes := []string{h1, h2, h3}

	root := security.CalculateMerkleRoot(hashes)
	if root == "" {
		t.Fatal("Expected non-empty Merkle root")
	}

	proof, err := security.GenerateMerkleProof(hashes, 0)
	if err != nil {
		t.Fatalf("Failed to generate Merkle proof: %v", err)
	}

	if !security.VerifyMerkleProof(h1, root, proof, 0) {
		t.Error("Merkle proof verification failed for target index 0")
	}
}
