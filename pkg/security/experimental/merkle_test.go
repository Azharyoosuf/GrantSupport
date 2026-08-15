package experimental_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"grantsupport/pkg/security/experimental"
)

func TestMerkleTreeProofs(t *testing.T) {
	h1 := hex.EncodeToString(sha256.New().Sum([]byte("event_1")))
	h2 := hex.EncodeToString(sha256.New().Sum([]byte("event_2")))
	h3 := hex.EncodeToString(sha256.New().Sum([]byte("event_3")))
	hashes := []string{h1, h2, h3}

	root := experimental.CalculateMerkleRoot(hashes)
	if root == "" {
		t.Fatal("Expected non-empty Merkle root")
	}

	proof, err := experimental.GenerateMerkleProof(hashes, 0)
	if err != nil {
		t.Fatalf("Failed to generate Merkle proof: %v", err)
	}

	if !experimental.VerifyMerkleProof(h1, root, proof, 0) {
		t.Error("Merkle proof verification failed for target index 0")
	}
}
