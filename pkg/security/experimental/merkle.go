// Package experimental contains reference and prototype security utilities (e.g. Merkle audit trees and KMS envelope encryption).
// These components are not in the critical execution path of GrantSupport core and are maintained for future multi-region extensions.
package experimental

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// CalculateMerkleRoot computes the binary Merkle tree root hash for a slice of event/audit SHA-256 hashes.
func CalculateMerkleRoot(hashes []string) string {
	if len(hashes) == 0 {
		h := sha256.Sum256([]byte(""))
		return hex.EncodeToString(h[:])
	}

	if len(hashes) == 1 {
		return hashes[0]
	}

	currentLevel := make([]string, len(hashes))
	copy(currentLevel, hashes)

	for len(currentLevel) > 1 {
		if len(currentLevel)%2 != 0 {
			currentLevel = append(currentLevel, currentLevel[len(currentLevel)-1])
		}

		nextLevel := make([]string, 0, len(currentLevel)/2)
		for i := 0; i < len(currentLevel); i += 2 {
			combined := currentLevel[i] + currentLevel[i+1]
			h := sha256.Sum256([]byte(combined))
			nextLevel = append(nextLevel, hex.EncodeToString(h[:]))
		}
		currentLevel = nextLevel
	}

	return currentLevel[0]
}

// GenerateMerkleProof generates sibling hashes required to verify that a hash at targetIndex belongs to the Merkle root.
func GenerateMerkleProof(hashes []string, targetIndex int) ([]string, error) {
	if targetIndex < 0 || targetIndex >= len(hashes) {
		return nil, errors.New("INVALID_INDEX: Target index out of bounds")
	}

	proof := make([]string, 0)
	currentLevel := make([]string, len(hashes))
	copy(currentLevel, hashes)
	currentIndex := targetIndex

	for len(currentLevel) > 1 {
		if len(currentLevel)%2 != 0 {
			currentLevel = append(currentLevel, currentLevel[len(currentLevel)-1])
		}

		var siblingIndex int
		if currentIndex%2 == 0 {
			siblingIndex = currentIndex + 1
		} else {
			siblingIndex = currentIndex - 1
		}

		if siblingIndex < len(currentLevel) {
			proof = append(proof, currentLevel[siblingIndex])
		}

		nextLevel := make([]string, 0, len(currentLevel)/2)
		for i := 0; i < len(currentLevel); i += 2 {
			combined := currentLevel[i] + currentLevel[i+1]
			h := sha256.Sum256([]byte(combined))
			nextLevel = append(nextLevel, hex.EncodeToString(h[:]))
		}
		currentLevel = nextLevel
		currentIndex = currentIndex / 2
	}

	return proof, nil
}

// VerifyMerkleProof verifies that targetHash exists in the Merkle root using the provided sibling proof.
func VerifyMerkleProof(targetHash, rootHash string, proof []string, targetIndex int) bool {
	currentHash := targetHash
	currentIndex := targetIndex

	for _, siblingHash := range proof {
		var combined string
		if currentIndex%2 == 0 {
			combined = currentHash + siblingHash
		} else {
			combined = siblingHash + currentHash
		}
		h := sha256.Sum256([]byte(combined))
		currentHash = hex.EncodeToString(h[:])
		currentIndex = currentIndex / 2
	}

	return currentHash == rootHash
}
