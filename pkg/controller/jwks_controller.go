package controller

import (
	"encoding/base64"
	"math/big"
	"net/http"

	"grantsupport/pkg/security"
)

// JWK represents a JSON Web Key as defined in RFC 7517.
type JWK struct {
	Kid string `json:"kid,omitempty"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSResponse represents a JSON Web Key Set.
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWKSController handles public key set retrieval for downstream JWT validation.
type JWKSController struct{}

// NewJWKSController constructs a new JWKSController instance.
func NewJWKSController() *JWKSController {
	return &JWKSController{}
}

// GetJWKS serves the public RSA keys for RS256 token verification.
// GET /.well-known/jwks.json
func (c *JWKSController) GetJWKS(w http.ResponseWriter, r *http.Request) error {
	km := security.GetDefaultKeyManager()
	keysMap := km.GetAllPublicKeys()

	if len(keysMap) == 0 {
		if pubKey := security.GetRSAPublicKey(); pubKey != nil {
			keysMap["grantsupport-primary"] = pubKey
		}
	}

	if len(keysMap) == 0 {
		return NewAppError(http.StatusServiceUnavailable, "JWKS_UNAVAILABLE", "RSA public key not initialized")
	}

	keys := make([]JWK, 0, len(keysMap))
	for kid, pubKey := range keysMap {
		if pubKey == nil {
			continue
		}
		nBytes := pubKey.N.Bytes()
		eBytes := big.NewInt(int64(pubKey.E)).Bytes()

		keys = append(keys, JWK{
			Kid: kid,
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(nBytes),
			E:   base64.RawURLEncoding.EncodeToString(eBytes),
		})
	}

	w.Header().Set("Cache-Control", "public, max-age=3600")
	WriteJSON(w, http.StatusOK, JWKSResponse{Keys: keys})
	return nil
}
