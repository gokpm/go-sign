package sign

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/gokpm/go-codec"
	"github.com/golang-jwt/jwt/v5"
)

// Signer interface provides methods for signing and verifying JWT tokens.
type Signer interface {
	Sign(*Claims) (string, error)
	Verify(string) (*Claims, error)
}

// Verifier interface provides methods for verifying JWT tokens.
type Verifier interface {
	Verify(string) (*Claims, error)
}

// eddsa implements both Signer and Verifier interfaces using Ed25519 cryptography.
type eddsa struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// Error definitions for Ed25519 key and signature validation.
var (
	ErrInvalidEd25519PrivateKey = errors.New("invalid Ed25519 private key")
	ErrInvalidEd25519PublicKey  = errors.New("invalid Ed25519 public key")
	ErrInvalidEdDSASignature    = errors.New("invalid EdDSA signature")
)

// Claims represents JWT claims with additional custom data.
type Claims struct {
	jwt.RegisteredClaims
	Data any `json:",omitempty"`
}

// NewClaims creates a new Claims instance with the provided options.
func NewClaims(opts ...ClaimOption) *Claims {
	c := &Claims{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ClaimOption is a functional option for configuring Claims.
type ClaimOption func(*Claims)

// WithIssuer sets the issuer claim.
func WithIssuer(issuer string) ClaimOption {
	return func(c *Claims) { c.Issuer = issuer }
}

// WithSubject sets the subject claim.
func WithSubject(subject string) ClaimOption {
	return func(c *Claims) { c.Subject = subject }
}

// WithAudience sets the audience claim.
func WithAudience(audience ...string) ClaimOption {
	return func(c *Claims) { c.Audience = audience }
}

// WithExpiresAt sets the expiration time claim.
func WithExpiresAt(expiresAt time.Time) ClaimOption {
	return func(c *Claims) { c.ExpiresAt = jwt.NewNumericDate(expiresAt) }
}

// WithNotBefore sets the not-before time claim.
func WithNotBefore(notBefore time.Time) ClaimOption {
	return func(c *Claims) { c.NotBefore = jwt.NewNumericDate(notBefore) }
}

// WithIssuedAt sets the issued-at time claim.
func WithIssuedAt(issuedAt time.Time) ClaimOption {
	return func(c *Claims) { c.IssuedAt = jwt.NewNumericDate(issuedAt) }
}

// WithID sets the JWT ID claim.
func WithID(id string) ClaimOption {
	return func(c *Claims) { c.ID = id }
}

// WithData sets custom data in the claims.
func WithData(data any) ClaimOption {
	return func(c *Claims) { c.Data = data }
}

// NewSigner creates a new Signer instance from a base64-encoded Ed25519 private key.
func NewSigner(b64PrivateKey string) (Signer, error) {
	privateBytes, err := codec.Decode(b64PrivateKey)
	if err != nil {
		return nil, err
	}
	privateKey := ed25519.PrivateKey(privateBytes)
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalidEd25519PublicKey
	}
	return &eddsa{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

// NewVerifier creates a new Verifier instance from a base64-encoded Ed25519 public key.
func NewVerifier(b64PublicKey string) (Verifier, error) {
	publicBytes, err := codec.Decode(b64PublicKey)
	if err != nil {
		return nil, err
	}
	publicKey := ed25519.PublicKey(publicBytes)
	return &eddsa{publicKey: publicKey}, nil
}

// Sign creates and signs a JWT token with the provided claims.
func (e *eddsa) Sign(claims *Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(e.privateKey)
	if err != nil {
		return "", err
	}
	return signed, nil
}

// Verify parses and validates a JWT token, returning the claims if valid.
func (e *eddsa) Verify(token string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(
		token,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodEdDSA {
				return nil, ErrInvalidEdDSASignature
			}
			return e.publicKey, nil
		},
	)
	if err != nil {
		return nil, err
	}
	return claims, nil
}
