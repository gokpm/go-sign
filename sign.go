package sign

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/gokpm/go-codec"
	"github.com/gokpm/go-sig"
	"github.com/golang-jwt/jwt/v5"
)

type Signer interface {
	Sign(context.Context, *Claims) (string, error)
	Verify(context.Context, string) (*Claims, error)
}

type Verifier interface {
	Verify(context.Context, string) (*Claims, error)
}

type eddsa struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

var ErrInvalidEd25519PrivateKey = errors.New("invalid Ed25519 private key")
var ErrInvalidEd25519PublicKey = errors.New("invalid Ed25519 public key")
var ErrInvalidEdDSASignature = errors.New("invalid EdDSA signature")

type Claims struct {
	jwt.RegisteredClaims
	Data any `json:",omitempty"`
}

func NewClaims(opts ...ClaimOption) *Claims {
	c := &Claims{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type ClaimOption func(*Claims)

func WithIssuer(issuer string) ClaimOption {
	return func(c *Claims) { c.Issuer = issuer }
}

func WithSubject(subject string) ClaimOption {
	return func(c *Claims) { c.Subject = subject }
}

func WithAudience(audience ...string) ClaimOption {
	return func(c *Claims) { c.Audience = audience }
}

func WithExpiresAt(expiresAt time.Time) ClaimOption {
	return func(c *Claims) { c.ExpiresAt = jwt.NewNumericDate(expiresAt) }
}

func WithNotBefore(notBefore time.Time) ClaimOption {
	return func(c *Claims) { c.NotBefore = jwt.NewNumericDate(notBefore) }
}

func WithIssuedAt(issuedAt time.Time) ClaimOption {
	return func(c *Claims) { c.IssuedAt = jwt.NewNumericDate(issuedAt) }
}

func WithID(id string) ClaimOption {
	return func(c *Claims) { c.ID = id }
}

func WithData(data any) ClaimOption {
	return func(c *Claims) { c.Data = data }
}

func NewSigner(ctx context.Context, b64PrivateKey string) (Signer, error) {
	log := sig.Start(ctx)
	defer log.End()
	privateBytes, err := codec.Decode(log.Ctx(), b64PrivateKey)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	privateKey := ed25519.PrivateKey(privateBytes)
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		log.Error(ErrInvalidEd25519PublicKey)
		return nil, ErrInvalidEd25519PublicKey
	}
	return &eddsa{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func NewVerifier(ctx context.Context, b64PublicKey string) (Verifier, error) {
	log := sig.Start(ctx)
	defer log.End()
	publicBytes, err := codec.Decode(log.Ctx(), b64PublicKey)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	publicKey := ed25519.PublicKey(publicBytes)
	return &eddsa{publicKey: publicKey}, nil
}

func (e *eddsa) Sign(ctx context.Context, claims *Claims) (string, error) {
	log := sig.Start(ctx)
	defer log.End()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(e.privateKey)
	if err != nil {
		log.Error(err)
		return "", err
	}
	return signed, nil
}

func (e *eddsa) Verify(ctx context.Context, token string) (*Claims, error) {
	log := sig.Start(ctx)
	defer log.End()
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(
		token,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodEdDSA {
				log.Error(ErrInvalidEdDSASignature)
				return nil, ErrInvalidEdDSASignature
			}
			return e.publicKey, nil
		},
	)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return claims, nil
}
