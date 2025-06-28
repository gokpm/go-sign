# go-sign

Go package for JWT signing and verification using Ed25519/EdDSA.

## Installation

```bash
go get github.com/gokpm/go-sign
```

## Usage

```go
import "github.com/gokpm/go-sign"

// Create claims with functional options
claims := sign.NewClaims(
    sign.WithIssuer("my-service"),
    sign.WithSubject("user-123"),
    sign.WithAudience("api", "web"),
    sign.WithExpiresAt(time.Now().Add(time.Hour)),
    sign.WithData(map[string]any{"role": "admin"}),
)

// Create signer
signer, err := sign.NewSigner(ctx, b64PrivateKey)
if err != nil {
    return err
}

// Sign token
token, err := signer.Sign(ctx, claims)
if err != nil {
    return err
}

// Create verifier
verifier, err := sign.NewVerifier(ctx, b64PublicKey)
if err != nil {
    return err
}

// Verify token
claims, err := verifier.Verify(ctx, token)
if err != nil {
    return err
}
```

## API

### Claims

```go
func NewClaims(opts ...ClaimOption) *Claims

// Claim options
func WithIssuer(issuer string) ClaimOption
func WithSubject(subject string) ClaimOption
func WithAudience(audience ...string) ClaimOption
func WithExpiresAt(expiresAt time.Time) ClaimOption
func WithNotBefore(notBefore time.Time) ClaimOption
func WithIssuedAt(issuedAt time.Time) ClaimOption
func WithID(id string) ClaimOption
func WithData(data any) ClaimOption
```

### Interfaces

```go
type Signer interface {
    Sign(context.Context, *Claims) (string, error)
    Verify(context.Context, string) (*Claims, error)
}

type Verifier interface {
    Verify(context.Context, string) (*Claims, error)
}
```

### Signer/Verifier

```go
func NewSigner(ctx context.Context, b64PrivateKey string) (Signer, error)
func NewVerifier(ctx context.Context, b64PublicKey string) (Verifier, error)
```

## Dependencies

- `github.com/golang-jwt/jwt/v5`
- `github.com/gokpm/go-codec`
- `github.com/gokpm/go-sig`