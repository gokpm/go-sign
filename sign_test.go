package sign_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gokpm/go-sign"
)

const (
	privateKey1 = "jXuOxIQoLSuKDQxFYTcy0VbBuuSnpaXbLSj25EKtaqB603M7iz3blfnPdFy7m5t3sZZhPp/Bwhf4yGBCUx6iog=="
	publicKey1  = "etNzO4s925X5z3Rcu5ubd7GWYT6fwcIX+MhgQlMeoqI="

	privateKey2 = "btAuwRbluwkSa8n4UgYGBtLTv9s1Yj8Omi5XddN5lopnwM9X2GlaB8O56D1ejW9zZb8YiFzxWqFzs7S6u8idlg=="
	publicKey2  = "Z8DPV9hpWgfDueg9Xo1vc2W/GIhc8Vqhc7O0urvInZY="
)

func TestNewSigner(t *testing.T) {
	_, err := sign.NewSigner(privateKey1)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewVerifier(t *testing.T) {
	_, err := sign.NewVerifier(publicKey1)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSigner(t *testing.T) {
	signer, err := sign.NewSigner(privateKey1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims1 := sign.NewClaims(
		sign.WithIssuer("sign_test"),
		sign.WithSubject("test"),
		sign.WithAudience("dev"),
		sign.WithExpiresAt(now.Add(1*time.Second)),
		sign.WithNotBefore(now),
		sign.WithIssuedAt(now),
		sign.WithID("0"),
	)
	token, err := signer.Sign(claims1)
	if err != nil {
		t.Fatal(err)
	}
	claims2, err := signer.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	bytes1, err := json.Marshal(claims1)
	if err != nil {
		t.Fatal(err)
	}
	bytes2, err := json.Marshal(claims2)
	if err != nil {
		t.Fatal(err)
	}
	if string(bytes1) != string(bytes2) {
		t.Fatal("bytes1 != bytes2")
	}
}

func TestSignerVerifier(t *testing.T) {
	signer, err := sign.NewSigner(privateKey1)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := sign.NewVerifier(publicKey1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims1 := sign.NewClaims(
		sign.WithIssuer("sign_test"),
		sign.WithSubject("test"),
		sign.WithAudience("dev"),
		sign.WithExpiresAt(now.Add(1*time.Second)),
		sign.WithNotBefore(now),
		sign.WithIssuedAt(now),
		sign.WithID("0"),
	)
	token, err := signer.Sign(claims1)
	if err != nil {
		t.Fatal(err)
	}
	claims2, err := verifier.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	bytes1, err := json.Marshal(claims1)
	if err != nil {
		t.Fatal(err)
	}
	bytes2, err := json.Marshal(claims2)
	if err != nil {
		t.Fatal(err)
	}
	if string(bytes1) != string(bytes2) {
		t.Fatal("bytes1 != bytes2")
	}
}

func TestSignerVerifierDifferentKeys1(t *testing.T) {
	signer, err := sign.NewSigner(privateKey1)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := sign.NewVerifier(publicKey2)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims1 := sign.NewClaims(
		sign.WithIssuer("sign_test"),
		sign.WithSubject("test"),
		sign.WithAudience("dev"),
		sign.WithExpiresAt(now.Add(1*time.Second)),
		sign.WithNotBefore(now),
		sign.WithIssuedAt(now),
		sign.WithID("0"),
	)
	token, err := signer.Sign(claims1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(token)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSignerVerifierDifferentKeys2(t *testing.T) {
	signer, err := sign.NewSigner(privateKey2)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := sign.NewVerifier(publicKey1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims1 := sign.NewClaims(
		sign.WithIssuer("sign_test"),
		sign.WithSubject("test"),
		sign.WithAudience("dev"),
		sign.WithExpiresAt(now.Add(1*time.Second)),
		sign.WithNotBefore(now),
		sign.WithIssuedAt(now),
		sign.WithID("0"),
	)
	token, err := signer.Sign(claims1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(token)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSignerVerifierSleep(t *testing.T) {
	signer, err := sign.NewSigner(privateKey1)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := sign.NewVerifier(publicKey1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims1 := sign.NewClaims(
		sign.WithIssuer("sign_test"),
		sign.WithSubject("test"),
		sign.WithAudience("dev"),
		sign.WithExpiresAt(now.Add(1*time.Millisecond)),
		sign.WithNotBefore(now),
		sign.WithIssuedAt(now),
		sign.WithID("0"),
	)
	token, err := signer.Sign(claims1)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1 * time.Millisecond)
	_, err = verifier.Verify(token)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSignerVerifierNotBefore(t *testing.T) {
	signer, err := sign.NewSigner(privateKey1)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := sign.NewVerifier(publicKey1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims1 := sign.NewClaims(
		sign.WithIssuer("sign_test"),
		sign.WithSubject("test"),
		sign.WithAudience("dev"),
		sign.WithExpiresAt(now.Add(2*time.Second)),
		sign.WithNotBefore(now.Add(1*time.Second)),
		sign.WithIssuedAt(now),
		sign.WithID("0"),
	)
	token, err := signer.Sign(claims1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(token)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSignerVerifierNotBeforeSleep(t *testing.T) {
	signer, err := sign.NewSigner(privateKey1)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := sign.NewVerifier(publicKey1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims1 := sign.NewClaims(
		sign.WithIssuer("sign_test"),
		sign.WithSubject("test"),
		sign.WithAudience("dev"),
		sign.WithExpiresAt(now.Add(2*time.Second)),
		sign.WithNotBefore(now.Add(1*time.Second)),
		sign.WithIssuedAt(now),
		sign.WithID("0"),
	)
	token, err := signer.Sign(claims1)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1 * time.Second)
	claims2, err := verifier.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	bytes1, err := json.Marshal(claims1)
	if err != nil {
		t.Fatal(err)
	}
	bytes2, err := json.Marshal(claims2)
	if err != nil {
		t.Fatal(err)
	}
	if string(bytes1) != string(bytes2) {
		t.Fatal("bytes1 != bytes2")
	}
}

type Data struct {
	ID    string
	Email string
}

func TestSignerVerifierNotBeforeSleepData(t *testing.T) {
	signer, err := sign.NewSigner(privateKey1)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := sign.NewVerifier(publicKey1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	data := &Data{
		ID:    "1",
		Email: "user@example.com",
	}
	claims1 := sign.NewClaims(
		sign.WithIssuer("sign_test"),
		sign.WithSubject("test"),
		sign.WithAudience("dev"),
		sign.WithExpiresAt(now.Add(2*time.Second)),
		sign.WithNotBefore(now.Add(1*time.Second)),
		sign.WithIssuedAt(now),
		sign.WithID("0"),
		sign.WithData(data),
	)
	token, err := signer.Sign(claims1)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1 * time.Second)
	claims2, err := verifier.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := json.Marshal(claims2.Data)
	if err != nil {
		t.Fatal(err)
	}
	data = &Data{}
	err = json.Unmarshal(bytes, data)
	if err != nil {
		t.Fatal(err)
	}
	if data.ID != "1" {
		t.Fatal("!= 1")
	}
	if data.Email != "user@example.com" {
		t.Fatal("!= user@example.com")
	}
}
