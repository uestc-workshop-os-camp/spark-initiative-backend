package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

type signer struct {
	key []byte
	now func() time.Time
}

type oauthCookie struct {
	State, Verifier string
	Expires         int64
}

type sessionCookie struct {
	GitHubID int64  `json:"github_id"`
	Login    string `json:"login"`
	Expires  int64  `json:"expires"`
}

func newSigner(key []byte) signer { return signer{append([]byte(nil), key...), time.Now} }

func (s signer) seal(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s signer) open(raw string, target any) error {
	separator := -1
	for i := len(raw) - 1; i >= 0; i-- {
		if raw[i] == '.' {
			separator = i
			break
		}
	}
	if separator <= 0 {
		return errors.New("invalid signed value")
	}
	encoded, signature := raw[:separator], raw[separator+1:]
	got, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return errors.New("invalid signed value")
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(encoded))
	if subtle.ConstantTimeCompare(got, mac.Sum(nil)) != 1 {
		return errors.New("invalid signed value")
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || json.Unmarshal(payload, target) != nil {
		return errors.New("invalid signed value")
	}
	return nil
}

func (s signer) csrf(sessionValue string) string {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte("csrf\n" + sessionValue))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
