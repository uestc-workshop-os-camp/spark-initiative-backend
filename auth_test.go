package main

import (
	"strings"
	"testing"
)

func TestSignerRejectsTampering(t *testing.T) {
	s := newSigner([]byte("0123456789abcdef0123456789abcdef"))
	want := sessionCookie{GitHubID: 42, Login: "alice", Expires: 12345}
	raw, err := s.seal(want)
	if err != nil {
		t.Fatal(err)
	}

	var got sessionCookie
	if err := s.open(raw, &got); err != nil || got != want {
		t.Fatalf("open valid value: got %#v, err %v", got, err)
	}
	first := raw[0]
	replacement := byte('A')
	if first == replacement {
		replacement = 'B'
	}
	tampered := string(replacement) + raw[1:]
	if err := s.open(tampered, &got); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("tampered value accepted: %v", err)
	}
}
