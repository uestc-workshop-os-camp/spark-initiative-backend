package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestProvisionUsesOnlyTokenGenerateAndCollaboratorRequests(t *testing.T) {
	const marker = "spark-claim:42:rust"
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch len(requests) {
		case 1:
			if requests[0] != "POST /app/installations/7/access_tokens" {
				t.Errorf("first request = %q", requests[0])
			}
			var body struct {
				Permissions map[string]string `json:"permissions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode token body: %v", err)
			}
			if body.Permissions["administration"] != "write" || body.Permissions["contents"] != "read" {
				t.Errorf("permissions = %#v", body.Permissions)
			}
			writeTestJSON(w, http.StatusCreated, map[string]any{"token": "installation-token"})
		case 2:
			if requests[1] != "POST /repos/template-owner/template/generate" {
				t.Errorf("second request = %q", requests[1])
			}
			if r.Header.Get("Authorization") != "Bearer installation-token" {
				t.Errorf("generate authorization = %q", r.Header.Get("Authorization"))
			}
			var body struct {
				Owner, Name, Description string
				AllBranches              bool `json:"include_all_branches"`
				Private                  bool `json:"private"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode generate body: %v", err)
			}
			if body.Owner != "camp" || body.Name != "course-alice" || body.Description != marker || !body.AllBranches || body.Private {
				t.Errorf("generate body = %#v", body)
			}
			writeTestJSON(w, http.StatusCreated, map[string]any{
				"id": 91, "name": "course-alice", "html_url": "https://github.test/camp/course-alice", "description": marker,
			})
		case 3:
			if requests[2] != "PUT /repos/camp/course-alice/collaborators/alice" {
				t.Errorf("third request = %q", requests[2])
			}
			writeTestJSON(w, http.StatusCreated, map[string]any{
				"id": 8, "html_url": "https://github.test/invitation/8", "invitee": map[string]any{"id": 42},
			})
		default:
			t.Errorf("unexpected extra request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	client := testGitHubClient(t, server)
	repo, access, err := client.Provision(context.Background(), phase{
		TemplateOwner: "template-owner", TemplateRepo: "template", AllBranches: true,
	}, "course-alice", "alice", marker, 42)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(requests) != 3 {
		t.Fatalf("request count = %d, want 3", len(requests))
	}
	if repo.ID != 91 || repo.Description != marker {
		t.Errorf("repository = %#v", repo)
	}
	if !access.Pending || access.InvitationURL != "https://github.test/invitation/8" {
		t.Errorf("grant = %#v", access)
	}
}

func TestProvisionRecoversGeneratedRepositoryByMarker(t *testing.T) {
	const marker = "spark-claim:42:rust"
	want := []string{
		"POST /app/installations/7/access_tokens",
		"POST /repos/template-owner/template/generate",
		"GET /repos/camp/course-alice",
		"PUT /repos/camp/course-alice/collaborators/alice",
	}
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		index := len(requests) - 1
		if index >= len(want) || requests[index] != want[index] {
			t.Errorf("request %d = %q", index+1, requests[index])
			http.Error(w, "unexpected request", http.StatusInternalServerError)
			return
		}
		switch index {
		case 0:
			writeTestJSON(w, http.StatusCreated, map[string]any{"token": "installation-token"})
		case 1:
			writeTestJSON(w, http.StatusUnprocessableEntity, map[string]any{"message": "name already exists"})
		case 2:
			writeTestJSON(w, http.StatusOK, map[string]any{
				"id": 91, "name": "course-alice", "html_url": "https://github.test/camp/course-alice", "description": marker,
			})
		case 3:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	client := testGitHubClient(t, server)
	repo, access, err := client.Provision(context.Background(), phase{
		TemplateOwner: "template-owner", TemplateRepo: "template",
	}, "course-alice", "alice", marker, 42)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(requests) != len(want) {
		t.Fatalf("request count = %d, want %d", len(requests), len(want))
	}
	if repo.ID != 91 || repo.Description != marker || access.Pending {
		t.Errorf("repository = %#v, grant = %#v", repo, access)
	}
}

func TestRecreateDeletesMatchingRepositoryBeforeProvisioning(t *testing.T) {
	const marker = "spark-claim:42:rust"
	want := []string{
		"POST /app/installations/7/access_tokens",
		"GET /repos/camp/course-alice",
		"DELETE /repos/camp/course-alice",
		"POST /repos/template-owner/template/generate",
		"PUT /repos/camp/course-alice/collaborators/alice",
	}
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		index := len(requests) - 1
		if index >= len(want) || requests[index] != want[index] {
			t.Errorf("request %d = %q", index+1, requests[index])
			http.Error(w, "unexpected request", http.StatusInternalServerError)
			return
		}
		switch index {
		case 0:
			writeTestJSON(w, http.StatusCreated, map[string]any{"token": "installation-token"})
		case 1:
			writeTestJSON(w, http.StatusOK, map[string]any{
				"id": 91, "name": "course-alice", "html_url": "https://github.test/camp/course-alice", "description": marker,
			})
		case 2:
			w.WriteHeader(http.StatusNoContent)
		case 3:
			writeTestJSON(w, http.StatusCreated, map[string]any{
				"id": 92, "name": "course-alice", "html_url": "https://github.test/camp/course-alice", "description": marker,
			})
		case 4:
			writeTestJSON(w, http.StatusCreated, map[string]any{
				"id": 12, "html_url": "https://github.test/invitation/12", "invitee": map[string]any{"id": 42},
			})
		}
	}))
	defer server.Close()

	client := testGitHubClient(t, server)
	repo, access, err := client.Recreate(context.Background(), phase{
		TemplateOwner: "template-owner", TemplateRepo: "template",
	}, "course-alice", "alice", marker, 42, 91)
	if err != nil {
		t.Fatalf("Recreate: %v", err)
	}
	if len(requests) != len(want) || repo.ID != 92 || !access.Pending {
		t.Fatalf("requests = %#v, repository = %#v, grant = %#v", requests, repo, access)
	}
}

func TestRecreateRejectsRepositoryThatNoLongerMatchesClaim(t *testing.T) {
	const marker = "spark-claim:42:rust"
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch len(requests) {
		case 1:
			writeTestJSON(w, http.StatusCreated, map[string]any{"token": "installation-token"})
		case 2:
			writeTestJSON(w, http.StatusOK, map[string]any{
				"id": 777, "name": "course-alice", "html_url": "https://github.test/camp/course-alice", "description": marker,
			})
		default:
			t.Errorf("unexpected destructive request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	client := testGitHubClient(t, server)
	_, _, err := client.Recreate(context.Background(), phase{
		TemplateOwner: "template-owner", TemplateRepo: "template",
	}, "course-alice", "alice", marker, 42, 91)
	if !errors.Is(err, errRepositoryChanged) {
		t.Fatalf("Recreate error = %v, want %v", err, errRepositoryChanged)
	}
	if len(requests) != 2 {
		t.Fatalf("requests = %#v; repository should not have been deleted", requests)
	}
}

func TestRecreateRebuildsRepositoryAlreadyDeletedFromGitHub(t *testing.T) {
	const marker = "spark-claim:42:rust"
	want := []string{
		"POST /app/installations/7/access_tokens",
		"GET /repos/camp/course-alice",
		"POST /repos/template-owner/template/generate",
		"PUT /repos/camp/course-alice/collaborators/alice",
	}
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		index := len(requests) - 1
		if index >= len(want) || requests[index] != want[index] {
			t.Errorf("request %d = %q", index+1, requests[index])
			http.Error(w, "unexpected request", http.StatusInternalServerError)
			return
		}
		switch index {
		case 0:
			writeTestJSON(w, http.StatusCreated, map[string]any{"token": "installation-token"})
		case 1:
			w.WriteHeader(http.StatusNotFound)
		case 2:
			writeTestJSON(w, http.StatusCreated, map[string]any{
				"id": 92, "name": "course-alice", "html_url": "https://github.test/camp/course-alice", "description": marker,
			})
		case 3:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	client := testGitHubClient(t, server)
	repo, _, err := client.Recreate(context.Background(), phase{
		TemplateOwner: "template-owner", TemplateRepo: "template",
	}, "course-alice", "alice", marker, 42, 91)
	if err != nil {
		t.Fatalf("Recreate: %v", err)
	}
	if len(requests) != len(want) || repo.ID != 92 {
		t.Fatalf("requests = %#v, repository = %#v", requests, repo)
	}
}

func TestIsCollaborator(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   bool
	}{
		{"accepted", http.StatusNoContent, true},
		{"pending", http.StatusNotFound, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.Method+" "+r.URL.Path)
				switch len(requests) {
				case 1:
					writeTestJSON(w, http.StatusCreated, map[string]any{"token": "installation-token"})
				case 2:
					w.WriteHeader(tt.status)
				default:
					http.Error(w, "unexpected request", http.StatusInternalServerError)
				}
			}))
			defer server.Close()

			client := testGitHubClient(t, server)
			got, err := client.IsCollaborator(context.Background(), "course-alice", "alice")
			if err != nil {
				t.Fatalf("IsCollaborator: %v", err)
			}
			if got != tt.want {
				t.Fatalf("IsCollaborator = %v, want %v", got, tt.want)
			}
			wantRequests := []string{
				"POST /app/installations/7/access_tokens",
				"GET /repos/camp/course-alice/collaborators/alice",
			}
			if !slices.Equal(requests, wantRequests) {
				t.Fatalf("requests = %#v, want %#v", requests, wantRequests)
			}
		})
	}
}

func TestExchangeUserParsesOAuthTokenAndIdentity(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Path {
		case "/login/oauth/access_token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse OAuth form: %v", err)
			}
			if r.Form.Get("code") != "code" || r.Form.Get("code_verifier") != "verifier" {
				t.Errorf("OAuth form = %#v", r.Form)
			}
			writeTestJSON(w, http.StatusOK, map[string]any{"access_token": "oauth-token"})
		case "/user":
			if r.Header.Get("Authorization") != "Bearer oauth-token" {
				t.Errorf("user authorization = %q", r.Header.Get("Authorization"))
			}
			writeTestJSON(w, http.StatusOK, map[string]any{"id": 42, "login": "alice-1"})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := testGitHubClient(t, server)
	user, err := client.ExchangeUser(context.Background(), "code", "verifier", "https://camp.test/auth/callback")
	if err != nil {
		t.Fatalf("ExchangeUser: %v", err)
	}
	if requests != 2 || user.ID != 42 || user.Login != "alice-1" {
		t.Errorf("requests = %d, user = %#v", requests, user)
	}
}

func testGitHubClient(t *testing.T, server *httptest.Server) *githubClient {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return &githubClient{
		http: server.Client(), apiBase: server.URL, webBase: server.URL, org: "camp",
		clientID: "client", secret: "secret", installationID: 7, privateKey: key, now: time.Now,
	}
}

func writeTestJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
