package main

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeStore struct {
	claims       map[string]claim
	reserveCalls int
}

func (s *fakeStore) Reserve(_ context.Context, id int64, login string, p phase) (claim, error) {
	s.reserveCalls++
	key := p.Key
	if item, ok := s.claims[key]; ok {
		return item, nil
	}
	item := claim{GitHubID: id, Phase: p.Key, GitHubLogin: login, RepoName: p.Prefix + login}
	s.claims[key] = item
	return item, nil
}

func (s *fakeStore) Find(_ context.Context, _ int64, phaseKey string) (claim, error) {
	item, ok := s.claims[phaseKey]
	if !ok {
		return claim{}, sql.ErrNoRows
	}
	return item, nil
}

func (s *fakeStore) List(context.Context, int64) ([]claim, error) {
	items := make([]claim, 0, len(s.claims))
	for _, item := range s.claims {
		items = append(items, item)
	}
	return items, nil
}

func (s *fakeStore) Complete(_ context.Context, _ int64, key string, repo repository, invitationURL string) error {
	item := s.claims[key]
	item.RepoID, item.RepoURL, item.InvitationURL = repo.ID, repo.HTMLURL, invitationURL
	s.claims[key] = item
	return nil
}

type fakeGitHub struct {
	authState, authChallenge, authRedirect string
	provisionLogin                         string
	provisionCalls                         int
	recreateName, recreateLogin            string
	recreateUserID, recreateRepoID         int64
	recreateCalls                          int
}

func (g *fakeGitHub) AuthorizationURL(state, challenge, redirect string) string {
	g.authState, g.authChallenge, g.authRedirect = state, challenge, redirect
	return "https://github.test/login"
}

func (*fakeGitHub) ExchangeUser(context.Context, string, string, string) (githubUser, error) {
	return githubUser{ID: 42, Login: "alice"}, nil
}

func (g *fakeGitHub) Provision(_ context.Context, _ phase, _, login, _ string, _ int64) (repository, grant, error) {
	g.provisionCalls++
	g.provisionLogin = login
	return repository{ID: 99, HTMLURL: "https://github.test/org/repo"}, grant{}, nil
}

func (g *fakeGitHub) Recreate(_ context.Context, _ phase, name, login, _ string, userID, repoID int64) (repository, grant, error) {
	g.recreateCalls++
	g.recreateName, g.recreateLogin = name, login
	g.recreateUserID, g.recreateRepoID = userID, repoID
	return repository{ID: 101, HTMLURL: "https://github.test/org/recreated"}, grant{Pending: true, InvitationURL: "https://github.test/invitation/12"}, nil
}

func testApplication(enabled bool) (*application, *fakeStore, *fakeGitHub) {
	cfg := config{
		PublicURL: "https://camp.test",
		CookieKey: []byte("0123456789abcdef0123456789abcdef"),
		Phases: map[string]phase{
			"rust":  {Key: "rust", Title: "Rust", Prefix: "rust-", Enabled: enabled},
			"rcore": {Key: "rcore", Title: "rCore", Prefix: "rcore-", Enabled: enabled},
		},
	}
	store, github := &fakeStore{claims: make(map[string]claim)}, &fakeGitHub{}
	app := newApplication(cfg, store, github, slog.New(slog.NewTextHandler(io.Discard, nil)))
	app.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return app, store, github
}

func TestLoginSetsStateAndPKCECookie(t *testing.T) {
	app, _, github := testApplication(true)
	recorder := httptest.NewRecorder()
	app.handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, basePath+"/auth/login", nil))

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != oauthCookieName || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != basePath+"/auth/callback" {
		t.Fatalf("unexpected OAuth cookie: %#v", cookie)
	}
	var saved oauthCookie
	if err := app.signer.open(cookie.Value, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.State == "" || saved.Verifier == "" || github.authState != saved.State {
		t.Fatalf("state/verifier not preserved: %#v", saved)
	}
	if github.authChallenge != pkceChallenge(saved.Verifier) || github.authRedirect != "https://camp.test"+basePath+"/auth/callback" {
		t.Fatalf("unexpected authorization arguments: %#v", github)
	}
}

func TestClaimIsIdempotent(t *testing.T) {
	app, store, github := testApplication(true)
	raw := sessionValue(t, app)

	for attempt := 0; attempt < 2; attempt++ {
		recorder := httptest.NewRecorder()
		app.handler().ServeHTTP(recorder, claimRequest(app, raw, "rust"))
		if recorder.Code != http.StatusOK {
			t.Fatalf("attempt %d: status = %d, body = %s", attempt+1, recorder.Code, recorder.Body.String())
		}
	}
	if github.provisionCalls != 1 {
		t.Fatalf("Provision calls = %d, want 1", github.provisionCalls)
	}
	if store.claims["rust"].RepoID != 99 {
		t.Fatalf("claim was not completed: %#v", store.claims["rust"])
	}
}

func TestClaimRetriesWithCurrentLogin(t *testing.T) {
	app, store, github := testApplication(true)
	store.claims["rust"] = claim{
		GitHubID: 42, Phase: "rust", GitHubLogin: "old-name", RepoName: "rust-old-name",
	}
	raw := sessionValue(t, app)
	recorder := httptest.NewRecorder()
	app.handler().ServeHTTP(recorder, claimRequest(app, raw, "rust"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if github.provisionLogin != "alice" {
		t.Fatalf("Provision login = %q, want current login", github.provisionLogin)
	}
}

func TestClaimRejectsClosedPhaseAndBadCSRF(t *testing.T) {
	tests := []struct {
		name, origin, csrf string
		enabled            bool
		want               int
	}{
		{"closed phase", "https://camp.test", "valid", false, http.StatusConflict},
		{"wrong origin", "https://evil.test", "valid", true, http.StatusForbidden},
		{"wrong token", "https://camp.test", "invalid", true, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, store, github := testApplication(tt.enabled)
			raw := sessionValue(t, app)
			req := claimRequest(app, raw, "rust")
			req.Header.Set("Origin", tt.origin)
			if tt.csrf != "valid" {
				req.Header.Set("X-CSRF-Token", tt.csrf)
			}
			recorder := httptest.NewRecorder()
			app.handler().ServeHTTP(recorder, req)
			if recorder.Code != tt.want {
				t.Fatalf("status = %d, want %d; body = %s", recorder.Code, tt.want, recorder.Body.String())
			}
			if github.provisionCalls != 0 || store.reserveCalls != 0 {
				t.Fatalf("rejected request reached store/GitHub: reserve=%d provision=%d", store.reserveCalls, github.provisionCalls)
			}
		})
	}
}

func TestRecreateReplacesCompletedClaim(t *testing.T) {
	app, store, github := testApplication(true)
	store.claims["rust"] = claim{
		GitHubID: 42, Phase: "rust", GitHubLogin: "alice", RepoName: "rust-alice",
		RepoID: 99, RepoURL: "https://github.test/org/rust-alice",
	}
	raw := sessionValue(t, app)
	recorder := httptest.NewRecorder()
	app.handler().ServeHTTP(recorder, recreateRequest(app, raw, "rust"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if github.recreateCalls != 1 || github.recreateName != "rust-alice" || github.recreateLogin != "alice" {
		t.Fatalf("unexpected recreate call: %#v", github)
	}
	if github.recreateUserID != 42 || github.recreateRepoID != 99 {
		t.Fatalf("recreate IDs = user %d repo %d", github.recreateUserID, github.recreateRepoID)
	}
	item := store.claims["rust"]
	if item.RepoID != 101 || item.RepoURL != "https://github.test/org/recreated" || item.InvitationURL != "https://github.test/invitation/12" {
		t.Fatalf("claim was not replaced: %#v", item)
	}
}

func TestRecreateRejectsIncompleteClaim(t *testing.T) {
	app, store, github := testApplication(true)
	store.claims["rust"] = claim{
		GitHubID: 42, Phase: "rust", GitHubLogin: "alice", RepoName: "rust-alice",
	}
	raw := sessionValue(t, app)
	recorder := httptest.NewRecorder()
	app.handler().ServeHTTP(recorder, recreateRequest(app, raw, "rust"))

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if github.recreateCalls != 0 {
		t.Fatalf("Recreate calls = %d, want 0", github.recreateCalls)
	}
}

func sessionValue(t *testing.T, app *application) string {
	t.Helper()
	raw, err := app.signer.seal(sessionCookie{GitHubID: 42, Login: "alice", Expires: app.now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func claimRequest(app *application, raw, phase string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, basePath+"/claim/"+phase, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: raw})
	req.Header.Set("Origin", app.cfg.PublicURL)
	req.Header.Set("X-CSRF-Token", app.signer.csrf(raw))
	return req
}

func recreateRequest(app *application, raw, phase string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, basePath+"/claim/"+phase+"/recreate", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: raw})
	req.Header.Set("Origin", app.cfg.PublicURL)
	req.Header.Set("X-CSRF-Token", app.signer.csrf(raw))
	return req
}
