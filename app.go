package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	basePath          = "/api/classroom/v1"
	oauthCookieName   = "spark_oauth"
	sessionCookieName = "spark_session"
)

type application struct {
	cfg    config
	store  claimStore
	github githubService
	signer signer
	logger *slog.Logger
	now    func() time.Time
	mux    *http.ServeMux
}

func newApplication(cfg config, store claimStore, github githubService, logger *slog.Logger) *application {
	app := &application{cfg, store, github, newSigner(cfg.CookieKey), logger, time.Now, http.NewServeMux()}
	app.mux.HandleFunc("GET "+basePath+"/auth/login", app.login)
	app.mux.HandleFunc("GET "+basePath+"/auth/callback", app.callback)
	app.mux.HandleFunc("POST "+basePath+"/auth/logout", app.withSession(app.logout))
	app.mux.HandleFunc("GET "+basePath+"/state", app.withSession(app.state))
	app.mux.HandleFunc("POST "+basePath+"/claim/{phase}", app.withSession(app.claim))
	app.mux.HandleFunc("POST "+basePath+"/claim/{phase}/recreate", app.withSession(app.recreate))
	return app
}

func (a *application) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		a.mux.ServeHTTP(w, r)
	})
}

func (a *application) login(w http.ResponseWriter, r *http.Request) {
	state, err := randomToken()
	if err != nil {
		a.internalError(w, "create OAuth state", err)
		return
	}
	verifier, err := randomToken()
	if err != nil {
		a.internalError(w, "create PKCE verifier", err)
		return
	}
	expires := a.now().Add(10 * time.Minute)
	value, err := a.signer.seal(oauthCookie{state, verifier, expires.Unix()})
	if err != nil {
		a.internalError(w, "sign OAuth cookie", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oauthCookieName, Value: value, Path: basePath + "/auth/callback",
		Expires: expires, MaxAge: 600, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	redirect := a.cfg.PublicURL + basePath + "/auth/callback"
	http.Redirect(w, r, a.github.AuthorizationURL(state, pkceChallenge(verifier), redirect), http.StatusFound)
}

func (a *application) callback(w http.ResponseWriter, r *http.Request) {
	a.clearCookie(w, oauthCookieName, basePath+"/auth/callback")
	cookie, err := r.Cookie(oauthCookieName)
	var saved oauthCookie
	if err != nil || a.signer.open(cookie.Value, &saved) != nil || saved.Expires <= a.now().Unix() ||
		subtle.ConstantTimeCompare([]byte(saved.State), []byte(r.URL.Query().Get("state"))) != 1 {
		writeError(w, http.StatusBadRequest, "invalid_oauth", "login session is invalid or expired")
		return
	}
	if r.URL.Query().Get("error") != "" {
		http.Redirect(w, r, "/os/?auth=denied", http.StatusFound)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" || len(code) > 512 {
		writeError(w, http.StatusBadRequest, "invalid_oauth", "GitHub did not return a login code")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	redirect := a.cfg.PublicURL + basePath + "/auth/callback"
	user, err := a.github.ExchangeUser(ctx, code, saved.Verifier, redirect)
	if err != nil {
		a.logger.Warn("GitHub login failed", "error", err)
		http.Redirect(w, r, "/os/?auth=failed", http.StatusFound)
		return
	}
	expires := a.now().Add(30 * time.Minute)
	value, err := a.signer.seal(sessionCookie{user.ID, user.Login, expires.Unix()})
	if err != nil {
		a.internalError(w, "sign session cookie", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: value, Path: basePath + "/",
		Expires: expires, MaxAge: 1800, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/os/", http.StatusFound)
}

type sessionHandler func(http.ResponseWriter, *http.Request, sessionCookie, string)

func (a *application) withSession(next sessionHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		var session sessionCookie
		if err != nil || a.signer.open(cookie.Value, &session) != nil || session.Expires <= a.now().Unix() ||
			session.GitHubID <= 0 || !validLogin(session.Login) {
			writeError(w, http.StatusUnauthorized, "login_required", "GitHub login required")
			return
		}
		next(w, r, session, cookie.Value)
	}
}

func (a *application) logout(w http.ResponseWriter, r *http.Request, _ sessionCookie, rawSession string) {
	if !a.validMutation(r, rawSession) {
		writeError(w, http.StatusForbidden, "csrf_failed", "invalid request origin or CSRF token")
		return
	}
	a.clearCookie(w, sessionCookieName, basePath+"/")
	w.WriteHeader(http.StatusNoContent)
}

func (a *application) state(w http.ResponseWriter, r *http.Request, session sessionCookie, rawSession string) {
	claims, err := a.store.List(r.Context(), session.GitHubID)
	if err != nil {
		a.internalError(w, "list claims", err)
		return
	}
	byPhase := make(map[string]claim, len(claims))
	for _, item := range claims {
		byPhase[item.Phase] = item
	}
	reconcileCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	views := make([]any, 0, 2)
	for _, key := range []string{"rust", "rcore"} {
		p := a.cfg.Phases[key]
		view := map[string]any{"key": p.Key, "title": p.Title, "enabled": p.Enabled}
		if item, exists := byPhase[key]; exists {
			status := "ready"
			switch {
			case item.RepoURL == "":
				status = "retry_required"
			case item.InvitationURL != "":
				status = "awaiting_acceptance"
				accepted, checkErr := a.github.IsCollaborator(reconcileCtx, item.RepoName, item.GitHubLogin)
				if checkErr != nil {
					a.logger.Warn("check GitHub collaborator", "phase", item.Phase, "error", checkErr)
				} else if accepted {
					if err := a.store.MarkReady(r.Context(), session.GitHubID, item.Phase); err != nil {
						a.internalError(w, "mark claim ready", err)
						return
					}
					item.InvitationURL = ""
					status = "ready"
				}
			}
			view["claim"] = claimView(item, status)
		}
		views = append(views, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":   map[string]any{"github_id": session.GitHubID, "login": session.Login},
		"phases": views, "csrf_token": a.signer.csrf(rawSession),
	})
}

func (a *application) claim(w http.ResponseWriter, r *http.Request, session sessionCookie, rawSession string) {
	if !a.validEmptyMutation(w, r, rawSession) {
		return
	}
	p, ok := a.cfg.Phases[r.PathValue("phase")]
	if !ok {
		writeError(w, http.StatusNotFound, "phase_not_found", "course phase was not found")
		return
	}
	if !p.Enabled {
		writeError(w, http.StatusConflict, "phase_closed", "course phase is not open")
		return
	}
	item, err := a.store.Reserve(r.Context(), session.GitHubID, session.Login, p)
	if err != nil {
		if errors.Is(err, errClaimConflict) {
			writeError(w, http.StatusConflict, "repository_name_taken", err.Error())
			return
		}
		a.internalError(w, "reserve claim", err)
		return
	}
	if item.RepoID > 0 {
		status := "ready"
		if item.InvitationURL != "" {
			status = "awaiting_acceptance"
		}
		writeJSON(w, http.StatusOK, map[string]any{"claim": claimView(item, status)})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	marker := fmt.Sprintf("spark-initiative:%s:%d", p.Key, session.GitHubID)
	repo, access, err := a.github.Provision(ctx, p, item.RepoName, session.Login, marker, session.GitHubID)
	if err != nil {
		switch {
		case errors.Is(err, errRepoCollision):
			writeError(w, http.StatusConflict, "repository_name_taken", "repository name is already in use")
		case errors.Is(err, errIdentityChanged):
			writeError(w, http.StatusConflict, "login_changed", "GitHub account identity changed; contact an organizer")
		default:
			a.upstreamError(w, "provision repository", err)
		}
		return
	}
	if err := a.store.Complete(r.Context(), session.GitHubID, p.Key, repo, access.InvitationURL); err != nil {
		a.internalError(w, "complete claim", err)
		return
	}
	status := "ready"
	if access.Pending {
		status = "awaiting_acceptance"
	}
	item.RepoID, item.RepoURL, item.InvitationURL = repo.ID, repo.HTMLURL, access.InvitationURL
	writeJSON(w, http.StatusOK, map[string]any{
		"claim": claimView(item, status),
	})
}

func (a *application) recreate(w http.ResponseWriter, r *http.Request, session sessionCookie, rawSession string) {
	if !a.validEmptyMutation(w, r, rawSession) {
		return
	}
	p, ok := a.cfg.Phases[r.PathValue("phase")]
	if !ok {
		writeError(w, http.StatusNotFound, "phase_not_found", "course phase was not found")
		return
	}
	if !p.Enabled {
		writeError(w, http.StatusConflict, "phase_closed", "course phase is not open")
		return
	}
	item, err := a.store.Find(r.Context(), session.GitHubID, p.Key)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && item.RepoID <= 0) {
		writeError(w, http.StatusConflict, "claim_incomplete", "repository has not been created")
		return
	}
	if err != nil {
		a.internalError(w, "find claim for recreation", err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	marker := fmt.Sprintf("spark-initiative:%s:%d", p.Key, session.GitHubID)
	repo, access, err := a.github.Recreate(ctx, p, item.RepoName, session.Login, marker, session.GitHubID, item.RepoID)
	if err != nil {
		switch {
		case errors.Is(err, errRepositoryChanged):
			writeError(w, http.StatusConflict, "repository_changed", "repository no longer matches its claim")
		case errors.Is(err, errRepoCollision):
			writeError(w, http.StatusConflict, "repository_name_taken", "repository name is already in use")
		case errors.Is(err, errIdentityChanged):
			writeError(w, http.StatusConflict, "login_changed", "GitHub account identity changed; contact an organizer")
		default:
			a.upstreamError(w, "recreate repository", err)
		}
		return
	}
	if err := a.store.Complete(r.Context(), session.GitHubID, p.Key, repo, access.InvitationURL); err != nil {
		a.internalError(w, "complete recreated claim", err)
		return
	}
	status := "ready"
	if access.Pending {
		status = "awaiting_acceptance"
	}
	item.RepoID, item.RepoURL, item.InvitationURL = repo.ID, repo.HTMLURL, access.InvitationURL
	writeJSON(w, http.StatusOK, map[string]any{
		"claim": claimView(item, status),
	})
}

func (a *application) validEmptyMutation(w http.ResponseWriter, r *http.Request, rawSession string) bool {
	if !a.validMutation(r, rawSession) {
		writeError(w, http.StatusForbidden, "csrf_failed", "invalid request origin or CSRF token")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	body, err := io.ReadAll(r.Body)
	if err != nil || strings.TrimSpace(string(body)) != "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be empty")
		return false
	}
	return true
}

func (a *application) validMutation(r *http.Request, rawSession string) bool {
	if r.Header.Get("Origin") != a.cfg.PublicURL {
		return false
	}
	want, got := a.signer.csrf(rawSession), r.Header.Get("X-CSRF-Token")
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

func (a *application) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: path, MaxAge: -1, Expires: time.Unix(1, 0), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func (a *application) internalError(w http.ResponseWriter, operation string, err error) {
	a.logger.Error(operation, "error", err)
	writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
}

func (a *application) upstreamError(w http.ResponseWriter, operation string, err error) {
	a.logger.Warn(operation, "error", err)
	writeError(w, http.StatusBadGateway, "github_unavailable", "GitHub request failed; retry")
}

func claimView(item claim, status string) map[string]any {
	return map[string]any{
		"phase": item.Phase, "repository_name": item.RepoName,
		"repository_url": item.RepoURL, "invitation_url": item.InvitationURL, "status": status,
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
