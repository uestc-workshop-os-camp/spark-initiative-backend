package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	errRepoCollision   = errors.New("repository name already exists")
	errIdentityChanged = errors.New("GitHub invitation points to another account")
)

type githubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

type repository struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	HTMLURL     string `json:"html_url"`
	Description string `json:"description"`
}

type grant struct {
	Pending       bool
	InvitationURL string
}

type githubService interface {
	AuthorizationURL(string, string, string) string
	ExchangeUser(context.Context, string, string, string) (githubUser, error)
	Provision(context.Context, phase, string, string, string, int64) (repository, grant, error)
}

type githubClient struct {
	http                  *http.Client
	apiBase, webBase, org string
	clientID, secret      string
	installationID        int64
	privateKey            *rsa.PrivateKey
	now                   func() time.Time
}

func newGitHub(cfg config) (*githubClient, error) {
	keyPEM, err := os.ReadFile(cfg.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read GitHub App private key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("GitHub App private key is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if pkcs8Err != nil {
			return nil, fmt.Errorf("parse GitHub App private key: %w", err)
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("GitHub App private key is not RSA")
		}
	}
	return &githubClient{
		http: &http.Client{Timeout: 12 * time.Second}, apiBase: "https://api.github.com",
		webBase: "https://github.com", org: cfg.GitHubOrg, clientID: cfg.ClientID,
		secret: cfg.Secret, installationID: cfg.InstallationID, privateKey: key, now: time.Now,
	}, nil
}

func (g *githubClient) AuthorizationURL(state, challenge, redirect string) string {
	values := url.Values{
		"client_id": {g.clientID}, "redirect_uri": {redirect}, "state": {state},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	return g.webBase + "/login/oauth/authorize?" + values.Encode()
}

func (g *githubClient) ExchangeUser(ctx context.Context, code, verifier, redirect string) (githubUser, error) {
	form := url.Values{
		"client_id": {g.clientID}, "client_secret": {g.secret}, "code": {code},
		"code_verifier": {verifier}, "redirect_uri": {redirect},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.webBase+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return githubUser{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.http.Do(req)
	if err != nil {
		return githubUser{}, err
	}
	defer resp.Body.Close()
	var token struct {
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := decodeJSONResponse(resp, &token, http.StatusOK); err != nil {
		return githubUser{}, err
	}
	if token.AccessToken == "" {
		return githubUser{}, fmt.Errorf("GitHub OAuth failed: %s", token.ErrorDescription)
	}
	var user githubUser
	_, err = g.api(ctx, http.MethodGet, "/user", token.AccessToken, nil, &user, http.StatusOK)
	if err != nil {
		return githubUser{}, err
	}
	if user.ID <= 0 || !validLogin(user.Login) {
		return githubUser{}, errors.New("GitHub returned an invalid user")
	}
	return user, nil
}

func (g *githubClient) Provision(ctx context.Context, p phase, name, login, marker string, expectedID int64) (repository, grant, error) {
	token, err := g.installationToken(ctx)
	if err != nil {
		return repository{}, grant{}, err
	}
	repo, createErr := g.generateRepository(ctx, token, p, name, marker)
	if createErr != nil {
		var found bool
		repo, found, err = g.getRepository(ctx, token, name)
		if err != nil {
			return repository{}, grant{}, err
		}
		if !found {
			return repository{}, grant{}, createErr
		}
	}
	if repo.Description != marker {
		return repository{}, grant{}, errRepoCollision
	}
	access, err := g.grant(ctx, token, name, login, expectedID)
	return repo, access, err
}

func (g *githubClient) grant(ctx context.Context, token, repoName, login string, expectedID int64) (grant, error) {
	var invitation struct {
		ID      int64  `json:"id"`
		HTMLURL string `json:"html_url"`
		Invitee struct {
			ID int64 `json:"id"`
		} `json:"invitee"`
	}
	path := "/repos/" + url.PathEscape(g.org) + "/" + url.PathEscape(repoName) + "/collaborators/" + url.PathEscape(login)
	status, err := g.api(ctx, http.MethodPut, path, token, map[string]string{"permission": "push"}, &invitation, http.StatusCreated, http.StatusNoContent)
	if err != nil {
		return grant{}, err
	}
	if status == http.StatusNoContent {
		return grant{}, nil
	}
	if invitation.ID <= 0 || invitation.Invitee.ID <= 0 || invitation.HTMLURL == "" {
		return grant{}, errors.New("GitHub returned an invalid invitation")
	}
	if invitation.Invitee.ID != expectedID {
		cancelPath := "/repos/" + url.PathEscape(g.org) + "/" + url.PathEscape(repoName) + "/invitations/" + strconv.FormatInt(invitation.ID, 10)
		_, cancelErr := g.api(ctx, http.MethodDelete, cancelPath, token, nil, nil, http.StatusNoContent, http.StatusNotFound)
		if cancelErr != nil {
			return grant{}, fmt.Errorf("unexpected invitee; cancellation also failed: %w", cancelErr)
		}
		return grant{}, errIdentityChanged
	}
	return grant{true, invitation.HTMLURL}, nil
}

func (g *githubClient) getRepository(ctx context.Context, token, name string) (repository, bool, error) {
	var repo repository
	path := "/repos/" + url.PathEscape(g.org) + "/" + url.PathEscape(name)
	status, err := g.api(ctx, http.MethodGet, path, token, nil, &repo, http.StatusOK, http.StatusNotFound)
	if err != nil || status == http.StatusNotFound {
		return repository{}, false, err
	}
	if repo.ID <= 0 || repo.HTMLURL == "" {
		return repository{}, false, errors.New("GitHub returned an invalid repository")
	}
	return repo, true, nil
}

func (g *githubClient) generateRepository(ctx context.Context, token string, p phase, name, marker string) (repository, error) {
	path := "/repos/" + url.PathEscape(p.TemplateOwner) + "/" + url.PathEscape(p.TemplateRepo) + "/generate"
	body := map[string]any{
		"owner": g.org, "name": name, "description": marker,
		"include_all_branches": p.AllBranches, "private": false,
	}
	var repo repository
	_, err := g.api(ctx, http.MethodPost, path, token, body, &repo, http.StatusCreated)
	if err == nil && (repo.ID <= 0 || repo.HTMLURL == "") {
		err = errors.New("GitHub returned an invalid repository")
	}
	return repo, err
}

func (g *githubClient) installationToken(ctx context.Context) (string, error) {
	jwt, err := g.appJWT()
	if err != nil {
		return "", err
	}
	var result struct {
		Token string `json:"token"`
	}
	path := "/app/installations/" + strconv.FormatInt(g.installationID, 10) + "/access_tokens"
	body := map[string]any{"permissions": map[string]string{"administration": "write", "contents": "read"}}
	_, err = g.api(ctx, http.MethodPost, path, jwt, body, &result, http.StatusCreated)
	if err != nil {
		return "", err
	}
	if result.Token == "" {
		return "", errors.New("GitHub returned an empty installation token")
	}
	return result.Token, nil
}

func (g *githubClient) appJWT() (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iat": g.now().Add(-time.Minute).Unix(), "exp": g.now().Add(9 * time.Minute).Unix(), "iss": g.clientID,
	})
	unsigned := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, g.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (g *githubClient) api(ctx context.Context, method, path, token string, input, output any, expected ...int) (int, error) {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.apiBase+path, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("User-Agent", "spark-initiative-backend")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if output == nil {
		return resp.StatusCode, checkResponse(resp, expected...)
	}
	return resp.StatusCode, decodeJSONResponse(resp, output, expected...)
}

func decodeJSONResponse(resp *http.Response, output any, expected ...int) error {
	if err := checkResponse(resp, expected...); err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(output)
}

func checkResponse(resp *http.Response, expected ...int) error {
	for _, status := range expected {
		if resp.StatusCode == status {
			return nil
		}
	}
	var result struct {
		Message string `json:"message"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&result)
	return fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, result.Message)
}

func validLogin(login string) bool {
	if len(login) == 0 || len(login) > 39 || login[0] == '-' || login[len(login)-1] == '-' {
		return false
	}
	previousHyphen := false
	for _, char := range login {
		valid := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-'
		if !valid || char == '-' && previousHyphen {
			return false
		}
		previousHyphen = char == '-'
	}
	return true
}
