package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var errClaimConflict = errors.New("repository name is already claimed")

type claim struct {
	GitHubID                     int64
	Phase, GitHubLogin, RepoName string
	RepoID                       int64
	RepoURL, InvitationURL       string
	CreatedAt, CompletedAt       int64
}

type claimStore interface {
	Reserve(context.Context, int64, string, phase) (claim, error)
	Find(context.Context, int64, string) (claim, error)
	List(context.Context, int64) ([]claim, error)
	Complete(context.Context, int64, string, repository, string) error
}

type mysqlStore struct{ db *sql.DB }

func openMySQL(ctx context.Context, dsn string) (*mysqlStore, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect to MySQL: %w", err)
	}
	return &mysqlStore{db}, nil
}

func (s *mysqlStore) Reserve(ctx context.Context, githubID int64, login string, p phase) (claim, error) {
	now := time.Now().Unix()
	repoName := p.Prefix + login
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO spark_repo_claims
			(github_id, phase, github_login, repo_name, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE github_id = github_id`,
		githubID, p.Key, login, repoName, now,
	)
	if err != nil {
		return claim{}, fmt.Errorf("reserve claim: %w", err)
	}
	item, err := s.Find(ctx, githubID, p.Key)
	if errors.Is(err, sql.ErrNoRows) {
		return claim{}, errClaimConflict
	}
	return item, err
}

func (s *mysqlStore) Find(ctx context.Context, githubID int64, phaseKey string) (claim, error) {
	var item claim
	err := s.db.QueryRowContext(ctx, `
		SELECT github_id, phase, github_login, repo_name,
		       COALESCE(repo_id, 0), repo_url, invitation_url,
		       created_at, COALESCE(completed_at, 0)
		FROM spark_repo_claims WHERE github_id = ? AND phase = ?`, githubID, phaseKey,
	).Scan(&item.GitHubID, &item.Phase, &item.GitHubLogin, &item.RepoName,
		&item.RepoID, &item.RepoURL, &item.InvitationURL, &item.CreatedAt, &item.CompletedAt)
	return item, err
}

func (s *mysqlStore) List(ctx context.Context, githubID int64) ([]claim, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT github_id, phase, github_login, repo_name,
		       COALESCE(repo_id, 0), repo_url, invitation_url,
		       created_at, COALESCE(completed_at, 0)
		FROM spark_repo_claims WHERE github_id = ? ORDER BY phase`, githubID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var claims []claim
	for rows.Next() {
		var item claim
		if err := rows.Scan(&item.GitHubID, &item.Phase, &item.GitHubLogin, &item.RepoName,
			&item.RepoID, &item.RepoURL, &item.InvitationURL, &item.CreatedAt, &item.CompletedAt); err != nil {
			return nil, err
		}
		claims = append(claims, item)
	}
	return claims, rows.Err()
}

func (s *mysqlStore) Complete(ctx context.Context, githubID int64, phaseKey string, repo repository, invitationURL string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE spark_repo_claims
		SET repo_id = ?, repo_url = ?, invitation_url = ?, completed_at = ?
		WHERE github_id = ? AND phase = ?`,
		repo.ID, repo.HTMLURL, invitationURL, time.Now().Unix(), githubID, phaseKey)
	return err
}
