package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type phase struct {
	Key, Title, TemplateOwner, TemplateRepo, Prefix string
	AllBranches, Enabled                            bool
}

type config struct {
	ListenAddr, PublicURL, MySQLDSN string
	CookieKey                       []byte
	GitHubOrg, ClientID, Secret     string
	InstallationID                  int64
	PrivateKeyFile                  string
	Phases                          map[string]phase
}

func loadConfig() (config, error) {
	required := func(name string) (string, error) {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			return "", fmt.Errorf("%s is required", name)
		}
		return value, nil
	}
	var cfg config
	var err error
	cfg.PublicURL, err = required("SPARK_PUBLIC_URL")
	if err != nil {
		return cfg, err
	}
	publicURL, err := url.Parse(cfg.PublicURL)
	if err != nil || publicURL.Scheme != "https" || publicURL.Host == "" || publicURL.User != nil ||
		(publicURL.Path != "" && publicURL.Path != "/") || publicURL.RawQuery != "" || publicURL.Fragment != "" {
		return cfg, errors.New("SPARK_PUBLIC_URL must be an HTTPS origin")
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	cfg.ListenAddr = envDefault("SPARK_LISTEN_ADDR", "127.0.0.1:8081")
	if !strings.HasPrefix(cfg.ListenAddr, "127.0.0.1:") && !strings.HasPrefix(cfg.ListenAddr, "[::1]:") {
		return cfg, errors.New("SPARK_LISTEN_ADDR must use loopback")
	}
	for name, target := range map[string]*string{
		"SPARK_MYSQL_DSN": &cfg.MySQLDSN, "SPARK_GITHUB_CLIENT_ID": &cfg.ClientID,
		"SPARK_GITHUB_CLIENT_SECRET": &cfg.Secret, "SPARK_GITHUB_PRIVATE_KEY_FILE": &cfg.PrivateKeyFile,
	} {
		*target, err = required(name)
		if err != nil {
			return cfg, err
		}
	}
	cfg.GitHubOrg = envDefault("SPARK_GITHUB_ORG", "uestc-workshop-os-camp")
	installationID, err := required("SPARK_GITHUB_INSTALLATION_ID")
	if err != nil {
		return cfg, err
	}
	cfg.InstallationID, err = strconv.ParseInt(installationID, 10, 64)
	if err != nil || cfg.InstallationID <= 0 {
		return cfg, errors.New("SPARK_GITHUB_INSTALLATION_ID must be a positive integer")
	}
	encodedKey, err := required("SPARK_COOKIE_KEY_BASE64")
	if err != nil {
		return cfg, err
	}
	cfg.CookieKey, err = base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(cfg.CookieKey) < 32 {
		return cfg, errors.New("SPARK_COOKIE_KEY_BASE64 must encode at least 32 bytes")
	}

	rustOwner, rustRepo, err := splitRepo(envDefault("SPARK_RUST_TEMPLATE", cfg.GitHubOrg+"/rustling-2026-template"))
	if err != nil {
		return cfg, fmt.Errorf("SPARK_RUST_TEMPLATE: %w", err)
	}
	rcoreOwner, rcoreRepo, err := splitRepo(envDefault("SPARK_RCORE_TEMPLATE", cfg.GitHubOrg+"/rCore-Camp-Code-2026"))
	if err != nil {
		return cfg, fmt.Errorf("SPARK_RCORE_TEMPLATE: %w", err)
	}
	cfg.Phases = map[string]phase{
		"rust":  {"rust", "Rust", rustOwner, rustRepo, "rcore-rustlings-2026-", false, envBool("SPARK_RUST_ENABLED")},
		"rcore": {"rcore", "rCore", rcoreOwner, rcoreRepo, "rcore-camp-2026-", true, envBool("SPARK_RCORE_ENABLED")},
	}
	return cfg, nil
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envBool(name string) bool {
	value, _ := strconv.ParseBool(strings.TrimSpace(os.Getenv(name)))
	return value
}

func splitRepo(value string) (string, string, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errors.New("expected owner/repository")
	}
	return parts[0], parts[1], nil
}
