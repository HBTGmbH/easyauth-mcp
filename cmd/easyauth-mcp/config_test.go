package main

import (
	"io"
	"strings"
	"testing"
)

func TestParseSettingsRejectsInsecureOpenAPI(t *testing.T) {
	s, _, err := parseSettings([]string{
		"--base-url", "https://example.test",
		"--openapi", "http://example.test/api/doc/api-docs",
	}, io.Discard)
	if err != nil {
		t.Fatalf("parseSettings returned a hard error: %v", err)
	}
	if s.ConfigError == nil {
		t.Fatal("expected insecure spec URL to be recorded in ConfigError")
	}
}

func TestParseSettingsCollectsMissingValues(t *testing.T) {
	t.Setenv("EASYAUTH_BASE_URL", "")
	t.Setenv("EASYAUTH_OPENAPI", "")
	s, _, err := parseSettings([]string{}, io.Discard)
	if err != nil {
		t.Fatalf("parseSettings returned a hard error: %v", err)
	}
	if s.ConfigError == nil {
		t.Fatal("expected ConfigError for a missing configuration")
	}
	if !strings.Contains(s.ConfigError.Error(), "base-url") {
		t.Errorf("ConfigError does not mention base-url: %v", s.ConfigError)
	}
}

func TestParseSettingsAllowsLocalSpecOverHTTP(t *testing.T) {
	_, _, err := parseSettings([]string{
		"--base-url", "http://localhost:8080",
		"--openapi", "http://localhost:8080/api/doc/api-docs",
		"--auth-header", "Bearer x",
	}, io.Discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseSettingsAllowsLocalSpecFile(t *testing.T) {
	_, _, err := parseSettings([]string{
		"--base-url", "https://example.test",
		"--openapi", "../../testdata/openapi-fixture.json",
		"--auth-header", "Bearer x",
	}, io.Discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
