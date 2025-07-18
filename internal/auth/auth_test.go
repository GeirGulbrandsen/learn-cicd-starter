package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{}
	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer somekey")
	_, err := GetAPIKey(headers)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected malformed authorization header error, got %v", err)
	}
}

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")
	key, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if key != "my-secret-key" {
		t.Errorf("expected 'my-secret-key', got '%s'", key)
	}
}

func TestGetAPIKey_EmptyApiKeyValue(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey ")
	key, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if key != "" {
		t.Errorf("expected empty string, got '%s'", key)
	}
}

func TestGetAPIKey_ExtraSpaces(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey mykey extra")
	key, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if key != "mykey" {
		t.Errorf("expected 'mykey', got '%s'", key)
	}
}
