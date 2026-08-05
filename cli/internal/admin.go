package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// API response types

type UserRow struct {
	ID          string  `json:"id"`
	Username    string  `json:"username"`
	Display     *string `json:"display"`
	Role        *string `json:"role"`
	Status      string  `json:"status"`
	Note        *string `json:"note"`
	LastLoginAt *string `json:"last_login_at"`
}

type UserMetrics struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Status   string `json:"status"`
	Req      int64  `json:"req"`
	TokIn    int64  `json:"tok_in"`
	TokOut   int64  `json:"tok_out"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

type SystemMetrics struct {
	ActiveConnections  int `json:"active_connections"`
	CertCacheEntries   int `json:"cert_cache_entries"`
	PrometheusRawLines int `json:"prometheus_raw_lines"`
	VaultConnected     int `json:"vault_connected"`
}

type QuotaResponse struct {
	Quota struct {
		ReqDay   *int64 `json:"req_day"`
		TokIn    *int64 `json:"tok_in"`
		TokOut   *int64 `json:"tok_out"`
		BytesIn  *int64 `json:"bytes_in"`
		BytesOut *int64 `json:"bytes_out"`
	} `json:"quota"`
	UsageToday struct {
		Req      int64 `json:"req"`
		TokIn    int64 `json:"tok_in"`
		TokOut   int64 `json:"tok_out"`
		BytesIn  int64 `json:"bytes_in"`
		BytesOut int64 `json:"bytes_out"`
	} `json:"usage_today"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Display  string `json:"display"`
	} `json:"user"`
	ExpiresInDays int `json:"expires_in_days"`
}

// AdminAPIBase returns the base URL for admin API calls.
func AdminAPIBase() string {
	return fmt.Sprintf("http://%s:%s/api", Cfg.AdminHost, Cfg.AdminPort)
}

// DirectClient returns an HTTP client that ignores HTTP(S)_PROXY env.
func DirectClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
}

// AdminReq performs an HTTP request against the admin API with token header.
func AdminReq(client *http.Client, url, method string, body []byte) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+Cfg.AuthToken)
	req.Header.Set("Content-Type", "application/json")
	return client.Do(req)
}

// APIGet performs a GET with auth token, bypassing proxy.
func APIGet(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+Cfg.AuthToken)
	return DirectClient().Do(req)
}

// ResolveUserID finds a user's UUID by username via the list endpoint.
func ResolveUserID(username string) (string, error) {
	resp, err := APIGet(AdminAPIBase() + "/users")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var users []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	json.Unmarshal(data, &users)
	for _, u := range users {
		if u.Username == username {
			return u.ID, nil
		}
	}
	return "", fmt.Errorf("user %q not found", username)
}

// ListUsers fetches all users from the admin API.
func ListUsers() ([]UserRow, error) {
	resp, err := APIGet(AdminAPIBase() + "/users")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("list failed: %s %s", resp.Status, data)
	}
	var users []UserRow
	json.Unmarshal(data, &users)
	return users, nil
}

// IsAdmin decodes the JWT token to check if the user has admin role.
func IsAdmin() bool {
	if Cfg.AuthToken == "" {
		return false
	}
	parts := strings.Split(Cfg.AuthToken, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Role string `json:"role"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return false
	}
	return claims.Role == "admin"
}

// CurrentUser returns the display name from JWT, or "" if not logged in.
func CurrentUser() string {
	if Cfg.AuthToken == "" {
		return ""
	}
	parts := strings.Split(Cfg.AuthToken, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Display string `json:"display"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Display
}
