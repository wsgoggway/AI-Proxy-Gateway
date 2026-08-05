package internal

import (
	"strings"
	"testing"
)

func argsContain(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--setenv" && args[i+1] == name {
			if i+2 < len(args) {
				return args[i+2]
			}
		}
	}
	return ""
}

func argsContainFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func setupTestCfg() {
	Cfg = Config{
		ProxyHost:  "proxy.example.com",
		ProxyPort:  "8443",
		LoginUser:  "alice",
		LoginPass:  "s3cr3t",
		CAFile:     "/tmp/ca.pem",
		BundleFile: "/tmp/ca-bundle.crt",
		AuthToken:  "test-token",
	}
}

func TestBuildBwrapArgs_clearenvFirst(t *testing.T) {
	setupTestCfg()
	args := BuildBwrapArgs([]string{"opencode"}, "/tmp/certs")
	if args[0] != "--clearenv" {
		t.Fatalf("expected --clearenv as first arg, got %q", args[0])
	}
}

func TestBuildBwrapArgs_includesCredentials(t *testing.T) {
	setupTestCfg()
	args := BuildBwrapArgs([]string{"opencode"}, "/tmp/certs")
	want := "http://alice:s3cr3t@proxy.example.com:8443"
	if got := argsContain(args, "HTTPS_PROXY"); got != want {
		t.Fatalf("HTTPS_PROXY = %q, want %q", got, want)
	}
	if argsContain(args, "HTTP_PROXY") != want {
		t.Fatalf("HTTP_PROXY mismatch: %q", argsContain(args, "HTTP_PROXY"))
	}
}

func TestBuildBwrapArgs_noCredentialsWhenEmpty(t *testing.T) {
	Cfg = Config{
		ProxyHost: "host",
		ProxyPort: "8443",
	}
	args := BuildBwrapArgs([]string{"opencode"}, "/tmp/certs")
	want := "http://host:8443"
	if got := argsContain(args, "HTTPS_PROXY"); got != want {
		t.Fatalf("HTTPS_PROXY = %q, want %q", got, want)
	}
}

func TestBuildBwrapArgs_setsCaAndNodeVars(t *testing.T) {
	setupTestCfg()
	args := BuildBwrapArgs([]string{"opencode"}, "/tmp/certs")
	for _, env := range []string{
		"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
		"GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS",
	} {
		if got := argsContain(args, env); got != "/etc/ssl/certs/ca-certificates.crt" {
			t.Fatalf("%s = %q, want /etc/ssl/certs/ca-certificates.crt", env, got)
		}
	}
	if got := argsContain(args, "NODE_OPTIONS"); got != "--use-openssl-ca" {
		t.Fatalf("NODE_OPTIONS = %q, want --use-openssl-ca", got)
	}
	if got := argsContain(args, "npm_config_cafile"); got != "/etc/ssl/certs/ca-certificates.crt" {
		t.Fatalf("npm_config_cafile = %q, want /etc/ssl/certs/ca-certificates.crt", got)
	}
}

func TestBuildBwrapArgs_authToken(t *testing.T) {
	setupTestCfg()
	args := BuildBwrapArgs([]string{"opencode"}, "/tmp/certs")
	if got := argsContain(args, "PROXY_AUTH_BEARER"); got != "test-token" {
		t.Fatalf("PROXY_AUTH_BEARER = %q, want test-token", got)
	}
}

func TestBuildBwrapArgs_fsLayoutAndCommand(t *testing.T) {
	setupTestCfg()
	args := BuildBwrapArgs([]string{"opencode"}, "/tmp/certs")
	if !argsContainFlag(args, "--ro-bind") {
		t.Fatal("missing --ro-bind")
	}
	if !argsContainFlag(args, "--dev") {
		t.Fatal("missing --dev")
	}
	if !argsContainFlag(args, "--proc") {
		t.Fatal("missing --proc")
	}
	if !argsContainFlag(args, "--die-with-parent") {
		t.Fatal("missing --die-with-parent")
	}
	// Command should be at the end after --
	lastIdx := -1
	for i, a := range args {
		if a == "--" {
			lastIdx = i
		}
	}
	if lastIdx == -1 {
		t.Fatal("missing -- separator")
	}
	if lastIdx+1 >= len(args) || args[lastIdx+1] != "opencode" {
		t.Fatalf("expected 'opencode' after --, got %v", args[lastIdx+1:])
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}
	for _, c := range cases {
		got := FormatBytes(c.in)
		if got != c.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFormatTokens(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1.0K"},
		{1500, "1.5K"},
		{1000000, "1.0M"},
	}
	for _, c := range cases {
		got := FormatTokens(c.in)
		if got != c.want {
			t.Errorf("FormatTokens(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestProgressBar(t *testing.T) {
	if got := ProgressBar(0); got != "░░░░░░░░" {
		t.Errorf("ProgressBar(0) = %q", got)
	}
	if got := ProgressBar(100); got != "████████" {
		t.Errorf("ProgressBar(100) = %q", got)
	}
	if got := ProgressBar(50); !strings.HasPrefix(got, "████") {
		t.Errorf("ProgressBar(50) = %q, expected some filled", got)
	}
}

func TestFormatOptionalInt64(t *testing.T) {
	if got := FormatOptionalInt64(nil); got != "∞" {
		t.Errorf("FormatOptionalInt64(nil) = %q, want ∞", got)
	}
	v := int64(42)
	if got := FormatOptionalInt64(&v); got != "42" {
		t.Errorf("FormatOptionalInt64(&42) = %q, want 42", got)
	}
}
