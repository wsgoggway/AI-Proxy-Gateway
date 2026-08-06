package internal

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// SetProxyEnv sets all proxy-related environment variables on the current process.
func SetProxyEnv() {
	if Cfg.LoginUser != "" && Cfg.LoginPass != "" {
		os.Setenv("HTTPS_PROXY", fmt.Sprintf("http://%s:%s@%s:%s", Cfg.LoginUser, Cfg.LoginPass, Cfg.ProxyHost, Cfg.ProxyPort))
	} else {
		os.Setenv("HTTPS_PROXY", fmt.Sprintf("http://%s:%s", Cfg.ProxyHost, Cfg.ProxyPort))
	}
	if Cfg.AuthToken != "" {
		os.Setenv("PROXY_AUTH_BEARER", Cfg.AuthToken)
	}
	os.Setenv("HTTP_PROXY", os.Getenv("HTTPS_PROXY"))
	os.Setenv("https_proxy", os.Getenv("HTTPS_PROXY"))
	os.Setenv("http_proxy", os.Getenv("HTTPS_PROXY"))
	os.Setenv("NO_PROXY", "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
	os.Setenv("no_proxy", "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
	os.Setenv("SSL_CERT_FILE", Cfg.BundleFile)
	os.Setenv("REQUESTS_CA_BUNDLE", Cfg.BundleFile)
	os.Setenv("CURL_CA_BUNDLE", Cfg.BundleFile)
	os.Setenv("GIT_SSL_CAINFO", Cfg.BundleFile)
	os.Setenv("NODE_EXTRA_CA_CERTS", Cfg.BundleFile)
	if !strings.Contains(os.Getenv("NODE_OPTIONS"), "use-openssl-ca") {
		nopt := strings.TrimSpace(os.Getenv("NODE_OPTIONS") + " --use-openssl-ca")
		os.Setenv("NODE_OPTIONS", nopt)
	}
	Vprintf("env: HTTPS_PROXY=%s", os.Getenv("HTTPS_PROXY"))
}

func FindSystemBundle() string {
	for _, p := range SystemBundlePaths {
		if FileExists(p) {
			return p
		}
	}
	return ""
}

func DownloadCA() error {
	u := fmt.Sprintf("http://%s:%s/ca.pem", Cfg.ProxyHost, Cfg.ProxyPort)
	resp, err := http.Get(u)
	if err != nil {
		return fmt.Errorf("GET %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("GET %s returned %d", u, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return os.WriteFile(Cfg.CAFile, data, 0644)
}

// DownloadCAIfChanged fetches the proxy CA and writes it only when the local
// copy is missing or differs. Returns true when the file was written.
func DownloadCAIfChanged() (bool, error) {
	u := fmt.Sprintf("http://%s:%s/ca.pem", Cfg.ProxyHost, Cfg.ProxyPort)
	resp, err := http.Get(u)
	if err != nil {
		return false, fmt.Errorf("GET %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("GET %s returned %d", u, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	if FileExists(Cfg.CAFile) {
		oldData, err := os.ReadFile(Cfg.CAFile)
		if err == nil {
			oldCert, oldErr := ParseCert(oldData)
			newCert, newErr := ParseCert(data)
			if oldErr == nil && newErr == nil && CertFingerprint(oldCert) == CertFingerprint(newCert) {
				return false, nil
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(Cfg.CAFile), 0755); err != nil {
		return false, err
	}
	if err := os.WriteFile(Cfg.CAFile, data, 0644); err != nil {
		return false, err
	}
	return true, nil
}

func BuildBundle() error {
	sysCA := FindSystemBundle()
	var combo []byte
	if sysCA != "" {
		data, err := os.ReadFile(sysCA)
		if err != nil {
			return fmt.Errorf("read system bundle %s: %w", sysCA, err)
		}
		combo = data
	}
	caData, err := os.ReadFile(Cfg.CAFile)
	if err != nil {
		return fmt.Errorf("read CA: %w", err)
	}
	combo = append(combo, caData...)
	return os.WriteFile(Cfg.BundleFile, combo, 0644)
}

func DownloadApx(dst string) error {
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}
	osName := runtime.GOOS
	if osName != "linux" && osName != "darwin" {
		return fmt.Errorf("unsupported OS: %s", osName)
	}
	u := fmt.Sprintf("http://%s:%s/cli/apx-%s-%s", Cfg.ProxyHost, Cfg.ProxyPort, osName, arch)
	resp, err := http.Get(u)
	if err != nil {
		return fmt.Errorf("GET %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("GET %s returned %d", u, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0755)
}

// CleanupSystemProxy removes all system-wide proxy env injection.
func CleanupSystemProxy() {
	sysEnv := filepath.Join(Home(), ".config", "environment.d", "ai-proxy.conf")
	if FileExists(sysEnv) {
		os.Remove(sysEnv)
		Vprintf("cleanup: removed %s", sysEnv)
	}
	RemoveShellEnv()
	exec.Command("systemctl", "--user", "unset-environment",
		"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
		"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
		"NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO").Run()
}

func RemoveShellEnv() {
	shellEnv := filepath.Join(Cfg.CfgDir, "shell-env.sh")
	os.Remove(shellEnv)
	for _, prof := range []string{
		filepath.Join(Home(), ".zshrc"),
		filepath.Join(Home(), ".bashrc"),
	} {
		if !FileExists(prof) {
			continue
		}
		data, err := os.ReadFile(prof)
		if err != nil {
			continue
		}
		var out []string
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "ai-proxy/shell-env.sh") {
				continue
			}
			out = append(out, line)
		}
		os.WriteFile(prof, []byte(strings.Join(out, "\n")), 0644)
	}
}

// ── Cert helpers ──

func ParseCert(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("not a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func ParseCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func CertFingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	parts := make([]string, sha256.Size)
	for i, b := range h {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// ── Filesystem helpers ──

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func DirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func CopyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, mode)
}
