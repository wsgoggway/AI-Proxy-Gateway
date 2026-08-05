package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const Version = "1.2.0"

// Config holds all CLI state — set once in PersistentPreRun, read everywhere.
var Cfg = Config{
	ProxyHost: "localhost",
	ProxyPort: "8443",
	AdminHost: "127.0.0.1",
	AdminPort: "8444",
}

type Config struct {
	ProxyHost   string
	ProxyPort   string
	CAFile      string
	BundleFile  string
	EnvConfig   string
	CfgDir      string
	CacheDir    string
	BinDir      string
	AuthToken   string
	LoginUser   string
	LoginPass   string
	AdminHost   string
	AdminPort   string
	AdminToken  string
	Verbose     bool
	FlagHostSet bool
	FlagPortSet bool
}

func Home() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	if runtime.GOOS == "windows" {
		return os.Getenv("USERPROFILE")
	}
	return ""
}

func Init() {
	cfgDir := filepath.Join(Home(), ".config", "ai-proxy")
	Cfg.CfgDir = cfgDir
	Cfg.CacheDir = filepath.Join(Home(), ".cache", "ai-proxy")
	Cfg.BinDir = filepath.Join(Home(), ".local", "bin")
	Cfg.CAFile = filepath.Join(Home(), "ai-proxy-ca.pem")
	Cfg.BundleFile = filepath.Join(Cfg.CacheDir, "ca-bundle.crt")
	Cfg.EnvConfig = filepath.Join(cfgDir, "env.conf")
}

// SystemBundlePaths lists well-known system CA bundle locations.
var SystemBundlePaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/cert.pem",
	"/opt/homebrew/etc/openssl@3/cert.pem",
	"/usr/local/etc/openssl@3/cert.pem",
	"/etc/ssl/certs/ca-bundle.crt",
	"/etc/static/ssl/certs/ca-bundle.crt",
}

func LoadEnvConfig() {
	data, err := os.ReadFile(Cfg.EnvConfig)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch k {
		case "AI_PROXY_HOST":
			if !Cfg.FlagHostSet && os.Getenv("AI_PROXY_HOST") == "" {
				Cfg.ProxyHost = v
			}
		case "AI_PROXY_PORT":
			if !Cfg.FlagPortSet && os.Getenv("AI_PROXY_PORT") == "" {
				Cfg.ProxyPort = v
			}
		case "AI_PROXY_CA_FILE":
			if os.Getenv("AI_PROXY_CA_FILE") == "" {
				Cfg.CAFile = v
			}
		case "AI_PROXY_TOKEN":
			if os.Getenv("AI_PROXY_TOKEN") == "" {
				Cfg.AuthToken = v
			}
		case "AI_PROXY_USER":
			if os.Getenv("AI_PROXY_USER") == "" {
				Cfg.LoginUser = v
			}
		case "AI_PROXY_PASS":
			if os.Getenv("AI_PROXY_PASS") == "" {
				Cfg.LoginPass = v
			}
		case "AI_PROXY_ADMIN_HOST":
			if os.Getenv("AI_PROXY_ADMIN_HOST") == "" {
				Cfg.AdminHost = v
			}
		case "AI_PROXY_ADMIN_PORT":
			if os.Getenv("AI_PROXY_ADMIN_PORT") == "" {
				Cfg.AdminPort = v
			}
		case "AI_PROXY_ADMIN_TOKEN":
			if os.Getenv("AI_PROXY_ADMIN_TOKEN") == "" {
				Cfg.AdminToken = v
			}
		}
	}
	// Env vars override config.
	if h := os.Getenv("AI_PROXY_HOST"); h != "" {
		Cfg.ProxyHost = h
	}
	if p := os.Getenv("AI_PROXY_PORT"); p != "" {
		Cfg.ProxyPort = p
	}
	if c := os.Getenv("AI_PROXY_CA_FILE"); c != "" {
		Cfg.CAFile = c
	}
	if t := os.Getenv("AI_PROXY_TOKEN"); t != "" {
		Cfg.AuthToken = t
	}
	if u := os.Getenv("AI_PROXY_USER"); u != "" {
		Cfg.LoginUser = u
	}
	if p := os.Getenv("AI_PROXY_PASS"); p != "" {
		Cfg.LoginPass = p
	}
	if h := os.Getenv("AI_PROXY_ADMIN_HOST"); h != "" {
		Cfg.AdminHost = h
	}
	if p := os.Getenv("AI_PROXY_ADMIN_PORT"); p != "" {
		Cfg.AdminPort = p
	}
	// If proxy is remote and admin host is still localhost, point admin at the proxy.
	if Cfg.ProxyHost != "127.0.0.1" && Cfg.ProxyHost != "localhost" && Cfg.AdminHost == "127.0.0.1" {
		Cfg.AdminHost = Cfg.ProxyHost
	}
}

func SaveEnvConfig(lines []string) error {
	if err := os.MkdirAll(Cfg.CfgDir, 0755); err != nil {
		return err
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(Cfg.EnvConfig, []byte(content), 0600); err != nil {
		return err
	}
	return os.Chmod(Cfg.EnvConfig, 0600)
}

// ReadEnvConfigLines reads the current env.conf as key→line pairs, preserving
// order. Returns nil if the file doesn't exist.
func ReadEnvConfigLines() []string {
	data, err := os.ReadFile(Cfg.EnvConfig)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// UpdateEnvConfig rewrites env.conf, replacing entries by key and appending new ones.
func UpdateEnvConfig(updates map[string]string) error {
	existing := ReadEnvConfigLines()
	seen := map[string]bool{}
	var out []string
	for _, line := range existing {
		kv := strings.SplitN(line, "=", 2)
		if len(kv) == 2 {
			k := strings.TrimSpace(kv[0])
			if newVal, ok := updates[k]; ok {
				if newVal != "" {
					out = append(out, k+"="+newVal)
				}
				seen[k] = true
				continue
			}
		}
		out = append(out, line)
	}
	for k, v := range updates {
		if !seen[k] && v != "" {
			out = append(out, k+"="+v)
		}
	}
	return SaveEnvConfig(out)
}

func Vprintf(format string, a ...interface{}) {
	if Cfg.Verbose {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
	}
}
