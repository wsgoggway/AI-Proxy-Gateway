package internal

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// QuickCheck verifies CA and bundle exist.
func QuickCheck() error {
	if _, err := os.Stat(Cfg.CAFile); err != nil {
		return fmt.Errorf("CA not found at %s", Cfg.CAFile)
	}
	if _, err := os.Stat(Cfg.BundleFile); err != nil {
		return fmt.Errorf("bundle not found at %s", Cfg.BundleFile)
	}
	return nil
}

// ExecCmd runs a command inheriting stdio + env, exiting with its code.
func ExecCmd(cmdArgs []string) {
	exe, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "apx: command not found: %s\n", cmdArgs[0])
		os.Exit(127)
	}
	cmd := exec.Command(exe, cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "apx: %v\n", err)
		os.Exit(1)
	}
}

// RunEnv sets proxy env then execs the command (no sandbox).
func RunEnv(cmdArgs []string) {
	SetProxyEnv()
	ExecCmd(cmdArgs)
}

// RunShell starts an interactive shell with proxy env.
func RunShell() {
	if err := QuickCheck(); err != nil {
		fmt.Fprintf(os.Stderr, "apx: %v\nRun 'apx install' first.\n", err)
		os.Exit(1)
	}
	SetProxyEnv()
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}
	fmt.Fprintf(os.Stderr, "Starting shell with proxy env (exit to leave)...\n")
	cmd := exec.Command(shell)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "apx: shell exited: %v\n", err)
		os.Exit(1)
	}
}

// ── bwrap sandbox ──

func CheckBwrap() error {
	_, err := exec.LookPath("bwrap")
	return err
}

func CheckKeychainTrust() error {
	kc := filepath.Join(Home(), "Library", "Keychains", "login.keychain-db")
	if !FileExists(kc) {
		return fmt.Errorf("login keychain not found: %s", kc)
	}
	cmd := exec.Command("security", "find-certificate", "-c", "AI Proxy CA", kc)
	return cmd.Run()
}

// BuildBwrapArgs assembles bwrap(1) arguments.
func BuildBwrapArgs(cmdArgs []string, certTmp string) []string {
	host, port, user, pass := Cfg.ProxyHost, Cfg.ProxyPort, Cfg.LoginUser, Cfg.LoginPass
	args := []string{"--clearenv"}
	for _, kv := range []struct{ k, v string }{
		{"PATH", os.Getenv("PATH")},
		{"HOME", os.Getenv("HOME")},
		{"TERM", os.Getenv("TERM")},
		{"USER", os.Getenv("USER")},
		{"SHELL", os.Getenv("SHELL")},
		{"LOGNAME", os.Getenv("LOGNAME")},
		{"LANG", os.Getenv("LANG")},
		{"COLORTERM", os.Getenv("COLORTERM")},
	} {
		if kv.v != "" {
			args = append(args, "--setenv", kv.k, kv.v)
		}
	}
	for _, kv := range []struct{ k, v string }{
		{"XDG_RUNTIME_DIR", os.Getenv("XDG_RUNTIME_DIR")},
		{"DISPLAY", os.Getenv("DISPLAY")},
		{"WAYLAND_DISPLAY", os.Getenv("WAYLAND_DISPLAY")},
		{"XAUTHORITY", os.Getenv("XAUTHORITY")},
		{"DBUS_SESSION_BUS_ADDRESS", os.Getenv("DBUS_SESSION_BUS_ADDRESS")},
		{"SSH_AUTH_SOCK", os.Getenv("SSH_AUTH_SOCK")},
	} {
		if kv.v != "" {
			args = append(args, "--setenv", kv.k, kv.v)
		}
	}
	proxyURL := fmt.Sprintf("http://%s:%s", host, port)
	if user != "" && pass != "" {
		proxyURL = fmt.Sprintf("http://%s:%s@%s:%s", user, pass, host, port)
	}
	args = append(args,
		"--setenv", "HTTPS_PROXY", proxyURL,
		"--setenv", "HTTP_PROXY", proxyURL,
		"--setenv", "https_proxy", proxyURL,
		"--setenv", "http_proxy", proxyURL,
		"--setenv", "NO_PROXY", "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
		"--setenv", "no_proxy", "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
		"--setenv", "SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt",
		"--setenv", "REQUESTS_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt",
		"--setenv", "CURL_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt",
		"--setenv", "GIT_SSL_CAINFO", "/etc/ssl/certs/ca-certificates.crt",
		"--setenv", "NODE_EXTRA_CA_CERTS", "/etc/ssl/certs/ca-certificates.crt",
		"--setenv", "NODE_OPTIONS", "--use-openssl-ca",
		"--setenv", "npm_config_cafile", "/etc/ssl/certs/ca-certificates.crt",
	)
	if Cfg.AuthToken != "" {
		args = append(args, "--setenv", "PROXY_AUTH_BEARER", Cfg.AuthToken)
	}
	args = append(args,
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		"--bind", Home(), Home(),
		"--ro-bind", certTmp, "/etc/ssl/certs",
		"--die-with-parent", "--new-session",
	)
	if DirExists("/etc/pki/tls/certs") {
		rhelCert := filepath.Join(certTmp, "pki", "tls", "certs")
		os.MkdirAll(rhelCert, 0755)
		CopyFile(Cfg.BundleFile, filepath.Join(rhelCert, "ca-bundle.crt"), 0644)
		args = append(args,
			"--ro-bind", filepath.Join(rhelCert, "ca-bundle.crt"),
			"/etc/pki/tls/certs/ca-bundle.crt")
	}
	args = append(args, "--")
	args = append(args, cmdArgs...)
	return args
}

// RunSandbox launches a command inside bwrap sandbox (Linux) or with
// keychain trust + env (macOS).
func RunSandbox(cmdArgs []string) {
	if runtime.GOOS == "darwin" {
		if err := CheckKeychainTrust(); err != nil {
			fmt.Fprintf(os.Stderr, "apx: %v\n", err)
			fmt.Fprintf(os.Stderr, "Run 'apx install' to add the CA to your login keychain.\n")
			os.Exit(1)
		}
		SetProxyEnv()
		Vprintf("sandbox: macOS keychain trust + env")
		ExecCmd(cmdArgs)
		return
	}

	if err := CheckBwrap(); err != nil {
		fmt.Fprintf(os.Stderr, "apx: bwrap (bubblewrap) not found. Install:\n")
		fmt.Fprintf(os.Stderr, "  Arch: sudo pacman -S bubblewrap\n")
		fmt.Fprintf(os.Stderr, "  Debian/Ubuntu: sudo apt-get install -y bubblewrap\n")
		fmt.Fprintf(os.Stderr, "  Fedora: sudo dnf install -y bubblewrap\n")
		fmt.Fprintf(os.Stderr, "Without bwrap, use: apx run --no-sandbox %s\n", strings.Join(cmdArgs, " "))
		os.Exit(127)
	}

	certTmp, err := os.MkdirTemp("", "apx-certs-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "apx: create cert temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(certTmp)

	bundleTarget := filepath.Join(certTmp, "ca-certificates.crt")
	if err := CopyFile(Cfg.BundleFile, bundleTarget, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "apx: write bundle to sandbox: %v\n", err)
		os.Exit(1)
	}

	bwrapArgs := BuildBwrapArgs(cmdArgs, certTmp)
	Vprintf("bwrap: entering sandbox with %s", Cfg.BundleFile)
	cmd := exec.Command("bwrap", bwrapArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "apx: bwrap: %v\n", err)
		os.Exit(1)
	}
}
