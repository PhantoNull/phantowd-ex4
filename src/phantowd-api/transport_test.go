// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func transportEnvironment(values map[string]string) environmentLookup {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func writeTestTLSFiles(t *testing.T, host string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func tlsEnvironment(address, origin, certPath, keyPath string) map[string]string {
	return map[string]string{
		listenAddressEnv: address,
		publicOriginEnv:  origin,
		tlsCertFileEnv:   certPath,
		tlsKeyFileEnv:    keyPath,
	}
}

func TestAPITransportDefaultsToDevelopmentLoopback(t *testing.T) {
	config, err := loadAPITransportConfigFrom(transportEnvironment(nil))
	if err != nil {
		t.Fatal(err)
	}
	if config.Address != defaultListenAddress || config.AllowedOrigin != defaultPublicOrigin || config.TLSConfig != nil {
		t.Fatalf("unexpected development defaults: %+v", config)
	}
}

func TestAPITransportRejectsPlaintextExternalListenerWithLoopbackOrigin(t *testing.T) {
	config, err := loadAPITransportConfigFrom(transportEnvironment(map[string]string{
		listenAddressEnv: "192.0.2.10:8080",
		publicOriginEnv:  "http://127.0.0.1:8080",
	}))
	if err == nil || config.Address != "" || config.AllowedOrigin != "" || config.TLSConfig != nil {
		t.Fatalf("loopback origin admitted a plaintext external listener: config=%+v err=%v", config, err)
	}
}

func TestAPITransportPlaintextRequiresBothLoopbackHosts(t *testing.T) {
	for _, test := range []struct {
		name, address, origin string
		allowed               bool
	}{
		{"IPv4", "127.0.0.1:8080", "http://127.0.0.1:8080", true},
		{"IPv4 alternate", "127.0.0.2:8080", "http://127.0.0.2:8080", true},
		{"IPv6", "[::1]:8080", "http://[::1]:8080", true},
		{"IPv4-mapped loopback", "[::ffff:127.0.0.1]:8080", "http://[::ffff:127.0.0.1]:8080", true},
		{"localhost", "localhost:8080", "http://localhost:8080", true},
		{"case-insensitive localhost", "LOCALHOST:8080", "http://localhost:8080", true},
		{"external IPv4", "192.0.2.10:8080", "http://127.0.0.1:8080", false},
		{"external IPv6", "[2001:db8::10]:8080", "http://[::1]:8080", false},
		{"mapped external IPv4", "[::ffff:192.0.2.10]:8080", "http://127.0.0.1:8080", false},
		{"IPv4 wildcard", "0.0.0.0:8080", "http://127.0.0.1:8080", false},
		{"IPv6 wildcard", "[::]:8080", "http://[::1]:8080", false},
		{"empty-host wildcard", ":8080", "http://localhost:8080", false},
		{"unresolved listener name", "unresolved.example:8080", "http://localhost:8080", false},
		{"external origin", "127.0.0.1:8080", "http://unresolved.example:8080", false},
		{"different loopback hosts", "127.0.0.1:8080", "http://127.0.0.2:8080", false},
		{"different ports", "127.0.0.1:8080", "http://127.0.0.1:8081", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := loadAPITransportConfigFrom(transportEnvironment(map[string]string{
				listenAddressEnv: test.address,
				publicOriginEnv:  test.origin,
			}))
			if test.allowed {
				if err != nil || config.Address != test.address || config.AllowedOrigin == "" || config.TLSConfig != nil {
					t.Fatalf("valid loopback development transport refused: %+v %v", config, err)
				}
			} else if err == nil || config.Address != "" || config.AllowedOrigin != "" || config.TLSConfig != nil {
				t.Fatalf("unsafe plaintext transport returned usable configuration: %+v %v", config, err)
			}
		})
	}
}

func TestAPITransportRejectsUnsafeOrIncompleteConfiguration(t *testing.T) {
	for _, test := range []struct {
		name   string
		values map[string]string
	}{
		{
			name: "remote HTTP",
			values: map[string]string{
				listenAddressEnv: "0.0.0.0:8080",
				publicOriginEnv:  "http://nas.home.arpa:8080",
			},
		},
		{
			name: "remote without explicit origin",
			values: map[string]string{
				listenAddressEnv: "192.168.1.16:8443",
				tlsCertFileEnv:   "unused.crt",
				tlsKeyFileEnv:    "unused.key",
			},
		},
		{
			name: "partial certificate pair",
			values: map[string]string{
				tlsCertFileEnv: "unused.crt",
			},
		},
		{
			name: "invalid listen port",
			values: map[string]string{
				listenAddressEnv: "127.0.0.1:70000",
			},
		},
		{
			name: "origin with path",
			values: map[string]string{
				publicOriginEnv: "http://127.0.0.1:8080/",
			},
		},
		{
			name: "wildcard listener without explicit origin",
			values: map[string]string{
				listenAddressEnv: "0.0.0.0:8080",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := loadAPITransportConfigFrom(transportEnvironment(test.values)); err == nil {
				t.Fatal("unsafe or incomplete transport configuration was accepted")
			}
		})
	}
}

func TestAPITransportLoadsTLSOnlyForMatchingOrigin(t *testing.T) {
	certPath, keyPath := writeTestTLSFiles(t, "nas.home.arpa")
	values := tlsEnvironment("0.0.0.0:8443", "https://nas.home.arpa:8443", certPath, keyPath)
	config, err := loadAPITransportConfigFrom(transportEnvironment(values))
	if err != nil {
		t.Fatal(err)
	}
	if config.TLSConfig == nil || config.TLSConfig.MinVersion != tls.VersionTLS12 || config.AllowedOrigin != "https://nas.home.arpa:8443" {
		t.Fatalf("TLS transport not configured safely: %+v", config)
	}

	request := httptest.NewRequest("POST", "https://nas.home.arpa:8443/api/v1/auth/login", nil)
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Origin", "https://nas.home.arpa:8443")
	if !validOrigin(request, config.AllowedOrigin) {
		t.Fatal("configured HTTPS origin was rejected")
	}
	request.Host = "attacker.home.arpa:8443"
	if validOrigin(request, config.AllowedOrigin) {
		t.Fatal("request with a mismatched Host header was accepted")
	}
}

func TestAPITransportRefusesOversizedCertificateMaterial(t *testing.T) {
	certPath, keyPath := writeTestTLSFiles(t, "nas.home.arpa")
	certificate, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	// A valid PEM prefix plus whitespace still parses. Refuse the complete
	// oversized input rather than silently accepting its valid prefix.
	certificate = append(certificate, bytes.Repeat([]byte{'\n'}, (256<<10)+1-len(certificate))...)
	if err := os.WriteFile(certPath, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	values := tlsEnvironment("0.0.0.0:8443", "https://nas.home.arpa:8443", certPath, keyPath)
	config, err := loadAPITransportConfigFrom(transportEnvironment(values))
	if err == nil || config.Address != "" || config.AllowedOrigin != "" || config.TLSConfig != nil {
		t.Fatal("oversized TLS input accepted or partial transport returned")
	}
}

func TestAPITransportTLSMaterialBoundsAndRedactedRefusals(t *testing.T) {
	for _, test := range []struct {
		name, target string
		size         int
		valid        bool
	}{
		{"certificate-at-limit", "certificate", 256 << 10, true},
		{"key-at-limit", "key", 64 << 10, true},
		{"key-over-limit", "key", (64 << 10) + 1, false},
		{"empty-certificate", "certificate", 0, false},
		{"empty-key", "key", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			certPath, keyPath := writeTestTLSFiles(t, "nas.home.arpa")
			path := certPath
			if test.target == "key" {
				path = keyPath
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(contents)
			if test.size == 0 {
				contents = nil
			} else {
				contents = append(contents, bytes.Repeat([]byte{'\n'}, test.size-len(contents))...)
			}
			defer func() { clear(contents) }()
			if err := os.WriteFile(path, contents, 0600); err != nil {
				t.Fatal(err)
			}
			values := tlsEnvironment("0.0.0.0:8443", "https://nas.home.arpa:8443", certPath, keyPath)
			config, err := loadAPITransportConfigFrom(transportEnvironment(values))
			if test.valid {
				if err != nil || config.TLSConfig == nil {
					t.Fatal("inclusive TLS material bound refused", err)
				}
			} else if err == nil || config.Address != "" || config.AllowedOrigin != "" || config.TLSConfig != nil || strings.Contains(err.Error(), path) {
				t.Fatal("unsafe TLS material accepted, leaked a path or returned partial config")
			}
		})
	}
	for _, target := range []string{"certificate", "key"} {
		for _, kind := range []string{"missing", "directory", "malformed"} {
			t.Run(target+"-"+kind, func(t *testing.T) {
				certPath, keyPath := writeTestTLSFiles(t, "nas.home.arpa")
				path := filepath.Join(t.TempDir(), "PRIVATE-TLS-PATH")
				switch kind {
				case "directory":
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				case "malformed":
					if err := os.WriteFile(path, []byte("PRIVATE-TLS-CONTENT"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if target == "certificate" {
					certPath = path
				} else {
					keyPath = path
				}
				config, err := loadAPITransportConfigFrom(transportEnvironment(tlsEnvironment("0.0.0.0:8443", "https://nas.home.arpa:8443", certPath, keyPath)))
				if err == nil || config.Address != "" || config.AllowedOrigin != "" || config.TLSConfig != nil || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatal("invalid TLS material accepted or private details returned")
				}
			})
		}
	}
}

func TestConfiguredTLSServerCompletesHTTPSRequest(t *testing.T) {
	certPath, keyPath := writeTestTLSFiles(t, "127.0.0.1")
	values := tlsEnvironment("127.0.0.1:8443", "https://127.0.0.1:8443", certPath, keyPath)
	transport, err := loadAPITransportConfigFrom(transportEnvironment(values))
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := newConfiguredServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), transport)
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.ServeTLS(listener, "", "") }()

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("could not trust the generated test certificate")
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: roots, MinVersion: tls.VersionTLS12,
		}},
	}
	response, err := client.Get("https://" + listener.Addr().String() + "/healthz")
	if err != nil {
		_ = server.Close()
		t.Fatalf("HTTPS request failed: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.TLS == nil || response.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("unexpected HTTPS response: status=%d tls=%v", response.StatusCode, response.TLS)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveResult; err != http.ErrServerClosed {
		t.Fatalf("TLS server exit = %v, want ErrServerClosed", err)
	}
}

func TestAPITransportRejectsCertificateHostMismatchAndLooseKeyPermissions(t *testing.T) {
	certPath, keyPath := writeTestTLSFiles(t, "other.home.arpa")
	values := tlsEnvironment("0.0.0.0:8443", "https://nas.home.arpa:8443", certPath, keyPath)
	if _, err := loadAPITransportConfigFrom(transportEnvironment(values)); err == nil {
		t.Fatal("certificate for a different host was accepted")
	}

	if runtime.GOOS != "windows" {
		certPath, keyPath = writeTestTLSFiles(t, "nas.home.arpa")
		if err := os.Chmod(keyPath, 0o644); err != nil {
			t.Fatal(err)
		}
		values = tlsEnvironment("0.0.0.0:8443", "https://nas.home.arpa:8443", certPath, keyPath)
		if _, err := loadAPITransportConfigFrom(transportEnvironment(values)); err == nil {
			t.Fatal("group/world-readable TLS private key was accepted")
		}
	}
}
