// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
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
		DNSNames:              []string{host},
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
