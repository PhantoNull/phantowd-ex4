//go:build qemu

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
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// exerciseQEMUTLS uses a disposable certificate and an ephemeral loopback
// listener to exercise the configured HTTPS path on the ARMv5 guest. Its key
// and certificate exist only under the test process's temporary directory.
func exerciseQEMUTLS() error {
	return exerciseQEMUTLSWithAccountFactory(openAccountStore)
}

// The non-Linux host test injects memory-only credentials. Actual ARMv5 runs
// always enter through exerciseQEMUTLS and use the production Linux adapter.
func exerciseQEMUTLSWithAccountFactory(openAccounts func(string) (*accountStore, error)) error {
	directory, err := os.MkdirTemp("", "phantowd-qemu-tls-")
	if err != nil {
		return errors.New("cannot create temporary TLS test state")
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		return errors.New("cannot secure temporary TLS test state")
	}
	certificatePath, keyPath, certificatePEM, err := createQEMUTLSFixture(directory)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.New("cannot create loopback TLS test listener")
	}
	address := listener.Addr().String()
	values := map[string]string{
		listenAddressEnv: address,
		tlsCertFileEnv:   certificatePath,
		tlsKeyFileEnv:    keyPath,
		publicOriginEnv:  "https://" + address,
	}
	transport, err := loadAPITransportConfigFrom(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
	if err != nil {
		listener.Close()
		return errors.New("temporary TLS test configuration was rejected")
	}
	if transport.TLSConfig == nil || transport.TLSConfig.MinVersion != tls.VersionTLS12 {
		listener.Close()
		return errors.New("TLS test configuration did not require TLS 1.2")
	}

	stateDirectory := filepath.Join(directory, "state")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		listener.Close()
		return errors.New("cannot create temporary TLS account state")
	}
	accounts, err := openAccounts(stateDirectory)
	if err != nil {
		listener.Close()
		return errors.New("cannot open temporary TLS account state")
	}
	defer accounts.Close()
	server := newConfiguredServer(newHandler(nil, nil, newAuthController(accounts, transport.AllowedOrigin)), transport)
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.ServeTLS(listener, "", "") }()
	serverStopped := false
	defer func() {
		_ = server.Close()
		if !serverStopped {
			<-serverResult
		}
	}()

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		return errors.New("temporary TLS test certificate could not be trusted")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Jar:     newQEMUCookieJar(),
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				RootCAs: roots, MinVersion: tls.VersionTLS12,
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()

	credentials := setupRequest{Username: "qemu-tls-admin", Password: "qemu-tls-self-test-password"}
	body, err := json.Marshal(credentials)
	if err != nil {
		return errors.New("cannot encode TLS account setup request")
	}
	request, err := http.NewRequest(http.MethodPost, "https://"+address+authSetupPath, bytes.NewReader(body))
	if err != nil {
		return errors.New("cannot create HTTPS account setup request")
	}
	request.Header.Set("Origin", transport.AllowedOrigin)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("ARMv5 HTTPS loopback handshake failed")
	}
	response.Body.Close()
	secureSessionCookie := false
	for _, cookie := range response.Cookies() {
		if strings.HasPrefix(cookie.Name, "__Host-") && cookie.Secure && cookie.HttpOnly {
			secureSessionCookie = true
		}
	}
	if response.StatusCode != http.StatusCreated || response.TLS == nil || response.TLS.Version < tls.VersionTLS12 || !secureSessionCookie {
		return errors.New("HTTPS account setup did not satisfy the TLS and cookie policy")
	}

	if err := exerciseQEMUFileServicePreview(client, transport.AllowedOrigin); err != nil {
		return err
	}
	request, err = http.NewRequest(http.MethodGet, "https://"+address+authSessionPath, nil)
	if err != nil {
		return errors.New("cannot create HTTPS session request")
	}
	response, err = client.Do(request)
	if err != nil {
		return errors.New("HTTPS authenticated session request failed")
	}
	sessionData, readErr := readSelfTestResponse(response, 4096)
	if readErr != nil || response.StatusCode != http.StatusOK {
		return errors.New("HTTPS authenticated session response was invalid")
	}
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	if json.Unmarshal(sessionData, &session) != nil || session.CSRFToken == "" {
		return errors.New("HTTPS session did not return a CSRF token")
	}
	request, err = http.NewRequest(http.MethodPost, "https://"+address+authLogoutPath, nil)
	if err != nil {
		return errors.New("cannot create HTTPS logout request")
	}
	request.Header.Set("Origin", transport.AllowedOrigin)
	request.Header.Set("X-PhantoWD-CSRF", session.CSRFToken)
	response, err = client.Do(request)
	if err != nil {
		return errors.New("HTTPS CSRF-protected logout request failed")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("HTTPS CSRF-protected logout was rejected")
	}
	request, err = http.NewRequest(http.MethodPost, "https://"+address+authLoginPath, bytes.NewReader(body))
	if err != nil {
		return errors.New("cannot create HTTPS origin-rejection request")
	}
	request.Header.Set("Origin", "https://attacker.invalid:"+strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	request.Header.Set("Content-Type", "application/json")
	response, err = client.Do(request)
	if err != nil {
		return errors.New("HTTPS origin-rejection request failed")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		return errors.New("HTTPS listener accepted an unconfigured Origin")
	}

	if err := server.Close(); err != nil {
		return errors.New("TLS test server did not close cleanly")
	}
	if err := <-serverResult; err != http.ErrServerClosed {
		return errors.New("TLS test server returned an unexpected result")
	}
	serverStopped = true
	return nil
}

func createQEMUTLSFixture(directory string) (string, string, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", nil, errors.New("cannot generate temporary TLS test key")
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", nil, errors.New("cannot create temporary TLS test certificate")
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", nil, errors.New("cannot encode temporary TLS test key")
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	certificatePath := filepath.Join(directory, "test.crt")
	keyPath := filepath.Join(directory, "test.key")
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		return "", "", nil, errors.New("cannot write temporary TLS test certificate")
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", nil, errors.New("cannot write temporary TLS test key")
	}
	return certificatePath, keyPath, certificatePEM, nil
}
