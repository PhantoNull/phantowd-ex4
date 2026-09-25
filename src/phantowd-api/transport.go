// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	listenAddressEnv = "PHANTOWD_LISTEN_ADDR"
	tlsCertFileEnv   = "PHANTOWD_TLS_CERT_FILE"
	tlsKeyFileEnv    = "PHANTOWD_TLS_KEY_FILE"
	publicOriginEnv  = "PHANTOWD_PUBLIC_ORIGIN"

	defaultListenAddress = "127.0.0.1:8080"
	defaultPublicOrigin  = "http://127.0.0.1:8080"
)

type apiTransportConfig struct {
	Address       string
	AllowedOrigin string
	TLSConfig     *tls.Config
}

type environmentLookup func(string) (string, bool)

func loadAPITransportConfig() (apiTransportConfig, error) {
	return loadAPITransportConfigFrom(os.LookupEnv)
}

func loadAPITransportConfigFrom(lookup environmentLookup) (apiTransportConfig, error) {
	address := defaultListenAddress
	if value, ok := lookup(listenAddressEnv); ok {
		address = value
	}
	host, port, wildcard, err := parseListenAddress(address)
	if err != nil {
		return apiTransportConfig{}, err
	}

	certFile, certSet := lookup(tlsCertFileEnv)
	keyFile, keySet := lookup(tlsKeyFileEnv)
	if certSet != keySet || certSet && (strings.TrimSpace(certFile) == "" || strings.TrimSpace(keyFile) == "") {
		return apiTransportConfig{}, errors.New("TLS certificate and key must be configured together")
	}
	tlsEnabled := certSet

	origin, originSet := lookup(publicOriginEnv)
	if originSet && strings.TrimSpace(origin) == "" {
		return apiTransportConfig{}, errors.New("public origin must not be empty")
	}
	if !originSet {
		if wildcard || !isLoopbackHost(host) {
			return apiTransportConfig{}, errors.New("non-loopback listeners require an explicit public origin")
		}
		origin = makeOrigin(host, port, tlsEnabled)
	}
	parsedOrigin, err := parseOrigin(origin)
	if err != nil {
		return apiTransportConfig{}, err
	}
	if tlsEnabled && parsedOrigin.Scheme != "https" {
		return apiTransportConfig{}, errors.New("TLS listeners require an HTTPS public origin")
	}
	if !tlsEnabled && parsedOrigin.Scheme != "http" {
		return apiTransportConfig{}, errors.New("HTTPS public origin requires a TLS certificate and key")
	}
	if !tlsEnabled && !isLoopbackHost(parsedOrigin.Hostname()) {
		return apiTransportConfig{}, errors.New("non-loopback listeners require TLS")
	}
	if !tlsEnabled && wildcard {
		return apiTransportConfig{}, errors.New("non-loopback listeners require TLS")
	}
	if !wildcard && isLoopbackHost(host) && !sameHost(host, parsedOrigin.Hostname()) {
		return apiTransportConfig{}, errors.New("public origin host must match the listener host")
	}
	if parsedOrigin.Port() != strconv.Itoa(port) && !(parsedOrigin.Port() == "" && defaultPort(parsedOrigin.Scheme) == port) {
		return apiTransportConfig{}, errors.New("public origin port must match the listener port")
	}

	config := apiTransportConfig{Address: address, AllowedOrigin: canonicalOrigin(parsedOrigin)}
	if tlsEnabled {
		if err := validatePrivateKeyFile(keyFile); err != nil {
			return apiTransportConfig{}, err
		}
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return apiTransportConfig{}, errors.New("TLS certificate/key pair could not be loaded")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return apiTransportConfig{}, errors.New("TLS leaf certificate could not be parsed")
		}
		now := time.Now()
		if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return apiTransportConfig{}, errors.New("TLS leaf certificate is outside its validity period")
		}
		if err := leaf.VerifyHostname(parsedOrigin.Hostname()); err != nil {
			return apiTransportConfig{}, errors.New("TLS certificate does not match the public origin host")
		}
		pair.Leaf = leaf
		config.TLSConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{pair},
		}
	}
	return config, nil
}

func parseListenAddress(address string) (host string, port int, wildcard bool, err error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, false, errors.New("listen address must be host:port")
	}
	port, err = strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false, errors.New("listen port must be between 1 and 65535")
	}
	host = strings.TrimSpace(host)
	wildcard = host == "" || host == "0.0.0.0" || host == "::"
	if !wildcard && strings.ContainsAny(host, " \t\r\n/\\") {
		return "", 0, false, errors.New("invalid listen host")
	}
	return host, port, wildcard, nil
}

func parseOrigin(raw string) (*url.URL, error) {
	origin, err := url.Parse(raw)
	if err != nil || origin == nil || origin.Opaque != "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" {
		return nil, errors.New("public origin must be a bare HTTP(S) origin")
	}
	origin.Scheme = strings.ToLower(origin.Scheme)
	if origin.Scheme != "http" && origin.Scheme != "https" || origin.Host == "" || origin.Hostname() == "" {
		return nil, errors.New("public origin must use HTTP or HTTPS and include a host")
	}
	if strings.ContainsAny(origin.Hostname(), "*%") {
		return nil, errors.New("public origin cannot use a wildcard or escaped hostname")
	}
	if portText := origin.Port(); portText != "" {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("public origin has an invalid port")
		}
	}
	return origin, nil
}

func makeOrigin(host string, port int, tlsEnabled bool) string {
	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	authority := net.JoinHostPort(host, strconv.Itoa(port))
	if host == "" {
		return ""
	}
	if port == defaultPort(scheme) {
		authority = host
		if strings.Contains(host, ":") {
			authority = "[" + host + "]"
		}
	}
	return scheme + "://" + authority
}

func defaultPort(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

func canonicalOrigin(origin *url.URL) string {
	port := origin.Port()
	authority := origin.Hostname()
	if strings.Contains(authority, ":") {
		authority = "[" + authority + "]"
	}
	if port != "" && port != strconv.Itoa(defaultPort(origin.Scheme)) {
		authority = net.JoinHostPort(origin.Hostname(), port)
	}
	return origin.Scheme + "://" + strings.ToLower(authority)
}

func canonicalAuthority(host, scheme string) (string, error) {
	parsed, err := url.Parse("//" + host)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Hostname() == "" {
		return "", fmt.Errorf("invalid authority")
	}
	port := parsed.Port()
	if port != "" {
		if _, err := strconv.Atoi(port); err != nil {
			return "", errors.New("invalid authority port")
		}
	}
	name := strings.ToLower(parsed.Hostname())
	if strings.Contains(name, ":") {
		name = "[" + name + "]"
	}
	if port != "" && port != strconv.Itoa(defaultPort(scheme)) {
		name = net.JoinHostPort(parsed.Hostname(), port)
	}
	return name, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func sameHost(left, right string) bool {
	return strings.EqualFold(strings.TrimSuffix(left, "."), strings.TrimSuffix(right, "."))
}

func validatePrivateKeyFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("TLS private key must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("TLS private key must not be accessible to group or other users")
	}
	return nil
}

func validOrigin(r *http.Request, allowedOrigin string) bool {
	expected, err := parseOrigin(allowedOrigin)
	if err != nil {
		return false
	}
	origins := r.Header.Values("Origin")
	if len(origins) != 1 {
		return false
	}
	origin, err := parseOrigin(origins[0])
	if err != nil || origin.Scheme != expected.Scheme {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if scheme != expected.Scheme || canonicalOrigin(origin) != canonicalOrigin(expected) {
		return false
	}
	requestAuthority, err := canonicalAuthority(r.Host, scheme)
	if err != nil {
		return false
	}
	expectedAuthority, err := canonicalAuthority(expected.Host, scheme)
	return err == nil && requestAuthority == expectedAuthority
}
