//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestQEMUFileServicePreviewHTTP(t *testing.T) {
	auth, cookie := newTestAuth(t)
	server := httptest.NewServer(newHandler(nil, nil, auth))
	defer server.Close()
	auth.allowedOrigin = server.URL
	client := server.Client()
	client.Jar = newQEMUCookieJar()
	address, _ := url.Parse(server.URL)
	client.Jar.SetCookies(address, []*http.Cookie{cookie})
	if err := exerciseQEMUFileServicePreview(client, server.URL); err != nil {
		t.Fatal(err)
	}
}
