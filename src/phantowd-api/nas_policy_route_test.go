// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestNASPolicyRoutePreservesFallback(t *testing.T) {
	nas := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) })
	for _, tc := range []struct {
		path       string
		configured bool
		want       int
	}{
		{"/api/v1/nas-services/configuration", false, 404},
		{"/api/v1/nas-services/configuration", true, 202},
		{"/api/v1/nas-services/configuration/extra", true, 404},
		{"/healthz", true, 200},
	} {
		var configured http.Handler
		if tc.configured {
			configured = nas
		}
		h := newHandlerWithNASPolicy(nil, nil, nil, nil, nil, nil, nil, nil, configured)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", tc.path, nil))
		if w.Code != tc.want {
			t.Fatal(tc.path, w.Code, tc.want)
		}
	}
}

func TestNASPolicyRouteSharesTheGlobalAdmissionBound(t *testing.T) {
	ready, release := make(chan struct{}, 9), make(chan struct{})
	nas := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ready <- struct{}{}; <-release })
	h := newHandlerWithNASPolicy(nil, nil, nil, nil, nil, nil, nil, nil, nas)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/nas-services/configuration", nil))
		}()
	}
	for i := 0; i < 8; i++ {
		<-ready
	}
	ninth, done := httptest.NewRecorder(), make(chan struct{})
	go func() {
		h.ServeHTTP(ninth, httptest.NewRequest("GET", "/api/v1/nas-services/configuration", nil))
		close(done)
	}()
	select {
	case <-ready:
		t.Error("NAS route bypassed global admission")
	case <-done:
		if ninth.Code != 503 {
			t.Error(ninth.Code)
		}
	}
	close(release)
	wg.Wait()
	<-done
}
