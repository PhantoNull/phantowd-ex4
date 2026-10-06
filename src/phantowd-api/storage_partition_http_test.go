// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func validStorageGPTSummaryForTest() storageGPTObservationSummary {
	return storageGPTObservationSummary{
		SchemaVersion: 1, Status: "complete", Scope: "manual-gpt-metadata-read-only",
		EligibleCandidateCount: 0, GPTDiskCount: 0, PartitionCount: 0,
		UnsupportedTableCount: 0, Coverage: gptIdentityCoverageEmpty,
		ContentRead: false, MountPerformed: false, AssemblyPerformed: false,
		ImportPerformed: false, MutationsPerformed: false,
		Limitations: append([]string{}, storageGPTObservationLimitations[:]...),
	}
}

func storageGPTRequest(auth *authController, cookie *http.Cookie) *http.Request {
	request := authRequest(http.MethodPost, storageGPTObservationPath, "")
	request.AddCookie(cookie)
	_, session, ok := auth.sessions.sessionFromRequest(request, time.Now())
	if !ok {
		panic("test session is unavailable")
	}
	request.Header.Set("X-PhantoWD-CSRF", session.csrf)
	return request
}

type storageGPTDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (recorder *storageGPTDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	recorder.deadline = deadline
	return nil
}

func (recorder *storageGPTDeadlineRecorder) Unwrap() http.ResponseWriter {
	return recorder.ResponseRecorder
}

func newStorageGPTDeadlineRecorder() *storageGPTDeadlineRecorder {
	return &storageGPTDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
}

func TestStorageGPTObservationHTTPRequiresExplicitProtectedRequest(t *testing.T) {
	auth, cookie := newTestAuth(t)
	var calls atomic.Int32
	handler := newStorageGPTObservationHandler(auth, func(ctx context.Context) (storageGPTObservationSummary, error) {
		calls.Add(1)
		return validStorageGPTSummaryForTest(), nil
	})
	for _, test := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{"valid", func(*http.Request) {}, http.StatusOK},
		{"get", func(r *http.Request) { r.Method = http.MethodGet }, http.StatusMethodNotAllowed},
		{"unauthenticated", func(r *http.Request) { r.Header.Del("Cookie") }, http.StatusUnauthorized},
		{"origin", func(r *http.Request) { r.Header.Set("Origin", "https://attacker.invalid") }, http.StatusForbidden},
		{"csrf", func(r *http.Request) { r.Header.Del("X-PhantoWD-CSRF") }, http.StatusForbidden},
		{"duplicate csrf", func(r *http.Request) { r.Header.Add("X-PhantoWD-CSRF", r.Header.Get("X-PhantoWD-CSRF")) }, http.StatusForbidden},
		{"query", func(r *http.Request) { r.URL.RawQuery = "device=sda" }, http.StatusBadRequest},
		{"content type", func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }, http.StatusBadRequest},
		{"body", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("{}")); r.ContentLength = 2 }, http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := storageGPTRequest(auth, cookie)
			before := calls.Load()
			test.change(request)
			response := newStorageGPTDeadlineRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if (test.status == http.StatusOK) != (calls.Load() == before+1) {
				t.Fatal("observer ran before every request check passed")
			}
			if test.status == http.StatusOK {
				if time.Until(response.deadline) <= storageGPTObservationTimeout {
					t.Fatal("long-running observation did not extend the server write deadline")
				}
				if !json.Valid(response.Body.Bytes()) || !validStorageGPTObservationSummary(validStorageGPTSummaryForTest()) {
					t.Fatal("invalid summary response")
				}
				for _, forbidden := range []string{`"disk_guid":`, `"partuuid":`, `"partition_number":`, `"start_512b_sectors":`, `"kernel_name":`} {
					if strings.Contains(response.Body.String(), forbidden) {
						t.Fatalf("HTTP response contains private identifier field %q", forbidden)
					}
				}
			}
		})
	}
}

func TestStorageGPTObservationHTTPDoesNotLeakErrorsAndHonorsBusy(t *testing.T) {
	auth, cookie := newTestAuth(t)
	for _, test := range []struct {
		name       string
		collect    storageGPTObservationCollector
		wantStatus int
		wantBody   string
	}{
		{"error", func(context.Context) (storageGPTObservationSummary, error) {
			return storageGPTObservationSummary{}, errors.New("private path and GUID 12345678-1234-4234-8234-123456789abc")
		}, http.StatusServiceUnavailable, "storage_observation_unavailable"},
		{"busy", func(context.Context) (storageGPTObservationSummary, error) {
			return storageGPTObservationSummary{}, errStorageGPTObservationBusy
		}, http.StatusServiceUnavailable, "storage_observation_busy"},
		{"invalid summary", func(context.Context) (storageGPTObservationSummary, error) {
			value := validStorageGPTSummaryForTest()
			value.Limitations[0] = "private path"
			return value, nil
		}, http.StatusServiceUnavailable, "storage_observation_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := newStorageGPTDeadlineRecorder()
			newStorageGPTObservationHandler(auth, test.collect).ServeHTTP(response, storageGPTRequest(auth, cookie))
			if response.Code != test.wantStatus || !strings.Contains(response.Body.String(), test.wantBody) ||
				strings.Contains(response.Body.String(), "private path") || strings.Contains(response.Body.String(), "12345678-1234-4234-8234-123456789abc") {
				t.Fatalf("error response leaked or mismatched: %d %s", response.Code, response.Body.String())
			}
			if test.wantBody == "storage_observation_busy" && response.Header().Get("Retry-After") != "1" {
				t.Fatal("busy response omitted backpressure hint")
			}
		})
	}
}

func TestStorageGPTObservationConcurrencyIsBoundedAndHealthRemainsAvailable(t *testing.T) {
	auth, cookie := newTestAuth(t)
	entered, release := make(chan struct{}), make(chan struct{})
	handler := newHandlerWithStorageGPTObservation(nil, nil, nil, nil, auth, nil, nil,
		func(ctx context.Context) (storageGPTObservationSummary, error) {
			close(entered)
			select {
			case <-release:
				return validStorageGPTSummaryForTest(), nil
			case <-ctx.Done():
				return storageGPTObservationSummary{}, ctx.Err()
			}
		})
	firstDone := make(chan *storageGPTDeadlineRecorder, 1)
	go func() {
		response := newStorageGPTDeadlineRecorder()
		handler.ServeHTTP(response, storageGPTRequest(auth, cookie))
		firstDone <- response
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first observation did not start")
	}
	second := newStorageGPTDeadlineRecorder()
	handler.ServeHTTP(second, storageGPTRequest(auth, cookie))
	if second.Code != http.StatusServiceUnavailable || second.Header().Get("Retry-After") != "1" {
		t.Fatalf("concurrent observation did not fail fast: %d %s", second.Code, second.Body.String())
	}
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, loopbackRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatal("slow GPT request blocked unrelated health")
	}
	close(release)
	select {
	case response := <-firstDone:
		if response.Code != http.StatusOK {
			t.Fatalf("first observation failed: %d %s", response.Code, response.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first observation did not release")
	}
}

func TestStorageGPTObservationExtendsOnlyItsSlowHTTPWriteDeadline(t *testing.T) {
	auth, cookie := newTestAuth(t)
	handler := newStorageGPTObservationHandler(auth, func(ctx context.Context) (storageGPTObservationSummary, error) {
		select {
		case <-time.After(100 * time.Millisecond):
			return validStorageGPTSummaryForTest(), nil
		case <-ctx.Done():
			return storageGPTObservationSummary{}, ctx.Err()
		}
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.WriteTimeout = 20 * time.Millisecond
	server.Start()
	defer server.Close()
	auth.allowedOrigin = server.URL

	request, err := http.NewRequest(http.MethodPost, server.URL+storageGPTObservationPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = server.Listener.Addr().String()
	request.Header.Set("Origin", server.URL)
	request.AddCookie(cookie)
	_, session, ok := auth.sessions.sessionFromRequest(request, time.Now())
	if !ok {
		t.Fatal("test session is unavailable")
	}
	request.Header.Set("X-PhantoWD-CSRF", session.csrf)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("slow observation exceeded the route's extended write deadline: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("slow observation returned %d: %s", response.StatusCode, body)
	}
}
