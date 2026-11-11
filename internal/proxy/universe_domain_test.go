// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn"
	"github.com/GoogleCloudPlatform/cloud-sql-proxy/v2/internal/proxy"
)

// hostRecorder is a fake Google API backend. It records the Host of every
// request it receives and answers IAM Credentials generateAccessToken calls
// with a fake token.
type hostRecorder struct {
	mu    sync.Mutex
	hosts []string
}

func (h *hostRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.hosts = append(h.hosts, r.Host)
	h.mu.Unlock()

	if strings.HasSuffix(r.URL.Path, ":generateAccessToken") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"accessToken": "impersonated-token",
			"expireTime":  time.Now().Add(time.Hour).Format(time.RFC3339),
		})
		return
	}
	http.Error(w, `{"error":{"code":404,"message":"not found"}}`, http.StatusNotFound)
}

func (h *hostRecorder) recorded() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.hosts...)
}

// TestImpersonationUsesUniverseDomain verifies that when both
// --impersonate-service-account and --universe-domain are set, the
// impersonation token request is sent to the IAM Credentials endpoint of the
// configured universe rather than iamcredentials.googleapis.com.
//
// See https://github.com/GoogleCloudPlatform/cloud-sql-proxy/issues/2640
func TestImpersonationUsesUniverseDomain(t *testing.T) {
	const universe = "test-universe.example"

	rec := &hostRecorder{}
	srv := httptest.NewTLSServer(rec)
	defer srv.Close()

	// Route every outbound HTTPS request, whatever its host, to the fake
	// backend. Both the google.golang.org/api and cloud.google.com/go/auth
	// transports are built by cloning http.DefaultTransport.
	orig := http.DefaultTransport
	http.DefaultTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
		// The test server's certificate is not valid for the hosts used
		// here.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	defer func() { http.DefaultTransport = orig }()

	c := &proxy.Config{
		Token:              "base-token",
		ImpersonationChain: "my-app@my-project.iam.gserviceaccount.com",
		UniverseDomain:     universe,
	}
	opts, err := c.DialerOptions(testLogger)
	if err != nil {
		t.Fatalf("DialerOptions: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := cloudsqlconn.NewDialer(ctx, opts...)
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	defer d.Close()

	// The dial is expected to fail because the fake backend does not serve
	// instance metadata. It is made only to trigger the token request.
	conn, err := d.Dial(ctx, "my-project:my-region:my-instance")
	if err == nil {
		conn.Close()
	}

	hosts := rec.recorded()
	want := "iamcredentials." + universe
	var sawWant bool
	for _, h := range hosts {
		if h == want {
			sawWant = true
		}
		if strings.HasSuffix(h, "googleapis.com") {
			t.Errorf("request sent to %q, want only hosts in universe %q", h, universe)
		}
	}
	if !sawWant {
		t.Errorf("no impersonation request sent to %q; hosts contacted: %v (dial error: %v)", want, hosts, err)
	}
}
