// Copyright 2022 Bobby Powers. All rights reserved.
// Use of this source code is governed by the ISC License
// that can be found in the LICENSE file.

package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	expectedBody = "hi hi"
)

func TestListenAndProxy(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, _ = rw.Write([]byte(expectedBody))
	}))
	defer upstream.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %s", err)
	}
	defer listener.Close()

	log.Printf("upstream listening at %s", upstream.Listener.Addr())
	log.Printf("mule listening at %s", listener.Addr())

	go func() {
		if err := ListenAndProxy(listener, upstream.Listener.Addr()); err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				t.Fatalf("ListenAndProxy: %s", err)
			}
		}
	}()

	client := upstream.Client()
	// resp, err := client.Get(upstream.URL)
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", listener.Addr().String()), nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %s", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Get: %s", err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 not %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(body): %s", err)
	}

	if string(body) != expectedBody {
		t.Fatalf("unexpected body: %q", string(body))
	}
}
