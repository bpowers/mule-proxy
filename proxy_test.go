// Copyright 2022 Bobby Powers. All rights reserved.
// Use of this source code is governed by the ISC License
// that can be found in the LICENSE file.

package proxy

import (
	"context"
	"errors"
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
		rw.Header().Set("Connection", "close")
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
		if err := ListenAndProxy(listener, upstream.Listener.Addr(), false); err != nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	time.Sleep(10 * time.Millisecond)
}

func userspaceUniProxy(from, to *net.TCPConn, done chan struct{}) {
	defer func() { close(done) }()

	buf := make([]byte, 64*1024)

	for {
		n, err := from.Read(buf)
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") && !errors.Is(err, io.EOF) {
				log.Printf("read: %s\n", err)
			}
			return
		}
		m, err := to.Write(buf[:n])
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") && !errors.Is(err, io.EOF) {
				log.Printf("write: %s\n", err)
			}
			return
		} else if n != m {
			log.Printf("short write: %d (want %d)\n", m, n)
		}
	}
}

func userspaceServe(client *net.TCPConn, upstreamAddr string) {
	defer func() { _ = client.Close() }()

	// TODO: rather than use a single upstreamAddr, call out to a func to find the
	//   upstreamAddr based on the TLS ClientHello
	upstream, err := dialTcp(upstreamAddr)
	if err != nil {
		log.Printf("dialTCP(%s): %s", upstreamAddr, err)
		return
	}
	defer func() { _ = upstream.Close() }()

	clientChan := make(chan struct{})
	upstreamChan := make(chan struct{})

	go userspaceUniProxy(client, upstream, clientChan)
	go userspaceUniProxy(upstream, client, upstreamChan)

	// don't return from this function until either a client or upstream
	// connection closes
	select {
	case <-clientChan:
	case <-upstreamChan:
	}
}

func l4listenAndProxy(l net.Listener, upstreamAddr string) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}

		// fmt.Printf("accepted connection: %s->%s\n", conn.RemoteAddr(), conn.LocalAddr())

		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			return fmt.Errorf("expected to accept *net.TCPConns, got %T", conn)
		}

		go userspaceServe(tcpConn, upstreamAddr)
	}
}

func benchmarkNewConn(b *testing.B, enableMule, enableGoL4, dupFDs bool) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// rw.Header().Set("Connection", "close")
		_, _ = rw.Write([]byte(expectedBody))
	}))
	defer upstream.Close()
	upstream.StartTLS()

	upstreamURL := upstream.URL
	upstream.EnableHTTP2 = true

	if enableMule {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatalf("net.Listen: %s", err)
		}
		defer listener.Close()

		go func() {
			if err := ListenAndProxy(listener, upstream.Listener.Addr(), dupFDs); err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					b.Fatalf("ListenAndProxy: %s", err)
				}
			}
		}()

		upstreamURL = fmt.Sprintf("https://%s/", listener.Addr().String())
	} else if enableGoL4 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatalf("net.Listen: %s", err)
		}
		defer listener.Close()

		go func() {
			if err := l4listenAndProxy(listener, upstream.Listener.Addr().String()); err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					b.Fatalf("ListenAndProxy: %s", err)
				}
			}
		}()

		upstreamURL = fmt.Sprintf("https://%s/", listener.Addr().String())
	}

	client := upstream.Client()
	baseReq, err := http.NewRequest("GET", upstreamURL, nil)
	if err != nil {
		b.Fatalf("http.NewRequest: %s", err)
	}
	//ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	//defer cancel()
	//req = req.WithContext(ctx)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := *baseReq

		resp, err := client.Do(&req)
		if err != nil {
			b.Fatalf("client.Get: %s", err)
		}

		if resp.StatusCode != 200 {
			b.Fatalf("expected 200 not %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			b.Fatalf("io.ReadAll(body): %s", err)
		}

		if err := resp.Body.Close(); err != nil {
			b.Fatalf("Body.Close: %s", err)
		}

		if string(body) != expectedBody {
			b.Fatalf("unexpected body: %q", string(body))
		}

	}
}

func BenchmarkNewConnBaseline(b *testing.B) {
	benchmarkNewConn(b, false, false, false)
}

func BenchmarkNewConnMule(b *testing.B) {
	benchmarkNewConn(b, true, false, false)
}

func BenchmarkNewConnGo(b *testing.B) {
	benchmarkNewConn(b, false, true, false)
}

func BenchmarkNewConnMuleFDsDuped(b *testing.B) {
	benchmarkNewConn(b, true, false, true)
}
