// Copyright 2022 Bobby Powers. All rights reserved.
// Use of this source code is governed by the ISC License
// that can be found in the LICENSE file.

package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"syscall"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf bpf_proxy.c

type socketKey struct {
	LocalIp    uint32
	LocalPort  uint32 // little-endian
	RemoteIp   uint32
	RemotePort uint32 // big-endian
}

func ip4AsInt(ip netip.Addr) uint32 {
	v4 := ip.As4()
	return binary.LittleEndian.Uint32(v4[:])
}

// newSocketKey matches the key we use in bpf
func newSocketKey(c net.Conn) (socketKey, error) {
	remote, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return socketKey{}, err
	}

	local, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return socketKey{}, err
	}

	if !local.Addr().Is4() || !remote.Addr().Is4() {
		return socketKey{}, fmt.Errorf("expected IPs to be v4, v6 not yet supported")
	}

	return socketKey{
		LocalIp:    ip4AsInt(local.Addr()),
		LocalPort:  uint32(local.Port()),
		RemoteIp:   ip4AsInt(remote.Addr()),
		RemotePort: uint32(remote.Port()),
	}, nil
}

func ListenAndProxy(l net.Listener, upstream net.Addr, dupFDs bool) error {
	// load objects into the kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return err
	}

	err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.FrontendConns.FD(),
		Program: objs.MuleGenericParser,
		Attach:  ebpf.AttachSkSKBStreamParser,
	})
	if err != nil {
		return err
	}

	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.FrontendConns.FD(),
		Program: objs.MuleFrontendVerdict,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	})
	if err != nil {
		return err
	}

	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.BackendConns.FD(),
		Program: objs.MuleGenericParser,
		Attach:  ebpf.AttachSkSKBStreamParser,
	})
	if err != nil {
		return err
	}

	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.BackendConns.FD(),
		Program: objs.MuleBackendVerdict,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	})
	if err != nil {
		return err
	}

	return listen(l, objs.FrontendConns, objs.BackendConns, upstream.String())
}

func listen(l net.Listener, feConns *ebpf.Map, beConns *ebpf.Map, upstreamAddr string) error {
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

		go serve(tcpConn, feConns, beConns, upstreamAddr)
	}
}

func dupFdAndCloseOrig(c *net.TCPConn) (*os.File, error) {
	// we need an integer FD for the eBPF program, so dup the conn
	f, err := c.File()
	if err != nil {
		return nil, fmt.Errorf("conn.File: %w", err)
	}

	// close the original connection -- we only need `f`
	if err = c.Close(); err != nil {
		return nil, fmt.Errorf("conn.Close: %w", err)
	}

	return f, nil
}

func serve(client *net.TCPConn, feConns, beConns *ebpf.Map, upstreamAddr string) {
	//defer func(r, l net.Addr) {
	//	fmt.Printf("finished serving: %s->%s\n", r, l)
	//}(client.RemoteAddr(), client.LocalAddr())

	// read the TLS ClientHello off the wire so that we can
	// use it in routing decisions
	clientHello, err := readClientHello(client)
	if err != nil {
		log.Printf("readClientHello: %s\n", err)
		return
	}

	// generate the key used in the kernel-side SOCKHASH eBPF map
	clientKey, err := newSocketKey(client)
	if err != nil {
		log.Printf("newSocketKey: %s\n", err)
		return
	}

	clientFd, err := dupFdAndCloseOrig(client)
	if err != nil {
		log.Printf("dupFd: %s\n", err)
		return
	}
	client = nil
	defer func() { _ = clientFd.Close() }()

	// TODO: rather than use a single upstreamAddr, call out to a func to find the
	//   upstreamAddr based on the TLS ClientHello
	upstream, err := dialTcp(upstreamAddr)
	if err != nil {
		log.Printf("dialTCP(%s): %s", upstreamAddr, err)
		return
	}

	// generate the clientKey used in the kernel-side SOCKHASH eBPF map
	upstreamKey, err := newSocketKey(upstream)
	if err != nil {
		log.Printf("newSocketKey(upstream): %s", err)
		return
	}

	upstreamFd, err := dupFdAndCloseOrig(upstream)
	if err != nil {
		log.Printf("dupFd: %s\n", err)
		return
	}
	upstream = nil
	defer func() { _ = upstreamFd.Close() }()

	// we need to criss-cross keys + connections here: we use the client clientKey
	// in the _backend_ map, so that we can route from frontend->backend and
	// vice-versa.

	if err = addToSockhash(beConns, upstreamFd, clientKey); err != nil {
		log.Printf("addToSockhash(be): %s\n", err)
		return
	}
	defer func() {
		if err = removeFromSockhash(beConns, clientKey); err != nil {
			log.Printf("removeFromSockhash(be): %s\n", err)
		}
	}()

	if err = addToSockhash(feConns, clientFd, upstreamKey); err != nil {
		log.Printf("addToSockhash(fe): %s\n", err)
		return
	}
	defer func() {
		if err = removeFromSockhash(feConns, upstreamKey); err != nil {
			log.Printf("removeFromSockhash(fe): %s\n", err)
		}
	}()

	// log.Printf("client %s -> %s (clientKey %#v) in be", client.RemoteAddr(), client.LocalAddr(), clientKey)
	// log.Printf("upstream %s -> %s (clientKey %#v) in fe", upstream.LocalAddr(), upstream.RemoteAddr(), upstreamKey)

	// now that everything is set up in our SOCKHASH maps, write the
	// ClientHello upstream.  This will trigger the ServerHello and "unblock"
	// proxying between the client and upstream
	n, err := upstreamFd.Write(clientHello)
	if err != nil {
		log.Printf("upstream.Write(clientHello): %s\n", err)
		return
	}
	if n != len(clientHello) {
		log.Printf("upstream.Write(clientHello) short write at %d (expected %d)\n", n, len(clientHello))
		return
	}

	clientChan := make(chan struct{})
	upstreamChan := make(chan struct{})

	go notifyOnClose(clientFd, clientChan)
	go notifyOnClose(upstreamFd, upstreamChan)

	// don't return from this function until either a client or upstream
	// connection closes
	select {
	case <-clientChan:
	case <-upstreamChan:
	}
}

func notifyOnClose(conn io.Reader, done chan<- struct{}) {
	defer func() { close(done) }()

	// this should never return any data -- the BPF verdict programs
	// redirect all packets before they can be read here.  This serves
	// to notify us on connection close.
	b := make([]byte, 1)
	n, err := conn.Read(b)

	if n != 0 {
		log.Printf("invariant broken: never expected to read bytes from socket")
		return
	}

	// TODO: check/test against specific error types here
	_ = err
}

type syscallConner interface {
	SyscallConn() (syscall.RawConn, error)
}

func addToSockhash(m *ebpf.Map, conn syscallConner, key socketKey) error {
	sc, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("conn.SyscallConn: %w\n", err)
	}
	var innerError error
	err = sc.Control(func(fd uintptr) {
		if err := m.Update(&key, int64(fd), ebpf.UpdateNoExist); err != nil {
			innerError = fmt.Errorf("conns.Update: %w\n", err)
			return
		}
	})
	if err != nil {
		return fmt.Errorf("uc.Control: %w\n", err)
	}
	if innerError != nil {
		return innerError
	}

	return nil
}

func removeFromSockhash(m *ebpf.Map, key socketKey) error {
	err := m.Delete(&key)
	if err != nil {
		return fmt.Errorf("m.Delete: %w\n", err)
	}

	return nil
}

func readClientHello(conn net.Conn) ([]byte, error) {
	clientHello := make([]byte, 4096)
	n, err := conn.Read(clientHello[:5])
	if err != nil {
		return nil, fmt.Errorf("conn.Read: %s", err)
	}
	if n != 5 {
		return nil, fmt.Errorf("short conn.Read, expected 5 not %d", n)
	}

	clientHelloLen := binary.BigEndian.Uint16(clientHello[3:5])
	if clientHelloLen > 4096-5 {
		return nil, fmt.Errorf("client hello too big at %d", clientHelloLen)
	}
	n, err = conn.Read(clientHello[5 : clientHelloLen+5])
	if err != nil {
		return nil, fmt.Errorf("conn.Read rest of ClientHello: %s\n", err)
	}
	if n != int(clientHelloLen) {
		return nil, fmt.Errorf("short conn.Read 2, expected 5 not %d\n", n)
	}
	clientHello = clientHello[:clientHelloLen+5]

	return clientHello, nil
}

func dialTcp(addr string) (*net.TCPConn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("net.Dial(%s): %s", addr, err)
	}

	// need the raw TCPConn for access to File() method
	tconn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, errors.New("expected upstream conn to be tcp")
	}

	return tconn, nil
}
