// Copyright 2022 Bobby Powers. All rights reserved.
// Use of this source code is governed by the ISC License
// that can be found in the LICENSE file.

package proxy

import (
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
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

// htons assumes it is running on a little endian system
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

// newSocketKey matches the key we use in bpf where annoyingly, on the kernel side,
// things are stored in network byte order.
func newSocketKey(c net.Conn) (socketKey, error) {
	remoteIp, remotePortStr, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return socketKey{}, err
	}
	remotePort, err := strconv.Atoi(remotePortStr)
	if err != nil {
		return socketKey{}, err
	}
	remote, err := netip.ParseAddr(remoteIp)
	if err != nil {
		return socketKey{}, err
	}

	localIp, localPortStr, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return socketKey{}, err
	}
	localPort, err := strconv.Atoi(localPortStr)
	if err != nil {
		return socketKey{}, err
	}
	local, err := netip.ParseAddr(localIp)
	if err != nil {
		return socketKey{}, err
	}

	if !local.Is4() || !remote.Is4() {
		return socketKey{}, fmt.Errorf("expected IPs to be v4, v6 not yet supported")
	}

	return socketKey{
		LocalIp:    ip4AsInt(local),
		LocalPort:  uint32(localPort),
		RemoteIp:   ip4AsInt(remote),
		RemotePort: uint32(htons(uint16(remotePort))),
	}, nil
}

func ListenAndProxy(l net.Listener, upstream net.Addr) error {
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

		fmt.Printf("accepted connection: %s->%s\n", conn.RemoteAddr(), conn.LocalAddr())

		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			return fmt.Errorf("expected to accept *net.TCPConns, got %T", conn)
		}

		go serve(tcpConn, feConns, beConns, upstreamAddr)
	}
}

func serve(conn *net.TCPConn, feConns, beConns *ebpf.Map, upstreamAddr string) {
	// read the client hello off the wire, as we want to make a routing
	// decision based on it
	clientHello, err := readClientHello(conn)
	if err != nil {
		log.Printf("readClientHello: %s\n", err)
		return
	}

	// log.Printf("read client hello len %d\n", len(clientHello))

	// generate the key used in the kernel-side SOCKHASH eBPF map
	key, err := newSocketKey(conn)
	if err != nil {
		log.Printf("newSocketKey: %s\n", err)
		return
	}

	// we need an integer FD for the eBPF program, so dup the conn
	f, err := conn.File()
	if err != nil {
		log.Printf("conn.File: %s\n", err)
		return
	}

	// close the original connection -- we only need `f`
	if err = conn.Close(); err != nil {
		log.Printf("conn.Close: %s\n", err)
		return
	}

	// get that file descriptor from the Go *os.File
	fd := int(f.Fd())

	// IDK if we actually need this?
	if err := syscall.SetNonblock(fd, true); err != nil {
		log.Printf("syscall.SetNonblock: %s\n", err)
		return
	}

	// TODO: rather than use a single upstreamAddr, call out to a func to find the
	//   upstreamAddr based on the TLS ClientHello
	upstreamConn, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		log.Printf("net.Dial(%s): %s", upstreamAddr, err)
		return
	}

	// generate the key used in the kernel-side SOCKHASH eBPF map
	upstreamKey, err := newSocketKey(upstreamConn)
	if err != nil {
		log.Printf("newSocketKey(upstream): %s", err)
		return
	}

	// need the raw TCPConn for access to File() method
	upstream, ok := upstreamConn.(*net.TCPConn)
	if !ok {
		log.Printf("expected upstream conn to be tcp")
		return
	}

	// get that file descriptor from the Go *os.File
	uf, err := upstream.File()
	if err != nil {
		log.Printf("upstream.File: %s", err)
		return
	}

	// close the original connection -- we only need `uf`
	if err = upstream.Close(); err != nil {
		log.Printf("conn.Close: %s\n", err)
		return
	}

	ufd := int(uf.Fd())

	// we need to criss-cross keys + connections here: we use the client key
	// in the _backend_ map, so that we can route from frontend->backend and
	// vice-versa.

	if err := beConns.Update(&key, int64(ufd), ebpf.UpdateNoExist); err != nil {
		log.Printf("conns.Update 2: %s\n", err)
		return
	}

	if err := feConns.Update(&upstreamKey, int64(fd), ebpf.UpdateNoExist); err != nil {
		log.Printf("conns.Update 1: %s\n", err)
		return
	}

	// log.Printf("client %s -> %s (key %#v) in be", conn.RemoteAddr(), conn.LocalAddr(), key)
	// log.Printf("upstream %s -> %s (key %#v) in fe", upstream.LocalAddr(), upstream.RemoteAddr(), upstreamKey)

	// now that everything is set up in our SOCKHASH maps, write the ClientHello upstream
	n, err := uf.Write(clientHello)
	if err != nil {
		log.Printf("upstream.Write(clientHello): %s\n", err)
		return
	}
	if n != len(clientHello) {
		log.Printf("upstream.Write(clientHello) short write at %d (expected %d)\n", n, len(clientHello))
		return
	}

	// TODO: clean everything up and stuff
	time.Sleep(time.Hour)
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
