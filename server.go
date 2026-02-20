package socks5

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
)

/*

Minimal SOCKS5 proxy server
No auth
Only connect command

*/

const versionSOCKS5 uint8 = 0x05

const auth_noAuth uint8 = 0x00

// addr types
const (
	TypeIPv4   uint8 = 0x01
	TypeDomain uint8 = 0x03
	TypeIPv6   uint8 = 0x04
)

// command codes
const (
	CommandConnect      uint8 = 0x01
	CommandBind         uint8 = 0x02
	CommandUDPAssociate uint8 = 0x03
)

const ResponseSuccess uint8 = 0x00

const ReservedByte uint8 = 0x00

type Server struct{}

func (s *Server) ListenAndServe(network, address string) error {
	listener, err := net.Listen(network, address)
	if err != nil {
		log.Fatalf("error start server: %s\n", err)
	}

	fmt.Printf("server started: %s\n", address)

	return s.Serve(listener)
}

func (s *Server) Serve(listener net.Listener) error {
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(localConn net.Conn) {
	defer localConn.Close()

	buf := bufio.NewReader(localConn)

	// read client greeting
	clientGreeting, err := ParseClientGreeting(buf)
	if err != nil {
		fmt.Printf("error parse client greeting: %s\n", err)
		return
	}

	// check SOCKS5
	if clientGreeting.ver != versionSOCKS5 {
		fmt.Println("not supported version")
		return
	}

	// Response
	_, err = localConn.Write([]byte{versionSOCKS5, auth_noAuth})
	if err != nil {
		fmt.Printf("error send response: %s\n", err)
		return
	}

	// end client greeting

	// start client connection request
	r, err := ParseClientConnectionRequest(buf)
	if err != nil {
		fmt.Printf("error parse client connection request: %s\n", err)
		return
	}

	if r.ver != versionSOCKS5 {
		fmt.Println("not supported version")
		return
	}

	err = r.setDstAddr(buf)
	if err != nil {
		fmt.Printf("error set dst addr: %s\n", err)
		return
	}

	// completed read request

	// response with connect

	r.reader = buf

	// handle request
	err = handleRequest(localConn, r)
	if err != nil {
		fmt.Printf("error handle request: %s\n", err)
	}
}

func handleRequest(w io.Writer, req *ClientConnectionRequest) error {
	switch req.cmd {
	case CommandConnect:
		return MakeConnect(w, req)
	case CommandBind:
		return fmt.Errorf("not implemented\n")
	case CommandUDPAssociate:
		return fmt.Errorf("not implemented\n")
	default:
		return fmt.Errorf("error unknown command\n")
	}
}

func MakeConnect(w io.Writer, req *ClientConnectionRequest) error {
	address := net.JoinHostPort(req.dstAddr.addrIP.String(), strconv.Itoa(req.dstPort))
	remoteConn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("connect to %v failed: %s\n", req.dstAddr.addrIP, err)
	}
	defer remoteConn.Close()

	// make and send response packet
	resp, err := makeResponse(req)
	if err != nil {
		return fmt.Errorf("error make response: %s\n", err)
	}

	_, err = w.Write(resp)
	if err != nil {
		return fmt.Errorf("error write response: %s\n", err)
	}

	// proxying
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(remoteConn, req.reader)
		wg.Done()
	}()

	go func() {
		io.Copy(w, remoteConn)
		wg.Done()
	}()

	wg.Wait()

	return nil
}

func makeResponse(req *ClientConnectionRequest) ([]byte, error) {
	var resp []byte

	switch req.dstAddr.addrType {
	case TypeIPv4:
		resp = []byte{versionSOCKS5, ResponseSuccess, ReservedByte, TypeIPv4}
		resp = append(resp, req.dstAddr.addrIP...)
		resp = append(resp, byte(req.dstPort>>8), byte(req.dstPort))
	case TypeIPv6:
		resp = []byte{versionSOCKS5, ResponseSuccess, ReservedByte, TypeIPv6}
		resp = append(resp, req.dstAddr.addrIP...)
		resp = append(resp, byte(req.dstPort>>8), byte(req.dstPort))
	case TypeDomain:
		resp = []byte{versionSOCKS5, ResponseSuccess, ReservedByte, TypeDomain}
		resp = append(resp, byte(len(req.dstAddr.domain)))
		resp = append(resp, []byte(req.dstAddr.domain)...)
		resp = append(resp, byte(req.dstPort>>8), byte(req.dstPort))
	default:
		return resp, fmt.Errorf("error unknown dst addr type: %T\n", req.dstAddr.addrType)
	}

	return resp, nil
}

// setDstAddr sets dst.IP and dst.PORT
func (req *ClientConnectionRequest) setDstAddr(r io.Reader) error {
	switch req.dstAddr.addrType {
	case TypeIPv4:
		addr := make([]byte, net.IPv4len+2)
		_, err := io.ReadFull(r, addr)
		if err != nil {
			return fmt.Errorf("error read address type: %s\n", err)
		}
		// req.dstAddr.addrIP = net.IPv4(addr[0], addr[1], addr[2], addr[3])
		req.dstAddr.addrIP = addr[:net.IPv4len]
		req.dstPort = int(binary.BigEndian.Uint16(addr[net.IPv4len:]))
	case TypeDomain:
		tmp := []byte{0}
		_, err := io.ReadFull(r, tmp)
		if err != nil {
			return err
		}
		domainLen := int(tmp[0])
		addr := make([]byte, domainLen+2)
		_, err = io.ReadFull(r, addr)
		if err != nil {
			return err
		}
		req.dstAddr.domain = string(addr[:domainLen])
		req.dstPort = int(binary.BigEndian.Uint16(addr[domainLen:]))
	case TypeIPv6:
		addr := make([]byte, net.IPv6len+2)
		_, err := io.ReadFull(r, addr)
		if err != nil {
			return fmt.Errorf("error read address type: %s\n", err)
		}
		req.dstAddr.addrIP = addr[:net.IPv6len]
		req.dstPort = int(binary.BigEndian.Uint16(addr[net.IPv6len:]))
	default:
		return fmt.Errorf("error address type undefined")
	}

	return nil
}

type ClientGreeting struct {
	ver uint8

	// number of methods
	nmethods uint8
	methods  []uint8
}

func ParseClientGreeting(r io.Reader) (*ClientGreeting, error) {
	clientGreeting := &ClientGreeting{}

	buf := make([]byte, 1)
	if _, err := r.Read(buf); err != nil {
		return nil, err
	}
	clientGreeting.ver = buf[0]

	if _, err := r.Read(buf); err != nil {
		return nil, err
	}
	clientGreeting.nmethods = buf[0]
	clientGreeting.methods = make([]uint8, clientGreeting.nmethods)

	_, err := io.ReadAtLeast(r, clientGreeting.methods, int(clientGreeting.nmethods))
	if err != nil {
		return nil, err
	}

	return clientGreeting, nil
}

type Address struct {

	// IPv4
	addrType uint8
	addrIP   net.IP

	// domain
	domain string
}

type ClientConnectionRequest struct {
	ver uint8

	// command
	cmd uint8

	// reserved, must be 0x00
	rsv uint8

	dstAddr Address

	// 2 bytes
	dstPort int

	// helpers, not request related
	reader io.Reader
}

func ParseClientConnectionRequest(r io.Reader) (*ClientConnectionRequest, error) {
	req := &ClientConnectionRequest{}

	tmp := []byte{0, 0, 0, 0}
	_, err := io.ReadFull(r, tmp)
	if err != nil {
		return nil, err
	}

	req.ver = tmp[0]
	req.cmd = tmp[1]

	// move out ?
	if req.ver != versionSOCKS5 {
		return nil, fmt.Errorf("not supported version\n")
	}

	req.rsv = tmp[2]
	req.dstAddr.addrType = tmp[3]

	return req, nil
}
