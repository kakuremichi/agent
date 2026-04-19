package exitnode

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// SOCKS5 constants
const (
	socks5Version = 0x05
	noAuth        = 0x00

	// Command types
	cmdConnect = 0x01

	// Address types
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	addrTypeIPv6   = 0x04

	// Reply codes
	repSuccess        = 0x00
	repGeneralFailure = 0x01
)

// LocalSOCKS5Proxy is a local SOCKS5 proxy that forwards to Gateway via netstack.
type LocalSOCKS5Proxy struct {
	listenAddr   string        // e.g., "localhost:1080"
	tnet         *netstack.Net // WireGuard netstack for outbound connections
	gatewayAddrs []string      // Gateway SOCKS5 addresses, tried in order for failover
	listener     net.Listener
	mu           sync.RWMutex
	running      bool
	cancel       context.CancelFunc
}

// NewLocalSOCKS5Proxy creates a new local SOCKS5 proxy
func NewLocalSOCKS5Proxy(listenAddr string, tnet *netstack.Net, gatewayAddrs []string) *LocalSOCKS5Proxy {
	return &LocalSOCKS5Proxy{
		listenAddr:   listenAddr,
		tnet:         tnet,
		gatewayAddrs: append([]string(nil), gatewayAddrs...),
	}
}

// dialGateway tries each configured gateway address until one connects.
func (p *LocalSOCKS5Proxy) dialGateway() (net.Conn, string, error) {
	p.mu.RLock()
	addrs := append([]string(nil), p.gatewayAddrs...)
	p.mu.RUnlock()
	if len(addrs) == 0 {
		return nil, "", fmt.Errorf("no gateway configured")
	}
	var lastErr error
	for _, addr := range addrs {
		conn, err := p.tnet.Dial("tcp", addr)
		if err == nil {
			return conn, addr, nil
		}
		lastErr = err
		slog.Debug("Gateway SOCKS5 dial failed, trying next", "gateway", addr, "error", err)
	}
	return nil, "", fmt.Errorf("all gateways failed: %w", lastErr)
}

// Start starts the local SOCKS5 proxy
func (p *LocalSOCKS5Proxy) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return nil
	}

	listener, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		p.mu.Unlock()
		return fmt.Errorf("failed to listen on %s: %w", p.listenAddr, err)
	}

	p.listener = listener
	p.running = true

	childCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.mu.Unlock()

	slog.Info("Local SOCKS5 proxy listening", "addr", p.listenAddr, "gateways", p.gatewayAddrs)

	go func() {
		<-childCtx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-childCtx.Done():
				return nil
			default:
				slog.Debug("SOCKS5 proxy accept error", "error", err)
				return err
			}
		}

		go p.handleConnection(conn)
	}
}

// handleConnection handles a single SOCKS5 connection
func (p *LocalSOCKS5Proxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// SOCKS5 handshake with client
	if err := p.handleHandshake(clientConn); err != nil {
		slog.Debug("SOCKS5 handshake failed", "error", err)
		return
	}

	// Read SOCKS5 request from client
	targetAddr, err := p.readRequest(clientConn)
	if err != nil {
		slog.Debug("SOCKS5 request failed", "error", err)
		return
	}

	gatewayConn, gatewayAddr, err := p.dialGateway()
	if err != nil {
		slog.Debug("Failed to connect to any gateway SOCKS5", "error", err)
		p.sendReply(clientConn, repGeneralFailure)
		return
	}
	defer gatewayConn.Close()
	slog.Debug("Local SOCKS5 request", "target", targetAddr, "via_gateway", gatewayAddr)

	// Perform SOCKS5 handshake with Gateway
	if err := p.gatewayHandshake(gatewayConn); err != nil {
		slog.Debug("Gateway SOCKS5 handshake failed", "error", err)
		p.sendReply(clientConn, repGeneralFailure)
		return
	}

	// Send CONNECT request to Gateway
	if err := p.gatewayConnect(gatewayConn, targetAddr); err != nil {
		slog.Debug("Gateway SOCKS5 connect failed", "error", err)
		p.sendReply(clientConn, repGeneralFailure)
		return
	}

	// Send success reply to client
	p.sendReply(clientConn, repSuccess)

	// Bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(gatewayConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, gatewayConn)
	}()

	wg.Wait()
}

// handleHandshake performs SOCKS5 authentication handshake with client
func (p *LocalSOCKS5Proxy) handleHandshake(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Check for no-auth method
	hasNoAuth := false
	for _, m := range methods {
		if m == noAuth {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		conn.Write([]byte{socks5Version, 0xFF})
		return fmt.Errorf("no acceptable auth method")
	}

	conn.Write([]byte{socks5Version, noAuth})
	return nil
}

// readRequest reads SOCKS5 request and returns target address
func (p *LocalSOCKS5Proxy) readRequest(conn net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	if header[0] != socks5Version {
		return "", fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	if header[1] != cmdConnect {
		p.sendReply(conn, 0x07) // Command not supported
		return "", fmt.Errorf("unsupported command: %d", header[1])
	}

	addrType := header[3]
	var host string

	switch addrType {
	case addrTypeIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	case addrTypeDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return "", err
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)

	case addrTypeIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	default:
		return "", fmt.Errorf("unsupported address type: %d", addrType)
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)

	return fmt.Sprintf("%s:%d", host, port), nil
}

// gatewayHandshake performs SOCKS5 handshake with Gateway
func (p *LocalSOCKS5Proxy) gatewayHandshake(conn net.Conn) error {
	// Send auth request (no auth)
	conn.Write([]byte{socks5Version, 1, noAuth})

	// Read response
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}

	if response[0] != socks5Version || response[1] != noAuth {
		return fmt.Errorf("gateway auth failed")
	}

	return nil
}

// gatewayConnect sends CONNECT request to Gateway
func (p *LocalSOCKS5Proxy) gatewayConnect(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// Build CONNECT request
	request := []byte{socks5Version, cmdConnect, 0x00}

	// Determine address type
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = append(request, addrTypeIPv4)
			request = append(request, ip4...)
		} else {
			request = append(request, addrTypeIPv6)
			request = append(request, ip...)
		}
	} else {
		// Domain name
		request = append(request, addrTypeDomain)
		request = append(request, byte(len(host)))
		request = append(request, []byte(host)...)
	}

	// Add port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	request = append(request, portBytes...)

	// Send request
	if _, err := conn.Write(request); err != nil {
		return err
	}

	// Read response
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}

	if response[1] != repSuccess {
		return fmt.Errorf("gateway connect failed: %d", response[1])
	}

	// Read bound address (we don't need it, but must consume it)
	addrType := response[3]
	switch addrType {
	case addrTypeIPv4:
		io.ReadFull(conn, make([]byte, 4+2))
	case addrTypeDomain:
		lenByte := make([]byte, 1)
		io.ReadFull(conn, lenByte)
		io.ReadFull(conn, make([]byte, int(lenByte[0])+2))
	case addrTypeIPv6:
		io.ReadFull(conn, make([]byte, 16+2))
	}

	return nil
}

// sendReply sends a SOCKS5 reply
func (p *LocalSOCKS5Proxy) sendReply(conn net.Conn, rep byte) {
	reply := []byte{
		socks5Version,
		rep,
		0x00,
		addrTypeIPv4,
		0, 0, 0, 0,
		0, 0,
	}
	conn.Write(reply)
}

// UpdateGateways replaces the full list of gateway SOCKS5 addresses.
func (p *LocalSOCKS5Proxy) UpdateGateways(gatewayAddrs []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gatewayAddrs = append([]string(nil), gatewayAddrs...)
}

// Stop stops the local SOCKS5 proxy
func (p *LocalSOCKS5Proxy) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cancel != nil {
		p.cancel()
	}
	if p.listener != nil {
		p.listener.Close()
	}
	p.running = false
}
