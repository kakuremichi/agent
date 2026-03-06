package exitnode

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// LocalHTTPProxy is a local HTTP CONNECT proxy that forwards to Gateway via netstack.
// It listens on localhost and routes traffic through WireGuard tunnel.
type LocalHTTPProxy struct {
	listenAddr  string        // e.g., "localhost:8080"
	tnet        *netstack.Net // WireGuard netstack for outbound connections
	gatewayAddr string        // Gateway proxy address e.g., "10.1.0.254:8080"
	listener    net.Listener
	mu          sync.Mutex
	running     bool
	cancel      context.CancelFunc
}

// NewLocalHTTPProxy creates a new local HTTP proxy
func NewLocalHTTPProxy(listenAddr string, tnet *netstack.Net, gatewayAddr string) *LocalHTTPProxy {
	return &LocalHTTPProxy{
		listenAddr:  listenAddr,
		tnet:        tnet,
		gatewayAddr: gatewayAddr,
	}
}

// Start starts the local HTTP proxy
func (p *LocalHTTPProxy) Start(ctx context.Context) error {
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

	slog.Info("Local HTTP proxy listening", "addr", p.listenAddr, "gateway", p.gatewayAddr)

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
				slog.Debug("HTTP proxy accept error", "error", err)
				return err
			}
		}

		go p.handleConnection(conn)
	}
}

// handleConnection handles a single proxy connection
func (p *LocalHTTPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		slog.Debug("Failed to read HTTP request", "error", err)
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(clientConn, req)
	} else {
		p.handleHTTP(clientConn, req, reader)
	}
}

// handleConnect handles HTTPS tunneling via CONNECT method
func (p *LocalHTTPProxy) handleConnect(clientConn net.Conn, req *http.Request) {
	slog.Debug("Local HTTP CONNECT request", "host", req.Host, "via_gateway", p.gatewayAddr)

	// Connect to Gateway's proxy via netstack
	gatewayConn, err := p.tnet.Dial("tcp", p.gatewayAddr)
	if err != nil {
		slog.Debug("Failed to connect to gateway proxy", "gateway", p.gatewayAddr, "error", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer gatewayConn.Close()

	// Forward CONNECT request to Gateway
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", req.Host, req.Host)
	if _, err := gatewayConn.Write([]byte(connectReq)); err != nil {
		slog.Debug("Failed to send CONNECT to gateway", "error", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Read Gateway's response
	gatewayReader := bufio.NewReader(gatewayConn)
	resp, err := http.ReadResponse(gatewayReader, req)
	if err != nil {
		slog.Debug("Failed to read gateway response", "error", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	if resp.StatusCode != http.StatusOK {
		slog.Debug("Gateway rejected CONNECT", "status", resp.StatusCode)
		clientConn.Write([]byte(fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", resp.StatusCode, resp.Status)))
		return
	}

	// Send 200 Connection Established to client
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

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

// handleHTTP handles plain HTTP requests (non-CONNECT)
func (p *LocalHTTPProxy) handleHTTP(clientConn net.Conn, req *http.Request, reader *bufio.Reader) {
	slog.Debug("Local HTTP request", "method", req.Method, "url", req.URL.String(), "via_gateway", p.gatewayAddr)

	// Connect to Gateway's proxy via netstack
	gatewayConn, err := p.tnet.Dial("tcp", p.gatewayAddr)
	if err != nil {
		slog.Debug("Failed to connect to gateway proxy", "gateway", p.gatewayAddr, "error", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer gatewayConn.Close()

	// Forward the request to Gateway
	if err := req.Write(gatewayConn); err != nil {
		slog.Debug("Failed to forward request to gateway", "error", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Copy response back to client
	io.Copy(clientConn, gatewayConn)
}

// UpdateGateway updates the gateway proxy address
func (p *LocalHTTPProxy) UpdateGateway(gatewayAddr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gatewayAddr = gatewayAddr
}

// Stop stops the local HTTP proxy
func (p *LocalHTTPProxy) Stop() {
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
