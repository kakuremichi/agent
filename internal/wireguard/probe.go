package wireguard

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultGatewayProbePort    = 80
	DefaultGatewayProbeTimeout = 2 * time.Second
)

// EndpointDialer is implemented by netstack.Net.
type EndpointDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// EndpointProbeResult records the outcome of one Gateway endpoint probe.
type EndpointProbeResult struct {
	Address string
	Error   error
}

// GatewayProbeAddresses returns unique tcp addresses for Gateway WireGuard IPs.
func GatewayProbeAddresses(gatewayIPs []string, port int) []string {
	if port <= 0 {
		port = DefaultGatewayProbePort
	}

	seen := map[string]struct{}{}
	addrs := make([]string, 0, len(gatewayIPs))
	for _, ip := range gatewayIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}

		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		addrs = append(addrs, addr)
	}
	return addrs
}

// ProbeGatewayEndpoints opens short TCP connections to Gateway WireGuard IPs.
// The connection itself is enough to force a WireGuard packet from Agent to
// Gateway, letting a restarted Gateway relearn the Agent's NAT endpoint.
func ProbeGatewayEndpoints(
	ctx context.Context,
	dialer EndpointDialer,
	gatewayIPs []string,
	port int,
	timeout time.Duration,
) []EndpointProbeResult {
	if dialer == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = DefaultGatewayProbeTimeout
	}

	addrs := GatewayProbeAddresses(gatewayIPs, port)
	results := make([]EndpointProbeResult, 0, len(addrs))
	for _, addr := range addrs {
		if err := ctx.Err(); err != nil {
			results = append(results, EndpointProbeResult{Address: addr, Error: err})
			continue
		}

		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := dialer.DialContext(probeCtx, "tcp", addr)
		cancel()
		if conn != nil {
			_ = conn.Close()
		}
		results = append(results, EndpointProbeResult{Address: addr, Error: err})
	}

	return results
}
