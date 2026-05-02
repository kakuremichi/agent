package wireguard

import (
	"sync"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// GatewayPeer represents a Gateway peer configuration
type GatewayPeer struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs []string // Gateway's virtual IPs (e.g., ["10.1.0.1/32", "10.2.0.1/32"])
}

// DeviceConfig represents WireGuard device configuration for Agent
type DeviceConfig struct {
	PrivateKey string
	VirtualIPs []string // Agent's virtual IPs (one per tunnel, e.g., ["10.1.0.100", "10.2.0.100"])
	Gateways   []GatewayPeer
}

// Device represents a WireGuard device manager for Agent
type Device struct {
	mu         sync.Mutex
	closed     bool
	config     *DeviceConfig
	privateKey string
	publicKey  string
	device     *device.Device
	tun        tun.Device
	net        *netstack.Net
}
