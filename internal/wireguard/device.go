package wireguard

import (
	"fmt"
	"log/slog"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// NewDevice creates a new WireGuard device with netstack
func NewDevice(config *DeviceConfig) (*Device, error) {
	slog.Info("Creating WireGuard device",
		"virtual_ips", config.VirtualIPs,
		"gateways", len(config.Gateways),
	)

	if len(config.VirtualIPs) == 0 {
		return nil, fmt.Errorf("no virtual IPs configured (no tunnels?)")
	}

	d := &Device{
		config: config,
	}

	// Parse private key
	privateKey, err := wgtypes.ParseKey(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	d.privateKey = config.PrivateKey
	d.publicKey = privateKey.PublicKey().String()

	// Parse all virtual IPs (one per tunnel)
	var virtualIPs []netip.Addr
	for _, ipStr := range config.VirtualIPs {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			return nil, fmt.Errorf("invalid virtual IP %s: %w", ipStr, err)
		}
		virtualIPs = append(virtualIPs, ip)
	}

	slog.Info("Parsed WireGuard configuration",
		"public_key", d.publicKey,
		"virtual_ips", virtualIPs,
	)

	// Create netstack TUN device with all virtual IPs
	tun, tnet, err := netstack.CreateNetTUN(
		virtualIPs,
		[]netip.Addr{}, // DNS servers (empty for now)
		1420,           // MTU
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create netstack TUN: %w", err)
	}
	d.tun = tun
	d.net = tnet

	// Create WireGuard device
	logger := device.NewLogger(
		device.LogLevelError,
		fmt.Sprintf("[WG-Agent] "),
	)

	wgDevice := device.NewDevice(tun, conn.NewDefaultBind(), logger)
	d.device = wgDevice

	// Configure WireGuard device
	if err := d.configureDevice(); err != nil {
		tun.Close()
		return nil, fmt.Errorf("failed to configure device: %w", err)
	}

	// Bring device up
	wgDevice.Up()

	slog.Info("WireGuard device created successfully",
		"public_key", d.publicKey,
		"virtual_ips", config.VirtualIPs,
	)

	return d, nil
}

// configureDevice configures the WireGuard device with initial settings
func (d *Device) configureDevice() error {
	// Parse the base64 private key and convert to hex for IPC
	privateKey, err := wgtypes.ParseKey(d.privateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Build IPC configuration string with hex-encoded key
	config := fmt.Sprintf("private_key=%x\nreplace_peers=true\n", privateKey[:])

	// Add peers (Gateways)
	for _, gw := range d.config.Gateways {
		if len(gw.AllowedIPs) == 0 {
			continue // Skip gateways with no allowed IPs
		}

		// Parse the base64 public key and convert to hex for IPC
		pubKey, err := wgtypes.ParseKey(gw.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to parse gateway public key: %w", err)
		}

		config += fmt.Sprintf("public_key=%x\n", pubKey[:])
		if gw.Endpoint != "" {
			config += fmt.Sprintf("endpoint=%s\n", gw.Endpoint)
		}

		// Add all allowed IPs from config
		for _, allowedIP := range gw.AllowedIPs {
			config += fmt.Sprintf("allowed_ip=%s\n", allowedIP)
		}

		// Persistent keepalive
		config += "persistent_keepalive_interval=25\n"

		slog.Info("Configured gateway peer",
			"endpoint", gw.Endpoint,
			"allowed_ips", gw.AllowedIPs,
			"public_key", gw.PublicKey,
		)
	}

	// Apply configuration via IPC
	if err := d.device.IpcSet(config); err != nil {
		return fmt.Errorf("failed to set IPC config: %w", err)
	}

	slog.Info("WireGuard device configured", "peers", len(d.config.Gateways))
	return nil
}

// UpdateGateways updates the Gateway peers
func (d *Device) UpdateGateways(gateways []GatewayPeer) error {
	slog.Info("Updating Gateway peers", "count", len(gateways))

	d.config.Gateways = gateways

	// Reconfigure device with new peer list
	return d.configureDevice()
}

// Close closes the WireGuard device
func (d *Device) Close() error {
	slog.Info("Closing WireGuard device")

	if d.device != nil {
		d.device.Close()
	}
	if d.tun != nil {
		d.tun.Close()
	}

	return nil
}

// Net returns the underlying netstack network for user-space networking
func (d *Device) Net() *netstack.Net {
	return d.net
}

// PublicKey returns the device's public key
func (d *Device) PublicKey() string {
	return d.publicKey
}

// VirtualIPs returns the device's virtual IPs (one per tunnel)
func (d *Device) VirtualIPs() []string {
	return d.config.VirtualIPs
}
