package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yourorg/kakuremichi/agent/internal/config"
	"github.com/yourorg/kakuremichi/agent/internal/exitnode"
	"github.com/yourorg/kakuremichi/agent/internal/proxy"
	"github.com/yourorg/kakuremichi/agent/internal/wireguard"
	"github.com/yourorg/kakuremichi/agent/internal/ws"
)

func main() {
	// Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("Starting kakuremichi Agent")

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	slog.Info("Configuration loaded",
		"control_url", cfg.ControlURL,
		"docker_enabled", cfg.DockerEnabled,
	)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Prevent "declared and not used" error
	_ = ctx

	// Generate or load WireGuard keys (persist locally to keep stable identity)
	privateKey, publicKey, err := loadOrCreateKeys(cfg.WireguardPrivateKey)
	if err != nil {
		log.Fatalf("Failed to prepare WireGuard keys: %v", err)
	}
	slog.Info("WireGuard keys ready", "public_key", publicKey)

	// WireGuard device will be initialized after receiving config from Control
	var wgDevice *wireguard.Device

	// Local proxy will be initialized after receiving virtual IP from Control
	var localProxy *proxy.LocalProxy

	// Exit Node proxies (will be initialized after receiving config)
	var exitHTTPProxy *exitnode.LocalHTTPProxy
	var exitSOCKS5Proxy *exitnode.LocalSOCKS5Proxy
	var gatewayProbeOnce sync.Once
	gatewayProbeTrigger := make(chan struct{}, 1)
	var gatewayProbeMu sync.RWMutex
	var gatewayProbeIPs []string
	setGatewayProbeIPs := func(ips []string) {
		gatewayProbeMu.Lock()
		gatewayProbeIPs = append(gatewayProbeIPs[:0], ips...)
		gatewayProbeMu.Unlock()
	}
	getGatewayProbeIPs := func() []string {
		gatewayProbeMu.RLock()
		defer gatewayProbeMu.RUnlock()
		return append([]string(nil), gatewayProbeIPs...)
	}
	triggerGatewayProbe := func() {
		select {
		case gatewayProbeTrigger <- struct{}{}:
		default:
		}
	}

	// Initialize WebSocket client (Control connection)
	// Pass public key and private key to the client
	wsClient := ws.NewClient(cfg, publicKey, privateKey)
	wsClient.SetConfigUpdateCallback(func(config ws.AgentConfig) {
		slog.Info("Received configuration update",
			"gateways_count", len(config.Gateways),
			"tunnels_count", len(config.Tunnels),
		)

		// Extract virtual IPs from tunnels (one per tunnel)
		var virtualIPs []string
		for _, t := range config.Tunnels {
			if t.AgentIP != "" {
				virtualIPs = append(virtualIPs, t.AgentIP)
			}
		}

		if len(virtualIPs) == 0 {
			slog.Warn("No tunnels with AgentIP configured, skipping WireGuard setup")
			return
		}

		// Collect Gateway tunnel IPs that the Agent can probe through WireGuard.
		// A short Agent->Gateway connection refreshes the Gateway's learned peer
		// endpoint after Gateway restarts or peer replacement.
		var probeIPs []string
		seenProbeIPs := map[string]struct{}{}
		for _, t := range config.Tunnels {
			for _, gw := range t.GatewayIPs {
				if gw.IP == "" {
					continue
				}
				if _, ok := seenProbeIPs[gw.IP]; ok {
					continue
				}
				seenProbeIPs[gw.IP] = struct{}{}
				probeIPs = append(probeIPs, gw.IP)
			}
		}
		setGatewayProbeIPs(probeIPs)

		// Build gateway peers with allowedIPs from config
		var gateways []wireguard.GatewayPeer
		for _, gw := range config.Gateways {
			peer := wireguard.GatewayPeer{
				PublicKey:  gw.WireguardPublicKey,
				Endpoint:   gw.Endpoint,
				AllowedIPs: gw.AllowedIPs,
			}
			gateways = append(gateways, peer)
		}

		// Initialize or update WireGuard device
		if wgDevice == nil {
			// First time initialization
			wgConfig := &wireguard.DeviceConfig{
				PrivateKey: privateKey,
				VirtualIPs: virtualIPs,
				Gateways:   gateways,
			}

			device, err := wireguard.NewDevice(wgConfig)
			if err != nil {
				slog.Error("Failed to create WireGuard device", "error", err)
			} else {
				wgDevice = device
				slog.Info("WireGuard device initialized", "public_key", wgDevice.PublicKey(), "virtual_ips", virtualIPs)
			}
		} else {
			// Update existing device (gateway peers only for now)
			if err := wgDevice.UpdateGateways(gateways); err != nil {
				slog.Error("Failed to update WireGuard gateways", "error", err)
			} else {
				slog.Info("Updated WireGuard gateways", "count", len(gateways))
			}
		}

		if wgDevice != nil {
			gatewayProbeOnce.Do(func() {
				go runGatewayEndpointProbeLoop(ctx, wgDevice.Net(), getGatewayProbeIPs, gatewayProbeTrigger)
			})
			triggerGatewayProbe()
		}

		// Initialize local proxy if not yet started (only if WireGuard device was successfully created)
		// Note: The proxy listens on all virtual IPs via netstack
		if localProxy == nil && wgDevice != nil && len(virtualIPs) > 0 {
			// Use first virtual IP for the proxy address (netstack handles all IPs)
			proxyAddr := virtualIPs[0] + ":80"
			localProxy = proxy.NewLocalProxy(wgDevice.Net(), proxyAddr)

			// Start proxy in background
			go func() {
				if err := localProxy.Start(ctx); err != nil {
					slog.Error("Local proxy stopped", "error", err)
				}
			}()

			slog.Info("Local proxy started", "addr", proxyAddr, "virtual_ips", virtualIPs)
		}

		// Update tunnel mappings
		if localProxy != nil {
			var tunnels []proxy.TunnelMapping
			for _, t := range config.Tunnels {
				tunnel := proxy.TunnelMapping{
					ID:      t.ID,
					Domain:  t.Domain,
					Target:  t.Target,
					Enabled: t.Enabled,
				}
				tunnels = append(tunnels, tunnel)
			}
			localProxy.UpdateTunnels(tunnels)
		}

		// Initialize Exit Node proxies (only if WireGuard device is available)
		if wgDevice != nil {
			// Collect all gateway addresses across tunnels with exit node enabled,
			// so we fail over instead of being pinned to a single gateway.
			var httpGatewayAddrs, socksGatewayAddrs []string
			seenHTTP := map[string]struct{}{}
			seenSOCKS := map[string]struct{}{}
			for _, t := range config.Tunnels {
				for _, gw := range t.GatewayIPs {
					if t.HTTPProxyEnabled {
						addr := fmt.Sprintf("%s:%d", gw.IP, config.ProxyConfig.HTTPProxyPort)
						if _, ok := seenHTTP[addr]; !ok {
							seenHTTP[addr] = struct{}{}
							httpGatewayAddrs = append(httpGatewayAddrs, addr)
						}
					}
					if t.SOCKSProxyEnabled {
						addr := fmt.Sprintf("%s:%d", gw.IP, config.ProxyConfig.SOCKSProxyPort)
						if _, ok := seenSOCKS[addr]; !ok {
							seenSOCKS[addr] = struct{}{}
							socksGatewayAddrs = append(socksGatewayAddrs, addr)
						}
					}
				}
			}

			// Start/update HTTP proxy
			if len(httpGatewayAddrs) > 0 {
				listenAddr := fmt.Sprintf("%s:%d", config.ProxyConfig.LocalListenAddr, config.ProxyConfig.HTTPProxyPort)
				if exitHTTPProxy == nil {
					exitHTTPProxy = exitnode.NewLocalHTTPProxy(listenAddr, wgDevice.Net(), httpGatewayAddrs)
					go func() {
						if err := exitHTTPProxy.Start(ctx); err != nil {
							slog.Error("Exit HTTP proxy stopped", "error", err)
						}
					}()
				} else {
					exitHTTPProxy.UpdateGateways(httpGatewayAddrs)
				}
			} else if exitHTTPProxy != nil {
				exitHTTPProxy.Stop()
				exitHTTPProxy = nil
			}

			// Start/update SOCKS5 proxy
			if len(socksGatewayAddrs) > 0 {
				listenAddr := fmt.Sprintf("%s:%d", config.ProxyConfig.LocalListenAddr, config.ProxyConfig.SOCKSProxyPort)
				if exitSOCKS5Proxy == nil {
					exitSOCKS5Proxy = exitnode.NewLocalSOCKS5Proxy(listenAddr, wgDevice.Net(), socksGatewayAddrs)
					go func() {
						if err := exitSOCKS5Proxy.Start(ctx); err != nil {
							slog.Error("Exit SOCKS5 proxy stopped", "error", err)
						}
					}()
				} else {
					exitSOCKS5Proxy.UpdateGateways(socksGatewayAddrs)
				}
			} else if exitSOCKS5Proxy != nil {
				exitSOCKS5Proxy.Stop()
				exitSOCKS5Proxy = nil
			}
		}
	})

	// Connect to Control server
	if err := wsClient.Connect(); err != nil {
		log.Fatalf("Failed to connect to Control: %v", err)
	}
	defer wsClient.Close()

	// TODO: Initialize WireGuard + netstack
	// wg, err := wireguard.NewDevice(cfg)
	// if err != nil {
	// 	log.Fatalf("Failed to create WireGuard device: %v", err)
	// }
	// defer wg.Close()

	// TODO: Initialize local proxy
	// proxy, err := proxy.NewLocalProxy(cfg)
	// if err != nil {
	// 	log.Fatalf("Failed to create local proxy: %v", err)
	// }

	// TODO: Initialize Docker integration (if enabled)
	// if cfg.DockerEnabled {
	// 	dockerClient, err := docker.NewClient(cfg)
	// 	if err != nil {
	// 		slog.Warn("Failed to create Docker client", "error", err)
	// 	} else {
	// 		go dockerClient.Watch(ctx)
	// 	}
	// }

	slog.Info("Agent started successfully")

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	slog.Info("Shutting down Agent")
	cancel()

	// Graceful shutdown
	if exitHTTPProxy != nil {
		exitHTTPProxy.Stop()
	}
	if exitSOCKS5Proxy != nil {
		exitSOCKS5Proxy.Stop()
	}
	if wgDevice != nil {
		wgDevice.Close()
	}
	if localProxy != nil {
		localProxy.Shutdown()
	}

	fmt.Println("Agent stopped")
}

// loadOrCreateKeys returns (private, public) WireGuard keys.
// Priority: env/flag -> persisted file -> new generate (and persist).
func loadOrCreateKeys(privateFromConfig string) (string, string, error) {
	const keyFile = "wireguard.key"

	// 1) Use provided private key if set
	if strings.TrimSpace(privateFromConfig) != "" {
		pub, err := wireguard.DerivePublicKey(strings.TrimSpace(privateFromConfig))
		if err != nil {
			return "", "", fmt.Errorf("invalid provided private key: %w", err)
		}
		return strings.TrimSpace(privateFromConfig), pub, nil
	}

	// 2) Try to load from file
	if data, err := os.ReadFile(keyFile); err == nil {
		priv := strings.TrimSpace(string(data))
		pub, err := wireguard.DerivePublicKey(priv)
		if err == nil {
			slog.Info("Loaded WireGuard key from file", "path", filepath.Clean(keyFile))
			return priv, pub, nil
		}
		slog.Warn("Existing key file is invalid, regenerating", "path", filepath.Clean(keyFile), "error", err)
	}

	// 3) Generate new and persist
	priv, pub, err := wireguard.GenerateKeyPair()
	if err != nil {
		return "", "", err
	}
	if writeErr := os.WriteFile(keyFile, []byte(priv+"\n"), 0600); writeErr != nil {
		slog.Warn("Failed to persist WireGuard key", "path", filepath.Clean(keyFile), "error", writeErr)
	} else {
		slog.Info("Generated new WireGuard key and saved", "path", filepath.Clean(keyFile))
	}
	return priv, pub, nil
}

func runGatewayEndpointProbeLoop(
	ctx context.Context,
	dialer wireguard.EndpointDialer,
	getGatewayIPs func() []string,
	trigger <-chan struct{},
) {
	const interval = 15 * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	probe := func(reason string) {
		ips := getGatewayIPs()
		if len(ips) == 0 {
			return
		}
		results := wireguard.ProbeGatewayEndpoints(
			ctx,
			dialer,
			ips,
			wireguard.DefaultGatewayProbePort,
			wireguard.DefaultGatewayProbeTimeout,
		)
		failures := 0
		for _, result := range results {
			if result.Error != nil {
				failures++
				slog.Debug("Gateway endpoint probe failed", "addr", result.Address, "reason", reason, "error", result.Error)
			}
		}
		slog.Debug("Gateway endpoint probe completed", "reason", reason, "targets", len(results), "failures", failures)
	}

	probe("startup")
	for {
		select {
		case <-trigger:
			probe("config_update")
		case <-ticker.C:
			probe("periodic")
		case <-ctx.Done():
			return
		}
	}
}
