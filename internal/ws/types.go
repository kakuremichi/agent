package ws

// MessageType represents the type of WebSocket message
type MessageType string

const (
	// Auth
	TypeAuth        MessageType = "auth"
	TypeAuthSuccess MessageType = "auth_success"
	TypeAuthError   MessageType = "auth_error"

	// Heartbeat
	TypePing MessageType = "ping"
	TypePong MessageType = "pong"

	// Configuration
	TypeConfigUpdate MessageType = "config_update"
	TypeConfigAck    MessageType = "config_ack"

	// Status updates
	TypeStatusUpdate MessageType = "status_update"

	// Errors
	TypeError MessageType = "error"
)

// BaseMessage is the base structure for all messages
type BaseMessage struct {
	Type      MessageType `json:"type"`
	Timestamp int64       `json:"timestamp"`
}

// AuthMessage is sent by Agent to authenticate
type AuthMessage struct {
	BaseMessage
	APIKey     string `json:"apiKey"`
	ClientType string `json:"clientType"` // "agent"
	PublicKey  string `json:"publicKey,omitempty"` // WireGuard public key generated locally
	// Note: virtualIp is calculated by Control server from subnet, not sent by Agent
}

// AuthSuccessMessage is received upon successful authentication
type AuthSuccessMessage struct {
	BaseMessage
	ClientID   string `json:"clientId"`
	ClientType string `json:"clientType"`
}

// AuthErrorMessage is received upon authentication failure
type AuthErrorMessage struct {
	BaseMessage
	Error string `json:"error"`
}

// PingMessage for heartbeat
type PingMessage struct {
	BaseMessage
}

// PongMessage for heartbeat response
type PongMessage struct {
	BaseMessage
}

// StatusUpdateMessage is sent to update Agent status
type StatusUpdateMessage struct {
	BaseMessage
	Status   string                 `json:"status"` // "online", "offline", "error"
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ConfigUpdateMessage is received from Control with configuration
type ConfigUpdateMessage struct {
	BaseMessage
	Config AgentConfig `json:"config"`
}

// ConfigAckMessage is sent to acknowledge configuration receipt
type ConfigAckMessage struct {
	BaseMessage
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// ErrorMessage for error communication
type ErrorMessage struct {
	BaseMessage
	Error string `json:"error"`
}

// TunnelGatewayIP represents a gateway's IP for a specific tunnel
type TunnelGatewayIP struct {
	GatewayID string `json:"gatewayId"`
	IP        string `json:"ip"`
}

// AgentConfig represents Agent configuration from Control
type AgentConfig struct {
	Agent struct {
		ID                 string `json:"id"`
		Name               string `json:"name"`
		WireguardPublicKey string `json:"wireguardPublicKey"`
	} `json:"agent"`
	Gateways []struct {
		ID                 string   `json:"id"`
		Name               string   `json:"name"`
		WireguardPublicKey string   `json:"wireguardPublicKey"`
		PublicIP           string   `json:"publicIp"`
		Endpoint           string   `json:"endpoint"`
		AllowedIPs         []string `json:"allowedIPs"` // Gateway IPs for WireGuard peer (e.g., ["10.1.0.254/32", "10.2.0.254/32"])
	} `json:"gateways"`
	Tunnels []struct {
		ID                string            `json:"id"`
		Domain            string            `json:"domain"`
		Target            string            `json:"target"`
		Enabled           bool              `json:"enabled"`
		Subnet            string            `json:"subnet"`     // e.g., "10.1.0.0/24"
		AgentIP           string            `json:"agentIp"`    // e.g., "10.1.0.2"
		GatewayIPs        []TunnelGatewayIP `json:"gatewayIps"` // All gateway IPs for this tunnel
		HTTPProxyEnabled  bool              `json:"httpProxyEnabled"`
		SOCKSProxyEnabled bool              `json:"socksProxyEnabled"`
	} `json:"tunnels"`
	// Exit Node proxy configuration
	ProxyConfig struct {
		HTTPProxyPort   int    `json:"httpProxyPort"`
		SOCKSProxyPort  int    `json:"socksProxyPort"`
		LocalListenAddr string `json:"localListenAddr"` // "localhost" or "0.0.0.0"
	} `json:"proxyConfig"`
}
