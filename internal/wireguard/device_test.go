package wireguard

import "testing"

func TestDeviceCloseIsIdempotent(t *testing.T) {
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	device, err := NewDevice(&DeviceConfig{
		PrivateKey: privateKey,
		VirtualIPs: []string{"10.255.0.2"},
	})
	if err != nil {
		t.Fatalf("NewDevice() error = %v", err)
	}

	if err := device.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
