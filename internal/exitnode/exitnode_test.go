package exitnode

import (
	"sync"
	"testing"
)

// snapshotGateways returns the current gateway list under the same lock
// dialGateway() uses, so tests can exercise the concurrent read path
// without depending on an active netstack.
func (p *LocalHTTPProxy) snapshotGateways() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.gatewayAddrs...)
}

func (p *LocalSOCKS5Proxy) snapshotGateways() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.gatewayAddrs...)
}

// TestLocalHTTPProxy_UpdateGateways_Concurrent exercises the RWMutex in
// UpdateGateways + the snapshot read path used by dialGateway. Regression
// test for feedback.md P2-7 (multi-gateway failover).
func TestLocalHTTPProxy_UpdateGateways_Concurrent(t *testing.T) {
	p := NewLocalHTTPProxy("localhost:0", nil, []string{"10.1.0.254:8080"})

	var wg sync.WaitGroup
	const workers = 16
	const iterations = 1000

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				p.UpdateGateways([]string{
					"10.1.0.254:8080",
					"10.2.0.254:8080",
					"10.3.0.254:8080",
				})
			}
		}(w)
	}

	for r := 0; r < workers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = p.snapshotGateways()
			}
		}()
	}

	wg.Wait()
}

func TestLocalHTTPProxy_UpdateGateways_ReplacesList(t *testing.T) {
	p := NewLocalHTTPProxy("localhost:0", nil, []string{"a:1", "b:2"})
	p.UpdateGateways([]string{"c:3"})
	addrs := p.snapshotGateways()
	if len(addrs) != 1 || addrs[0] != "c:3" {
		t.Fatalf("expected [c:3], got %v", addrs)
	}
}

func TestLocalHTTPProxy_EmptyGatewaysError(t *testing.T) {
	p := NewLocalHTTPProxy("localhost:0", nil, nil)
	if _, _, err := p.dialGateway(); err == nil {
		t.Fatal("expected error when no gateways configured")
	}
}

func TestLocalSOCKS5Proxy_UpdateGateways_Concurrent(t *testing.T) {
	p := NewLocalSOCKS5Proxy("localhost:0", nil, []string{"10.1.0.254:1080"})

	var wg sync.WaitGroup
	const workers = 16
	const iterations = 1000

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				p.UpdateGateways([]string{
					"10.1.0.254:1080",
					"10.2.0.254:1080",
				})
			}
		}(w)
	}

	for r := 0; r < workers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = p.snapshotGateways()
			}
		}()
	}

	wg.Wait()
}

func TestLocalSOCKS5Proxy_EmptyGatewaysError(t *testing.T) {
	p := NewLocalSOCKS5Proxy("localhost:0", nil, nil)
	if _, _, err := p.dialGateway(); err == nil {
		t.Fatal("expected error when no gateways configured")
	}
}
