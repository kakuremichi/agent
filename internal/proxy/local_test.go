package proxy

import (
	"sync"
	"testing"
)

// TestLocalProxy_Tunnels_ConcurrentReadWrite exercises the RWMutex around
// the tunnels map. Regression test for feedback.md P1-2.
func TestLocalProxy_Tunnels_ConcurrentReadWrite(t *testing.T) {
	p := NewLocalProxy(nil, "127.0.0.1:0")
	p.UpdateTunnels([]TunnelMapping{
		{ID: "t1", Domain: "a.test", Target: "127.0.0.1:65535", Enabled: true},
	})

	var wg sync.WaitGroup
	const workers = 32
	const iterations = 500

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				p.UpdateTunnels([]TunnelMapping{
					{ID: "t1", Domain: "a.test", Target: "127.0.0.1:65535", Enabled: true},
					{ID: "t2", Domain: "b.test", Target: "127.0.0.1:65534", Enabled: i%2 == 0},
				})
			}
		}(w)
	}

	for r := 0; r < workers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = p.GetTunnels()
			}
		}()
	}

	wg.Wait()
}

func TestLocalProxy_UpdateTunnels_ReplacesMap(t *testing.T) {
	p := NewLocalProxy(nil, "127.0.0.1:0")

	p.UpdateTunnels([]TunnelMapping{
		{Domain: "a.test", Target: "127.0.0.1:1", Enabled: true},
		{Domain: "b.test", Target: "127.0.0.1:2", Enabled: true},
	})
	if got := len(p.GetTunnels()); got != 2 {
		t.Fatalf("expected 2 tunnels, got %d", got)
	}

	p.UpdateTunnels([]TunnelMapping{
		{Domain: "c.test", Target: "127.0.0.1:3", Enabled: true},
	})
	tunnels := p.GetTunnels()
	if _, ok := tunnels["a.test"]; ok {
		t.Error("old tunnel a.test should have been removed")
	}
	if _, ok := tunnels["c.test"]; !ok {
		t.Error("new tunnel c.test missing")
	}
}

func TestLocalProxy_DisabledTunnelsSkipped(t *testing.T) {
	p := NewLocalProxy(nil, "127.0.0.1:0")

	p.UpdateTunnels([]TunnelMapping{
		{Domain: "on.test", Target: "127.0.0.1:1", Enabled: true},
		{Domain: "off.test", Target: "127.0.0.1:2", Enabled: false},
	})
	tunnels := p.GetTunnels()
	if _, ok := tunnels["off.test"]; ok {
		t.Error("disabled tunnel should not be active")
	}
	if _, ok := tunnels["on.test"]; !ok {
		t.Error("enabled tunnel missing")
	}
}
