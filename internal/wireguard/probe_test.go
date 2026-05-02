package wireguard

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type fakeProbeDialer struct {
	calls []string
	err   error
}

func (d *fakeProbeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls = append(d.calls, network+" "+address)
	if d.err != nil {
		return nil, d.err
	}
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

func TestGatewayProbeAddresses(t *testing.T) {
	got := GatewayProbeAddresses([]string{"10.2.0.254", " 10.2.0.253 ", "10.2.0.254", ""}, 80)
	want := []string{"10.2.0.254:80", "10.2.0.253:80"}
	if len(got) != len(want) {
		t.Fatalf("expected %d addresses, got %d: %#v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("address %d: expected %q, got %q", i, want[i], got[i])
		}
	}
}

func TestProbeGatewayEndpointsDialsEachUniqueAddress(t *testing.T) {
	dialer := &fakeProbeDialer{}
	results := ProbeGatewayEndpoints(
		context.Background(),
		dialer,
		[]string{"10.2.0.254", "10.2.0.253", "10.2.0.254"},
		80,
		time.Second,
	)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	wantCalls := []string{"tcp 10.2.0.254:80", "tcp 10.2.0.253:80"}
	for i := range wantCalls {
		if dialer.calls[i] != wantCalls[i] {
			t.Fatalf("call %d: expected %q, got %q", i, wantCalls[i], dialer.calls[i])
		}
		if results[i].Error != nil {
			t.Fatalf("result %d expected nil error, got %v", i, results[i].Error)
		}
	}
}

func TestProbeGatewayEndpointsRecordsDialErrors(t *testing.T) {
	expectedErr := errors.New("dial failed")
	dialer := &fakeProbeDialer{err: expectedErr}
	results := ProbeGatewayEndpoints(context.Background(), dialer, []string{"10.2.0.254"}, 80, time.Second)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !errors.Is(results[0].Error, expectedErr) {
		t.Fatalf("expected %v, got %v", expectedErr, results[0].Error)
	}
}
