package conn

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/sciond/pathprobe"
)

const initTimeout = 1 * time.Second

func findSciond(ctx context.Context) (sciond.Connector, error) {
	address, ok := os.LookupEnv("SCION_DAEMON_ADDRESS")
	if !ok {
		address = sciond.DefaultAPIAddress
	}
	sciondConn, err := sciond.NewService(address).Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to SCIOND at %s (override with SCION_DAEMON_ADDRESS): %w", address, err)
	}
	return sciondConn, nil
}

// findAnyHostInLocalAS returns the IP address of some (infrastructure) host in the local AS.
func findAnyHostInLocalAS(ctx context.Context, sciondConn sciond.Connector) (net.IP, error) {
	addr, err := sciond.TopoQuerier{Connector: sciondConn}.UnderlayAnycast(ctx, addr.SvcCS)
	if err != nil {
		return nil, err
	}
	return addr.IP, nil
}

func getProber(ia string) (pathprobe.Prober, error) {
	var prober pathprobe.Prober
	ctx, cancel := context.WithTimeout(context.Background(), initTimeout)
	defer cancel()
	sciondConn, err := findSciond(ctx)
	if err != nil {
		return prober, err
	}
	localIA, err := sciondConn.LocalIA(ctx)
	if err != nil {
		return prober, err
	}
	hostInLocalAS, err := findAnyHostInLocalAS(ctx, sciondConn)
	if err != nil {
		return prober, err
	}
	IA, err := addr.IAFromString(ia)
	if err != nil {
		return prober, err
	}
	prober.DstIA = IA
	prober.LocalIA = localIA
	prober.LocalIP = hostInLocalAS
	return prober, nil
}
