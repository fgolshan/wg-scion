/* Used to simulate different types of on-path adversaries
   Works with native endpoints from conn_linux.go only
*/

package conn

import (
	"sync"

	"github.com/scionproto/scion/go/lib/snet"
)

// Constants from device/noise-protocol.go. Should be passed over to the respective adversaries properly.
const (
	MessageInitiationSize  = 148
	MessageResponseSize    = 92
	MessageCookieReplySize = 64
)

type Adversary interface {
	getsDropped(e Endpoint, b []byte) (bool, error)

	UpdatePaths(ps map[string]snet.Path)
}

// This adversary lets all packets through. Should behave as the non-test version.
type GhostAdversary struct{}

func (adversary *GhostAdversary) getsDropped(end Endpoint, buffer []byte) (bool, error) {
	return false, nil
}

func (adversary *GhostAdversary) UpdatePaths(paths map[string]snet.Path) {
	return
}

// This adversary is on the first used outward path and blocks all WireGuard packets.
type SimpleAdversary struct {
	sync.Mutex
	blockedPath snet.Path
}

func (adversary *SimpleAdversary) getsDropped(end Endpoint, buffer []byte) (bool, error) {
	adversary.Lock()
	defer adversary.Unlock()
	nend := end.(*NativeEndpoint)
	if adversary.blockedPath == nil {
		path, err := nend.GetDstPath()
		adversary.blockedPath = path
		return true, err
	}
	path, err := nend.GetDstPath()
	return Fingerprint(path) == Fingerprint(adversary.blockedPath), err
}

func (adversary *SimpleAdversary) UpdatePaths(paths map[string]snet.Path) {
	return
}

/* This adversary blocks all WireGuard packets on all but one outgoing path of an initiating peer.
   It's not intended for blocking traffic on responder paths or for long-run testing. T
   The safe path is chosen as the last one when iterating through a map of exposed paths.
*/
type AllButOneAdversary struct {
	sync.Mutex
	blockedPaths map[string]snet.Path
	safePath     snet.Path
}

func (adversary *AllButOneAdversary) getsDropped(end Endpoint, buffer []byte) (bool, error) {
	adversary.Lock()
	defer adversary.Unlock()
	nend := end.(*NativeEndpoint)
	path, err := nend.GetDstPath()
	if err != nil {
		return true, err
	}
	fp := Fingerprint(path)
	if adversary.blockedPaths == nil {
		return true, nil
	}
	_, ok := adversary.blockedPaths[fp]
	return ok, nil
}

func (adversary *AllButOneAdversary) UpdatePaths(paths map[string]snet.Path) {
	adversary.Lock()
	defer adversary.Unlock()
	var fp string
	var p snet.Path
	if adversary.blockedPaths == nil {
		adversary.blockedPaths = make(map[string]snet.Path)
		for fp, p = range paths {
			adversary.blockedPaths[fp] = p
		}
		delete(adversary.blockedPaths, fp)
		adversary.safePath = p
		return
	}
	spfp := Fingerprint(adversary.safePath)
	adversary.safePath = nil
	for fp, p = range paths {
		if fp == spfp {
			adversary.safePath = p
			continue
		}
		adversary.blockedPaths[fp] = p
	}
	if adversary.safePath == nil {
		delete(adversary.blockedPaths, fp)
		adversary.safePath = p
	}
	return
}

// This adversary behaves the same as the AllButOneAdversary but the first packet on the safe path gets lost.
type AllButOneLossyAdversary struct {
	AllButOneAdversary
	hadLoss bool
}

func (adversary *AllButOneLossyAdversary) getsDropped(end Endpoint, buffer []byte) (bool, error) {
	drop, err := adversary.AllButOneAdversary.getsDropped(end, buffer)
	adversary.Lock()
	defer adversary.Unlock()
	if !drop && !adversary.hadLoss {
		adversary.hadLoss = true
		return true, err
	}
	return drop, err
}

// This adversary behaves the same as the SimpleAdversary but let's the first wakeUp number of packets through.
type LazyAdversary struct {
	SimpleAdversary
	once    sync.Once
	counter int
	wakeUp  int
}

func (adversary *LazyAdversary) getsDropped(end Endpoint, buffer []byte) (bool, error) {
	adversary.Lock()
	adversary.once.Do(func() { adversary.wakeUp = 3 })
	if adversary.counter < adversary.wakeUp {
		adversary.counter++
		adversary.Unlock()
		return false, nil
	}
	adversary.Unlock()
	return adversary.SimpleAdversary.getsDropped(end, buffer)
}

// This adversary behaves the same as the AllButOneAdversary but always lets handhshake messages through.
type AllButOneAdvancedAdversary struct {
	AllButOneAdversary
}

func isHandshakeMsgSize(n int) bool {
	return n == MessageInitiationSize || n == MessageResponseSize || n == MessageCookieReplySize
}

func (adversary *AllButOneAdvancedAdversary) getsDropped(end Endpoint, buffer []byte) (bool, error) {
	if isHandshakeMsgSize(len(buffer)) {
		return false, nil
	}
	return adversary.AllButOneAdversary.getsDropped(end, buffer)
}
