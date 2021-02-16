/* Used to simulate different types of on-path adversaries
   Works with native endpoints from conn_linux.go only
*/

package conn

import (
	"sync"

	"github.com/scionproto/scion/go/lib/snet"
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

// This adversary blocks all WireGuard packets on all but one paths.
type AllButOneAdversary struct {
	sync.Mutex
	blockedPaths map[string]snet.Path
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
		adversary.blockedPaths = make(map[string]snet.Path)
		adversary.blockedPaths[fp] = path
		return true, nil
	}
	_, ok := adversary.blockedPaths[fp]
	return ok, nil
}

func (adversary *AllButOneAdversary) UpdatePaths(paths map[string]snet.Path) {
	adversary.Lock()
	defer adversary.Unlock()
	adversary.blockedPaths = make(map[string]snet.Path)
	var fp string
	var p snet.Path
	for fp, p = range paths {
		adversary.blockedPaths[fp] = p
	}
	delete(adversary.blockedPaths, fp)
	return
}
