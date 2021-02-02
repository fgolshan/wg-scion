/* Used to simulate different types of on-path adversaries
   Works with native endpoints from conn_linux.go only
*/

package device

import (
	"github.com/scionproto/scion/go/lib/snet"
	"golang.zx2c4.com/wireguard/conn"
)

type Adversary interface {
	getsDropped(e conn.Endpoint, b []byte) (bool, error)

	updatePaths(ps []snet.Path)
}

// This adversary is on the first chosen path and blocks all WireGuard packets
type SimpleAdversary struct {
	blockedPath snet.Path
}

func (adversary *SimpleAdversary) getsDropped(end conn.Endpoint, buffer []byte) (bool, error) {
	nend := end.(*conn.NativeEndpoint)
	nend.Lock()
	defer nend.Unlock()
	var err error
	if adversary.blockedPath == nil {
		adversary.blockedPath, err = nend.GetDstPath()
		return true, err
	}
	path, err := nend.GetDstPath()
	return snet.Fingerprint(path).String() == snet.Fingerprint(adversary.blockedPath).String(), err
}

func (adversary *SimpleAdversary) updatePaths(paths []snet.Path) {
	return
}
