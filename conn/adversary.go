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

	UpdatePaths(ps []snet.Path)
}

// This adversary is on the first chosen path and blocks all WireGuard packets
type SimpleAdversary struct {
	sync.Mutex
	blockedPath snet.Path
}

func (adversary *SimpleAdversary) getsDropped(end Endpoint, buffer []byte) (bool, error) {
	adversary.Lock()
	defer adversary.Unlock()
	nend := end.(*NativeEndpoint)
	if adversary.blockedPath == nil {
		currpath, err := nend.GetDstPath()
		adversary.blockedPath = currpath
		return true, err
	}
	path, err := nend.GetDstPath()
	return Fingerprint(path.Path()) == Fingerprint(adversary.blockedPath.Path()), err
}

func (adversary *SimpleAdversary) UpdatePaths(paths []snet.Path) {
	return
}
