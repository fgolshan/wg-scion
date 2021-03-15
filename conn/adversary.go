/* Used to simulate different types of on-path adversaries.
   Works with native endpoints from conn_linux.go only.
*/

package conn

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/poly1305"

	"github.com/scionproto/scion/go/lib/sciond/pathprobe"
	"github.com/scionproto/scion/go/lib/snet"
)

// Constants from device/noise-protocol.go. Should be passed over to the respective adversaries properly instead.
const (
	SealedFingerprintSize     = sha256.Size + poly1305.TagSize
	MessageInitiationSize     = 148
	MessageResponseSize       = 92
	MessageCookieReplySize    = 64
	MessageInitiationMultSize = MessageInitiationSize + SealedFingerprintSize
)

const PathProbingTime = time.Second * 1

type Adversary interface {
	Init()

	getsDropped(e Endpoint, b []byte) (bool, error) // called only when endpoint is locked

	UpdatePaths(e Endpoint, ps map[string]snet.Path) error // never called when endpoint is locked
}

// This adversary lets all packets through. Should behave as the non-test version.
type GhostAdversary struct{}

func (adversary *GhostAdversary) Init() {
	return
}

func (adversary *GhostAdversary) getsDropped(end Endpoint, buffer []byte) (bool, error) {
	return false, nil
}

func (adversary *GhostAdversary) UpdatePaths(end Endpoint, paths map[string]snet.Path) error {
	return nil
}

// This adversary is on the first used outward path to each IA and blocks all WireGuard packets.
type SimpleAdversary struct {
	sync.Mutex
	blockedPaths map[string]snet.Path
}

func (adversary *SimpleAdversary) Init() {
	adversary.blockedPaths = make(map[string]snet.Path)
}

func (adversary *SimpleAdversary) getsDropped(end Endpoint, buffer []byte) (bool, error) {
	adversary.Lock()
	defer adversary.Unlock()
	nend := end.(*NativeEndpoint)

	ia := nend.dst.IA.String()
	path, err := nend.dst.GetPath()

	if err != nil {
		return false, err
	}

	if _, ok := adversary.blockedPaths[ia]; !ok {
		adversary.blockedPaths[ia] = path
		return true, nil
	}

	return Fingerprint(path) == Fingerprint(adversary.blockedPaths[ia]), nil
}

func (adversary *SimpleAdversary) UpdatePaths(end Endpoint, paths map[string]snet.Path) error {
	return nil
}

/* This adversary blocks all WireGuard packets on all but one outgoing path of an initiating peer for each destination IA.
   It's not intended for blocking traffic on responder paths or for long-run testing.
   The adversary tries to choose a safe path by probing (best effort). This slows down the multipath handshake.
*/
type AllButOneAdversary struct {
	sync.Mutex
	blockedPathSets map[string](map[string]snet.Path)
	safePaths       map[string]snet.Path
}

func (adversary *AllButOneAdversary) Init() {
	adversary.blockedPathSets = make(map[string](map[string]snet.Path))
	adversary.safePaths = make(map[string]snet.Path)
}

func (adversary *AllButOneAdversary) getsDropped(end Endpoint, buffer []byte) (bool, error) {
	adversary.Lock()
	defer adversary.Unlock()
	nend := end.(*NativeEndpoint)

	ia := nend.dst.IA.String()
	path, err := nend.dst.GetPath()
	if err != nil {
		return true, err
	}
	fp := Fingerprint(path)

	if adversary.blockedPathSets[ia] == nil {
		return true, nil
	}
	_, ok := adversary.blockedPathSets[ia][fp]
	return ok, nil
}

func chooseSafePath(paths map[string]snet.Path, ia string) (string, snet.Path, error) {
	pathList := make([]snet.Path, 0, len(paths))
	for _, p := range paths {
		pathList = append(pathList, p)
	}

	var path snet.Path
	var fp string

	prober, err := getProber(ia)
	if err != nil {
		return fp, path, err
	}
	ctx, _ := context.WithDeadline(context.Background(), time.Now().Add(PathProbingTime))
	pathList = pathprobe.FilterEmptyPaths(pathList)
	statusMap, err := prober.GetStatuses(ctx, pathList)
	if err != nil || len(statusMap) == 0 {
		return fp, path, err
	}

	var alivePath, timeoutPath snet.Path
	var aliveFp, timeoutFp string

	for fp, path = range paths {
		key := pathprobe.PathKey(path)
		status := statusMap[key]
		if status.Status == pathprobe.StatusAlive {
			aliveFp = fp
			alivePath = path
		}
		if status.Status == pathprobe.StatusTimeout {
			timeoutFp = fp
			timeoutPath = path
		}
	}
	if alivePath != nil {
		return aliveFp, alivePath, nil
	}
	if timeoutPath != nil {
		return timeoutFp, timeoutPath, nil
	}

	return fp, path, nil
}

func (adversary *AllButOneAdversary) UpdatePaths(end Endpoint, paths map[string]snet.Path) error {
	if end == nil {
		return errors.New("Adversary received nil endpoint with path update")
	}
	nend := end.(*NativeEndpoint)
	nend.RLock()
	defer nend.RUnlock()

	ia := nend.dst.IA.String()

	adversary.Lock()
	defer adversary.Unlock()

	if adversary.blockedPathSets[ia] == nil {
		adversary.blockedPathSets[ia] = make(map[string]snet.Path)
		for fp, p := range paths {
			adversary.blockedPathSets[ia][fp] = p
		}
		safePathFp, safePath, err := chooseSafePath(paths, ia)
		if err != nil || safePath == nil {
			adversary.blockedPathSets[ia] = nil
			return err
		}
		delete(adversary.blockedPathSets[ia], safePathFp)
		adversary.safePaths[ia] = safePath
		return nil
	}

	safePathFp := Fingerprint(adversary.safePaths[ia])
	adversary.safePaths[ia] = nil

	for fp, p := range paths {
		if fp == safePathFp {
			adversary.safePaths[ia] = p
			continue
		}
		adversary.blockedPathSets[ia][fp] = p
	}

	if adversary.safePaths[ia] == nil {
		safePathFp, safePath, err := chooseSafePath(paths, ia)
		if err != nil || safePath == nil {
			adversary.blockedPathSets[ia] = nil
			return err
		}
		delete(adversary.blockedPathSets[ia], safePathFp)
		adversary.safePaths[ia] = safePath
	}

	return nil
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
	adversary.once.Do(func() { adversary.wakeUp = 2 })
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
	return n == MessageInitiationSize || n == MessageResponseSize || n == MessageCookieReplySize || n == MessageInitiationMultSize
}

func (adversary *AllButOneAdvancedAdversary) getsDropped(end Endpoint, buffer []byte) (bool, error) {
	if isHandshakeMsgSize(len(buffer)) {
		return false, nil
	}
	return adversary.AllButOneAdversary.getsDropped(end, buffer)
}
