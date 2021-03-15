// +build !android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strconv"
	"sync"
	"unsafe"

	"github.com/netsec-ethz/scion-apps/pkg/appnet"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	FD_ERR = -1
)

type NativeEndpoint struct {
	sync.RWMutex
	dst snet.UDPAddr
	src snet.UDPAddr
}

type nativeBind struct {
	scionconn *snet.Conn
}

var _ Endpoint = (*NativeEndpoint)(nil)
var _ Bind = (*nativeBind)(nil)

func CreateEndpoint(s string) (Endpoint, error) {
	var end NativeEndpoint
	addr, err := snet.ParseUDPAddr(s)
	if err != nil {
		return nil, err
	}
	end.dst = *addr
	return &end, nil
}

func createBind(port uint16) (Bind, uint16, error) {
	var err error
	var bind nativeBind

	bind.scionconn, err = appnet.ListenPort(port)
	if err != nil {
		return nil, 0, err
	}
	if newladdr, ok := bind.scionconn.LocalAddr().(*net.UDPAddr); ok {
		port = uint16(newladdr.Port)
	}

	return &bind, port, nil
}

func (bind *nativeBind) Close() error {
	return bind.scionconn.Close()
}

func FingerprintRaw(path snet.Path) [sha256.Size]byte {
	return sha256.Sum256(path.Path().Raw)
}

func Fingerprint(path snet.Path) string {
	tmp := FingerprintRaw(path)
	return string(tmp[:])
}

func (bind *nativeBind) ReceiveIP(buff []byte) (int, Endpoint, error) {
	var end NativeEndpoint
	var size int
	var newDst net.Addr
	var err error

	for {
		size, newDst, err = bind.scionconn.ReadFrom(buff)
		if err != nil {
			if _, ok := err.(*snet.OpError); ok {
				continue
			}
			return 0, nil, err
		}
		break
	}

	if newDstUDP, ok := newDst.(*snet.UDPAddr); ok {
		end.dst = *newDstUDP
		path, _ := end.dst.GetPath()
		fmt.Printf("Receiving packet over: % x\n", Fingerprint(path))
	}
	return size, &end, err
}

func (bind *nativeBind) Send(buff []byte, end Endpoint, adv Adversary) error {
	nend := end.(*NativeEndpoint)
	nend.Lock()
	defer nend.Unlock()
	if nend.dst.Path.IsEmpty() {
		err := appnet.SetDefaultPath(&nend.dst)
		if err != nil {
			return err
		}
	}
	path, _ := nend.dst.GetPath()
	fmt.Printf("Sending packet over: % x\n", Fingerprint(path))
	if drop, err := adv.getsDropped(end, buff); drop {
		if err != nil {
			return err
		}
		fmt.Println("Adversary is dropping packet")
		return nil
	}
	_, err := bind.scionconn.WriteTo(buff, &nend.dst)
	return err
}

func GetNewEndpointOver(end Endpoint, path snet.Path) (Endpoint, error) {
	nend := end.(*NativeEndpoint)
	nend.RLock()
	newend, err := CreateEndpoint(nend.dst.String())
	nend.RUnlock()
	if err != nil {
		return newend, err
	}
	newend.SetDstPath(path)
	return newend, nil
}

func (end *NativeEndpoint) SrcIP() net.IP {
	end.RLock()
	defer end.RUnlock()
	return end.src.Host.IP
}

func (end *NativeEndpoint) DstIP() net.IP {
	end.RLock()
	defer end.RUnlock()
	return end.dst.Host.IP
}

func (end *NativeEndpoint) DstToBytes() []byte {
	end.RLock()
	defer end.RUnlock()
	ip := end.dst.Host.IP
	ipport := append(ip, (*[unsafe.Sizeof(end.dst.Host.Port)]byte)(unsafe.Pointer(&end.dst.Host.Port))[:]...)
	ia := (*[unsafe.Sizeof(end.dst.IA)]byte)(unsafe.Pointer(&end.dst.IA))[:]
	return append(ia, ipport...)

}

func (end *NativeEndpoint) SrcToString() string {
	end.RLock()
	defer end.RUnlock()
	return end.src.String()
}

func (end *NativeEndpoint) DstToString() string {
	end.RLock()
	defer end.RUnlock()
	return end.dst.String()
}

func (end *NativeEndpoint) ClearDst() {
	end.Lock()
	defer end.Unlock()
	end.dst = snet.UDPAddr{}
}

func (end *NativeEndpoint) ClearSrc() {
	end.Lock()
	defer end.Unlock()
	end.src = snet.UDPAddr{}
}

func (end *NativeEndpoint) GetDstPath() (snet.Path, error) {
	end.RLock()
	defer end.RUnlock()
	return end.dst.GetPath()
}

func (end *NativeEndpoint) SetDstPath(path snet.Path) {
	end.Lock()
	defer end.Unlock()
	appnet.SetPath(&end.dst, path)
}

func (end *NativeEndpoint) GetDstPaths() ([]snet.Path, error) {
	end.RLock()
	defer end.RUnlock()
	return appnet.QueryPaths(end.dst.IA)
}

func zoneToUint32(zone string) (uint32, error) {
	if zone == "" {
		return 0, nil
	}
	if intr, err := net.InterfaceByName(zone); err == nil {
		return uint32(intr.Index), nil
	}
	n, err := strconv.ParseUint(zone, 10, 32)
	return uint32(n), err
}
