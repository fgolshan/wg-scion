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
	"github.com/scionproto/scion/go/lib/spath"
)

const (
	FD_ERR = -1
)

type NativeEndpoint struct {
	sync.Mutex
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

func Fingerprint(path spath.Path) string {
	hash := sha256.New()
	hash.Write(path.Raw)
	return string(hash.Sum(nil))
}

func (bind *nativeBind) ReceiveIP(buff []byte) (int, Endpoint, error) {
	var end NativeEndpoint
	size, newDst, err := bind.scionconn.ReadFrom(buff)
	if err != nil {
		return 0, nil, err
	}
	if newDstUDP, ok := newDst.(*snet.UDPAddr); ok {
		end.dst = *newDstUDP
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
	fmt.Println("Sending packet over: ", Fingerprint(nend.dst.Path))
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
	nend.Lock()
	defer nend.Unlock()
	newend, err := CreateEndpoint(nend.dst.String())
	if err != nil {
		return newend, err
	}
	newend.SetDstPath(path)
	return newend, nil
}

func (end *NativeEndpoint) SrcIP() net.IP {
	return end.src.Host.IP
}

func (end *NativeEndpoint) DstIP() net.IP {
	return end.dst.Host.IP
}

func (end *NativeEndpoint) DstToBytes() []byte {
	ipprt := (*[unsafe.Offsetof(end.dst.Host.Port) + unsafe.Sizeof(end.dst.Host.Port)]byte)(unsafe.Pointer(&end.dst.Host))[:]
	ia := (*[unsafe.Offsetof(end.dst.IA) + unsafe.Sizeof(end.dst.IA)]byte)(unsafe.Pointer(&end.dst))[:]
	return append(ia, ipprt...)
}

func (end *NativeEndpoint) SrcToString() string {
	return end.src.String()
}

func (end *NativeEndpoint) DstToString() string {
	return end.dst.String()
}

func (end *NativeEndpoint) ClearDst() {
	end.dst = snet.UDPAddr{}
}

func (end *NativeEndpoint) ClearSrc() {
	end.src = snet.UDPAddr{}
}

func (end *NativeEndpoint) GetDstPath() (snet.Path, error) {
	return end.dst.GetPath()
}

func (end *NativeEndpoint) SetDstPath(path snet.Path) {
	appnet.SetPath(&end.dst, path)
}

func (end *NativeEndpoint) GetDstPaths() ([]snet.Path, error) {
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
