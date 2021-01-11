// +build !android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"strconv"
	"sync"
	"unsafe"
)

const (
	FD_ERR = -1
)

type NativeEndpoint struct {
	sync.Mutex
	dst net.UDPAddr
	src net.UDPAddr
}

type nativeBind struct {
	udpconn *net.UDPConn
}

var _ Endpoint = (*NativeEndpoint)(nil)
var _ Bind = (*nativeBind)(nil)

func CreateEndpoint(s string) (Endpoint, error) {
	var end NativeEndpoint
	addr, err := parseEndpoint(s)
	if err != nil {
		return nil, err
	}
	end.dst = *addr
	return &end, nil
}

func createBind(port uint16) (Bind, uint16, error) {
	var err error
	var bind nativeBind
	var laddr net.UDPAddr

	laddr.Port = int(port)
	bind.udpconn, err = net.ListenUDP("udp", &laddr)
	if err != nil {
		return nil, 0, err
	}
	if newladdr, ok := bind.udpconn.LocalAddr().(*net.UDPAddr); ok {
		port = uint16(newladdr.Port)
	}

	return &bind, port, nil
}

func (bind *nativeBind) Close() error {
	return bind.udpconn.Close()
}

func (bind *nativeBind) ReceiveIP(buff []byte) (int, Endpoint, error) {
	var end NativeEndpoint
	size, newDst, err := bind.udpconn.ReadFrom(buff)
	if err != nil {
		return 0, nil, err
	}
	if newDstUDP, ok := newDst.(*net.UDPAddr); ok {
		end.dst = *newDstUDP
	}
	return size, &end, err
}

func (bind *nativeBind) Send(buff []byte, end Endpoint) error {
	nend := end.(*NativeEndpoint)
	nend.Lock()
	_, err := bind.udpconn.WriteTo(buff, &nend.dst)
	nend.Unlock()
	return err
}

func (end *NativeEndpoint) SrcIP() net.IP {
	return end.src.IP
}

func (end *NativeEndpoint) DstIP() net.IP {
	return end.dst.IP
}

func (end *NativeEndpoint) DstToBytes() []byte {
	return (*[unsafe.Offsetof(end.dst.Port) + unsafe.Sizeof(end.dst.Port)]byte)(unsafe.Pointer(&end.dst))[:]
}

func (end *NativeEndpoint) SrcToString() string {
	return end.src.String()
}

func (end *NativeEndpoint) DstToString() string {
	return end.dst.String()
}

func (end *NativeEndpoint) ClearDst() {
	end.dst.IP = net.IPv4(0, 0, 0, 0)
}

func (end *NativeEndpoint) ClearSrc() {
	end.src.IP = net.IPv4(0, 0, 0, 0)
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
