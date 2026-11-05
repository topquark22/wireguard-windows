/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"fmt"
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func (conf *Config) ToWgQuick() string {
	var output strings.Builder

	writeLine := func(c Comments, line string) {
		for _, before := range c.Before {
			output.WriteString(before)
			output.WriteByte('\n')
		}
		output.WriteString(line)
		if len(c.Suffix) != 0 {
			output.WriteByte(' ')
			output.WriteString(c.Suffix)
		}
		output.WriteByte('\n')
	}
	writeField := func(comments SectionComments, key string, present bool, value any) {
		c := comments.Lines[strings.ToLower(key)]
		if !present && len(c.Before) == 0 && len(c.Suffix) == 0 {
			return
		}
		writeLine(c, key+" = "+fmt.Sprint(value))
	}

	writeLine(conf.Interface.Comments.Header, "[Interface]")
	writeField(conf.Interface.Comments, "PrivateKey", true, conf.Interface.PrivateKey.String())
	writeField(conf.Interface.Comments, "ListenPort", conf.Interface.ListenPort > 0, conf.Interface.ListenPort)

	if len(conf.Interface.Addresses) > 0 {
		addrStrings := make([]string, len(conf.Interface.Addresses))
		for i, address := range conf.Interface.Addresses {
			addrStrings[i] = address.String()
		}
		writeField(conf.Interface.Comments, "Address", true, strings.Join(addrStrings, ", "))
	}

	if len(conf.Interface.DNS)+len(conf.Interface.DNSSearch) > 0 {
		addrStrings := make([]string, 0, len(conf.Interface.DNS)+len(conf.Interface.DNSSearch))
		for _, address := range conf.Interface.DNS {
			addrStrings = append(addrStrings, address.String())
		}
		addrStrings = append(addrStrings, conf.Interface.DNSSearch...)
		writeField(conf.Interface.Comments, "DNS", true, strings.Join(addrStrings, ", "))
	}

	writeField(conf.Interface.Comments, "MTU", conf.Interface.MTU > 0, conf.Interface.MTU)
	writeField(conf.Interface.Comments, "PreUp", len(conf.Interface.PreUp) > 0, conf.Interface.PreUp)
	writeField(conf.Interface.Comments, "PostUp", len(conf.Interface.PostUp) > 0, conf.Interface.PostUp)
	writeField(conf.Interface.Comments, "PreDown", len(conf.Interface.PreDown) > 0, conf.Interface.PreDown)
	writeField(conf.Interface.Comments, "PostDown", len(conf.Interface.PostDown) > 0, conf.Interface.PostDown)

	if len(conf.Interface.KillSwitchExceptions) > 0 {
		prefixStrings := make([]string, len(conf.Interface.KillSwitchExceptions))
		for i, prefix := range conf.Interface.KillSwitchExceptions {
			prefixStrings[i] = prefix.String()
		}
		writeField(conf.Interface.Comments, "KillSwitchExceptions", true, strings.Join(prefixStrings, ", "))
	}

	table := "auto"
	if conf.Interface.TableOff {
		table = "off"
	}
	writeField(conf.Interface.Comments, "Table", conf.Interface.TableOff, table)

	for _, peer := range conf.Peers {
		output.WriteByte('\n')
		writeLine(peer.Comments.Header, "[Peer]")
		writeField(peer.Comments, "PublicKey", true, peer.PublicKey.String())
		writeField(peer.Comments, "PresharedKey", !peer.PresharedKey.IsZero(), peer.PresharedKey.String())

		if len(peer.AllowedIPs) > 0 {
			addrStrings := make([]string, len(peer.AllowedIPs))
			for i, address := range peer.AllowedIPs {
				addrStrings[i] = address.String()
			}
			writeField(peer.Comments, "AllowedIPs", true, strings.Join(addrStrings, ", "))
		}

		writeField(peer.Comments, "Endpoint", !peer.Endpoint.IsEmpty(), peer.Endpoint.String())
		writeField(peer.Comments, "PersistentKeepalive", peer.PersistentKeepalive > 0, peer.PersistentKeepalive)
	}

	for _, comment := range conf.TrailingComments {
		output.WriteString(comment)
		output.WriteByte('\n')
	}
	return output.String()
}

func (config *Config) ToDriverConfiguration() (*driver.Interface, uint32) {
	preallocation := unsafe.Sizeof(driver.Interface{}) + uintptr(len(config.Peers))*unsafe.Sizeof(driver.Peer{})
	for i := range config.Peers {
		preallocation += uintptr(len(config.Peers[i].AllowedIPs)) * unsafe.Sizeof(driver.AllowedIP{})
	}
	var c driver.ConfigBuilder
	c.Preallocate(uint32(preallocation))
	c.AppendInterface(&driver.Interface{
		Flags:      driver.InterfaceHasPrivateKey | driver.InterfaceHasListenPort,
		ListenPort: config.Interface.ListenPort,
		PrivateKey: config.Interface.PrivateKey,
		PeerCount:  uint32(len(config.Peers)),
	})
	for i := range config.Peers {
		flags := driver.PeerHasPublicKey | driver.PeerHasPersistentKeepalive
		if !config.Peers[i].PresharedKey.IsZero() {
			flags |= driver.PeerHasPresharedKey
		}
		var endpoint winipcfg.RawSockaddrInet
		if !config.Peers[i].Endpoint.IsEmpty() {
			addr, err := netip.ParseAddr(config.Peers[i].Endpoint.Host)
			if err == nil {
				flags |= driver.PeerHasEndpoint
				endpoint.SetAddrPort(netip.AddrPortFrom(addr, config.Peers[i].Endpoint.Port))
			}
		}
		c.AppendPeer(&driver.Peer{
			Flags:               flags,
			PublicKey:           config.Peers[i].PublicKey,
			PresharedKey:        config.Peers[i].PresharedKey,
			PersistentKeepalive: config.Peers[i].PersistentKeepalive,
			Endpoint:            endpoint,
			AllowedIPsCount:     uint32(len(config.Peers[i].AllowedIPs)),
		})
		for j := range config.Peers[i].AllowedIPs {
			a := &driver.AllowedIP{Cidr: uint8(config.Peers[i].AllowedIPs[j].Bits())}
			copy(a.Address[:], config.Peers[i].AllowedIPs[j].Addr().AsSlice())
			if config.Peers[i].AllowedIPs[j].Addr().Is4() {
				a.AddressFamily = windows.AF_INET
			} else if config.Peers[i].AllowedIPs[j].Addr().Is6() {
				a.AddressFamily = windows.AF_INET6
			}
			c.AppendAllowedIP(a)
		}
	}
	return c.Interface()
}
