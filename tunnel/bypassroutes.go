/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"log"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type bypassRoute struct {
	luid        winipcfg.LUID
	destination netip.Prefix
	nextHop     netip.Addr
}

// addBypassRoutes pins each kill-switch exception to the route it would have used had the tunnel not been
// brought up, so that it keeps working even when the tunnel claims the default route.
func addBypassRoutes(conf *conf.Config, tunnelLUID winipcfg.LUID) (added []bypassRoute) {
	if conf.Interface.TableOff {
		return
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		var exceptions []netip.Prefix
		for _, prefix := range conf.Interface.KillSwitchExceptions {
			if (family == windows.AF_INET && prefix.Addr().Is4()) || (family == windows.AF_INET6 && prefix.Addr().Is6()) {
				exceptions = append(exceptions, prefix.Masked())
			}
		}
		if len(exceptions) == 0 {
			continue
		}

		routes, err := winipcfg.GetIPForwardTable2(family)
		if err != nil {
			log.Printf("Unable to read routing table for kill-switch exceptions: %v", err)
			continue
		}
		interfaces, err := winipcfg.GetIPInterfaceTable(family)
		if err != nil {
			log.Printf("Unable to read interface table for kill-switch exceptions: %v", err)
			continue
		}
		interfaceMetrics := make(map[winipcfg.LUID]uint32, len(interfaces))
		for i := range interfaces {
			interfaceMetrics[interfaces[i].InterfaceLUID] = interfaces[i].Metric
		}

		for _, exception := range exceptions {
			var best *winipcfg.MibIPforwardRow2
			var bestBits int
			var bestMetric uint32
			for i := range routes {
				route := &routes[i]
				if route.InterfaceLUID == tunnelLUID || route.Loopback {
					continue
				}
				destination := route.DestinationPrefix.Prefix()
				if !destination.IsValid() || destination.Bits() > exception.Bits() || !destination.Contains(exception.Addr()) {
					continue
				}
				metric := route.Metric + interfaceMetrics[route.InterfaceLUID]
				if best == nil || destination.Bits() > bestBits || (destination.Bits() == bestBits && metric < bestMetric) {
					best, bestBits, bestMetric = route, destination.Bits(), metric
				}
			}
			if best == nil {
				log.Printf("No existing route found for kill-switch exception %s", exception)
				continue
			}
			nextHop := best.NextHop.Addr()
			if !nextHop.IsValid() || nextHop.IsUnspecified() {
				continue // Already on-link; no route is needed.
			}
			err = best.InterfaceLUID.AddRoute(exception, nextHop, 0)
			if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
				continue
			} else if err != nil {
				log.Printf("Unable to add route for kill-switch exception %s via %s: %v", exception, nextHop, err)
				continue
			}
			log.Printf("Routing kill-switch exception %s via %s outside the tunnel", exception, nextHop)
			added = append(added, bypassRoute{best.InterfaceLUID, exception, nextHop})
		}
	}
	return
}

func removeBypassRoutes(routes []bypassRoute) {
	for _, route := range routes {
		err := route.luid.DeleteRoute(route.destination, route.nextHop)
		if err != nil && err != windows.ERROR_NOT_FOUND {
			log.Printf("Unable to remove route for kill-switch exception %s: %v", route.destination, err)
		}
	}
}
