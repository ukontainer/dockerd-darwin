package iptables

import (
	"net"

	"github.com/vishvananda/netlink"
)

func DeleteConntrackEntries(nlh *netlink.Handle, ipv4List []net.IP, ipv6List []net.IP) (uint, uint, error) {
	return 0, 0, nil
}
