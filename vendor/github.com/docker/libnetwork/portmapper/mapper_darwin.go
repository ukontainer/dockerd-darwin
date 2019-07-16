// +build darwin

package portmapper

import (
	"net"
	"sync"

	"github.com/docker/libnetwork/iptables"
	"github.com/docker/libnetwork/portallocator"
)

// PortMapper manages the network address translation
type PortMapper struct {
	bridgeName string
	// udp:ip:port
	currentMappings map[string]*mapping
	lock            sync.Mutex

	proxyPath string

	Allocator *portallocator.PortAllocator
}

// SetIptablesChain sets the specified chain into portmapper
func (pm *PortMapper) SetIptablesChain(c *iptables.ChainInfo, bridgeName string) {}

// AppendForwardingTableEntry adds a port mapping to the forwarding table
func (pm *PortMapper) AppendForwardingTableEntry(proto string, sourceIP net.IP, sourcePort int, containerIP string, containerPort int) error {
	return nil
}

// DeleteForwardingTableEntry removes a port mapping from the forwarding table
func (pm *PortMapper) DeleteForwardingTableEntry(proto string, sourceIP net.IP, sourcePort int, containerIP string, containerPort int) error {
	return nil
}
