// +build !linux,!windows darwin

package libnetwork

import (
	"fmt"
	"net"
)

func (c *controller) cleanupServiceBindings(nid string) {
}

func (c *controller) addContainerNameResolution(nID, eID, containerName string, taskAliases []string, ip net.IP, method string) error {
	return nil
}

func (c *controller) deleteEndpointNameResolution(svcName, svcID, nID, eID, containerName string, vip net.IP, serviceAliases, taskAliases []string, ip net.IP, rmService, multipleEntries bool, method string) error {
	return nil
}

func (c *controller) cleanupServiceDiscovery(cleanupNID string) {}

func (c *controller) delContainerNameResolution(nID, eID, containerName string, taskAliases []string, ip net.IP, method string) error {
	return nil
}

func (c *controller) addServiceBinding(svcName, svcID, nID, eID, containerName string, vip net.IP, ingressPorts []*PortConfig, serviceAliases, taskAliases []string, ip net.IP, method string) error {
	return fmt.Errorf("not supported")
}

func (c *controller) rmServiceBinding(svcName, svcID, nID, eID, containerName string, vip net.IP, ingressPorts []*PortConfig, serviceAliases []string, taskAliases []string, ip net.IP, method string, deleteSvcRecords bool, fullRemove bool) error {
	return fmt.Errorf("not supported")
}

func (c *controller) getLBIndex(sid, nid string, ingressPorts []*PortConfig) int {
	return 0
}

func (sb *sandbox) populateLoadBalancers(ep *endpoint) {
}

func arrangeIngressFilterRule() {
}

func (n *network) rmLBBackend(ip net.IP, lb *loadBalancer, rmService bool, fullRemove bool) {
}

// Add loadbalancer backend to the loadbalncer sandbox for the network.
// If needed add the service as well.
func (n *network) addLBBackend(ip net.IP, lb *loadBalancer) {
}
