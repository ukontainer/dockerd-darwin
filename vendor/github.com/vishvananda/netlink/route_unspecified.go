// +build !linux

package netlink

func (r *Route) ListFlags() []string {
	return []string{}
}

func (n *NexthopInfo) ListFlags() []string {
	return []string{}
}

// RouteAdd will add a route to the system.
// Equivalent to: `ip route add $route`
// func (h *Handle) RouteAdd(route *Route) error {
// 	return nil
// }
