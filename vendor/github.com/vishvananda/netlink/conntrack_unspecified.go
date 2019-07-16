// +build !linux

package netlink

import "net"

// ConntrackTableType Conntrack table for the netlink operation
type ConntrackTableType uint8

// Filter types
type ConntrackFilterType uint8

// InetFamily Family type
type InetFamily uint8

const (
	ConntrackOrigSrcIP = iota // -orig-src ip   Source address from original direction
	ConntrackOrigDstIP        // -orig-dst ip   Destination address from original direction
	ConntrackNatSrcIP         // -src-nat ip    Source NAT ip
	ConntrackNatDstIP         // -dst-nat ip    Destination NAT ip
	ConntrackNatAnyIP         // -any-nat ip    Source or destination NAT ip
)

// ConntrackFlow placeholder
type ConntrackFlow struct{}

// ConntrackFilter placeholder
type ConntrackFilter struct{}

// ConntrackTableList returns the flow list of a table of a specific family
// conntrack -L [table] [options]          List conntrack or expectation table
func ConntrackTableList(table ConntrackTableType, family InetFamily) ([]*ConntrackFlow, error) {
	return nil, ErrNotImplemented
}

// ConntrackTableFlush flushes all the flows of a specified table
// conntrack -F [table]            Flush table
// The flush operation applies to all the family types
func ConntrackTableFlush(table ConntrackTableType) error {
	return ErrNotImplemented
}

// ConntrackDeleteFilter deletes entries on the specified table on the base of the filter
// conntrack -D [table] parameters         Delete conntrack or expectation
func ConntrackDeleteFilter(table ConntrackTableType, family InetFamily, filter *ConntrackFilter) (uint, error) {
	return 0, ErrNotImplemented
}

// ConntrackTableList returns the flow list of a table of a specific family using the netlink handle passed
// conntrack -L [table] [options]          List conntrack or expectation table
func (h *Handle) ConntrackTableList(table ConntrackTableType, family InetFamily) ([]*ConntrackFlow, error) {
	return nil, ErrNotImplemented
}

// ConntrackTableFlush flushes all the flows of a specified table using the netlink handle passed
// conntrack -F [table]            Flush table
// The flush operation applies to all the family types
func (h *Handle) ConntrackTableFlush(table ConntrackTableType) error {
	return ErrNotImplemented
}

// ConntrackDeleteFilter deletes entries on the specified table on the base of the filter using the netlink handle passed
// conntrack -D [table] parameters         Delete conntrack or expectation
func (h *Handle) ConntrackDeleteFilter(table ConntrackTableType, family InetFamily, filter *ConntrackFilter) (uint, error) {
	return 0, ErrNotImplemented
}

// AddIP adds an IP to the conntrack filter
func (f *ConntrackFilter) AddIP(tp ConntrackFilterType, ip net.IP) error {
	return nil
}
