// +build darwin

package ns

import (
	"sync"

	"github.com/vishvananda/netlink"
)

var initOnce sync.Once
var initNl *netlink.Handle

func Init() {}

// NlHandle returns the netlink handler
func NlHandle() *netlink.Handle {
	initOnce.Do(Init)
	return initNl
}
