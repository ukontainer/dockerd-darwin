// +build !linux

package nl

import (
	"encoding/binary"
	"syscall"
)

const (
	// Family type definitions
	FAMILY_ALL  = syscall.AF_UNSPEC
	FAMILY_V4   = syscall.AF_INET
	FAMILY_V6   = syscall.AF_INET6
	FAMILY_MPLS = AF_MPLS
)

var SupportedNlFamilies = []int{}

func NativeEndian() binary.ByteOrder {
	return nil
}
