// +build !linux

package security

import "github.com/containerd/containerd/oci"

// WithInsecureSpec sets spec with All capability.
// Ignored in darwin port.
func WithInsecureSpec() oci.SpecOpts {
	return nil
}
