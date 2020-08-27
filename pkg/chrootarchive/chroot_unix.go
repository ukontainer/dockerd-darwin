// +build !windows,!linux

package chrootarchive // import "github.com/docker/docker/pkg/chrootarchive"

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func chroot(path string) error {
	if err := unix.Chroot(path); err != nil {
		return err
	}
	return unix.Chdir("/")
}

func realChroot(path string) error {
	if err := unix.Chroot(path); err != nil {
		return fmt.Errorf("Error after fallback to chroot: %v", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("Error changing to new root after chroot: %v", err)
	}
	return nil
}
