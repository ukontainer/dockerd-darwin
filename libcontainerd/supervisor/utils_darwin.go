// +build darwin

package supervisor

import "syscall"

func containerdSysProcAttr() *syscall.SysProcAttr {
	return nil
}
