// +build darwin

package daemon

import (
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/container"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/libnetwork"
)

// setupDaemonProcess sets various settings for the daemon's process
func setupDaemonProcess(config *config.Config) error {
	return nil
}

func (daemon *Daemon) setupSeccompProfile() error {
	return nil
}

func initBridgeDriver(controller libnetwork.NetworkController, config *config.Config) error {
	return nil
}

func (daemon *Daemon) stats(c *container.Container) (*types.StatsJSON, error) {
	return nil, nil
}
