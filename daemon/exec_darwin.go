package daemon

import (
	"github.com/docker/docker/container"
	"github.com/docker/docker/daemon/exec"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func (daemon *Daemon) execSetPlatformOpt(c *container.Container, ec *exec.Config, p *specs.Process) error {
	p.User.Username = ec.User
	return nil
}
