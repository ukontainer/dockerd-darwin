// +build darwin

package daemon

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/containers"
	coci "github.com/containerd/containerd/oci"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/container"
	"github.com/docker/docker/oci"
	"github.com/docker/docker/pkg/mount"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
)

const (
	sharedPropagationOption = "shared:"
	slavePropagationOption  = "master:"
)

// Get the source mount point of directory passed in as argument. Also return
// optional fields.
func getSourceMount(source string) (string, string, error) {
	// Ensure any symlinks are resolved.
	sourcePath, err := filepath.EvalSymlinks(source)
	if err != nil {
		return "", "", err
	}

	mi, err := mount.GetMounts(mount.ParentsFilter(sourcePath))
	if err != nil {
		return "", "", err
	}
	if len(mi) < 1 {
		return "", "", fmt.Errorf("Can't find mount point of %s", source)
	}

	// find the longest mount point
	var idx, maxlen int
	for i := range mi {
		if len(mi[i].Mountpoint) > maxlen {
			maxlen = len(mi[i].Mountpoint)
			idx = i
		}
	}
	return mi[idx].Mountpoint, mi[idx].Optional, nil
}

// hasMountinfoOption checks if any of the passed any of the given option values
// are set in the passed in option string.
func hasMountinfoOption(opts string, vals ...string) bool {
	for _, opt := range strings.Split(opts, " ") {
		for _, val := range vals {
			if strings.HasPrefix(opt, val) {
				return true
			}
		}
	}
	return false
}

// mergeUlimits merge the Ulimits from HostConfig with daemon defaults, and update HostConfig
// It will do nothing on non-Linux platform
func (daemon *Daemon) mergeUlimits(c *containertypes.HostConfig) {
	return
}

func (daemon *Daemon) createSpec(c *container.Container) (*specs.Spec, error) {
	var (
		opts []coci.SpecOpts
		s    = oci.DefaultSpec()
	)

	if c.BaseFS == nil {
		return nil, errors.New("populateCommonSpec: BaseFS of container " + c.ID + " is unexpectedly nil")
	}

	linkedEnv, err := daemon.setupLinkedContainers(c)
	if err != nil {
		return nil, err
	}
	s.Root = &specs.Root{
		Path:     c.BaseFS.Path(),
		Readonly: c.HostConfig.ReadonlyRootfs,
	}

	if err := c.SetupWorkingDirectory(daemon.idMapping.RootPair()); err != nil {
		return nil, err
	}
	cwd := c.Config.WorkingDir
	if len(cwd) == 0 {
		cwd = "/"
	}

	s.Process.Args = append([]string{c.Path}, c.Args...)

	s.Process.Cwd = cwd
	s.Process.Env = c.CreateDaemonEnvironment(c.Config.Tty, linkedEnv)
	s.Process.Terminal = c.Config.Tty

	return &s, coci.ApplyOpts(context.Background(), nil, &containers.Container{
		ID: c.ID,
	}, &s, opts...)
}
