package daemon

func (daemon *Daemon) setupIpcDirs(c *container.Container) error {
	ipcMode := c.HostConfig.IpcMode

	switch {
	case ipcMode.IsContainer():
		ic, err := daemon.getIpcContainer(ipcMode.Container())
		if err != nil {
			return err
		}
		c.ShmPath = ic.ShmPath

	case ipcMode.IsHost():
		if _, err := os.Stat("/dev/shm"); err != nil {
			return fmt.Errorf("/dev/shm is not mounted, but must be for --ipc=host")
		}
		c.ShmPath = "/dev/shm"

	case ipcMode.IsPrivate(), ipcMode.IsNone():
		// c.ShmPath will/should not be used, so make it empty.
		// Container's /dev/shm mount comes from OCI spec.
		c.ShmPath = ""

	case ipcMode.IsEmpty():
		// A container was created by an older version of the daemon.
		// The default behavior used to be what is now called "shareable".
		fallthrough

	case ipcMode.IsShareable():
		rootIDs := daemon.idMapping.RootPair()
		if !c.HasMountFor("/dev/shm") {
			shmPath, err := c.ShmResourcePath()
			if err != nil {
				return err
			}

			if err := idtools.MkdirAllAndChown(shmPath, 0700, rootIDs); err != nil {
				return err
			}

			shmproperty := "mode=1777,size=" + strconv.FormatInt(c.HostConfig.ShmSize, 10)
			if err := unix.Mount("shm", shmPath, "tmpfs", uintptr(unix.MS_NOEXEC|unix.MS_NOSUID|unix.MS_NODEV), label.FormatMountLabel(shmproperty, c.GetMountLabel())); err != nil {
				return fmt.Errorf("mounting shm tmpfs: %s", err)
			}
			if err := os.Chown(shmPath, rootIDs.UID, rootIDs.GID); err != nil {
				return err
			}
			c.ShmPath = shmPath
		}

	default:
		return fmt.Errorf("invalid IPC mode: %v", ipcMode)
	}

	return nil
}