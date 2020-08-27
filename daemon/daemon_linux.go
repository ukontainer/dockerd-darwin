package daemon // import "github.com/docker/docker/daemon"

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/container"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/libnetwork/resolvconf"
	"github.com/moby/sys/mount"
	"github.com/moby/sys/mountinfo"
	"github.com/docker/docker/pkg/fileutils"
	"github.com/docker/docker/pkg/mount"
	"github.com/docker/docker/pkg/sysinfo"
	"github.com/docker/libnetwork"
	"github.com/docker/libnetwork/drivers/bridge"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/netutils"
	"github.com/docker/libnetwork/resolvconf"
	lntypes "github.com/docker/libnetwork/types"
	rsystem "github.com/opencontainers/runc/libcontainer/system"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// On Linux, plugins use a static path for storing execution state,
// instead of deriving path from daemon's exec-root. This is because
// plugin socket files are created here and they cannot exceed max
// path length of 108 bytes.
func getPluginExecRoot(root string) string {
	return "/run/docker/plugins"
}

func (daemon *Daemon) cleanupMountsByID(id string) error {
	logrus.Debugf("Cleaning up old mountid %s: start.", id)
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer f.Close()

	return daemon.cleanupMountsFromReaderByID(f, id, mount.Unmount)
}

func (daemon *Daemon) cleanupMountsFromReaderByID(reader io.Reader, id string, unmount func(target string) error) error {
	if daemon.root == "" {
		return nil
	}
	var errs []string

	regexps := getCleanPatterns(id)
	sc := bufio.NewScanner(reader)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) >= 4 {
			if mnt := fields[4]; strings.HasPrefix(mnt, daemon.root) {
				for _, p := range regexps {
					if p.MatchString(mnt) {
						if err := unmount(mnt); err != nil {
							logrus.Error(err)
							errs = append(errs, err.Error())
						}
					}
				}
			}
		}
	}

	if err := sc.Err(); err != nil {
		return err
	}

	if len(errs) > 0 {
		return fmt.Errorf("Error cleaning up mounts:\n%v", strings.Join(errs, "\n"))
	}

	logrus.Debugf("Cleaning up old mountid %v: done.", id)
	return nil
}

// cleanupMounts umounts used by container resources and the daemon root mount
func (daemon *Daemon) cleanupMounts() error {
	if err := daemon.cleanupMountsByID(""); err != nil {
		return err
	}

	info, err := mountinfo.GetMounts(mountinfo.SingleEntryFilter(daemon.root))
	if err != nil {
		return errors.Wrap(err, "error reading mount table for cleanup")
	}

	if len(info) < 1 {
		// no mount found, we're done here
		return nil
	}

	// `info.Root` here is the root mountpoint of the passed in path (`daemon.root`).
	// The ony cases that need to be cleaned up is when the daemon has performed a
	//   `mount --bind /daemon/root /daemon/root && mount --make-shared /daemon/root`
	// This is only done when the daemon is started up and `/daemon/root` is not
	// already on a shared mountpoint.
	if !shouldUnmountRoot(daemon.root, info[0]) {
		return nil
	}

	unmountFile := getUnmountOnShutdownPath(daemon.configStore)
	if _, err := os.Stat(unmountFile); err != nil {
		return nil
	}

	logrus.WithField("mountpoint", daemon.root).Debug("unmounting daemon root")
	if err := mount.Unmount(daemon.root); err != nil {
		return err
	}
	return os.Remove(unmountFile)
}

func getCleanPatterns(id string) (regexps []*regexp.Regexp) {
	var patterns []string
	if id == "" {
		id = "[0-9a-f]{64}"
		patterns = append(patterns, "containers/"+id+"/shm")
	}
	patterns = append(patterns, "aufs/mnt/"+id+"$", "overlay/"+id+"/merged$", "zfs/graph/"+id+"$")
	for _, p := range patterns {
		r, err := regexp.Compile(p)
		if err == nil {
			regexps = append(regexps, r)
		}
	}
	return
}

func shouldUnmountRoot(root string, info *mountinfo.Info) bool {
	if !strings.HasSuffix(root, info.Root) {
		return false
	}
	return hasMountInfoOption(info.Optional, sharedPropagationOption)
}

// setupResolvConf sets the appropriate resolv.conf file if not specified
// When systemd-resolved is running the default /etc/resolv.conf points to
// localhost. In this case fetch the alternative config file that is in a
// different path so that containers can use it
// In all the other cases fallback to the default one
func setupResolvConf(config *config.Config) {
	if config.ResolvConf != "" {
		return
	}
	config.ResolvConf = resolvconf.Path()
}

func initBridgeDriver(controller libnetwork.NetworkController, config *config.Config) error {
	bridgeName := bridge.DefaultBridgeName
	if config.BridgeConfig.Iface != "" {
		bridgeName = config.BridgeConfig.Iface
	}
	netOption := map[string]string{
		bridge.BridgeName:         bridgeName,
		bridge.DefaultBridge:      strconv.FormatBool(true),
		netlabel.DriverMTU:        strconv.Itoa(config.Mtu),
		bridge.EnableIPMasquerade: strconv.FormatBool(config.BridgeConfig.EnableIPMasq),
		bridge.EnableICC:          strconv.FormatBool(config.BridgeConfig.InterContainerCommunication),
	}

	// --ip processing
	if config.BridgeConfig.DefaultIP != nil {
		netOption[bridge.DefaultBindingIP] = config.BridgeConfig.DefaultIP.String()
	}

	var (
		ipamV4Conf *libnetwork.IpamConf
		ipamV6Conf *libnetwork.IpamConf
	)

	ipamV4Conf = &libnetwork.IpamConf{AuxAddresses: make(map[string]string)}

	nwList, nw6List, err := netutils.ElectInterfaceAddresses(bridgeName)
	if err != nil {
		return errors.Wrap(err, "list bridge addresses failed")
	}

	nw := nwList[0]
	if len(nwList) > 1 && config.BridgeConfig.FixedCIDR != "" {
		_, fCIDR, err := net.ParseCIDR(config.BridgeConfig.FixedCIDR)
		if err != nil {
			return errors.Wrap(err, "parse CIDR failed")
		}
		// Iterate through in case there are multiple addresses for the bridge
		for _, entry := range nwList {
			if fCIDR.Contains(entry.IP) {
				nw = entry
				break
			}
		}
	}

	ipamV4Conf.PreferredPool = lntypes.GetIPNetCanonical(nw).String()
	hip, _ := lntypes.GetHostPartIP(nw.IP, nw.Mask)
	if hip.IsGlobalUnicast() {
		ipamV4Conf.Gateway = nw.IP.String()
	}

	if config.BridgeConfig.IP != "" {
		ipamV4Conf.PreferredPool = config.BridgeConfig.IP
		ip, _, err := net.ParseCIDR(config.BridgeConfig.IP)
		if err != nil {
			return err
		}
		ipamV4Conf.Gateway = ip.String()
	} else if bridgeName == bridge.DefaultBridgeName && ipamV4Conf.PreferredPool != "" {
		logrus.Infof("Default bridge (%s) is assigned with an IP address %s. Daemon option --bip can be used to set a preferred IP address", bridgeName, ipamV4Conf.PreferredPool)
	}

	if config.BridgeConfig.FixedCIDR != "" {
		_, fCIDR, err := net.ParseCIDR(config.BridgeConfig.FixedCIDR)
		if err != nil {
			return err
		}

		ipamV4Conf.SubPool = fCIDR.String()
	}

	if config.BridgeConfig.DefaultGatewayIPv4 != nil {
		ipamV4Conf.AuxAddresses["DefaultGatewayIPv4"] = config.BridgeConfig.DefaultGatewayIPv4.String()
	}

	var deferIPv6Alloc bool
	if config.BridgeConfig.FixedCIDRv6 != "" {
		_, fCIDRv6, err := net.ParseCIDR(config.BridgeConfig.FixedCIDRv6)
		if err != nil {
			return err
		}

		// In case user has specified the daemon flag --fixed-cidr-v6 and the passed network has
		// at least 48 host bits, we need to guarantee the current behavior where the containers'
		// IPv6 addresses will be constructed based on the containers' interface MAC address.
		// We do so by telling libnetwork to defer the IPv6 address allocation for the endpoints
		// on this network until after the driver has created the endpoint and returned the
		// constructed address. Libnetwork will then reserve this address with the ipam driver.
		ones, _ := fCIDRv6.Mask.Size()
		deferIPv6Alloc = ones <= 80

		if ipamV6Conf == nil {
			ipamV6Conf = &libnetwork.IpamConf{AuxAddresses: make(map[string]string)}
		}
		ipamV6Conf.PreferredPool = fCIDRv6.String()

		// In case the --fixed-cidr-v6 is specified and the current docker0 bridge IPv6
		// address belongs to the same network, we need to inform libnetwork about it, so
		// that it can be reserved with IPAM and it will not be given away to somebody else
		for _, nw6 := range nw6List {
			if fCIDRv6.Contains(nw6.IP) {
				ipamV6Conf.Gateway = nw6.IP.String()
				break
			}
		}
	}

	if config.BridgeConfig.DefaultGatewayIPv6 != nil {
		if ipamV6Conf == nil {
			ipamV6Conf = &libnetwork.IpamConf{AuxAddresses: make(map[string]string)}
		}
		ipamV6Conf.AuxAddresses["DefaultGatewayIPv6"] = config.BridgeConfig.DefaultGatewayIPv6.String()
	}

	v4Conf := []*libnetwork.IpamConf{ipamV4Conf}
	v6Conf := []*libnetwork.IpamConf{}
	if ipamV6Conf != nil {
		v6Conf = append(v6Conf, ipamV6Conf)
	}
	// Initialize default network on "bridge" with the same name
	_, err = controller.NewNetwork("bridge", "bridge", "",
		libnetwork.NetworkOptionEnableIPv6(config.BridgeConfig.EnableIPv6),
		libnetwork.NetworkOptionDriverOpts(netOption),
		libnetwork.NetworkOptionIpam("default", "", v4Conf, v6Conf, nil),
		libnetwork.NetworkOptionDeferIPv6Alloc(deferIPv6Alloc))
	if err != nil {
		return fmt.Errorf("Error creating default \"bridge\" network: %v", err)
	}
	return nil
}

func (daemon *Daemon) setupSeccompProfile() error {
	if daemon.configStore.SeccompProfile != "" {
		daemon.seccompProfilePath = daemon.configStore.SeccompProfile
		b, err := ioutil.ReadFile(daemon.configStore.SeccompProfile)
		if err != nil {
			return fmt.Errorf("opening seccomp profile (%s) failed: %v", daemon.configStore.SeccompProfile, err)
		}
		daemon.seccompProfile = b
	}
	return nil
}

func setupOOMScoreAdj(score int) error {
	f, err := os.OpenFile("/proc/self/oom_score_adj", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	stringScore := strconv.Itoa(score)
	_, err = f.WriteString(stringScore)
	if os.IsPermission(err) {
		// Setting oom_score_adj does not work in an
		// unprivileged container. Ignore the error, but log
		// it if we appear not to be in that situation.
		if !rsystem.RunningInUserNS() {
			logrus.Debugf("Permission denied writing %q to /proc/self/oom_score_adj", stringScore)
		}
		return nil
	}

	return err
}

// setupDaemonProcess sets various settings for the daemon's process
func setupDaemonProcess(config *config.Config) error {
	// setup the daemons oom_score_adj
	if err := setupOOMScoreAdj(config.OOMScoreAdjust); err != nil {
		return err
	}
	if err := setMayDetachMounts(); err != nil {
		logrus.WithError(err).Warn("Could not set may_detach_mounts kernel parameter")
	}
	return nil
}

func (daemon *Daemon) initCgroupsPath(path string) error {
	if path == "/" || path == "." {
		return nil
	}

	if daemon.configStore.CPURealtimePeriod == 0 && daemon.configStore.CPURealtimeRuntime == 0 {
		return nil
	}

	// Recursively create cgroup to ensure that the system and all parent cgroups have values set
	// for the period and runtime as this limits what the children can be set to.
	daemon.initCgroupsPath(filepath.Dir(path))

	mnt, root, err := cgroups.FindCgroupMountpointAndRoot("", "cpu")
	if err != nil {
		return err
	}
	// When docker is run inside docker, the root is based of the host cgroup.
	// Should this be handled in runc/libcontainer/cgroups ?
	if strings.HasPrefix(root, "/docker/") {
		root = "/"
	}

	path = filepath.Join(mnt, root, path)
	sysinfo := sysinfo.New(true)
	if err := maybeCreateCPURealTimeFile(sysinfo.CPURealtimePeriod, daemon.configStore.CPURealtimePeriod, "cpu.rt_period_us", path); err != nil {
		return err
	}
	return maybeCreateCPURealTimeFile(sysinfo.CPURealtimeRuntime, daemon.configStore.CPURealtimeRuntime, "cpu.rt_runtime_us", path)
}

func (daemon *Daemon) stats(c *container.Container) (*types.StatsJSON, error) {
	if !c.IsRunning() {
		return nil, errNotRunning(c.ID)
	}
	cs, err := daemon.containerd.Stats(context.Background(), c.ID)
	if err != nil {
		if strings.Contains(err.Error(), "container not found") {
			return nil, containerNotFound(c.ID)
		}
		return nil, err
	}
	s := &types.StatsJSON{}
	s.Read = cs.Read
	stats := cs.Metrics
	if stats.Blkio != nil {
		s.BlkioStats = types.BlkioStats{
			IoServiceBytesRecursive: copyBlkioEntry(stats.Blkio.IoServiceBytesRecursive),
			IoServicedRecursive:     copyBlkioEntry(stats.Blkio.IoServicedRecursive),
			IoQueuedRecursive:       copyBlkioEntry(stats.Blkio.IoQueuedRecursive),
			IoServiceTimeRecursive:  copyBlkioEntry(stats.Blkio.IoServiceTimeRecursive),
			IoWaitTimeRecursive:     copyBlkioEntry(stats.Blkio.IoWaitTimeRecursive),
			IoMergedRecursive:       copyBlkioEntry(stats.Blkio.IoMergedRecursive),
			IoTimeRecursive:         copyBlkioEntry(stats.Blkio.IoTimeRecursive),
			SectorsRecursive:        copyBlkioEntry(stats.Blkio.SectorsRecursive),
		}
	}
	if stats.CPU != nil {
		s.CPUStats = types.CPUStats{
			CPUUsage: types.CPUUsage{
				TotalUsage:        stats.CPU.Usage.Total,
				PercpuUsage:       stats.CPU.Usage.PerCPU,
				UsageInKernelmode: stats.CPU.Usage.Kernel,
				UsageInUsermode:   stats.CPU.Usage.User,
			},
			ThrottlingData: types.ThrottlingData{
				Periods:          stats.CPU.Throttling.Periods,
				ThrottledPeriods: stats.CPU.Throttling.ThrottledPeriods,
				ThrottledTime:    stats.CPU.Throttling.ThrottledTime,
			},
		}
	}

	if stats.Memory != nil {
		raw := make(map[string]uint64)
		raw["cache"] = stats.Memory.Cache
		raw["rss"] = stats.Memory.RSS
		raw["rss_huge"] = stats.Memory.RSSHuge
		raw["mapped_file"] = stats.Memory.MappedFile
		raw["dirty"] = stats.Memory.Dirty
		raw["writeback"] = stats.Memory.Writeback
		raw["pgpgin"] = stats.Memory.PgPgIn
		raw["pgpgout"] = stats.Memory.PgPgOut
		raw["pgfault"] = stats.Memory.PgFault
		raw["pgmajfault"] = stats.Memory.PgMajFault
		raw["inactive_anon"] = stats.Memory.InactiveAnon
		raw["active_anon"] = stats.Memory.ActiveAnon
		raw["inactive_file"] = stats.Memory.InactiveFile
		raw["active_file"] = stats.Memory.ActiveFile
		raw["unevictable"] = stats.Memory.Unevictable
		raw["hierarchical_memory_limit"] = stats.Memory.HierarchicalMemoryLimit
		raw["hierarchical_memsw_limit"] = stats.Memory.HierarchicalSwapLimit
		raw["total_cache"] = stats.Memory.TotalCache
		raw["total_rss"] = stats.Memory.TotalRSS
		raw["total_rss_huge"] = stats.Memory.TotalRSSHuge
		raw["total_mapped_file"] = stats.Memory.TotalMappedFile
		raw["total_dirty"] = stats.Memory.TotalDirty
		raw["total_writeback"] = stats.Memory.TotalWriteback
		raw["total_pgpgin"] = stats.Memory.TotalPgPgIn
		raw["total_pgpgout"] = stats.Memory.TotalPgPgOut
		raw["total_pgfault"] = stats.Memory.TotalPgFault
		raw["total_pgmajfault"] = stats.Memory.TotalPgMajFault
		raw["total_inactive_anon"] = stats.Memory.TotalInactiveAnon
		raw["total_active_anon"] = stats.Memory.TotalActiveAnon
		raw["total_inactive_file"] = stats.Memory.TotalInactiveFile
		raw["total_active_file"] = stats.Memory.TotalActiveFile
		raw["total_unevictable"] = stats.Memory.TotalUnevictable

		if stats.Memory.Usage != nil {
			s.MemoryStats = types.MemoryStats{
				Stats:    raw,
				Usage:    stats.Memory.Usage.Usage,
				MaxUsage: stats.Memory.Usage.Max,
				Limit:    stats.Memory.Usage.Limit,
				Failcnt:  stats.Memory.Usage.Failcnt,
			}
		} else {
			s.MemoryStats = types.MemoryStats{
				Stats: raw,
			}
		}

		// if the container does not set memory limit, use the machineMemory
		if s.MemoryStats.Limit > daemon.machineMemory && daemon.machineMemory > 0 {
			s.MemoryStats.Limit = daemon.machineMemory
		}
	}

	if stats.Pids != nil {
		s.PidsStats = types.PidsStats{
			Current: stats.Pids.Current,
			Limit:   stats.Pids.Limit,
		}
	}

	return s, nil
}

// Remove default bridge interface if present (--bridge=none use case)
func removeDefaultBridgeInterface() {
	if lnk, err := netlink.LinkByName(bridge.DefaultBridgeName); err == nil {
		if err := netlink.LinkDel(lnk); err != nil {
			logrus.Warnf("Failed to remove bridge interface (%s): %v", bridge.DefaultBridgeName, err)
		}
	}
}

// RawSysInfo returns *sysinfo.SysInfo .
func (daemon *Daemon) RawSysInfo(quiet bool) *sysinfo.SysInfo {
	var opts []sysinfo.Opt
	if daemon.getCgroupDriver() == cgroupSystemdDriver {
		rootlesskitParentEUID := os.Getenv("ROOTLESSKIT_PARENT_EUID")
		if rootlesskitParentEUID != "" {
			groupPath := fmt.Sprintf("/user.slice/user-%s.slice", rootlesskitParentEUID)
			opts = append(opts, sysinfo.WithCgroup2GroupPath(groupPath))
		}
	}
	return sysinfo.New(quiet, opts...)
}
