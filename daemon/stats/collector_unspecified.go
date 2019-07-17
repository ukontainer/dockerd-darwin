// +build !darwin

package stats

import "golang.org/x/sys/unix"

func (s *Collector) getNumberOnlineCPUs() (uint32, error) {
	var cpuset unix.CPUSet
	err := unix.SchedGetaffinity(0, &cpuset)
	if err != nil {
		return 0, err
	}
	return uint32(cpuset.Count()), nil
}
