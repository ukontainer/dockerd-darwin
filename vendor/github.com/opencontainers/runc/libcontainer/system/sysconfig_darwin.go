package system

import "github.com/tklauser/go-sysconf"

func GetClockTicks() int {
	clktck, _ := sysconf.Sysconf(sysconf.SC_CLK_TCK)
	return int(clktck)
}
