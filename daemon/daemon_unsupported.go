// +build !linux,!freebsd,!windows, !darwin

package daemon // import "github.com/docker/docker/daemon"
import "github.com/docker/docker/daemon/config"

const platformSupported = false

func setupResolvConf(config *config.Config) {
}
