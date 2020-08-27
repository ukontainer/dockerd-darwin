/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package reaper

import (
	"os"
	"syscall"
	"time"

	proc "github.com/containerd/containerd/pkg/process"
	runc "github.com/containerd/go-runc"
	"github.com/sirupsen/logrus"
)


// ReapMore is additional reap process upon receipt of SIGCHLD.
// Since macOS doesn't raise SIGCHLD on orphaned children's exit,
// ReapMore polls the status of registered process and terminate it
// if it's already exited.

func ReapMore(processes map[string]proc.Process) error {
	var (
		exits []exit
		err error
	)

	now := time.Now()
	for _, p := range processes {
		process, err := os.FindProcess(p.Pid())
		if process != nil {
			err = process.Signal(syscall.Signal(0))
		}
		logrus.Debugf("checking pid=%d stat=%s", p.Pid(), err)
		// XXX: avoid duplicate exit call
		if (err != nil && !p.(*proc.Init).IsExited()) {
			exits = append(exits, exit{
				Pid:    p.Pid(),
				Status: 0, // XXX
			})

			logrus.Debugf("detect exited (no SIGCHILD?) pid=%d",
				p.Pid())
		}
	}

	Default.Lock()
	for c := range Default.subscribers {
		for _, e := range exits {
			c <- runc.Exit{
				Timestamp: now,
				Pid:       e.Pid,
				Status:    e.Status,
			}
		}
	}
	Default.Unlock()
	return err
}
