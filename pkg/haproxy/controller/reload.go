/*
Copyright The Voyager Authors.

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

package controller

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/golang/glog"
	ps "github.com/mitchellh/go-ps"
	"github.com/pkg/errors"
)

const (
	haproxyConfig = "/etc/haproxy/haproxy.cfg"
	haproxyPID    = "/var/run/haproxy.pid"
	haproxySocket = "/var/run/haproxy.sock"
)

var haproxyDaemonMux sync.Mutex

func getHAProxyPid() (int, error) {
	checkDirectory()
	file, err := os.Open(haproxyPID)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var pid int
	_, err = fmt.Fscan(file, &pid)
	return pid, err
}

func checkDirectory() {
	s := "/var/run: "
	if files, err := ioutil.ReadDir("/var/run"); err != nil {
		glog.Error("Error during ls /var/run: " + err.Error())
	} else {
		for _, file := range files {
			s += file.Name() + " (" + strconv.FormatInt(file.Size(), 10) + ") - "
		}
		content, err := ioutil.ReadFile("/var/run/haproxy.pid")
		if err != nil {
			glog.Error("Error during cat /var/run/haproxy.pid: " + err.Error())
		} else {
			s += "haproxy.pid: " + string(content)
		}
		processes, err := ps.Processes()
		if err != nil {
			glog.Error("Error during ps: " + err.Error())
		} else {
			for _, p := range processes {
				if strings.Contains(strings.ToLower(p.Executable()), "haproxy") {
					s += " -> " + strconv.Itoa(p.Pid()) + " " + p.Executable()
				}
			}
		}
		glog.Info(s)
	}
}

func checkHAProxyDaemon() (int, error) {
	pid, err := getHAProxyPid()
	if err != nil {
		return 0, errors.Wrap(err, "error reading haproxy.pid file")
	}

	if process, err := ps.FindProcess(pid); err != nil {
		return 0, errors.Wrap(err, "failed to get haproxy daemon process")
	} else if process == nil {
		return 0, errors.Errorf("haproxy daemon not running (pid %d)", pid)
	}

	glog.Infof("haproxy daemon running (pid %d)", pid)
	return pid, nil
}

func checkHAProxyConfig() error {
	glog.Info("Checking haproxy config...")
	output, err := exec.Command("haproxy", "-c", "-f", haproxyConfig).CombinedOutput()
	if err != nil {
		return errors.Errorf("haproxy-check failed, reason: %s %s", string(output), err)
	}
	glog.Infof("haproxy-check: %s", string(output))
	return nil
}

func startHAProxy() error {
	if err := checkHAProxyConfig(); err != nil {
		return err
	}
	glog.Info("Starting haproxy...")

	output, err := exec.Command("haproxy", "-f", haproxyConfig, "-p", haproxyPID).CombinedOutput()
	if err != nil {
		return errors.Errorf("failed to start haproxy, reason: %s %s", string(output), err)
	}

	glog.Infof("haproxy started: %s", string(output))
	checkDirectory()
	return nil
}

func reloadHAProxy(pid int) error {
	if err := checkHAProxyConfig(); err != nil {
		return err
	}
	glog.Info("Reloading haproxy...")

	output, err := exec.Command(
		"haproxy",
		"-f", haproxyConfig,
		"-p", haproxyPID,
		"-x", haproxySocket,
		"-sf", strconv.Itoa(pid),
	).CombinedOutput()
	if err != nil {
		return errors.Errorf("failed to reload haproxy, reason: %s %s", string(output), err)
	}

	glog.Infof("haproxy reloaded: %s", string(output))
	checkDirectory()
	return nil
}

// reload if old haproxy daemon exists, otherwise start
func startOrReloadHaproxy() error {
	glog.Info("startOrReloadHaproxy: locking...")
	haproxyDaemonMux.Lock()
	glog.Info("startOrReloadHaproxy: locked!")
	defer haproxyDaemonMux.Unlock()
	if pid, err := checkHAProxyDaemon(); err != nil {
		return startHAProxy()
	} else {
		return reloadHAProxy(pid)
	}
}

// start haproxy if daemon doesn't exist, otherwise do nothing
func startHaproxyIfNeeded() {
	haproxyDaemonMux.Lock()
	defer haproxyDaemonMux.Unlock()
	if _, err := checkHAProxyDaemon(); err != nil {
		glog.Error(err)
		if err = startHAProxy(); err != nil {
			glog.Error(err)
		}
	}
}
