//go:build linux

package processsecurity

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestHardenDisablesCoreDumpDumpableAndPrivilegeGainInChild(t *testing.T) {
	if os.Getenv("AIOPS_PROCESS_SECURITY_LAUNCHER") == "1" {
		runtime.LockOSThread()
		if err := prctlSet(prSetNoNewPrivs, 1); err != nil {
			os.Exit(80)
		}
		environment := make([]string, 0, len(os.Environ())+1)
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "AIOPS_PROCESS_SECURITY_LAUNCHER=") &&
				!strings.HasPrefix(entry, "AIOPS_PROCESS_SECURITY_HELPER=") {
				environment = append(environment, entry)
			}
		}
		environment = append(environment, "AIOPS_PROCESS_SECURITY_HELPER=1")
		if err := syscall.Exec(os.Args[0], []string{
			os.Args[0], "-test.run=^TestHardenDisablesCoreDumpDumpableAndPrivilegeGainInChild$",
		}, environment); err != nil {
			os.Exit(80)
		}
	}
	if os.Getenv("AIOPS_PROCESS_SECURITY_HELPER") == "1" {
		if err := Harden(); err != nil {
			os.Exit(81)
		}
		var limit syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &limit); err != nil || limit.Cur != 0 || limit.Max != 0 {
			os.Exit(82)
		}
		if dumpable, err := prctlGet(prGetDumpable); err != nil || dumpable != 0 {
			os.Exit(83)
		}
		if noNewPrivileges, err := prctlGet(prGetNoNewPrivs); err != nil || noNewPrivileges != 1 {
			os.Exit(84)
		}
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestHardenDisablesCoreDumpDumpableAndPrivilegeGainInChild$")
	command.Env = append(os.Environ(), "AIOPS_PROCESS_SECURITY_LAUNCHER=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("hardening helper failed: %v: %s", err, output)
	}
}
