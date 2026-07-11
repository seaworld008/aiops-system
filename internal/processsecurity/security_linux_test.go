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

func TestThreadStatusRequiresNoNewPrivilegesAndEmptyCapabilitySets(t *testing.T) {
	valid := []byte("Name:\taiops\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n")
	if !threadStatusHardened(valid) {
		t.Fatal("threadStatusHardened(valid) = false")
	}
	for _, replacement := range []string{
		"CapInh:\t0000000000000001", "CapPrm:\t0000000000000001",
		"CapEff:\t0000000000000001", "CapAmb:\t0000000000000001", "NoNewPrivs:\t0",
	} {
		candidate := strings.Replace(string(valid), strings.Split(replacement, "\t")[0]+"\t0000000000000000", replacement, 1)
		if strings.HasPrefix(replacement, "NoNewPrivs") {
			candidate = strings.Replace(string(valid), "NoNewPrivs:\t1", replacement, 1)
		}
		if threadStatusHardened([]byte(candidate)) {
			t.Fatalf("threadStatusHardened(%q) = true", replacement)
		}
	}
	if threadStatusHardened([]byte("NoNewPrivs:\t1\n")) {
		t.Fatal("threadStatusHardened(missing capabilities) = true")
	}
}
