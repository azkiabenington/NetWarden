//go:build windows

package helperclient

import (
	"os/exec"
	"syscall"
)

func configureHelperCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
