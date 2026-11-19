//go:build !windows

package helperclient

import "os/exec"

func configureHelperCommand(*exec.Cmd) {}
