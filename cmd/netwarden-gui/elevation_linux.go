//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	coreapp "github.com/amdzy/NetWarden/internal/app"
	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/capture/helperclient"
)

func configureCapture(ctx context.Context, dependencies *coreapp.Dependencies) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate NetWarden executable: %w", err)
	}
	isRoot := os.Geteuid() == 0
	pkexec, pkexecErr := exec.LookPath("pkexec")
	dependencies.Open = func(interfaceName string) (capture.Driver, error) {
		driver, directErr := helperclient.Open(ctx, executable, "capture-helper", "--interface", interfaceName)
		if directErr == nil || isRoot {
			return driver, directErr
		}
		if pkexecErr != nil {
			return nil, errors.New("PolicyKit pkexec or setcap cap_net_raw,cap_net_admin=eip is required to request packet-capture privileges")
		}
		return helperclient.Open(ctx, pkexec, executable, "capture-helper", "--interface", interfaceName)
	}
	return nil
}

func platformAskpass() error {
	return errors.New("askpass mode is only supported on macOS")
}
