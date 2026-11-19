//go:build windows

package main

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32           = windows.NewLazySystemDLL("user32.dll")
	modShell32          = windows.NewLazySystemDLL("shell32.dll")
	procCreateWindowExW = modUser32.NewProc("CreateWindowExW")
	procDestroyWindow   = modUser32.NewProc("DestroyWindow")
	procLoadIconW       = modUser32.NewProc("LoadIconW")
	procShellNotifyIcon = modShell32.NewProc("Shell_NotifyIconW")

	notificationSequence atomic.Uint32
)

const (
	nimAdd    = 0x00000000
	nimDelete = 0x00000002

	nifIcon = 0x00000002
	nifTip  = 0x00000004
	nifInfo = 0x00000010

	niifInfo  = 0x00000001
	idiShield = 32518
)

// notifyIconData mirrors the Win32 NOTIFYICONDATAW structure.
type notifyIconData struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UTimeout         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     uintptr
}

// sendNativeNotification shows a native Windows balloon/toast notification
// directly via Shell_NotifyIconW without spawning powershell.exe or conhost.exe.
func sendNativeNotification(title, body string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	className, err := windows.UTF16PtrFromString("STATIC")
	if err != nil {
		return err
	}
	windowName, err := windows.UTF16PtrFromString(applicationName)
	if err != nil {
		return err
	}
	hwnd, _, createErr := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		0, 0, 0, 0, 0, 0, 0, 0, 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("create notification window: %w", createErr)
	}
	defer procDestroyWindow.Call(hwnd)

	icon, _, _ := procLoadIconW.Call(0, uintptr(idiShield))
	data := notifyIconData{
		CbSize:      uint32(unsafe.Sizeof(notifyIconData{})),
		HWnd:        hwnd,
		UID:         notificationSequence.Add(1),
		UFlags:      nifIcon | nifTip | nifInfo,
		HIcon:       icon,
		UTimeout:    5000,
		DwInfoFlags: niifInfo,
	}
	copyUTF16(data.SzTip[:], applicationName)
	copyUTF16(data.SzInfoTitle[:], title)
	copyUTF16(data.SzInfo[:], body)

	added, _, notifyErr := procShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&data)))
	if added == 0 {
		return fmt.Errorf("show Windows notification: %w", notifyErr)
	}
	time.Sleep(5500 * time.Millisecond)
	_, _, _ = procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&data)))
	return nil
}

func copyUTF16(dst []uint16, value string) {
	if len(dst) == 0 {
		return
	}
	encoded := utf16.Encode([]rune(value))
	limit := len(dst) - 1
	if len(encoded) > limit {
		if limit > 0 && encoded[limit-1] >= 0xd800 && encoded[limit-1] <= 0xdbff {
			limit--
		}
		encoded = encoded[:limit]
	}
	copy(dst, encoded)
	dst[len(encoded)] = 0
}
