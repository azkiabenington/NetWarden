//go:build windows

package main

import (
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"
)

func TestNotifyIconDataLayout(t *testing.T) {
	want := uintptr(976)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		want = 956
	}
	if got := unsafe.Sizeof(notifyIconData{}); got != want {
		t.Fatalf("sizeof(notifyIconData) = %d, want %d", got, want)
	}
}

func TestCopyUTF16TruncatesAndNullTerminates(t *testing.T) {
	var buf [6]uint16
	copyUTF16(buf[:], "NetWarden")
	if buf[5] != 0 {
		t.Fatalf("missing NUL terminator: %v", buf)
	}
	if got := string(utf16.Decode(buf[:5])); got != "NetWa" {
		t.Fatalf("got %q, want %q", got, "NetWa")
	}

	// Surrogate pair should not be split at the truncation boundary.
	var emojiBuf [3]uint16
	copyUTF16(emojiBuf[:], "a"+strings.Repeat("\U0001F6E1", 2))
	if emojiBuf[1] != 0 {
		t.Fatalf("split surrogate pair at boundary: %v", emojiBuf)
	}
}
