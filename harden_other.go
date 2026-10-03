//go:build !unix

package main

// This file exists only so the portable helpers in harden.go can be unit tested on
// a non-unix host. The services are linux-only and must never be built for
// another platform, so every stub here fails closed rather than silently
// executing user code without isolation.

import (
	"errors"
	"syscall"
)

var errIsolationUnsupported = errors.New("sandbox isolation is only implemented on unix")

func sandboxExec() bool { return false }

func newJobDir(uid uint32) (string, error) { return "", errIsolationUnsupported }

func chownToSandbox(path string, uid uint32) error { return errIsolationUnsupported }

func selfPath() (string, error) { return "", errIsolationUnsupported }

func hardenProcAttr(uid uint32) *syscall.SysProcAttr { return &syscall.SysProcAttr{} }

func killProcessGroup(pid int) error { return errIsolationUnsupported }
