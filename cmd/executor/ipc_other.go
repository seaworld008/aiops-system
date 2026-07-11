//go:build !linux

package main

import "os"

func validAnonymousPipes(...*os.File) bool { return false }
