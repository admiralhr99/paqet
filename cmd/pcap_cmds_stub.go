//go:build !cgo

package main

import "github.com/spf13/cobra"

func addPcapCommands(_ *cobra.Command) {
	// ping and dump commands require pcap (CGO).
	// Build with CGO_ENABLED=1 to enable them.
}
