//go:build cgo

package main

import (
	"paqet/cmd/dump"
	"paqet/cmd/ping"

	"github.com/spf13/cobra"
)

func addPcapCommands(root *cobra.Command) {
	root.AddCommand(dump.Cmd)
	root.AddCommand(ping.Cmd)
}
