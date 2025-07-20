package ca

import (
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "ca",
	Short: "Commands related to Certificate Authority management.",
}
