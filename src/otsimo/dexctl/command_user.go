package main

import (
	"github.com/spf13/cobra"
)

var (
	cmdMakeAdmin = &cobra.Command{
		Use:     "make-admin",
		Short:   "Make a user admin",
		Long:    "Make a user admin",
		Example: `  dexctl make-admin --db-url=${DB_URL} 'info@otsimo.com'`,
		Run:     wrapRun(runMakeAdmin),
	}
)

func init() {
	rootCmd.AddCommand(cmdMakeAdmin)
}

func runMakeAdmin(cmd *cobra.Command, args []string) int {
	if len(args) != 1 {
		stderr("Provide an email address")
		return 2
	}
	err := getDriver().MakeAdmin(args[0])
	if err != nil {
		stderr("Failed to make user admin %v", err)
		return 1
	}
	stdout("success")
	return 0
}
