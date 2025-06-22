package main

import (
	"fmt"
	"os"

	"github.com/arch-mage/mdb"
	"github.com/spf13/cobra"
)

var (
	mdbFilepath string
)

const version = "0.0.1"
const ASCII_ART = `

        \    /\
 mdbls   )  ( ')
  ---   (  /  )
 ~djnn   \(__)|         v0.0.1

------------------------------------------------
      simple cli to find out which columns of
         a .mdb file are worth looking at

       ===> evil.djnn.sh/djnn/mdb-ls  <===
------------------------------------------------

`

var rootCmd = &cobra.Command{
	Use:   "mdb-ls",
	Short: "simple cli to find out which columns of a .mdb file are worth looking at",
	Long:  ASCII_ART,
	Run: func(cmd *cobra.Command, args []string) {

		if mdbFilepath == "" {
			println("[!] mbdFilepath is not specified.")
			os.Exit(1)
		}

		file, err := os.Open(mdbFilepath)
		if err != nil {
			panic(err)
		}
		defer file.Close()

		tables, err := mdb.Tables(file)
		if err != nil {
			panic(err)
		}

		fmt.Printf("[+] Found %d tables....\n", len(tables))
		for _, table := range tables {

			if table.Sys {
				println("SYS table found....skipping")
				continue
			}

			if len(table.Columns) != 0 {
				fmt.Printf("\t%s => %d columns", table.Name, len(table.Columns))
			}
		}
	},
}

func main() {

	rootCmd.Flags().StringVarP(&mdbFilepath, "file", "f", "", ".mdb file path")
	rootCmd.ExecuteC()

}
