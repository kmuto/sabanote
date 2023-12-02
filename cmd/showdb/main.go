// Just show internal DB
package main

import (
	"fmt"
	"path/filepath"

	"github.com/akrylysov/pogreb"
	"github.com/mackerelio/golib/pluginutil"
)

func main() {
	stateDir := filepath.Join(pluginutil.PluginWorkDir(), "__sabanote")
	db, err := pogreb.Open(filepath.Join(stateDir, "sabanote-db"), nil)
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()

	it := db.Items()
	for {
		key, val, err := it.Next()
		if err == pogreb.ErrIterationDone {
			break
		}
		if err != nil {
			fmt.Println(err)
			break
		}
		fmt.Printf("KEY=%v\nVAL=%v\n", string(key), string(val))
	}
}
