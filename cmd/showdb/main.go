// Just show internal DB
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/akrylysov/pogreb"
	"github.com/mackerelio/golib/pluginutil"
)

func main() {
	stateDir := filepath.Join(pluginutil.PluginWorkDir(), "__sabanote")
	if len(os.Args) > 1 {
		stateDir = os.Args[1]
	}
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

		var t time.Time
		if string(key) == "alertCheckedTime" {
			ti, _ := strconv.ParseInt(string(val), 10, 64)
			t = time.Unix(ti, 0)
		} else {
			ti, _ := strconv.ParseInt(string(key), 10, 64)
			t = time.Unix(ti, 0)
		}
		fmt.Printf("KEY=%v (%s)\nVAL=%v\n", string(key), t, string(val))
	}
}
