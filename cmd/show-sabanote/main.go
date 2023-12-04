package main

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

func main() {
	err := Do()
	if err != nil {
		fmt.Println(err)
	}
}

func Do() error {
	if len(os.Args) != 2 {
		fmt.Println("show-sabanote <dbfile>")
		return nil
	}
	file := os.Args[1]
	db, err := sql.Open("sqlite", file)
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.Query("SELECT value FROM metainfo WHERE key = 'lastAlertChecked' LIMIT 1")
	var t int64
	if err != nil {
		return err
	}
	for rows.Next() {
		var s string
		err = rows.Scan(&s)
		if err != nil {
			return err
		}
		t, _ = strconv.ParseInt(s, 10, 64)
	}
	fmt.Printf("Last Alert Check: %s\n\n", time.Unix(t, 0))

	rows, err = db.Query("SELECT time, report, posted FROM reports ORDER BY time")
	if err != nil {
		return err
	}

	var report string
	var posted int
	for rows.Next() {
		err = rows.Scan(&t, &report, &posted)
		if err != nil {
			return err
		}
		postedBool := false
		if posted == 1 {
			postedBool = true
		}

		fmt.Printf("%s posted=%v:\n%s\n", time.Unix(t, 0), postedBool, report)
	}

	return nil
}
