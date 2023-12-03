package sabanote

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/alexflint/go-arg"
	"github.com/mackerelio/checkers"
	"github.com/mackerelio/golib/pluginutil"
	"github.com/mackerelio/mackerel-agent/config"
	"github.com/mackerelio/mackerel-client-go"
)

// XXX: better option name and description
type sabanoteOpts struct {
	Monitors   []string `arg:"-m,--monitor,separate,required" help:"monitor ID (accept multiple)" placeholder:"MONITOR_ID"`
	Service    string   `arg:"-s,--service,required" help:"target service" placeholder:"SERVICE"`
	Roles      []string `arg:"-r,--role,separate,required" help:"target role (accept multiple)" placeholder:"ROLE"`
	Host       string   `arg:"-H,--host" help:"host ID" placeholder:"HOST_ID"`
	Title      string   `arg:"--title" help:"annotation title" default:"Host <HOST> status when <ALERT> is alerted (<TIME>)" placeholder:"TITLE"`
	MemorySort bool     `arg:"--mem" help:"sort by memory size (sort by CPU% by default)"`
	Cmd        string   `arg:"-c,--cmd" help:"custom command path" placeholder:"CMD_PATH"`
	StateDir   string   `arg:"--state" help:"state file folder" placeholder:"DIR"`
	Before     int      `arg:"--before" help:"post the report N times before the alert occured (0-5)" default:"3" placeholder:"MINUTES"`
	After      int      `arg:"--after" help:"post the report N times after the alert occured (0-5)" default:"1" placeholder:"MINUTES"`
	AlertFreq  int      `arg:"--alert-frequency" help:"interval for querying the presence of alerts (0 (don't check an alert), 2-30)" default:"5" placeholder:"MINUTES"`
	Delay      int      `arg:"--delay" help:"delay seconds before running command (0-29)" default:"0" placeholder:"SECONDS"`
	Verbose    bool     `arg:"--verbose" help:"print steps to stderr (for debug)"`
	Test       bool     `arg:"-"`
}

var version string
var revision string

// interface implementation for go-arg
func (sabanoteOpts) Version() string {
	return fmt.Sprintf("version %s (rev %s)", version, revision)
}

func Do() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	ckr := opts.run()
	ckr.Name = "sabanote"
	ckr.Exit()
}

func parseArgs(args []string) (*sabanoteOpts, error) {
	var so sabanoteOpts
	p, _ := arg.NewParser(arg.Config{}, &so)
	err := p.Parse(args)

	switch {
	case err == arg.ErrHelp:
		p.WriteHelp(os.Stdout)
		os.Exit(0)
	case err == arg.ErrVersion:
		fmt.Println(so.Version())
		os.Exit(0)
	case err != nil:
		return &so, err
	}

	if so.Cmd != "" && !fileExists(so.Cmd) {
		err = fmt.Errorf("not found %s", so.Cmd)
	}

	if so.MemorySort && so.Cmd != "" {
		err = fmt.Errorf("both --mem and --cmd cannot be specified")
	}

	if so.AlertFreq != 0 && (so.AlertFreq < 2 || so.AlertFreq > 30) {
		err = fmt.Errorf("the value of --alert-frequency must be in the range 2 to 30, or 0")
	}

	if so.Before < 0 || so.Before > 5 {
		err = fmt.Errorf("the value of --before must be in the range 0 to 5")
	}

	if so.After < 0 || so.After > 5 {
		err = fmt.Errorf("the value of --after must be in the range 0 to 5")
	}

	if so.Delay < 0 || so.Delay > 29 {
		err = fmt.Errorf("the value of --delay must be in the range 0 to 29")
	}

	if so.StateDir == "" {
		so.StateDir = filepath.Join(pluginutil.PluginWorkDir(), "__sabanote")
	}

	return &so, err
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func (opts *sabanoteOpts) run() *checkers.Checker {
	apikey := os.Getenv("MACKEREL_APIKEY")
	apibase := os.Getenv("MACKEREL_APIBASE")

	timeOut := 5 * time.Second // quick give up

	conf, err := config.LoadConfig(config.DefaultConfig.Conffile)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("%v", err))
	}

	if apikey == "" {
		apikey = conf.Apikey
	}
	if apibase == "" {
		apibase = conf.Apibase
	}
	if apibase == "" || apikey == "" {
		return checkers.Unknown("not found apibase or apikey in " + config.DefaultConfig.Conffile)
	}

	if opts.Host == "" {
		id, err := conf.LoadHostID()
		if err != nil {
			return checkers.Unknown("not found host ID in this environment. Specify host ID by --host")
		}
		opts.Host = id
	}

	client, err := mackerel.NewClientWithOptions(apikey, apibase, false)
	client.HTTPClient.Timeout = timeOut
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("%v", err))
	}

	return handleInfo(client, opts)
}

func findLastAlertCheckedTime(db *sql.DB) (int64, error) {
	rows, err := db.Query("SELECT value FROM metainfo WHERE key = 'lastAlertChecked' LIMIT 1")
	var t int64
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var s string
		err = rows.Scan(&s)
		if err != nil {
			return 0, err
		}
		t, _ = strconv.ParseInt(s, 10, 64)
	}
	return t, nil
}

func updateLastAlertCheckedTime(db *sql.DB, now int64) error {
	_, err := db.Exec("INSERT OR REPLACE INTO metainfo VALUES ($1, $2)", "lastAlertChecked", now)
	return err
}

func findReport(db *sql.DB, time int64) (string, bool, error) {
	rows, err := db.Query("SELECT report, posted FROM reports WHERE time = $1", time)
	if err != nil {
		return "", false, err
	}

	var report string
	var posted int
	for rows.Next() {
		err = rows.Scan(&report, &posted)
		if err != nil {
			return "", false, err
		}
	}
	postedBool := false
	if posted == 1 {
		postedBool = true
	}
	return report, postedBool, nil
}

func createTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS reports(time INTEGER PRIMARY KEY NOT NULL, report TEXT NOT NULL, posted INTEGER DEFAULT 0);
		CREATE TABLE IF NOT EXISTS metainfo(key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)`)
	return err
}

func handleInfo(client *mackerel.Client, opts *sabanoteOpts) *checkers.Checker { // XXX: better name
	const retentionMinutes = 60 * 6 // keep 6 hours
	now := time.Now().Unix()

	err := os.MkdirAll(opts.StateDir, 0755)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("failed to create state folder: %v", err))
	}
	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "[info] state folder: %s\n", opts.StateDir)
	}

	db, err := sql.Open("sqlite", filepath.Join(opts.StateDir, "sabanote.db"))

	if err != nil {
		return checkers.Unknown(fmt.Sprintf("failed to create sabanote.db: %v", err))
	}
	defer db.Close()

	err = createTable(db)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("%v", err))
	}

	err = writeInfo(db, now, opts)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("%v", err))
	}

	lastCheckTime, err := findLastAlertCheckedTime(db)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("%v", err))
	}

	if opts.AlertFreq > 0 && lastCheckTime+int64(opts.AlertFreq*60) > now {
		if opts.Verbose {
			fmt.Fprintln(os.Stderr, "[info] cleanup")
		}
		err := vacuumDB(db, now, retentionMinutes)
		if err != nil {
			return checkers.Unknown(fmt.Sprintf("%v", err))
		}
		return checkers.Ok("running")
	} else {
		err := updateLastAlertCheckedTime(db, now)
		if err != nil {
			return checkers.Unknown(fmt.Sprintf("%v", err))
		}
	}
	if opts.AlertFreq == 0 {
		return checkers.Ok("running (recording only mode)")
	}

	connection, alerts, err := getAlerts(client, opts)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("%v", err))
	}
	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "[info] connection status: %v, alerts size: %v\n", connection, len(alerts))
	}

	alert, err := matchAlert(connection, alerts, opts)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("%v", err))
	}

	if alert != nil {
		if connection {
			err = postInfo(alert, client, db, opts)
			if err != nil {
				return checkers.Ok(fmt.Sprintf("post failure: %v", err))
			}
		} else {
			return checkers.Ok("connection failure")
		}
	}

	return checkers.Ok("running")
}

func getAlerts(client *mackerel.Client, opts *sabanoteOpts) (bool, []*mackerel.Alert, error) {
	const maxNumAlerts = 20 // XXX: takes max 20 alerts

	resp, err := client.FindWithClosedAlerts()
	if err != nil {
		switch err.(type) {
		case *url.Error:
			if opts.Verbose {
				fmt.Fprintf(os.Stderr, "[info] url.Error: %v\n", err)
			}
			return false, nil, nil // maybe connection problem, may be recovered
		default:
			return false, nil, err // *mackerel.APIError and something
		}
	}
	if resp.NextID != "" {
		for {
			if maxNumAlerts <= len(resp.Alerts) {
				break
			}
			nextResp, err := client.FindAlertsByNextID(resp.NextID)
			if err != nil {
				return false, nil, err
			}
			if opts.Verbose {
				fmt.Fprintln(os.Stderr, "[info] getting next alert pages")
			}
			resp.Alerts = append(resp.Alerts, nextResp.Alerts...)
			resp.NextID = nextResp.NextID
			if resp.NextID == "" {
				break
			}
			time.Sleep(1 * time.Second)
		}
	}
	if len(resp.Alerts) > maxNumAlerts {
		resp.Alerts = resp.Alerts[:maxNumAlerts]
	}
	return true, resp.Alerts, nil
}

func matchAlert(connection bool, alerts []*mackerel.Alert, opts *sabanoteOpts) (*mackerel.Alert, error) {
	if !connection {
		if opts.Verbose {
			fmt.Fprintln(os.Stderr, "[info] connection is dead")
		}
		return nil, nil
	}
	if opts.Verbose {
		fmt.Fprintln(os.Stderr, "[info] connection is alive")
	}
	for _, alert := range alerts {
		for _, monitor := range opts.Monitors {
			if alert.Type != "check" && monitor != alert.MonitorID { // XXX: check monitor has dynamic ID
				if opts.Verbose {
					fmt.Fprintf(os.Stderr, "[info] monitorID: %s != targetID: %s\n", alert.MonitorID, monitor)
				}
				continue
			}
			if alert.HostID == "" || alert.HostID == opts.Host {
				if opts.Verbose {
					fmt.Fprintf(os.Stderr, "[info] alert.HostID: %s, targetHost: %s\n", alert.HostID, opts.Host)
				}
				return alert, nil // XXX: avoid duplicate posting. but it should be reconsidered
			}
		}
	}
	return nil, nil
}

func writeInfo(db *sql.DB, now int64, opts *sabanoteOpts) error {
	// write
	var out []byte
	var err error

	if opts.Delay > 0 {
		time.Sleep(time.Duration(opts.Delay) * time.Second)
	}

	if opts.Cmd != "" {
		out, err = execCmd(opts.Verbose, opts.Cmd)
		if err != nil {
			return err
		}
	} else {
		if opts.Test {
			out = []byte(fmt.Sprintf("Result %d", now))
		} else {
			switch runtime.GOOS {
			case "linux":
				out, err = getPSInfo_linux(opts)
			case "darwin":
				out, err = getPSInfo_darwin(opts)
			case "windows":
				out, err = getPSInfo_windows(opts)
			default:
				err = fmt.Errorf("unsupported OS")
			}
		}
	}
	if err != nil {
		return err
	}

	_, err = db.Exec("INSERT OR REPLACE INTO reports(time, report) VALUES ($1, $2)", now, string(out))
	if err != nil {
		return err
	}
	return nil
}

func execCmd(verbose bool, name string, cmdargs ...string) ([]byte, error) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[info] execute: %s %s\n", name, cmdargs)
	}
	cmd := exec.Command(name, cmdargs...)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	if len(out) > 1023 {
		out = out[:1023]
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("command returns nothing")
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "[info] output: %s\n", string(out))
	}
	return out, nil
}

func getPSInfo_linux(opts *sabanoteOpts) ([]byte, error) {
	if opts.MemorySort {
		return execCmd(opts.Verbose, "/bin/sh", "-c", "ps axc o %cpu,%mem,time,command --sort -%mem | head -n 21")
	} else {
		return execCmd(opts.Verbose, "/bin/sh", "-c", "ps axc o %cpu,%mem,time,command --sort -%cpu | head -n 21")
	}
}

func getPSInfo_darwin(opts *sabanoteOpts) ([]byte, error) {
	if opts.MemorySort {
		return execCmd(opts.Verbose, "/bin/sh", "-c", "ps axc -o %cpu,%mem,time,command -m | head -n 21")
	} else {
		return execCmd(opts.Verbose, "/bin/sh", "-c", "ps axc -o %cpu,%mem,time,command -r | head -n 21")
	}
}

func getPSInfo_windows(opts *sabanoteOpts) ([]byte, error) {
	if opts.MemorySort {
		return execCmd(opts.Verbose, "powershell.exe", "-Command", "Get-Process | Sort-Object -Property WS -Descending | Select-Object -First 20 CPU,WS,ProcessName | Format-Table -AutoSize | Out-String -Stream | ?{$_ -ne \"\"}")
	} else {
		return execCmd(opts.Verbose, "powershell.exe", "-Command", "Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 20 CPU,WS,ProcessName | Format-Table -AutoSize | Out-String -Stream | ?{$_ -ne \"\"}")
	}
}

func replaceTitle(title string, alert *mackerel.Alert, opts *sabanoteOpts) string {
	title = strings.Replace(title, "<HOST>", opts.Host, -1)
	title = strings.Replace(title, "<ALERT>", alert.ID, -1)
	title = strings.Replace(title, "<TIME>", fmt.Sprintf("%v", time.Unix(alert.OpenedAt, 0)), -1)
	return title
}

func postInfo(alert *mackerel.Alert, client *mackerel.Client, db *sql.DB, opts *sabanoteOpts) error {
	countLimit := 10                // max posts per once running
	annotationDuration := int64(30) // set annotation endtime to time + 30 seconds

	rows, err := db.Query("SELECT time, report FROM reports WHERE posted = 0 ORDER BY time")
	if err != nil {
		return err
	}

	postCount := 0
	alertTime := alert.OpenedAt

	type report struct {
		Time   int64
		Report string
	}

	var reports []report

	for rows.Next() {
		r := &report{}
		err := rows.Scan(&r.Time, &r.Report)
		if err != nil {
			return err
		}

		if r.Time < alertTime-int64(opts.Before*60) || r.Time > alertTime+int64(opts.After*60) {
			continue
		}

		postCount++
		if postCount == countLimit {
			break
		}
		reports = append(reports, *r)
	}

	for i, r := range reports {
		if i > 0 && !opts.Test {
			time.Sleep(1 * time.Second)
		}

		title := replaceTitle(opts.Title, alert, opts)

		annotation := &mackerel.GraphAnnotation{
			Title:       title,
			Description: r.Report,
			From:        r.Time,
			To:          r.Time + annotationDuration,
			Service:     opts.Service,
			Roles:       opts.Roles,
		}

		_, err = client.CreateGraphAnnotation(annotation)
		if err != nil {
			return err
		}
		if opts.Verbose {
			fmt.Fprintf(os.Stderr, "[info] annotation: %v\n", annotation)
		}

		_, err := db.Exec("UPDATE reports SET posted=1 WHERE time = $1", r.Time)
		if err != nil {
			return err
		}
	}

	return nil
}

func vacuumDB(db *sql.DB, now int64, retentionMinutes int) error {
	_, err := db.Exec("DELETE FROM reports WHERE time < $1", now-int64(retentionMinutes*60))
	if err != nil {
		return err
	}

	return nil
}
