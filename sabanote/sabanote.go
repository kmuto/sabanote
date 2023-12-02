package sabanote

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/akrylysov/pogreb"
	"github.com/alexflint/go-arg"
	"github.com/mackerelio/checkers"
	"github.com/mackerelio/golib/pluginutil"
	"github.com/mackerelio/mackerel-agent/config"
	"github.com/mackerelio/mackerel-client-go"
	"github.com/mackerelio/mkr/format"
)

// XXX: better option name and description
type sabanoteOpts struct {
	Host       string   `arg:"-H,--host" help:"host ID" placeholder:"HOST_ID"`
	Monitors   []string `arg:"-m,--monitor,separate,required" help:"monitor ID (accept multiple)" placeholder:"MONITOR_ID"`
	Service    string   `arg:"-s,--service,required" help:"target service" placeholder:"SERVICE"`
	Roles      []string `arg:"-r,--role,required" help:"target role (accept multiple)" placeholder:"ROLE"`
	Title      string   `arg:"--title" help:"annotation title (default: 'Host HOST_ID')" placeholder:"TITLE"`
	MemorySort bool     `arg:"--mem" help:"sort by memory size (sort by CPU% by default)"`
	Cmd        string   `arg:"-c,--cmd" help:"custom command path" placeholder:"CMD_PATH"`
	StateDir   string   `arg:"--state" help:"state file folder" placeholder:"DIR"`
	MinutesAgo int      `arg:"--since-minutes" help:"post the report from N minutes before the alert occured (0-5)" default:"3" placeholder:"MINUTES"`
	AlertFreq  int      `arg:"--alert-frequency" help:"how many minutes to check alerts every (0 (don't check alert), 2-30)" default:"5" placeholder:"MINUTES"`
	Delay      int      `arg:"--delay" help:"delay seconds before running command (0-29)" default:"0" placeholder:"SECONDS"`
	Force      bool     `arg:"--force" help:"force to write and post (for debug)"`
	DryRun     bool     `arg:"--dry-run" help:"print an output instead of posting (for debug)"`
	Verbose    bool     `arg:"--verbose" help:"print steps (for debug)"`
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

	if so.MemorySort && so.Cmd != "" {
		err = fmt.Errorf("both --mem and --cmd cannot be specified")
	}

	if so.Cmd != "" && !fileExists(so.Cmd) {
		err = fmt.Errorf("not found %s", so.Cmd)
	}

	if so.AlertFreq != 0 && (so.AlertFreq < 2 || so.AlertFreq > 30) {
		err = fmt.Errorf("the value of --alert-frequency must in the range 2 to 30, or 0")
	}

	if so.MinutesAgo < 0 || so.MinutesAgo > 5 {
		err = fmt.Errorf("the value of --minutes must be in the range 0 to 5")
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

func handleInfo(client *mackerel.Client, opts *sabanoteOpts) *checkers.Checker { // XXX: better name
	const retentionMinutes = 60 * 6 // keep 6 hours
	now := time.Now().Unix()

	err := os.MkdirAll(opts.StateDir, 0755)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("failed to create state folder: %v", err))
	}
	if opts.Verbose {
		fmt.Printf("[info] state folder: %s\n", opts.StateDir)
	}

	db, err := pogreb.Open(filepath.Join(opts.StateDir, "sabanote-db"), nil)

	if err != nil {
		return checkers.Unknown(fmt.Sprintf("failed to create sabanote-db: %v", err))
	}
	defer db.Close()

	// writing process info per call
	err = writeInfo(db, now, opts)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("%v", err))
	}

	// check alert based on alert requency XXX:future RDB: use metainfo table
	lastCheckedByte, err := db.Get([]byte("alertCheckedTime"))
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("%v", lastCheckedByte))
	}

	lastCheckTime, _ := strconv.ParseInt(string(lastCheckedByte), 10, 64)

	if opts.AlertFreq > 0 && lastCheckTime+int64(opts.AlertFreq*60) > now {
		if opts.Verbose {
			fmt.Println("[info] cleanup")
		}
		err := vacuumDB(db, now, retentionMinutes)
		if err != nil {
			return checkers.Unknown(fmt.Sprintf("%v", err))
		}
		return checkers.Ok("running")
	} else {
		err := db.Put([]byte("alertCheckedTime"), []byte(strconv.FormatInt(now, 10)))
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
		fmt.Printf("[info] connection status: %v, alerts size: %v\n", connection, len(alerts))
	}

	alert, err := matchAlert(db, connection, alerts, now, opts)
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
	const limit = 50 // XXX: takes max 50 alerts

	resp, err := client.FindAlerts()
	if err != nil {
		if fmt.Sprintf("%T", err) == "*url.Error" { // FIXME: better check!
			if opts.Verbose {
				fmt.Printf("[info] url.Error: %v\n", err)
			}
			return false, nil, nil // maybe connection problem, may be recovered
		} else {
			return false, nil, err // *mackerel.APIError and something
		}
	}
	if resp.NextID != "" {
		for {
			if limit <= len(resp.Alerts) {
				break
			}
			nextResp, err := client.FindAlertsByNextID(resp.NextID)
			if err != nil {
				return false, nil, err
			}
			if opts.Verbose {
				fmt.Println("[info] getting next alert pages")
			}
			resp.Alerts = append(resp.Alerts, nextResp.Alerts...)
			resp.NextID = nextResp.NextID
			if resp.NextID == "" {
				break
			}
			time.Sleep(1 * time.Second)
		}
	}
	if len(resp.Alerts) > limit {
		resp.Alerts = resp.Alerts[:limit]
	}

	return true, resp.Alerts, nil
}

func matchAlert(db *pogreb.DB, connection bool, alerts []*mackerel.Alert, now int64, opts *sabanoteOpts) (*mackerel.Alert, error) {
	if connection && !opts.Force {
		if opts.Verbose {
			fmt.Println("[info] connection is alive")
		}
		for _, alert := range alerts {
			for _, monitor := range opts.Monitors {
				if alert.Type != "check" && monitor != alert.MonitorID { // XXX: check monitor has dynamic ID
					if opts.Verbose {
						fmt.Printf("[info] monitorID: %s != targetID: %s\n", alert.MonitorID, monitor)
					}
					continue
				}
				if alert.HostID == "" || alert.HostID == opts.Host {
					if opts.Verbose {
						fmt.Printf("[info] alert.HostID: %s, targetHost: %s\n", alert.HostID, opts.Host)
					}
					err := writeInfo(db, now, opts)
					if err != nil {
						return nil, err
					}
					return alert, nil // XXX: avoid duplicate posting
				}
			}
		}
	} else {
		// connection error. write info to DB
		if opts.Verbose {
			fmt.Println("[info] connection is dead (or --force is used)")
		}
		err := writeInfo(db, now, opts)
		if err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func writeInfo(db *pogreb.DB, now int64, opts *sabanoteOpts) error {
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
	if err != nil {
		return err
	}

	err = db.Put([]byte(strconv.FormatInt(now, 10)), out)
	if err != nil {
		return err
	}
	return nil
}

func execCmd(verbose bool, name string, cmdargs ...string) ([]byte, error) {
	if verbose {
		fmt.Printf("[info] execute: %s %s\n", name, cmdargs)
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
		fmt.Printf("[info] output: %s\n", string(out))
	}
	return out, nil
}

func getPSInfo_linux(opts *sabanoteOpts) ([]byte, error) {
	if opts.MemorySort {
		return execCmd(opts.Verbose, "/bin/sh", "-c", "ps axc o %cpu,%mem,time,command --sort -%mem | head -n 20")
	} else {
		return execCmd(opts.Verbose, "/bin/sh", "-c", "ps axc o %cpu,%mem,time,command --sort -%cpu | head -n 20")
	}
}

func getPSInfo_darwin(opts *sabanoteOpts) ([]byte, error) {
	if opts.MemorySort {
		return execCmd(opts.Verbose, "/bin/sh", "-c", "ps axc -o %cpu,%mem,time,command -m | head -n 20")
	} else {
		return execCmd(opts.Verbose, "/bin/sh", "-c", "ps axc -o %cpu,%mem,time,command -r | head -n 20")
	}
}

func getPSInfo_windows(opts *sabanoteOpts) ([]byte, error) {
	if opts.MemorySort {
		return execCmd(opts.Verbose, "powershell.exe", "-Command", "Get-Process | Sort-Object -Property WS -Descending | Select-Object -First 20 CPU,WS,ProcessName | Format-Table -AutoSize | Out-String -Stream | ?{$_ -ne \"\"}")
	} else {
		return execCmd(opts.Verbose, "powershell.exe", "-Command", "Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 20 CPU,WS,ProcessName | Format-Table -AutoSize | Out-String -Stream | ?{$_ -ne \"\"}")
	}
}

func postInfo(alert *mackerel.Alert, client *mackerel.Client, db *pogreb.DB, opts *sabanoteOpts) error {
	countLimit := 10 + 1            // max posts per once running (+1 means alertCheckedTime skip (XXX: should be replaced the implementation))
	annotationDuration := int64(30) // set annotation endtime to time + 30 seconds

	it := db.Items()
	for i := 0; i < countLimit; i++ {
		k, val, err := it.Next()
		if err == pogreb.ErrIterationDone {
			break
		}
		if err != nil {
			return err
		}

		key := string(k)
		if key == "alertCheckedTime" {
			continue
		}

		if i > 0 {
			time.Sleep(1 * time.Second)
		}

		title := opts.Title
		if opts.Title == "" {
			title = fmt.Sprintf("Host %s", opts.Host)
		}

		keyTime, _ := strconv.ParseInt(key, 10, 64)
		alertTime := alert.OpenedAt

		if keyTime > alertTime-int64(opts.MinutesAgo*60) && keyTime <= alertTime {
			annotation := &mackerel.GraphAnnotation{
				Title:       title,
				Description: string(val),
				From:        keyTime,
				To:          keyTime + annotationDuration,
				Service:     opts.Service,
				Roles:       opts.Roles,
			}
			if opts.DryRun {
				_ = format.PrettyPrintJSON(os.Stdout, annotation, "")
			} else {
				_, err := client.CreateGraphAnnotation(annotation)
				if err != nil {
					return err
				}
				if opts.Verbose {
					fmt.Printf("[info] annotation: %v\n", annotation)
				}
			}
		}
		// XXX: for future RDB, better to use "posted" flag
		err = db.Delete(k)
		if err != nil {
			return err
		}
		if opts.Verbose {
			fmt.Printf("[info] deleted entry: %s\n", key)
		}
	}

	return nil
}

func vacuumDB(db *pogreb.DB, now int64, retentionMinutes int) error {
	// XXX: I know, this should use RDB, not KV
	it := db.Items()
	for {
		k, _, err := it.Next()
		if err == pogreb.ErrIterationDone {
			break
		}
		if err != nil {
			return err
		}

		key := string(k)
		if key == "alertCheckedTime" {
			continue
		}
		time, _ := strconv.ParseInt(key, 10, 64)
		if now > time+int64(retentionMinutes*60) {
			err := db.Delete(k)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
