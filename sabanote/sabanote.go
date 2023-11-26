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

type sabanoteOpts struct {
	Host       string   `arg:"-H,--host" help:"host ID" placeholder:"HOST_ID"`
	Monitors   []string `arg:"-m,--monitor,separate,required" help:"monitor ID (accept multiple)" placeholder:"MONITOR_ID"`
	Service    string   `arg:"-s,--service,required" help:"target service" placeholder:"SERVICE"`
	Roles      []string `arg:"-r,--role,required" help:"target role (accept multiple)" placeholder:"ROLE"`
	Title      string   `arg:"--title" help:"annotation title (default: 'Host HOST_ID')" placeholder:"TITLE"`
	MemorySort bool     `arg:"--mem" help:"sort by memory size (sort by CPU% by default)"`
	Cmd        string   `arg:"-c,--cmd" help:"custom command path" placeholder:"CMD_PATH"`
	StateDir   string   `arg:"--state" help:"state file folder" placeholder:"DIR"`
	Delay      int      `arg:"--delay" help:"delay seconds before running command (0-29)" placeholder:"SECONDS"`
	Force      bool     `arg:"--force" help:"force to write and post (for debug)"`
	DryRun     bool     `arg:"--dry-run" help:"print an output instead of posting (for debug)"`
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

func getAlerts(client *mackerel.Client, opts *sabanoteOpts) (*checkers.Checker, bool, []*mackerel.Alert) {
	const limit = 50 // XXX: takes max 50 alerts

	resp, err := client.FindAlerts()
	if err != nil {
		if fmt.Sprintf("%T", err) == "*url.Error" { // FIXME: better check!
			return nil, false, nil // maybe connection problem, may be recovered
		} else {
			return checkers.Unknown(fmt.Sprintf("%v", err)), false, nil // *mackerel.APIError and something
		}
	}
	if resp.NextID != "" {
		for {
			if limit <= len(resp.Alerts) {
				break
			}
			nextResp, err := client.FindAlertsByNextID(resp.NextID)
			if err != nil {
				return checkers.Unknown(fmt.Sprintf("%v", err)), false, nil
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

	return nil, true, resp.Alerts
}

func handleInfo(client *mackerel.Client, opts *sabanoteOpts) *checkers.Checker { // XXX: better name. it may need refactoring
	const limit = 50 // XXX: takes max 50 alerts

	err := os.MkdirAll(opts.StateDir, 0755)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("failed to create state folder: %v", err))
	}

	db, err := pogreb.Open(filepath.Join(opts.StateDir, "sabanote-db"), nil)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("failed to create sabanote-db: %v", err))
	}
	defer db.Close()

	connection := true
	resp, err := client.FindAlerts()
	if err != nil {
		if fmt.Sprintf("%T", err) == "*url.Error" { // FIXME: better check!
			connection = false // maybe connection problem, may be recovered
		} else {
			return checkers.Unknown(fmt.Sprintf("%v", err)) // *mackerel.APIError and something
		}
	}

	if connection && !opts.Force {
		if resp.NextID != "" {
			for {
				if limit <= len(resp.Alerts) {
					break
				}
				nextResp, err := client.FindAlertsByNextID(resp.NextID)
				if err != nil {
					return checkers.Unknown(fmt.Sprintf("%v", err))
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
		for _, alert := range resp.Alerts {
			for _, monitor := range opts.Monitors {
				if alert.Type != "check" && monitor != alert.MonitorID { // XXX: check monitor has dynamic ID
					continue
				}
				if alert.HostID == "" || alert.HostID == opts.Host {
					err := writeInfo(db, opts)
					if err != nil {
						return checkers.Unknown(fmt.Sprintf("%v", err))
					}
					break // FIXME: break more
				}
			}
		}
	} else {
		// connection error. write info to DB
		err := writeInfo(db, opts)
		if err != nil {
			return checkers.Unknown(fmt.Sprintf("%v", err))
		}
	}

	if connection {
		err = postInfo(client, db, opts)
		if err != nil {
			return checkers.Ok(fmt.Sprintf("post failure: %v", err))
		}
	} else {
		return checkers.Ok("connection failure")
	}

	return checkers.Ok("running")
}

func writeInfo(db *pogreb.DB, opts *sabanoteOpts) error {
	// write
	now := time.Now().Unix()
	var out []byte
	var err error

	if opts.Delay > 0 {
		time.Sleep(time.Duration(opts.Delay) * time.Second)
	}

	if opts.Cmd != "" {
		out, err = execCmd(opts.Cmd)
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

func execCmd(name string, cmdargs ...string) ([]byte, error) {
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
	return out, nil
}

func getPSInfo_linux(opts *sabanoteOpts) ([]byte, error) {
	if opts.MemorySort {
		return execCmd("/bin/sh", "-c", "ps axc o %cpu,%mem,time,command --sort -%mem | head -n 20")
	} else {
		return execCmd("/bin/sh", "-c", "ps axc o %cpu,%mem,time,command --sort -%cpu | head -n 20")
	}
}

func getPSInfo_darwin(opts *sabanoteOpts) ([]byte, error) {
	if opts.MemorySort {
		return execCmd("/bin/sh", "-c", "ps axc -o %cpu,%mem,time,command -m | head -n 20")
	} else {
		return execCmd("/bin/sh", "-c", "ps axc -o %cpu,%mem,time,command -r | head -n 20")
	}
}

func getPSInfo_windows(opts *sabanoteOpts) ([]byte, error) {
	if opts.MemorySort {
		return execCmd("powershell.exe", "-Command", "{Get-Process | Sort-Object -Property WS -Descending | Select-Object -First 20 CPU,WS,ProcessName | Format-Table -AutoSize | Out-String -Stream | ?{$_ -ne \"\"}}")
	} else {
		return execCmd("powershell.exe", "-Command", "{Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 20 CPU,WS,ProcessName | Format-Table -AutoSize | Out-String -Stream | ?{$_ -ne \"\"}}")
	}
}

func postInfo(client *mackerel.Client, db *pogreb.DB, opts *sabanoteOpts) error {
	countLimit := 10                // max posts per once running
	postLimit := int64(48 * 24)     // drop posts if it overs 48 hours ago
	annotationDuration := int64(30) // set annotation endtime to now + 30 seconds

	now := time.Now().Unix()

	it := db.Items()
	for i := 0; i < countLimit; i++ {
		key, val, err := it.Next()
		if err == pogreb.ErrIterationDone {
			break
		}
		if err != nil {
			return err
		}
		if i > 0 {
			time.Sleep(1 * time.Second)
		}

		title := opts.Title
		if opts.Title == "" {
			title = fmt.Sprintf("Host %s", opts.Host)
		}
		keyTime, _ := strconv.ParseInt(string(key), 10, 64)

		if keyTime <= now && keyTime > now-postLimit {
			annotation := &mackerel.GraphAnnotation{
				Title:       title,
				Description: string(val),
				From:        keyTime,
				To:          keyTime + annotationDuration,
				Service:     opts.Service,
				Roles:       opts.Roles,
			}
			if opts.DryRun {
				format.PrettyPrintJSON(os.Stdout, annotation, "")
			} else {
				_, err := client.CreateGraphAnnotation(annotation)
				if err != nil {
					return err
				}
			}
		}
		db.Delete([]byte(key))
	}

	return nil
}
