package sabanote

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/akrylysov/pogreb"
	"github.com/alexflint/go-arg"
	"github.com/mackerelio/checkers"
	"github.com/mackerelio/golib/pluginutil"
	"github.com/mackerelio/mackerel-agent/config"
	"github.com/mackerelio/mackerel-client-go"
)

type sabanoteOpts struct {
	Host       string   `arg:"-H,--host" help:"host ID" placeholder:"HOST_ID"`
	Monitors   []string `arg:"-m,--monitor,separate,required" help:"monitor ID (accept multiple)" placeholder:"MONITOR_ID"`
	Services   []string `arg:"-s,--service,separate,required" help:"target service:role or service (accept multiple)" placeholder:"SERVICE:ROLE"`
	StateDir   string   `arg:"--state" help:"state file folder" placeholder:"DIR"`
	Cmd        string   `arg:"-c,--cmd" help:"custom command path" placeholder:"CMD_PATH"`
	MemorySort bool     `arg:"--mem" help:"sort by memory size (sort by CPU% by default)"`
}

var version string
var revision string

// for go-arg interface
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

	if so.StateDir == "" {
		so.StateDir = filepath.Join(pluginutil.PluginWorkDir(), "sabanote")
	}

	return &so, err
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func (opts *sabanoteOpts) run() *checkers.Checker {
	apikey := os.Getenv("MACKEREL_APIKEY")

	conf, err := config.LoadConfig(config.DefaultConfig.Conffile)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("%v", err))
	}

	apibase := conf.Apibase
	if apikey == "" {
		apikey = conf.Apikey
	}
	if apibase == "" || apikey == "" {
		return checkers.Unknown("Not found apibase or apikey in " + config.DefaultConfig.Conffile)
	}

	if opts.Host == "" {
		id, err := conf.LoadHostID()
		if err != nil {
			return checkers.Unknown("Not found host ID from this environment. Specify host ID by --host")
		}
		opts.Host = id
	}

	client, err := mackerel.NewClientWithOptions(apikey, apibase, false)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("%v", err))
	}

	return findAlert(client, opts)
}

func findAlert(client *mackerel.Client, opts *sabanoteOpts) *checkers.Checker {
	const limit = 50 // XXX: limit for taking Alerts

	err := os.MkdirAll(opts.StateDir, 0755)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("failed to create state folder: %v", err))
	}

	db, err := pogreb.Open(filepath.Join(opts.StateDir, "sabanote.db"), nil)
	if err != nil {
		return checkers.Unknown(fmt.Sprintf("failed to create sabanote.db: %v", err))
	}
	defer db.Close()

	resp, err := client.FindAlerts()
	if err != nil {
		// FIXME
	}

	// next page
	if resp.NextID != "" {
		for {
			if limit <= len(resp.Alerts) {
				break
			}
			nextResp, err := client.FindAlertsByNextID(resp.NextID)
			if err != nil {
				// FIXME
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
			if monitor != alert.MonitorID {
				continue
			}
			if alert.HostID == "" || alert.HostID == opts.Host {
				err := writeInfo(db, opts)
				if err != nil {
					// FIXME
					fmt.Println(err)
				}
			}
		}
	}
	// FIXME: POST!
	err = postInfo(client, db, opts)
	if err != nil {
		// FIXME
	}

	return checkers.Ok("running")
}

func writeInfo(db *pogreb.DB, opts *sabanoteOpts) error {
	// write
	currentTime := time.Now().Unix()
	// FIXME:call process nad get stdout
	err := db.Put([]byte(strconv.FormatInt(currentTime, 10)), []byte("BBBBB"))
	if err != nil {
		return err
	}
	return nil
}

func postInfo(client *mackerel.Client, db *pogreb.DB, opts *sabanoteOpts) error {
	// post and remove
	it := db.Items()
	for {
		key, val, err := it.Next()
		if err == pogreb.ErrIterationDone {
			break
		}
		if err != nil {
			return err
		}
		// FIXME:post by API
		fmt.Printf("POST %s: %s\n", key, val)
		db.Delete([]byte(key))
		time.Sleep(1 * time.Second)
		// FIXME:stop by 10 times
	}

	return nil
}
