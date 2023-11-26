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
	Service    string   `arg:"-s,--service,required" help:"target service" placeholder:"SERVICE"`
	Roles      []string `arg:"-r,--role,required" help:"target role (accept multiple)" placeholder:"ROLE"`
	StateDir   string   `arg:"--state" help:"state file folder" placeholder:"DIR"`
	Cmd        string   `arg:"-c,--cmd" help:"custom command path" placeholder:"CMD_PATH"`
	MemorySort bool     `arg:"--mem" help:"sort by memory size (sort by CPU% by default)"`
	Force      bool     `arg:"--force" help:"force to write and post (for debug)"`
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
	client.HTTPClient.Timeout = timeOut
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

	connection := true
	resp, err := client.FindAlerts()
	if err != nil {
		if fmt.Sprintf("%T", err) == "*url.Error" { // FIXME: better check!
			connection = false // suspect as connection problem
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
				if monitor != alert.MonitorID {
					continue
				}
				if alert.HostID == "" || alert.HostID == opts.Host {
					err := writeInfo(db, opts)
					if err != nil {
						return checkers.Unknown(fmt.Sprintf("%v", err))
					}
				}
			}
		}
	} else {
		// seems connection error. write DB
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
	// FIXME:call process nad get stdout
	err := db.Put([]byte(strconv.FormatInt(now, 10)), []byte("BBBBB"))
	if err != nil {
		return err
	}
	return nil
}

func postInfo(client *mackerel.Client, db *pogreb.DB, opts *sabanoteOpts) error {
	countLimit := 10
	postLimit := int64(48 * 24) // 48 hours ago
	annotationDuration := int64(30)

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

		keyTime, _ := strconv.ParseInt(string(key), 10, 64)
		if keyTime <= now && keyTime > now-postLimit {
			annotation := &mackerel.GraphAnnotation{
				Title:       fmt.Sprintf("Host %s", opts.Host), // XXX: better Title? option?
				Description: string(val),
				From:        keyTime,
				To:          keyTime + annotationDuration, // XXX
				Service:     opts.Service,
				Roles:       opts.Roles,
			}
			_, err := client.CreateGraphAnnotation(annotation)
			if err != nil {
				return err
			}
		}
		db.Delete([]byte(key))
	}

	return nil
}
