package sabanote

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mackerelio/mackerel-client-go"
	"github.com/stretchr/testify/assert"
)

func TestParseArgs(t *testing.T) {
	opts, err := parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE", " "))
	assert.Equal(t, nil, err, "normal parameters should be passed")
	assert.Equal(t, "MONITOR", opts.Monitors[0], "monitor is passed correctly")
	assert.Equal(t, "SERVICE", opts.Service, "service is passed correctly")
	assert.Equal(t, "ROLE", opts.Roles[0], "role is passed correctly")

	opts, _ = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE -H HOST --title TITLE --mem --state DIR --before 5 --after 4 --alert-frequency 2 --delay 29 --verbose", " "))
	assert.Equal(t, "HOST", opts.Host, "host is passed correctly")
	assert.Equal(t, "TITLE", opts.Title, "title is passed correctly")
	assert.Equal(t, true, opts.MemorySort, "mem is passed correctly")
	assert.Equal(t, "DIR", opts.StateDir, "state is passed correctly")
	assert.Equal(t, 5, opts.Before, "before is passed correctly")
	assert.Equal(t, 4, opts.After, "after is passed correctly")
	assert.Equal(t, 2, opts.AlertFreq, "alert-frequency is passed correctly")
	assert.Equal(t, 29, opts.Delay, "delay is passed correctly")
	assert.Equal(t, true, opts.Verbose, "verbose is passed correctly")

	opts, _ = parseArgs(strings.Split("-m MONITOR1 -r ROLE1 -s SERVICE -r ROLE2 -r ROLE3 -m MONITOR2", " "))
	assert.Equal(t, []string{"MONITOR1", "MONITOR2"}, opts.Monitors, "--monitor takes multiple")
	assert.Equal(t, []string{"ROLE1", "ROLE2", "ROLE3"}, opts.Roles, "--role takes multiple")

	opts, _ = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --alert-frequency 0", " "))
	assert.Equal(t, 0, opts.AlertFreq, "alert-frequency accepts 0")
	opts, _ = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --alert-frequency 30", " "))
	assert.Equal(t, 30, opts.AlertFreq, "alert-frequency accepts 30")

	opts, _ = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --before 0", " "))
	assert.Equal(t, 0, opts.Before, "before accepts 0")
	opts, _ = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --before 5", " "))
	assert.Equal(t, 5, opts.Before, "before accepts 5")
	opts, _ = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --after 0", " "))
	assert.Equal(t, 0, opts.After, "after accepts 0")
	opts, _ = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --after 5", " "))
	assert.Equal(t, 5, opts.After, "after accepts 5")

	opts, _ = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --delay 0", " "))
	assert.Equal(t, 0, opts.Delay, "delay accepts 0")
	opts, _ = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --delay 29", " "))
	assert.Equal(t, 29, opts.Delay, "delay accepts 29")

	dir, _ := os.Getwd()

	opts, _ = parseArgs(strings.Split(fmt.Sprintf("-m MONITOR -s SERVICE -r ROLE --cmd %s/go.mod", dir), " "))
	assert.Equal(t, fmt.Sprintf("%s/go.mod", dir), opts.Cmd, "cmd is passed correctly")

	_, err = parseArgs(strings.Split(fmt.Sprintf("-m MONITOR -s SERVICE -r ROLE --cmd %s/go.mod --mem", dir), " "))
	assert.Equal(t, fmt.Errorf("both --mem and --cmd cannot be specified"), err, "--cmd and --mem conflict")

	_, err = parseArgs(strings.Split(fmt.Sprintf("-m MONITOR -s SERVICE -r ROLE --cmd %s/unknown/go.mod", dir), " "))
	assert.Equal(t, fmt.Errorf(fmt.Sprintf("not found %s/unknown/go.mod", dir)), err, "missing file")

	_, err = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --alert-frequency 1", " "))
	assert.Equal(t, fmt.Errorf("the value of --alert-frequency must be in the range 2 to 30, or 0"), err, "alert-frequency range under")
	_, err = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --alert-frequency 31", " "))
	assert.Equal(t, fmt.Errorf("the value of --alert-frequency must be in the range 2 to 30, or 0"), err, "alert-frequency range over")

	_, err = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --before -1", " "))
	assert.Equal(t, fmt.Errorf("the value of --before must be in the range 0 to 5"), err, "before range under")
	_, err = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --before 6", " "))
	assert.Equal(t, fmt.Errorf("the value of --before must be in the range 0 to 5"), err, "before range over")
	_, err = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --after -1", " "))
	assert.Equal(t, fmt.Errorf("the value of --after must be in the range 0 to 5"), err, "after range under")
	_, err = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --after 6", " "))
	assert.Equal(t, fmt.Errorf("the value of --after must be in the range 0 to 5"), err, "after range over")

	_, err = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --delay -1", " "))
	assert.Equal(t, fmt.Errorf("the value of --delay must be in the range 0 to 29"), err, "delay range under")
	_, err = parseArgs(strings.Split("-m MONITOR -s SERVICE -r ROLE --delay 30", " "))
	assert.Equal(t, fmt.Errorf("the value of --delay must be in the range 0 to 29"), err, "delay range over")
}

func AlertServer(jsonMarshal []byte) *httptest.Server {
	type Annotations struct {
		GraphAnnotations []*mackerel.GraphAnnotation `json:"graphAnnotations"`
	}
	annotations := Annotations{
		GraphAnnotations: make([]*mackerel.GraphAnnotation, 0),
	}
	ts := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		var respJSON []byte
		switch fmt.Sprintf("%v", req.URL.Path) {
		case "/api/v0/alerts":
			respJSON = jsonMarshal
		case "/api/v0/graph-annotations":
			if req.Method == "GET" {
				respJSON, _ = json.Marshal(annotations)
			} else {
				body, _ := io.ReadAll(req.Body)
				var data *mackerel.GraphAnnotation
				_ = json.Unmarshal(body, &data)
				annotations.GraphAnnotations = append(annotations.GraphAnnotations, data)
				respJSON, _ = json.Marshal(map[string]map[string]string{
					"ok": {"message": "received"},
				})
			}
		default:
			respJSON, _ = json.Marshal(map[string]map[string]string{
				"error": {"message": "unimplemented"},
			})
		}

		res.Header()["Content-Type"] = []string{"application/json"}
		fmt.Fprint(res, string(respJSON))
	}))

	return ts
}

func TestGetAlerts(t *testing.T) {
	jsonMarshal, _ := json.Marshal(map[string][]map[string]interface{}{
		"alerts": {
			{
				"id":        "ALERT2",
				"status":    "CRITICAL",
				"monitorId": "MONITOR1",
				"type":      "host",
				"hostId":    "HOST1",
				"openedAt":  1000 + 1000,
			},
			{
				"id":        "ALERT1",
				"status":    "OK",
				"monitorId": "MONITOR1",
				"type":      "service",
				"hostId":    "HOST1",
				"reason":    "test close",
				"openedAt":  1000,
				"closedAt":  1000 + 60,
			},
		},
	})
	ts := AlertServer(jsonMarshal)
	var opts = &sabanoteOpts{}

	client, _ := mackerel.NewClientWithOptions("dummy-key", ts.URL, false)
	_, alerts, _ := getAlerts(client, opts)
	assert.Equal(t, "ALERT2", alerts[0].ID, "got alert2")
	assert.Equal(t, "ALERT1", alerts[1].ID, "got alert1")
	ts.Close()

	jsonMarshal, _ = json.Marshal(map[string][]map[string]interface{}{
		"alerts": {
			{"id": "ALERT21"}, {"id": "ALERT20"}, {"id": "ALERT19"},
			{"id": "ALERT18"}, {"id": "ALERT17"}, {"id": "ALERT16"},
			{"id": "ALERT15"}, {"id": "ALERT14"}, {"id": "ALERT13"},
			{"id": "ALERT12"}, {"id": "ALERT11"}, {"id": "ALERT10"},
			{"id": "ALERT9"}, {"id": "ALERT8"}, {"id": "ALERT7"},
			{"id": "ALERT6"}, {"id": "ALERT5"}, {"id": "ALERT4"},
			{"id": "ALERT3"}, {"id": "ALERT2"}, {"id": "ALERT1"},
		},
	})
	ts = AlertServer(jsonMarshal)
	client, _ = mackerel.NewClientWithOptions("dummy-key", ts.URL, false)
	_, alerts, _ = getAlerts(client, opts)
	assert.Equal(t, 20, len(alerts), "limit is 20")
	assert.Equal(t, "ALERT21", alerts[0].ID, "got 1st")
	assert.Equal(t, "ALERT2", alerts[19].ID, "got 20th")
	ts.Close()
}

func TestMatchAlert(t *testing.T) {
	var alerts []*mackerel.Alert

	var opts = &sabanoteOpts{
		Host:     "HOST1",
		Monitors: []string{"MONITOR1", "MONITOR2"},
	}

	alerts = []*mackerel.Alert{
		{
			ID:        "ALERT1",
			Type:      "host",
			MonitorID: "MONITOR1",
			HostID:    "HOST1",
		},
	}
	alert, _ := matchAlert(true, alerts, opts)
	assert.Equal(t, "ALERT1", alert.ID, "hit alert1")
	assert.Equal(t, "MONITOR1", alert.MonitorID, "hit alert1 monitorID")

	alerts = []*mackerel.Alert{
		{
			ID:        "ALERT1",
			Type:      "host",
			MonitorID: "MONITOR2",
			HostID:    "HOST1",
		},
	}
	alert, _ = matchAlert(true, alerts, opts)
	assert.Equal(t, "MONITOR2", alert.MonitorID, "hit monitor2 also")

	alerts = []*mackerel.Alert{
		{
			ID:        "ALERT1",
			Type:      "host",
			MonitorID: "MONITOR1",
			HostID:    "HOST2",
		},
	}
	alert, _ = matchAlert(true, alerts, opts)
	assert.Equal(t, (*mackerel.Alert)(nil), alert, "monitorID is target, but hostID is not target")

	alerts = []*mackerel.Alert{
		{
			ID:        "ALERT1",
			Type:      "host",
			MonitorID: "MONITOR3",
			HostID:    "HOST1",
		},
	}
	alert, _ = matchAlert(true, alerts, opts)
	assert.Equal(t, (*mackerel.Alert)(nil), alert, "no target monitorID")

	alerts = []*mackerel.Alert{
		{
			ID:        "ALERT1",
			Type:      "check",
			MonitorID: "MONITOR3",
			HostID:    "HOST1",
		},
	}
	alert, _ = matchAlert(true, alerts, opts)
	assert.Equal(t, "MONITOR3", alert.MonitorID, "catch check alert")

	alerts = []*mackerel.Alert{
		{
			ID:        "ALERT1",
			Type:      "external",
			MonitorID: "MONITOR1",
		},
	}
	alert, _ = matchAlert(true, alerts, opts)
	assert.Equal(t, "MONITOR1", alert.MonitorID, "catch alert if monitor is target and hostID is null")

	alerts = []*mackerel.Alert{
		{
			ID:        "ALERT3",
			Type:      "host",
			MonitorID: "MONITOR1",
			HostID:    "HOST2",
		},
		{
			ID:        "ALERT2",
			Type:      "host",
			MonitorID: "MONITOR1",
			HostID:    "HOST1",
		},
		{
			ID:        "ALERT1",
			Type:      "host",
			MonitorID: "MONITOR1",
			HostID:    "HOST1",
		},
	}
	alert, _ = matchAlert(true, alerts, opts)
	assert.Equal(t, "ALERT2", alert.ID, "use first hit")
}

func TestWriteInfo(t *testing.T) {
	dir, _ := os.MkdirTemp("", "sabanote-test")
	defer os.RemoveAll(dir)

	opts := &sabanoteOpts{
		StateDir: dir,
		Delay:    0,
		Verbose:  false,
		Cmd:      "",
		Test:     true,
	}

	db, _ := sql.Open("sqlite", filepath.Join(opts.StateDir, "sabanote.db"))
	defer db.Close()
	_ = createTable(db)

	_ = writeInfo(db, 1000, opts)
	v, _, _ := findReport(db, 1000)
	assert.Equal(t, "Result 1000", v, "string is written")
	v, _, _ = findReport(db, 0)
	assert.Equal(t, "", v, "empty is returned for invalid key")
}

func TestPostInfo(t *testing.T) {
	dir, _ := os.MkdirTemp("", "sabanote-test")
	defer os.RemoveAll(dir)

	opts := &sabanoteOpts{
		StateDir: dir,
		Delay:    0,
		Verbose:  false,
		Cmd:      "",
		Test:     true,
		Before:   3,
		After:    2,
		Host:     "HOST",
		Service:  "SERVICE",
		Roles:    []string{"ROLE1"},
	}

	db, _ := sql.Open("sqlite", filepath.Join(opts.StateDir, "sabanote.db"))
	defer db.Close()
	_ = createTable(db)

	_ = writeInfo(db, 1000-60*4, opts)
	_ = writeInfo(db, 1000-60*3, opts)
	_ = writeInfo(db, 1000-60*2, opts)
	_ = writeInfo(db, 1000-60*1, opts)
	_ = writeInfo(db, 1000, opts)
	_ = writeInfo(db, 1000+60*1, opts)
	_ = writeInfo(db, 1000+60*2, opts)
	_ = writeInfo(db, 1000+60*3, opts)
	_ = writeInfo(db, 10000, opts)

	ts := AlertServer(nil)
	defer ts.Close()
	client, _ := mackerel.NewClientWithOptions("dummy-key", ts.URL, false)
	alert := &mackerel.Alert{
		ID:       "ALERT1",
		OpenedAt: 1000,
	}
	_, p, _ := findReport(db, 1000)
	assert.Equal(t, false, p, "not posted yet")
	err := postInfo(alert, client, db, opts)
	assert.Equal(t, nil, err, "post is succeeded")
	_, p, _ = findReport(db, 1000)
	assert.Equal(t, true, p, "posted")

	annotations, _ := client.FindGraphAnnotations("SERVICE", 0, 99999)
	assert.Equal(t, 6, len(annotations), "before 3 + alert time + after 2 = 6")
	assert.Equal(t, int64(1000-60*3), annotations[0].From, "alert - 3min")
	assert.Equal(t, int64(1000-60*2), annotations[1].From, "alert - 2min")
	assert.Equal(t, int64(1000-60*1), annotations[2].From, "alert - 1min")
	assert.Equal(t, int64(1000-60*0), annotations[3].From, "alert min")
	assert.Equal(t, int64(1000+60*1), annotations[4].From, "alert + 1min")
	assert.Equal(t, int64(1000+60*2), annotations[5].From, "alert + 2min")

	_, p, _ = findReport(db, int64(1000-60*4))
	assert.Equal(t, false, p, "alet - 4min not posted")
	_, p, _ = findReport(db, int64(1000-60*3))
	assert.Equal(t, true, p, "alert - 3min posted")
	_, p, _ = findReport(db, int64(1000+60*1))
	assert.Equal(t, true, p, "alert + 1min posted")
	_, p, _ = findReport(db, int64(1000+60*3))
	assert.Equal(t, false, p, "alert + 3min not posted")
}

func TestVacuumDB(t *testing.T) {
	dir, _ := os.MkdirTemp("", "sabanote-test")
	defer os.RemoveAll(dir)

	opts := &sabanoteOpts{
		StateDir: dir,
		Test:     true,
	}

	db, _ := sql.Open("sqlite", filepath.Join(opts.StateDir, "sabanote.db"))
	defer db.Close()
	_ = createTable(db)

	_ = writeInfo(db, 100000-60*60*6-1, opts) // 6h+1 ago
	_ = writeInfo(db, 100000-60*60*6, opts)   // 6h ago
	_ = writeInfo(db, 100000-60*60+1, opts)   // 6h-1 ago
	_ = writeInfo(db, 100000, opts)

	_ = vacuumDB(db, 100000, 60*6) // 6 h

	v, _, _ := findReport(db, 100000)
	assert.Equal(t, "Result 100000", string(v), "now time exists")
	v, _, _ = findReport(db, 96401) // 100000-60*60*6+1
	assert.Equal(t, "Result 96401", string(v), "6h-1m ago exists")
	v, _, _ = findReport(db, 96400) // 100000-60*60*6
	assert.Equal(t, "", string(v), "6h ago is removed")
	v, _, _ = findReport(db, 96399) // 10000-60*60*6-1
	assert.Equal(t, "", string(v), "6h+1m ago is removed")
}

func TestReplaceTitle(t *testing.T) {
	opts := &sabanoteOpts{
		Host:  "MYHOST",
		Title: "Host <HOST> status when <ALERT> is alerted (<TIME>)",
	}

	now := time.Now().Unix()

	alert := &mackerel.Alert{
		ID:       "ALERT1",
		OpenedAt: now,
	}

	s := replaceTitle(opts.Title, alert, opts)
	assert.Equal(t, fmt.Sprintf("Host MYHOST status when ALERT1 is alerted (%s)", time.Unix(now, 0)), s, "default title")

	s = replaceTitle("<HOST>, <ALERT>, <HOST>, <ALERT HOST>, <ALERT>", alert, opts)
	assert.Equal(t, "MYHOST, ALERT1, MYHOST, <ALERT HOST>, ALERT1", s, "multiple replace")
}

func TestExecCmd(t *testing.T) {
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		output, err := execCmd(false, "/bin/ls")
		assert.Equal(t, nil, err, "command call is succeeeded")
		assert.NotEmpty(t, output, "something is returned")
	}
}
