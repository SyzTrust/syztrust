// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/google/syzkaller/pkg/html"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/gorilla/handlers"
)

func (ctx *TestbedContext) setupHTTPServer() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", ctx.httpMain)
	mux.HandleFunc("/graph", ctx.httpGraph)

	listener, err := net.Listen("tcp", ctx.Config.HTTP)
	if err != nil {
		log.Fatalf("failed to listen on %s", ctx.Config.HTTP)
	}

	log.Printf("handling HTTP on %s", listener.Addr())
	go func() {
		err := http.Serve(listener, handlers.CompressHandler(mux))
		if err != nil {
			log.Fatalf("failed to listen on %v: %v", ctx.Config.HTTP, err)
		}
	}()
}

func (ctx *TestbedContext) httpGraph(w http.ResponseWriter, r *http.Request) {
	viewName := r.FormValue("view")
	over := r.FormValue("over")

	if ctx.Config.BenchCmp == "" {
		http.Error(w, "the path to the benchcmp tool is not specified", http.StatusInternalServerError)
		return
	}

	views, err := ctx.GetStatViews()
	if err != nil {
		http.Error(w, "failed to retrieve stat views", http.StatusInternalServerError)
		return
	}
	var targetView *StatView
	for _, view := range views {
		if view.Name == viewName {
			targetView = &view
			break
		}
	}
	if targetView == nil {
		http.Error(w, "the requested view was not found", http.StatusInternalServerError)
		return
	}

	// TODO: move syz-benchcmp functionality to pkg/ and just import it?
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		http.Error(w, "failed to create temp folder", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(dir)

	file, err := osutil.TempFile("")
	if err != nil {
		http.Error(w, "failed to create temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(file)

	benches, err := targetView.SaveAvgBenches(dir)
	if err != nil {
		http.Error(w, "failed to save avg benches", http.StatusInternalServerError)
		return
	}

	args := append([]string{"-all", "-over", over, "-out", file}, benches...)
	if out, err := osutil.RunCmd(time.Hour, "", ctx.Config.BenchCmp, args...); err != nil {
		http.Error(w, "syz-benchcmp failed\n"+string(out), http.StatusInternalServerError)
		return
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		http.Error(w, "failed to read the temporary file", http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

type uiStatView struct {
	Name  string
	Table [][]string
}

type uiMainPage struct {
	Name    string
	Summary [][]string
	Views   []uiStatView
}

func (ctx *TestbedContext) httpMain(w http.ResponseWriter, r *http.Request) {
	uiViews := []uiStatView{}
	views, err := ctx.GetStatViews()
	if err != nil {
		log.Printf("%s", err)
		views = nil
	}
	for _, view := range views {
		table, err := view.StatsTable()
		if err != nil {
			log.Printf("stat table generation failed: %s", err)
			continue
		}
		sort.SliceStable(table, func(i, j int) bool {
			if len(table[i]) == 0 || len(table[j]) == 0 {
				return i < j
			}
			return table[i][0] < table[j][0]
		})
		uiViews = append(uiViews, uiStatView{
			Name:  view.Name,
			Table: table,
		})
	}
	data := &uiMainPage{
		Name:    ctx.Config.Name,
		Summary: ctx.TestbedStatsTable(),
		Views:   uiViews,
	}

	executeTemplate(w, mainTemplate, data)
}

func executeTemplate(w http.ResponseWriter, templ *template.Template, data interface{}) {
	buf := new(bytes.Buffer)
	if err := templ.Execute(buf, data); err != nil {
		log.Printf("failed to execute template: %v", err)
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes())
}

var mainTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>{{.Name }} syzkaller</title>
	{{HEAD}}
</head>
<body>

{{define "Table"}}
{{if .}}
<table class="list_table">
	{{range $c := .}}
	<tr>
	{{range $v := $c}}
		<td>{{$v}}</td>
	{{end}}
	</tr>
	{{end}}
</table>
{{end}}
{{end}}

<b>{{.Name }} syz-testbed</b>
{{template "Table" .Summary}}

{{range $view := .Views}}
<b>Stat view "{{$view.Name}}"</b><br />
<a href="/graph?view={{$view.Name}}&over=fuzzing">Graph over time</a> /
<a href="/graph?view={{$view.Name}}&over=exec+total">Graph over executions</a> <br />
{{template "Table" .Table}}
{{end}}

</body>
</html>
`)
