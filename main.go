// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// A simple example exposing fictional RPC latencies with different types of
// random distributions (uniform, normal, and exponential) as Prometheus
// metrics.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/justinas/alice"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"

	"github.com/simonswine/tplink-switch-exporter/switches"
)

var log = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().
	Timestamp().
	Logger()

func run() error {

	var (
		addr     string
		username string
		password string
		hostname string
	)
	flag.StringVar(&addr, "listen-address", ":9108", "The address to listen on for HTTP requests.")
	flag.StringVar(&username, "switch-username", "admin", "Username used to login to the switch.")
	flag.StringVar(&password, "switch-password", "", "Password used to login to the switch.")
	flag.StringVar(&hostname, "switch-hostname", "", "TODO")
	flag.Parse()

	if password == "" {
		password = strings.TrimSpace(os.Getenv("SWITCH_PASSWORD"))
		if password == "" {
			return fmt.Errorf("no switch-password set")
		}
	}

	if hostname == "" {
		return fmt.Errorf("no switch-hostname set")
	}

	// create switch collector
	s := switches.NewTPLinkSwitch(
		log,
		hostname,
		username,
		password,
	).Collector()

	reg := prometheus.NewRegistry()
	if err := reg.Register(s); err != nil {
		return err
	}

	// go module build info.
	if err := reg.Register(collectors.NewBuildInfoCollector()); err != nil {
		return err
	}
	if err := reg.Register(collectors.NewGoCollector()); err != nil {
		return err
	}

	// Install the logger handler with default output on the console
	c := alice.New()
	c = c.Append(hlog.NewHandler(log))

	// Expose the registered metrics via HTTP.
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(
		reg,
		promhttp.HandlerOpts{
			// Opt into OpenMetrics to support exemplars.
			EnableOpenMetrics: true,
		},
	))

	c = c.Append(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().
			Str("method", r.Method).
			Stringer("url", r.URL).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Msg("")
	}))

	return http.ListenAndServe(addr, c.Then(mux))
}

func main() {
	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("failed")
	}
}
