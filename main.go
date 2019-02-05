package main

import (
	"fmt"
	"net/http"

	"github.com/alecthomas/kingpin"
	"github.com/tnwhitwell/safebrowsing_exporter/client"
	"github.com/tnwhitwell/safebrowsing_exporter/collector"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
)

// nolint: gochecknoglobals
var (
	bind     = kingpin.Flag("bind", "addr to bind the server").Short('b').Default(":9222").String()
	debug    = kingpin.Flag("debug", "show debug logs").Default("false").Bool()
	interval = kingpin.Flag("cache", "time to cache the result of whois calls").Default("2h").Duration()
	apiKey = kingpin.Flag("apikey", "Google API key with access to safebrowsing.").Short('k').Required().Envar("API_KEY").String()
	version  = "master"
)

func main() {
	kingpin.Version("safebrowsing_exporter version " + version)
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	if *debug {
		_ = log.Base().SetLevel("debug")
		log.Debug("enabled debug mode")
	}

	log.Info("starting safebrowsing_exporter", version)
	var cli = client.NewSafeBrowsingClient(*apiKey)

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/probe", probeHandler(cli))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(
			w, `
			<html>
			<head><title>Domain Exporter</title></head>
			<body>
				<h1>Domain Exporter</h1>
				<p><a href="/metrics">Metrics</a></p>
				<p><a href="/probe?target=https://google.com">probe https://google.com</a></p>
			</body>
			</html>
			`,
		)
	})
	log.Info("listening on", *bind)
	if err := http.ListenAndServe(*bind, nil); err != nil {
		log.Fatalf("error starting server: %s", err)
	}
}

func probeHandler(cli client.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var params = r.URL.Query()
		var target = params.Get("target")
		if target == "" {
			log.Error("target parameter missing")
			http.Error(w, "target parameter is missing", http.StatusBadRequest)
			return
		}

		var registry = prometheus.NewRegistry()
		registry.MustRegister(collector.NewSafeBrowsingCollector(cli, target))
		promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
	}
}
