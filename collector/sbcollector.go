package collector

import (
	"sync"
	"time"

	"github.com/tnwhitwell/safebrowsing_exporter/client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

type safebrowsingCollector struct {
	mutex  sync.Mutex
	client client.Client
	url string

	isThreat    *prometheus.Desc
	probeSuccess  *prometheus.Desc
	probeDuration *prometheus.Desc
}

// NewDomainCollector returns a domain collector
func NewSafeBrowsingCollector(client client.Client, url string) prometheus.Collector {
	const namespace = "safebrowsing"
	const subsystem = ""
	return &safebrowsingCollector{
		client: client,
		url: url,
		isThreat: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "is_threat"),
			"if Google Safe Browsing API reports url is a threat",
			nil,
			nil,
		),
		probeSuccess: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "probe_success"),
			"whether the probe was successful or not",
			nil,
			nil,
		),
		probeDuration: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "probe_duration_seconds"),
			"returns how long the probe took to complete in seconds",
			nil,
			nil,
		),
	}
}

// Describe all metrics
func (c *safebrowsingCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.isThreat
	ch <- c.probeDuration
	ch <- c.probeSuccess
}

// Collect all metrics
func (c *safebrowsingCollector) Collect(ch chan<- prometheus.Metric) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var start = time.Now()

	threat, err := c.client.CheckThreat(c.url)
	if err != nil {
		log.Errorf("failed to probe %s: %v", c.url, err)
	}
	var success = err == nil
	ch <- prometheus.MustNewConstMetric(
		c.probeSuccess,
		prometheus.GaugeValue,
		boolToFloat(success),
	)
	ch <- prometheus.MustNewConstMetric(
		c.isThreat,
		prometheus.GaugeValue,
		boolToFloat(threat),
	)
	ch <- prometheus.MustNewConstMetric(
		c.probeDuration,
		prometheus.GaugeValue,
		time.Since(start).Seconds(),
	)
}

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}
