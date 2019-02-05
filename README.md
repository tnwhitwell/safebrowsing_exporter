# safebrowsing_exporter

Exports the status of a URL when queried against the Google Safe Browsing API

## Running

### API key as parameter

```console
./safebrowsing_exporter -b ":9222" -k $GOOGLE_API_KEY
```

### API key as environment variable

```console
export API_KEY=$GOOGLE_API_KEY
./safebrowsing_exporter -b ":9222"
```

## Configuration

On the prometheus settings, add the safebrowsing_exporter prober:

```yaml
- job_name: safebrowsing
  metrics_path: /probe
  relabel_configs:
    - source_labels: [__address__]
      target_label: __param_target
    - source_labels: [__param_target]
      target_label: target
    - target_label: __address__
      replacement: localhost:9222 # safebrowsing_exporter address
  static_configs:
    - targets:
      - example.com
      - example.co.uk
      - example.org
```

It works more or less like prometheus's
[blackbox_exporter](https://github.com/prometheus/blackbox_exporter).

## Building locally

Run with:

```console
go run -mod=vendor main.go
```
