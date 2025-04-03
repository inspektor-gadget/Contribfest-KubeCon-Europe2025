# Collecting metrics with Inspektor Gadget

## Overview

In this track, we're exploring Inspektor Gadget's metric collection abilities.

We've prepared an installation of Prometheus and Grafana on the Lab node - the former will
collect the metrics from Inspektor Gadget (it does so by looking for specific annotations - in this
case Inspektor Gadget has them set on its DaemonSet), the latter will present them to you in a
graphical user interface.

> Optional: You can view the annotation by looking at the DaemonSet definition using
> `kubectl describe -n gadget daemonset gadget`. Inspektor Gadget is configured to expose
> the metrics on a http endpoint that Prometheus will scrape periodically.

We'll look at the "profile_blockio" gadget (you can find more information on this particular
gadget [here](https://inspektor-gadget.io/docs/latest/gadgets/profile_blockio)).
The source code of the gadget can be found
[here](https://github.com/inspektor-gadget/inspektor-gadget/tree/main/gadgets/profile_blockio).
(But you don't need to worry about that now. We will reference the source code over this doc so
you can follow more closely what is happening, but feel free to skip those parts.)

As per the documentation, this gadget "gathers information about the usage of the block device
I/O (disk I/O), generating a histogram distribution of I/O latency (time)"

## Running the Gadget in the default way

Let's run this gadget directly and see what it outputs:

```sh
$ kubectl-gadget run profile_blockio
```

You should see something a histogram like this, updated every second.

```
latency
        µs               : count    distribution
         0 -> 1          : 0        |                                        |
         1 -> 2          : 0        |                                        |
         2 -> 4          : 0        |                                        |
         4 -> 8          : 0        |                                        |
         8 -> 16         : 0        |                                        |
        16 -> 32         : 10       |*************************               |
        32 -> 64         : 16       |****************************************|
        64 -> 128        : 1        |**                                      |
       128 -> 256        : 0        |                                        |
```

Press Ctrl+C to stop the gadget.

So this shows the different latency buckets (0-1µs, 1-2µs, ...) and how often I/O operations
landed in these buckets, timewise. The longer you leave the gadget running, the more operations
you will see.

Let's now manipulate this gadget so it exports data to Prometheus instead of printing it to
the command line.

## Manipulating a Gadget behavior using annotations

Inspektor Gadget uses `annotations` to control how data is handled. In this case, on the eBPF
side of the Gadget, Inspektor Gadget collects the durations of I/O calls in an eBPF map and
increases the counter of the bucket that duration falls into by 1.

> [Here's](https://github.com/inspektor-gadget/inspektor-gadget/blob/097b84a88d4d6a00696b9facf41058d62715929f/gadgets/profile_blockio/program.bpf.c#L32-L47) where the structs are defined in eBPF.
> The line directly after that `GADGET_MAPITER(blockio, hists);` will let IG iterate over that map periodically and name it
> `blockio`.

An operator inside of Inspektor Gadget (called [otel-metrics](https://inspektor-gadget.io/docs/latest/spec/operators/otel-metrics))
will pick up the data coming from that map and convert it into a human-readable format. It does it, because
the gadget is configured to do so in its [metadata file](https://github.com/inspektor-gadget/inspektor-gadget/blob/097b84a88d4d6a00696b9facf41058d62715929f/gadgets/profile_blockio/gadget.yaml#L9).

So the default for the gadget is to use `metrics.print: true` - let's make it actually export the histogram by
adjusting the annotations on the fly:

```
$ kubectl gadget run profile_blockio:v0.38.1 \
    --annotate=blockio:metrics.collect=true,blockio:metrics.print=false \
    --otel-metrics-name blockio:blockio-metrics
```

This will set `metrics.print: false` and `metrics.collect: true` for our data source (`blockio`).
It will also give it an explicit name, which is _required_ if you want to export metrics. We're
doing that by mapping the data source (`blockio`) to the name `blockio-metrics` using
`--otel-metrics-name blockio:blockio-metrics`. `blockio-metrics` will later on show up on Grafana.

> If you're writing your own gadgets, you would probably directly set the required annotations in
> the gadget metadata information so you won't have to change annotations on-the-fly like we just did.

If you run it using the command above, you will still see periodic messages, but they won't be formatted
nicely on the terminal anymore.

Let's now keep this gadget running in the background (otherwise it'll stop when you exit the shell).
This can simply be done by adding a `--detach` to the command.

```
$ kubectl gadget run profile_blockio:v0.38.1 \
    --annotate=blockio:metrics.collect=true,blockio:metrics.print=false \
    --otel-metrics-name blockio:blockio-metrics \
    --detach
```

It should return with the ID of that newly created gadget instance. You can see what's already running
using `kubectl gadget list` and remove gadget instances by calling `kubectl gadget delete INSTANCEID`
(where INSTANCEID is the id returned by the `--detach` command).

## Viewing the metrics inside of Grafana

Let's now expose Grafana so that we can access it from the browser. We've prepared a command
that let's you do it:

```shell
$ expose-grafana
```

Now open your browser and point it to `http://ip-address:3000/` and login with `admin` and `abcd`.
Goto `Dashboards` and click `New` -> `Import`. For the sake of simplicity we've prepared a simple
Dashboard showing the latency - you can just copy the JSON below and paste it into the `JSON model`
textarea and then click `Load` -> `Import`.

```json
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": {
          "type": "grafana",
          "uid": "-- Grafana --"
        },
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "fiscalYearStartMonth": 0,
  "graphTooltip": 0,
  "id": 1,
  "links": [],
  "panels": [
    {
      "datasource": {
        "type": "prometheus",
        "uid": "PBFA97CFB590B2093"
      },
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "fillOpacity": 80,
            "gradientMode": "none",
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            },
            "lineWidth": 1,
            "stacking": {
              "group": "A",
              "mode": "none"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green"
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          }
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "id": 1,
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "hideZeros": false,
          "mode": "single",
          "sort": "none"
        }
      },
      "pluginVersion": "11.6.0",
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "PBFA97CFB590B2093"
          },
          "disableTextWrap": false,
          "editorMode": "builder",
          "expr": "latency_bucket{otel_scope_name=\"blockio-metrics\"}",
          "format": "table",
          "fullMetaSearch": false,
          "includeNullMetadata": false,
          "legendFormat": "__auto",
          "range": true,
          "refId": "A",
          "useBackend": false
        }
      ],
      "title": "Latency",
      "type": "histogram"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "PBFA97CFB590B2093"
      },
      "fieldConfig": {
        "defaults": {
          "custom": {
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            },
            "scaleDistribution": {
              "type": "linear"
            }
          }
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 0
      },
      "id": 2,
      "options": {
        "calculate": false,
        "cellGap": 1,
        "color": {
          "exponent": 0.5,
          "fill": "dark-orange",
          "mode": "scheme",
          "reverse": false,
          "scale": "exponential",
          "scheme": "Oranges",
          "steps": 64
        },
        "exemplars": {
          "color": "rgba(255,0,255,0.7)"
        },
        "filterValues": {
          "le": 1e-9
        },
        "legend": {
          "show": true
        },
        "rowsFrame": {
          "layout": "auto"
        },
        "tooltip": {
          "mode": "single",
          "showColorScale": false,
          "yHistogram": false
        },
        "yAxis": {
          "axisPlacement": "left",
          "reverse": false,
          "unit": "µs"
        }
      },
      "pluginVersion": "11.6.0",
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "PBFA97CFB590B2093"
          },
          "disableTextWrap": false,
          "editorMode": "builder",
          "exemplar": false,
          "expr": "rate(latency_bucket{otel_scope_name=\"blockio-metrics\"}[1m])",
          "format": "heatmap",
          "fullMetaSearch": false,
          "includeNullMetadata": false,
          "instant": false,
          "legendFormat": "__auto",
          "range": true,
          "refId": "A",
          "useBackend": false
        }
      ],
      "title": "Latency",
      "type": "heatmap"
    }
  ],
  "preload": false,
  "refresh": "auto",
  "schemaVersion": 41,
  "tags": [],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-5m",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "browser",
  "title": "Latency Dashboard",
  "uid": "behsa6ehpu7swe",
  "version": 3
}
```

Congratulations! You can by now hopefully see the collected metrics inside of Grafana!

This is the end of this track - feel free to continue with another track.
