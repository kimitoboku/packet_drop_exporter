package collector

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type MetricsCollector struct {
	store   *Store
	runtime *Runtime

	dropsDesc             *prometheus.Desc
	bytesDesc             *prometheus.Desc
	dimensionLocation     bool
	dimensionProtocol     bool
	dimensionInterface    bool
	buildInfoDesc         *prometheus.Desc
	readyDesc             *prometheus.Desc
	attachedDesc          *prometheus.Desc
	mapEntriesDesc        *prometheus.Desc
	mapMaxDesc            *prometheus.Desc
	mapBytesDesc          *prometheus.Desc
	eventsSeenDesc        *prometheus.Desc
	eventsConsDesc        *prometheus.Desc
	eventsExpDesc         *prometheus.Desc
	mapFailDesc           *prometheus.Desc
	skbFailDesc           *prometheus.Desc
	ifaceFailDesc         *prometheus.Desc
	symbolFailDesc        *prometheus.Desc
	reasonFailDesc        *prometheus.Desc
	collectDurDesc        *prometheus.Desc
	lastCollectDesc       *prometheus.Desc
	snapshotAgeDesc       *prometheus.Desc
	symbolAvailDesc       *prometheus.Desc
	collectFailDesc       *prometheus.Desc
	symbolRefreshFailDesc *prometheus.Desc
}

func NewMetricsCollector(store *Store, runtime *Runtime, version string, interfaceDimension bool) *MetricsCollector {
	return NewMetricsCollectorWithDimensions(store, runtime, version, MetricDimensions{
		Location:  true,
		Protocol:  true,
		Interface: interfaceDimension,
	})
}

type MetricDimensions struct {
	Location  bool
	Protocol  bool
	Interface bool
}

func NewMetricsCollectorWithDimensions(store *Store, runtime *Runtime, version string, dimensions MetricDimensions) *MetricsCollector {
	labels := []string{"reason"}
	if dimensions.Location {
		labels = append(labels, "location")
	}
	if dimensions.Protocol {
		labels = append(labels, "protocol")
	}
	if dimensions.Interface {
		labels = append(labels, "netns", "ifindex")
	}
	return &MetricsCollector{
		store:                 store,
		runtime:               runtime,
		dimensionLocation:     dimensions.Location,
		dimensionProtocol:     dimensions.Protocol,
		dimensionInterface:    dimensions.Interface,
		dropsDesc:             prometheus.NewDesc("linux_skb_drops_total", "Number of skb drops observed by kfree_skb.", labels, nil),
		bytesDesc:             prometheus.NewDesc("linux_skb_drop_bytes_total", "Bytes in skb drops observed by kfree_skb.", labels, nil),
		buildInfoDesc:         prometheus.NewDesc("packet_drop_exporter_build_info", "Build information.", nil, prometheus.Labels{"version": version}),
		readyDesc:             prometheus.NewDesc("packet_drop_exporter_ready", "Whether the exporter has an attached BPF program and a valid snapshot.", nil, nil),
		attachedDesc:          prometheus.NewDesc("packet_drop_exporter_bpf_attached", "Whether the kfree_skb BPF program is attached.", nil, nil),
		mapEntriesDesc:        prometheus.NewDesc("packet_drop_exporter_bpf_map_entries", "Number of entries in the last BPF snapshot.", nil, nil),
		mapMaxDesc:            prometheus.NewDesc("packet_drop_exporter_bpf_map_max_entries", "Configured maximum number of BPF map entries.", nil, nil),
		mapBytesDesc:          prometheus.NewDesc("packet_drop_exporter_bpf_map_estimated_bytes", "Lower-bound estimate of per-CPU BPF key/value storage bytes.", nil, nil),
		eventsSeenDesc:        prometheus.NewDesc("packet_drop_exporter_events_seen_total", "Tracepoint events observed by the BPF program.", nil, nil),
		eventsConsDesc:        prometheus.NewDesc("packet_drop_exporter_events_consumed_total", "SKB events classified as normal consumption.", nil, nil),
		eventsExpDesc:         prometheus.NewDesc("packet_drop_exporter_events_exported_total", "Drop events added to the BPF map.", nil, nil),
		mapFailDesc:           prometheus.NewDesc("packet_drop_exporter_map_update_failures_total", "BPF map insert or lookup failures.", nil, nil),
		skbFailDesc:           prometheus.NewDesc("packet_drop_exporter_skb_read_failures_total", "BPF skb read failures.", nil, nil),
		ifaceFailDesc:         prometheus.NewDesc("packet_drop_exporter_interface_read_failures_total", "BPF interface metadata read failures.", nil, nil),
		symbolFailDesc:        prometheus.NewDesc("packet_drop_exporter_symbol_resolution_failures_total", "Map entries whose location could not be symbolized.", nil, nil),
		reasonFailDesc:        prometheus.NewDesc("packet_drop_exporter_reason_resolution_failures_total", "Map entries whose reason was not present in kernel BTF.", nil, nil),
		collectDurDesc:        prometheus.NewDesc("packet_drop_exporter_collection_duration_seconds", "Duration of the last successful map collection.", nil, nil),
		lastCollectDesc:       prometheus.NewDesc("packet_drop_exporter_last_successful_collection_timestamp_seconds", "Unix timestamp of the last successful map collection.", nil, nil),
		snapshotAgeDesc:       prometheus.NewDesc("packet_drop_exporter_snapshot_age_seconds", "Age of the current immutable snapshot.", nil, nil),
		symbolAvailDesc:       prometheus.NewDesc("packet_drop_exporter_symbolizer_available", "Whether kallsyms provided at least one addressable symbol.", nil, nil),
		collectFailDesc:       prometheus.NewDesc("packet_drop_exporter_collection_failures_total", "Number of failed map collections since process start.", nil, nil),
		symbolRefreshFailDesc: prometheus.NewDesc("packet_drop_exporter_symbol_refresh_failures_total", "Number of failed kernel symbol refreshes since process start.", nil, nil),
	}
}

func (c *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{
		c.dropsDesc, c.bytesDesc, c.buildInfoDesc, c.readyDesc, c.attachedDesc,
		c.mapEntriesDesc, c.mapMaxDesc, c.mapBytesDesc, c.eventsSeenDesc,
		c.eventsConsDesc, c.eventsExpDesc, c.mapFailDesc, c.skbFailDesc,
		c.ifaceFailDesc, c.symbolFailDesc, c.reasonFailDesc, c.collectDurDesc,
		c.lastCollectDesc, c.snapshotAgeDesc, c.symbolAvailDesc, c.collectFailDesc,
		c.symbolRefreshFailDesc,
	} {
		ch <- desc
	}
}

func (c *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	snapshot := c.store.Load()
	if snapshot == nil {
		return
	}
	for _, drop := range snapshot.Drops {
		labels := []string{drop.Reason}
		if c.dimensionLocation {
			labels = append(labels, drop.Location)
		}
		if c.dimensionProtocol {
			labels = append(labels, drop.Protocol)
		}
		if c.dimensionInterface {
			labels = append(labels, drop.Netns, drop.Ifindex)
		}
		ch <- prometheus.MustNewConstMetric(c.dropsDesc, prometheus.CounterValue, float64(drop.Packets), labels...)
		ch <- prometheus.MustNewConstMetric(c.bytesDesc, prometheus.CounterValue, float64(drop.Bytes), labels...)
	}

	self := snapshot.Self
	ch <- prometheus.MustNewConstMetric(c.buildInfoDesc, prometheus.GaugeValue, 1)
	ch <- prometheus.MustNewConstMetric(c.readyDesc, prometheus.GaugeValue, boolFloat(c.runtime.Ready()))
	ch <- prometheus.MustNewConstMetric(c.attachedDesc, prometheus.GaugeValue, boolFloat(c.runtime.Attached()))
	ch <- prometheus.MustNewConstMetric(c.mapEntriesDesc, prometheus.GaugeValue, float64(self.MapEntries))
	ch <- prometheus.MustNewConstMetric(c.mapMaxDesc, prometheus.GaugeValue, float64(self.MapMaxEntries))
	ch <- prometheus.MustNewConstMetric(c.mapBytesDesc, prometheus.GaugeValue, float64(self.MapEstimatedBytes))
	ch <- prometheus.MustNewConstMetric(c.eventsSeenDesc, prometheus.CounterValue, float64(self.EventsSeen))
	ch <- prometheus.MustNewConstMetric(c.eventsConsDesc, prometheus.CounterValue, float64(self.EventsConsumed))
	ch <- prometheus.MustNewConstMetric(c.eventsExpDesc, prometheus.CounterValue, float64(self.EventsExported))
	ch <- prometheus.MustNewConstMetric(c.mapFailDesc, prometheus.CounterValue, float64(self.MapUpdateFailures))
	ch <- prometheus.MustNewConstMetric(c.skbFailDesc, prometheus.CounterValue, float64(self.SKBReadFailures))
	ch <- prometheus.MustNewConstMetric(c.ifaceFailDesc, prometheus.CounterValue, float64(self.InterfaceReadFailures))
	ch <- prometheus.MustNewConstMetric(c.symbolFailDesc, prometheus.CounterValue, float64(self.SymbolResolutionFailures))
	ch <- prometheus.MustNewConstMetric(c.reasonFailDesc, prometheus.CounterValue, float64(self.ReasonResolutionFailures))
	ch <- prometheus.MustNewConstMetric(c.collectDurDesc, prometheus.GaugeValue, self.CollectionDurationSeconds)
	ch <- prometheus.MustNewConstMetric(c.lastCollectDesc, prometheus.GaugeValue, timestamp(self.LastSuccessfulCollection))
	ch <- prometheus.MustNewConstMetric(c.snapshotAgeDesc, prometheus.GaugeValue, age(self.CollectedAt))
	ch <- prometheus.MustNewConstMetric(c.symbolAvailDesc, prometheus.GaugeValue, boolFloat(self.SymbolizerAvailable))
	ch <- prometheus.MustNewConstMetric(c.collectFailDesc, prometheus.CounterValue, float64(c.runtime.CollectionFailures()))
	ch <- prometheus.MustNewConstMetric(c.symbolRefreshFailDesc, prometheus.CounterValue, float64(c.runtime.SymbolRefreshFailures()))
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func timestamp(value time.Time) float64 {
	if value.IsZero() {
		return 0
	}
	return float64(value.UnixNano()) / 1e9
}

func age(value time.Time) float64 {
	if value.IsZero() {
		return 0
	}
	result := time.Since(value).Seconds()
	if result < 0 {
		return 0
	}
	return result
}
