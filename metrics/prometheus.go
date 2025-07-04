package metrics

import (
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
)

func InitPrometheus() (*metric.MeterProvider, error) {
	exporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize prometheus exporter: %w", err)
	}

	// Custom histogram buckets with millisecond precision
	histogramView := metric.NewView(
		metric.Instrument{Kind: metric.InstrumentKindHistogram},
		metric.Stream{
			Aggregation: metric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
			},
		},
	)

	provider := metric.NewMeterProvider(
		metric.WithReader(exporter),
		metric.WithView(histogramView),
	)
	otel.SetMeterProvider(provider)

	return provider, nil
}
