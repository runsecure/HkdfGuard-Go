package diagnostics

type cacheMetricNames struct {
	Operations string
}

type metricNamesT struct {
	Cache cacheMetricNames
}

// MetricNames holds metric instrument names, following the same hkdfguard.<component>.<noun>
// convention as ActivityNames.
var MetricNames = metricNamesT{
	Cache: cacheMetricNames{
		Operations: "hkdfguard.cache.operations",
	},
}
