package diagnostics

type eventNamesT struct {
	SensitiveOperation string
}

// EventNames holds fixed span event names. Unlike the operation-specific ActivityNames, an
// event's own name stays constant regardless of which operation raised it - the operation itself
// is carried as the AttributeNames.OperationName attribute instead - so event names stay
// low-cardinality and stable for dashboards/queries.
var EventNames = eventNamesT{
	SensitiveOperation: "hkdfguard.sensitive_operation",
}
