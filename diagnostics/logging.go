package diagnostics

import "log/slog"

// SensitiveOperationLogged logs a debug-level message recording that operationName completed
// for name, mirroring the C# original's source-generated ILogger extension. Only worth calling
// when ComponentTelemetry.EnableSensitiveLogging is set - failures (OperationFailed) are always
// worth logging, but a routine sensitive operation completing is not.
//
// logger may be nil - every HkdfGuard component that accepts one treats it as optional (matching
// the C# original's ILogger<T>? default of null), and a nil logger is silently a no-op here
// rather than requiring every call site to guard it separately.
func SensitiveOperationLogged(logger *slog.Logger, operationName string, name string) {
	if logger == nil {
		return
	}
	logger.Debug(operationName+" completed for "+name+".",
		"operation", operationName,
		"name", name)
}

// OperationFailed logs an error-level message recording that operationName failed with err.
// Unlike SensitiveOperationLogged, this is unconditional - failures are always worth logging.
//
// logger may be nil (see SensitiveOperationLogged).
func OperationFailed(logger *slog.Logger, operationName string, err error) {
	if logger == nil {
		return
	}
	logger.Error(operationName+" failed.",
		"operation", operationName,
		"error", err)
}
