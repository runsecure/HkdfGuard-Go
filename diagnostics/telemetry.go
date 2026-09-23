package diagnostics

// Root, Cache, DataProtection, EncryptedConfiguration, CryptoSessionAesGcm256, and KeyWrapping
// are the one ComponentTelemetry instance per component in the library - the single place every
// package's Tracer/Meter/EnableSensitiveLogging telemetry lives. Preserves the flag-sharing
// split from the C# original: Root, Cache, DataProtection, and EncryptedConfiguration all share
// one EnableSensitiveLogging flag (set any of them, all four read the new value);
// CryptoSessionAesGcm256 and KeyWrapping each keep their own, independent flag.
var (
	Root                   = newComponentTelemetry("HkdfGuard", nil)
	Cache                  = newComponentTelemetry("HkdfGuard.Cache", Root)
	DataProtection         = newComponentTelemetry("HkdfGuard.DataEncryptionKey", Root)
	EncryptedConfiguration = newComponentTelemetry("HkdfGuard.EncryptedConfiguration", Root)
	CryptoSessionAesGcm256 = newComponentTelemetry("HkdfGuard.CryptoSession.AesGcm256", nil)
	KeyWrapping            = newComponentTelemetry("HkdfGuard.KeyWrapping.V1", nil)
)
