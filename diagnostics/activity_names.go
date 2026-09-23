package diagnostics

// cacheActivityNames holds Cache component span names.
type cacheActivityNames struct {
	Add         string
	AddOrUpdate string
	Decrypt     string
}

// dataProtectionActivityNames holds DataProtection component span names.
type dataProtectionActivityNames struct {
	ProtectorEncrypt                    string
	ProtectorDecrypt                    string
	KeyWrappedKeyEncrypt                string
	KeyWrappedKeyDecrypt                string
	EphemeralKeyInitialize              string
	PipelineKeyInitialize               string
	KeyRingAdd                          string
	KeyRingGet                          string
	KeyRingGetCurrent                   string
	FormatProviderFormat                string
	FormatProviderParse                 string
	FormatProviderGetMaxDecryptedLength string
}

// cryptoSessionAesGcm256ActivityNames holds CryptoSessionAesGcm256 component span names.
type cryptoSessionAesGcm256ActivityNames struct {
	Encrypt           string
	Decrypt           string
	BackgroundRefresh string
}

// encryptedConfigurationActivityNames holds EncryptedConfiguration component span names.
type encryptedConfigurationActivityNames struct {
	Decrypt string
}

type activityNamesT struct {
	Cache                  cacheActivityNames
	DataProtection         dataProtectionActivityNames
	CryptoSessionAesGcm256 cryptoSessionAesGcm256ActivityNames
	EncryptedConfiguration encryptedConfigurationActivityNames
}

// ActivityNames holds span/operation names, grouped by component - lowercase, dot-separated
// (OpenTelemetry semantic-convention style: hkdfguard.<component>.<operation>), so the same
// names translate identically across every HkdfGuard port's own OTel SDK usage.
var ActivityNames = activityNamesT{
	Cache: cacheActivityNames{
		Add:         "hkdfguard.cache.add",
		AddOrUpdate: "hkdfguard.cache.add_or_update",
		Decrypt:     "hkdfguard.cache.decrypt",
	},
	DataProtection: dataProtectionActivityNames{
		ProtectorEncrypt:                    "hkdfguard.data_protection.protector.encrypt",
		ProtectorDecrypt:                    "hkdfguard.data_protection.protector.decrypt",
		KeyWrappedKeyEncrypt:                "hkdfguard.data_protection.key_wrapped_key.encrypt",
		KeyWrappedKeyDecrypt:                "hkdfguard.data_protection.key_wrapped_key.decrypt",
		EphemeralKeyInitialize:              "hkdfguard.data_protection.ephemeral_key.initialize",
		PipelineKeyInitialize:               "hkdfguard.data_protection.pipeline_key.initialize",
		KeyRingAdd:                          "hkdfguard.data_protection.key_ring.add",
		KeyRingGet:                          "hkdfguard.data_protection.key_ring.get",
		KeyRingGetCurrent:                   "hkdfguard.data_protection.key_ring.get_current",
		FormatProviderFormat:                "hkdfguard.data_protection.format.format",
		FormatProviderParse:                 "hkdfguard.data_protection.format.parse",
		FormatProviderGetMaxDecryptedLength: "hkdfguard.data_protection.format.get_max_decrypted_length",
	},
	CryptoSessionAesGcm256: cryptoSessionAesGcm256ActivityNames{
		Encrypt:           "hkdfguard.crypto_session_aes_gcm256.encrypt",
		Decrypt:           "hkdfguard.crypto_session_aes_gcm256.decrypt",
		BackgroundRefresh: "hkdfguard.crypto_session_aes_gcm256.background_refresh",
	},
	EncryptedConfiguration: encryptedConfigurationActivityNames{
		Decrypt: "hkdfguard.encrypted_configuration.decrypt",
	},
}
