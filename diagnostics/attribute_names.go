package diagnostics

type attributeNamesT struct {
	Name                 string
	PlaintextLength      string
	CiphertextLength     string
	EncryptedLength      string
	AadLength            string
	ValueLength          string
	KeyVersion           string
	KeyRingBecameCurrent string
	OperationName        string
	Result               string
}

// AttributeNames holds attribute/tag keys shared across every component's spans, events, and
// metrics - lowercase, dot-separated (OpenTelemetry semantic-convention style), so the same keys
// translate identically across every HkdfGuard port's own OTel SDK usage.
var AttributeNames = attributeNamesT{
	Name:                 "hkdfguard.name",
	PlaintextLength:      "hkdfguard.plaintext_length",
	CiphertextLength:     "hkdfguard.ciphertext_length",
	EncryptedLength:      "hkdfguard.encrypted_length",
	AadLength:            "hkdfguard.aad_length",
	ValueLength:          "hkdfguard.value_length",
	KeyVersion:           "hkdfguard.key_version",
	KeyRingBecameCurrent: "hkdfguard.key_ring.became_current",
	OperationName:        "hkdfguard.operation.name",
	Result:               "hkdfguard.result",
}
