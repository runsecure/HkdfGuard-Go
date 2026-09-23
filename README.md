# HkdfGuard-Go

A Go port of HkdfGuard (originally a C# library) for protecting data-at-rest encryption keys
using native, platform-backed key management (TPM2 on Linux, Secure Enclave on macOS, the
Platform Crypto Provider/TPM on Windows - see `keywrapping`) combined with AES-256-GCM for the
actual data encryption. Application code works against a `dataencryptionkey.KeyRing` to
encrypt/decrypt strings and binary data, with key-version tracking and purpose-scoped Additional
Authenticated Data (AAD).

## Key concepts

- **No plaintext key ever touches disk or this process's memory for longer than a single
  operation.** Wrapping/unwrapping a data encryption key (DEK) is delegated entirely to the native
  KMS library for the current OS (`keywrapping.NativeHkdfKeyWrapperV1`) - the KEK never leaves
  that native library, and this library only ever sees the wrapped payload plus the
  momentarily-revealed DEK.
- **Identified by service name, not a shared master key.** A key is identified to the native KMS
  library by a service name - not by any secret this library holds itself.
  `dataencryptionkey.KeyRingBuilder` carries this, along with a cache-expiry/rotation policy,
  fluently.
- **One `abstractions.KeyWrapper` per KEK, not per wrapped payload.** `KeyWrapper.Decrypt` takes
  the wrapped payload as an explicit argument, so a single wrapper instance (bound only to a KEK -
  e.g. a `NativeHkdfKeyWrapperV1` for one service name) can reveal any number of different wrapped
  DEKs sharing that KEK, one per registered key file.
- **Cached, expiring, proactively-refreshed cipher sessions via `abstractions.CryptoProvider`.** A
  revealed DEK is bound into an internal cipher session once, not re-derived on every
  Encrypt/Decrypt - the configured expiry (1-300 seconds) marks when it should be refreshed
  instead of reused. `CryptoProvider` owns that refresh itself, and does it ahead of time: a
  background goroutine, ticking every `expirySeconds` via `time.Ticker`, reveals and builds the
  next session before the current one expires, then swaps it in (behind a `sync.RWMutex`) and
  closes the outgoing one (zeroing its key) - so an Encrypt/Decrypt call almost never pays the
  unwrap cost itself. The concrete session type (`aesGcmCryptoSession`) is unexported - callers
  only ever see it through the public `CryptoProvider` they were given (e.g.
  `cryptosession.AesGcmCryptoProvider`), which exposes Encrypt/Decrypt directly.
  `abstractions.CryptoProviderFactory` is the single seam every consumer
  (`KeyRingBuilder`, `PipelineKeyFactory`) mints providers through, for each of the three ways a
  DEK is revealed: `Create` (wrapped-on-disk), `CreateEphemeral` (generated fresh via
  `KeyWrapper.GenerateAndWrap`), and `CreateForPipeline` (an already-plaintext DEK, used as-is).
- **Versioned, rotatable keys via `KeyRing`.** A `KeyRing` tracks any number of independently
  wrapped keys by an integer version. The highest version added automatically becomes the ring's
  `CurrentVersion` - no separate "mark as current" step, so it can never drift out of sync with
  what's actually registered.
- **Purpose-scoped protectors.** `abstractions.DataProtector` binds a `name` (purpose) to every
  operation as AAD, so a value protected for one purpose can never be decrypted under another -
  even using the same underlying key.
- **`[]byte`-based, error-returning API - no exceptions, no method overloading.** Every fallible
  operation returns `(result, error)`; Go has no optional/overloaded parameters, so where the
  C#/Java originals overload Encrypt/Decrypt with and without an `aad` parameter, Go's version
  always takes `aad []byte` and a caller with none passes `nil`. Secrets are zeroed immediately
  after use via `abstractions.ZeroMemory`.
- **Built-in telemetry.** Every package emits OpenTelemetry (`go.opentelemetry.io/otel`)
  spans/metrics via `diagnostics.ComponentTelemetry`, with exceptions recorded on failure, and an
  opt-in sensitive-logging mode that emits operation metadata (never raw key/plaintext/ciphertext
  bytes).

## Architecture overview

```
                      +------------------------------------------+
                      | Hardware Security Module (TPM2 / Enclave) |
                      +------------------------------------------+
                                           |
                                  (Wraps / Unwraps)
                                           v
+---------------------+       +---------------------------------------+
| Native KMS Library  | <---> | abstractions.KeyWrapper                |
+---------------------+       | (keywrapping.NativeHkdfKeyWrapperV1,   |
                               |  resolved once per process by         |
                               |  getLibrary)                          |
                               +---------------------------------------+
                                           |
                                  (Reveals DEK)
                                           v
                              +---------------------------+
                              | abstractions.CryptoProvider |  <-- background goroutine refreshes
                              | (cryptosession.             |      + zeroes the outgoing session
                              |  AesGcmCryptoProvider)       |
                              +---------------------------+
                                           |
                                   (AEAD Encrypt/Decrypt)
                                           v
                              +---------------------------+
                              | abstractions.DataEncryptionKey |
                              | (KeyWrapped / Pipeline, via     |
                              |  dataencryptionkey.              |
                              |  EncryptionKeyBase)              |
                              +---------------------------+
                                           |
                               (Version Management / AAD)
                                           v
               +-------------------------------------------------------+
               |               dataencryptionkey.KeyRing                |
               +-------------------------------------------------------+
                                /                              \
                               v                                v
             +------------------------------+     +--------------------------------+
             | abstractions.DataProtector    |     | cache.ProtectedCache /          |
             | (dataProtector, unexported -   |     | cache.ProtectedReadOnlyCache    |
             |  built only via                |     | (ProtectedCache/ProtectedRead-  |
             |  KeyRing.CreateProtector)       |     |  OnlyCache/ProtectedCacheBase   |
             +------------------------------+     |  live only in cache, not         |
                                                    |  abstractions - see below)       |
                                                    +--------------------------------+
```

Same shape as every other port in this workspace (the .NET repo drives the design, so Go mirrors
its layering), with one deliberate deviation: `ProtectedCache`/`ProtectedReadOnlyCache`/
`ProtectedCacheBase` live entirely in the `cache` package here, not in `abstractions` - every
other port keeps them in its abstractions layer, matching .NET's `IProtectedCache` placement, but
`abstractions` has no other consumer of them in this repo, so they're scoped to the one package
that actually implements/uses them.

1. **KEK (Key Encryption Key)** - a hardware-backed key managed by the OS/TPM/Enclave, referenced
   only by a service name. The plaintext KEK never enters this process's memory.
2. **DEK (Data Encryption Key)** - a 256-bit symmetric key wrapped by the KEK. Can be persisted to
   disk or generated ephemerally in memory - both are an `EncryptionKeyBase` around a
   `CryptoProvider` minted via `CryptoProviderFactory.Create`/`CreateEphemeral` respectively - or
   used unwrapped before a KEK exists yet (`PipelineDataEncryptionKey`, via `CreateForPipeline`).
3. **`CryptoProvider`** - the active AEAD (AES-256-GCM) cipher session holding the unwrapped DEK.
   Automatically rotates and zeroes expired sessions on a configured schedule (1-300 seconds).
4. **`KeyRing`** - manages multiple versioned keys. Adding a new key version doesn't break
   decryption of data already protected under older versions.
5. **Formatted encrypted value** - the standardized `enc::v{version}::{base64}` string, handled by
   `abstractions.EncryptedFormatProvider`/`dataencryptionkey.DefaultFormatProvider`.

## Package layout

| Package | Purpose |
|---|---|
| `diagnostics` | Every package's telemetry, centralized: `Root`/`Cache`/`DataProtection`/`EncryptedConfiguration`/`CryptoSessionAesGcm256`/`KeyWrapping` (one `*ComponentTelemetry` each - `Tracer()`, `Meter()`, `EnableSensitiveLogging()`/`SetEnableSensitiveLogging`, `RecordException`, `LogSensitiveOperation`), `ActivityNames`/`AttributeNames`/`EventNames`/`MetricNames` (OpenTelemetry semantic-convention-style names, e.g. `hkdfguard.cache.add`), `RecordCacheOperation`, and `SensitiveOperationLogged`/`OperationFailed` (`log/slog`-based logger helpers). No dependency on any other package in this module - the lowest layer, its naming/shape kept identical across every HkdfGuard port. |
| `abstractions` | Interfaces and pure data types only (`KeyWrapper`, `CryptoProvider`, `CryptoProviderFactory`, `DataEncryptionKey`, `DataProtector`, `EncryptedFormatProvider`, `KeyTrackingValue`, `IsNullOrEmpty`/`ZeroMemory`). Depends only on `diagnostics`. Does **not** hold `ProtectedCache`/`ProtectedReadOnlyCache` - see `cache`. |
| `cryptosession` | `aesGcmCryptoSession` (unexported, key-bound at construction) wrapped directly by the public `AesGcmCryptoProvider` (a `CryptoProvider` that reveals/refreshes it from a `KeyWrapper` + wrapped bytes via a goroutine + `time.Ticker`, and is the sole place the 1-300 second expiry range is validated - it only ever holds one active session at a time; also exposes `GetEncryptedAllocationLength`/`GetDecryptedAllocationLength`, and a pipeline-only construction path with no background refresh), minted via `AesGcmCryptoProviderFactory` (a `CryptoProviderFactory`). Depends on `abstractions`/`diagnostics`; its `CryptoSessionAesGcm256` telemetry component keeps its own independent `EnableSensitiveLogging` flag rather than sharing `Root`'s. |
| `keywrapping` | `NativeHkdfKeyWrapperV1` (a `KeyWrapper`) and per-OS native bindings (`kms_library_{linux,darwin,windows,other}.go`), resolved once per process via `getLibrary` (a `sync.OnceValues`-wrapped `newPlatformKmsLibrary`), to wrap and unwrap a 32-byte DEK under a service-identified KEK held entirely outside this process. |
| `dataencryptionkey` | The application-facing API: `KeyRing`/`KeyRingBuilder`, `dataProtector` (unexported - a `DataProtector`), `EncryptionKeyBase` (shared allocation-sizing/telemetry logic - also *is* the key-wrapped case directly, unlike the C#/Java originals' separate `KeyWrappedDataEncryptionKey` type), `PipelineDataEncryptionKey`, `PipelineKeyFactory` (mints a fresh-DEK `PipelineDataEncryptionKey` via a `CryptoProviderFactory`, through the inert unexported `dummyKeyWrapper`), and `DefaultFormatProvider` (the default `enc::v{version}::{base64}` wire format, built on Go's stdlib `encoding/base64` directly). Depends on `abstractions`/`diagnostics`. |
| `cache` | `ProtectedCache`/`ProtectedReadOnlyCache` (interfaces) and `ProtectedCacheBase` (shared plumbing - a `TryPopulate func(name string) bool` field stands in for the C#/Java originals' virtual-method override, since Go has no dispatch through embedding), `DefaultProtectedCache` (the default `ProtectedCache`, backed by one `abstractions.DataEncryptionKey` - encrypts on Add/AddOrUpdate, reveals on Decrypt, nothing held as plaintext beyond a single call) and `ProtectedCacheCollection` (aggregates multiple `ProtectedReadOnlyCache` sources behind one read-only surface, checked in registration order). Depends on `abstractions`/`diagnostics`. |

Requires **Go 1.26+**. Every package has its own `_test.go` files (standard `go test`, no
separate test module).

## Getting started

### 1. Wrap or reveal a DEK

`NativeHkdfKeyWrapperV1` is a `KeyWrapper` bound to whichever native KMS library matches the
current OS (resolved once per process via `getLibrary`), identified only by a service name. Since
`Decrypt` takes the wrapped payload as an explicit argument rather than one bound at construction,
a single instance freely handles both directions, and any number of different wrapped payloads
sharing that service name:

```go
wrapper, err := keywrapping.NewNativeHkdfKeyWrapperV1("my-service")
if err != nil {
    log.Fatal(err)
}

// Protect a fresh 32-byte DEK under the KEK identified by "my-service":
wrapped := make([]byte, 512) // native library's own payload format/size
written, err := wrapper.Encrypt(freshDek, wrapped)

// Later, reveal a DEK from a previously-wrapped payload for the same service:
dek := make([]byte, 32)
_, err = wrapper.Decrypt(wrapped[:written], dek)
```

The native ABI has no concept of Additional Authenticated Data - `KeyWrapper` itself does not
expose an AAD-taking method.

### 2. Build a `KeyRing`

`KeyRingBuilder` fluently collects a service name/cache-expiry/rotation policy, a shared
`KeyWrapper` and a `CryptoProviderFactory`, and any number of wrapped-DEK files - one per version
- then reads each file, mints its own `CryptoProvider` (via `CryptoProviderFactory.Create`), and
wires it into an `EncryptionKeyBase`. `WithEphemeralKey` registers a version whose own key is
instead generated fresh in memory on first use (via `CryptoProviderFactory.CreateEphemeral`) - it
shares the same `KeyWrapper`/`CryptoProviderFactory`, so no extra configuration is needed for it.
Unlike the C#/Java originals, whose `With*` setters validate and reject out-of-range values
immediately, every `With*` method here just stores its value - `Build` is the single place
everything is validated (including that `WithCachedKeyExpiry` was actually called; there's no
default), matching the fluent-builder-then-`Build` idiom Go client builders commonly use:

```go
ring, err := dataencryptionkey.NewKeyRingBuilder().
    WithServiceName("my-service").
    WithCachedKeyExpiry(60). // seconds, 0-300 - required before Build
    WithKeyRotationDays(90). // 1-180
    WithKeyWrapper(wrapper).
    WithCryptoProviderFactory(cryptosession.AesGcmCryptoProviderFactory{}).
    WithKeyFile(1, "/path/to/wrapped-dek-v1.bin").
    WithEphemeralKey(2).
    Build()
```

Registering additional key files at higher version numbers (e.g. during a rotation) is all that's
needed to advance `ring.CurrentVersion()` - existing ciphertext tagged with older versions
continues to decrypt correctly as long as those files stay registered.

### 3. Encrypt and decrypt

```go
protector := ring.CreateProtector("cookie-auth") // "cookie-auth" becomes this protector's AAD

encrypted, err := protector.Encrypt("secret value")
// e.g. "enc::v1::AbCdEf..."

maxLen, err := protector.GetMaxDecryptedLength(encrypted)
buffer := make([]byte, maxLen)
written, err := protector.Decrypt(encrypted, buffer)
decrypted := string(buffer[:written])
```

A value encrypted by one protector name can never be decrypted by a protector created with a
different name, even from the same `KeyRing` - the name is bound in as AAD on every operation.

### Ephemeral, in-memory-only keys

For scenarios that don't need a durable, file-backed key at all, `CryptoProviderFactory.
CreateEphemeral` generates and wraps a fresh DEK once via `KeyWrapper.GenerateAndWrap` - the
plaintext DEK never crosses that call's return value, and nothing here is ever written to or read
from a file. Wrap the resulting `CryptoProvider` in an `EncryptionKeyBase`, exactly as for a
file-backed key (or just call `KeyRingBuilder.WithEphemeralKey` - see above, which does exactly
this):

```go
factory := cryptosession.AesGcmCryptoProviderFactory{}
provider, err := factory.CreateEphemeral(wrapper, 60)
ephemeralKey := dataencryptionkey.NewEncryptionKeyBase(provider) // an abstractions.DataEncryptionKey
```

### Pipeline keys - encrypt now, wrap later

`PipelineDataEncryptionKey` is for the moment before a durable KEK even exists yet - e.g. a
provisioning pipeline that needs to encrypt secrets in-flight, then hand the same plaintext DEK to
the platform's native "initialize" CLI utility at the end of the chain, which independently
wraps/registers it against a real KEK. Unlike every other `DataEncryptionKey` here, its DEK is
never wrapped or unwrapped - it's used exactly as given via a trivial, unexported identity
`KeyWrapper` (`dummyKeyWrapper`). `PipelineKeyFactory` generates a fresh, random 32-byte DEK and
builds one around it via `CryptoProviderFactory.CreateForPipeline` - unlike the C#/Java
originals' `Create`, which also accepts a format-provider argument and an optional key version
that its own implementation never reads, Go's `Create` drops both rather than carrying two
parameters that do nothing:

```go
factory := dataencryptionkey.PipelineKeyFactory{}
pipelineKey, err := factory.Create(cryptosession.AesGcmCryptoProviderFactory{})
defer pipelineKey.Close()

encrypted, err := pipelineKey.Encrypt([]byte("secret value"), nil)

// At the end of the pipeline, hand the plaintext DEK off to be wrapped for real:
dek := pipelineKey.AsBytes()
initializeWithNativeCli(dek)
```

`Close` (called via `defer` above) zeroes the DEK.

## Diagnostics

All telemetry lives in `diagnostics`. Package-level vars expose one `*ComponentTelemetry` per
component (`Root`, `Cache`, `DataProtection`, `EncryptedConfiguration`, `CryptoSessionAesGcm256`,
`KeyWrapping`), each with its own `Tracer()`/`Meter()` and an `EnableSensitiveLogging` flag -
`Root`/`Cache`/`DataProtection`/`EncryptedConfiguration` share one flag (set any of them, all four
read the new value); `CryptoSessionAesGcm256` and `KeyWrapping` each keep their own, independent
flag. When enabled, operations emit a fixed-name `hkdfguard.sensitive_operation` debug event
carrying only non-sensitive metadata (lengths, versions, identifiers) as attributes - raw key,
plaintext, and ciphertext bytes are never logged, regardless of this setting.

Span, event, attribute, and metric names all follow OpenTelemetry semantic-convention style -
lowercase, dot-separated (e.g. `hkdfguard.cache.add`, attribute `hkdfguard.plaintext_length`) - see
`ActivityNames`/`AttributeNames`/`EventNames`/`MetricNames`. This naming is the part of the design
meant to translate identically into every HkdfGuard port's own OpenTelemetry SDK usage, regardless
of implementation language.

`DefaultProtectedCache` accepts an optional `*slog.Logger` (nil is a silent no-op - see
`diagnostics.SensitiveOperationLogged`) alongside its existing tracing, and records every
Add/AddOrUpdate via `diagnostics.RecordCacheOperation` (a counter on `HkdfGuardTelemetry.Cache`'s
meter).

## Testing

```bash
go build ./...
go vet ./...
go test ./...
go test ./keywrapping/... -run TestNativeHost -v   # single test
```

Every package's tests use fakes for the native KMS library and for `KeyWrapper`/`CryptoProvider`
dependencies where a real cipher isn't the thing under test, matching the same fakes-over-mocks
style used across every HkdfGuard port.
