using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core;

/// <summary>
/// Centralised constants for OpenTelemetry activity tag names used across
/// Lumoin.Veridical components.
/// </summary>
/// <remarks>
/// <para>
/// Where <see cref="CryptographyMetrics"/> centralises <c>Meter</c> instrument
/// names (counters, histograms, gauges), this class centralises the activity
/// tag names that backends and leaf types stamp onto OTel spans. The shape
/// follows OTel naming conventions: lowercase, dot-separated, namespaced
/// under <c>crypto.</c>.
/// </para>
/// <para>
/// Subscribe to lifetime spans at application startup:
/// </para>
/// <code>
/// using var tracerProvider = Sdk.CreateTracerProviderBuilder()
///     .AddSource(CryptoActivitySource.Name)
///     .AddOtlpExporter()
///     .Build();
/// </code>
/// </remarks>
public static class CryptoTelemetry
{
    /// <summary>Activity source name for the library.</summary>
    public const string ActivitySourceName = "Lumoin.Veridical";


    /// <summary>Activity tag for the assembly that produced a value.</summary>
    public const string ProviderLibrary = "crypto.provider.library";

    /// <summary>Activity tag for the version of the assembly that produced a value.</summary>
    public const string ProviderLibraryVersion = "crypto.provider.version";

    /// <summary>Activity tag for the underlying cryptographic library used to produce a value.</summary>
    public const string LibraryName = "crypto.library.name";

    /// <summary>Activity tag for the version of the underlying cryptographic library.</summary>
    public const string LibraryVersion = "crypto.library.version";

    /// <summary>Activity tag for the static class that produced a value.</summary>
    public const string ProviderClass = "crypto.provider.class";

    /// <summary>Activity tag for the specific operation (method name) that produced a value.</summary>
    public const string ProviderOperation = "crypto.provider.operation";


    /// <summary>Activity tag for the byte length of a produced value.</summary>
    public const string ByteLength = "crypto.byte_length";

    /// <summary>Activity tag for the algebraic role of a produced value (Scalar, G1Point, Commitment, etc.).</summary>
    public const string AlgebraicRole = "crypto.algebraic_role";

    /// <summary>Activity tag for the curve parameter set (Bls12Curve381, Bn254, etc.).</summary>
    public const string CurveParameterSet = "crypto.curve";

    /// <summary>Activity tag for the proof system (Groth16, Plonk, Nova, etc.).</summary>
    public const string ProofSystem = "crypto.proof_system";

    /// <summary>Activity tag for the polynomial commitment scheme (Kzg, Ipa, Fri, etc.).</summary>
    public const string CommitmentScheme = "crypto.commitment_scheme";

    /// <summary>Activity tag for the lifetime of a sensitive value in milliseconds, set when the lifetime span is stopped.</summary>
    public const string LifetimeMs = "crypto.lifetime_ms";


    /// <summary>Activity name constants for the lifetime spans of common cryptographic value categories.</summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Nested name matches the OTel dotted-name convention at call sites (CryptoTelemetry.ActivityNames.Nonce mirrors the emitted crypto.nonce span name) and keeps activity-name constants discoverable as a group.")]
    public static class ActivityNames
    {
        /// <summary>Activity name for the lifetime of a nonce.</summary>
        public const string Nonce = "crypto.nonce";

        /// <summary>Activity name for the lifetime of a salt.</summary>
        public const string Salt = "crypto.salt";

        /// <summary>Activity name for the lifetime of a digest computation.</summary>
        public const string Digest = "crypto.digest";

        /// <summary>Activity name for the lifetime of a cryptographic key.</summary>
        public const string Key = "crypto.key";

        /// <summary>Activity name for the lifetime of a scalar field element.</summary>
        public const string Scalar = "crypto.scalar";

        /// <summary>Activity name for the lifetime of a group element (G1, G2, or Gt).</summary>
        public const string GroupElement = "crypto.group_element";

        /// <summary>Activity name for the lifetime of a polynomial commitment.</summary>
        public const string Commitment = "crypto.commitment";

        /// <summary>Activity name for the lifetime of a zero-knowledge proof.</summary>
        public const string ZkProof = "crypto.zk_proof";
    }
}