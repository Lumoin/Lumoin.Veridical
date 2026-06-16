namespace Lumoin.Veridical.Bbs;

/// <summary>
/// Domain-separation-tag suffix strings used by the BBS+ Interface
/// operations per IETF <c>draft-irtf-cfrg-bbs-signatures-10</c>.
/// </summary>
/// <remarks>
/// <para>
/// Each per-operation DST is computed at call time as the ciphersuite
/// <c>api_id</c> (see <see cref="WellKnownBbsCiphersuites"/>) concatenated
/// with the appropriate suffix from this class. The suffixes are kept
/// here as <c>const string</c> values rather than precomputed
/// byte arrays so the call site can choose how to encode (the BBS+
/// spec mandates ASCII, which is what UTF-8 emits for the
/// printable-ASCII characters used in these tags).
/// </para>
/// </remarks>
public static class WellKnownBbsDomainSeparationTags
{
    /// <summary>The KeyGen DST suffix: appended to api_id per Section 3.4.1.</summary>
    public const string KeygenDstSuffix = "KEYGEN_DST_";

    /// <summary>The hash-to-scalar DST suffix: appended to api_id per Section 4.2.2.</summary>
    public const string HashToScalarDstSuffix = "H2S_";

    /// <summary>The map-message-to-scalar DST suffix: appended to api_id per Section 4.2.1.</summary>
    public const string MapMessageToScalarDstSuffix = "MAP_MSG_TO_SCALAR_AS_HASH_";

    /// <summary>The generator-seed DST suffix used inside <c>create_generators</c>; appended to api_id per Section 4.1.1.</summary>
    public const string SignatureGeneratorSeedDstSuffix = "SIG_GENERATOR_SEED_";

    /// <summary>The generator-output DST suffix passed to <c>hash_to_curve_g1</c> inside <c>create_generators</c>; appended to api_id per Section 4.1.1.</summary>
    public const string SignatureGeneratorDstSuffix = "SIG_GENERATOR_DST_";

    /// <summary>The initial generator seed; appended to api_id per Section 4.1.1.</summary>
    public const string MessageGeneratorSeedSuffix = "MESSAGE_GENERATOR_SEED";
}