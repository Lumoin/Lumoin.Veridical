namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Stable domain labels and derivation suffixes that pin the Hyrax v1
/// construction to a specific byte-level convention. Tests, protocol
/// implementers, and external interop authors key on these strings; do
/// not rename them.
/// </summary>
/// <remarks>
/// <para>
/// The Hyrax commitment key's <c>Derive</c> factory builds a UTF-8
/// hash-to-curve input by concatenating a caller-supplied <em>seed</em>
/// with one of the suffix constants here (and, for vector generators,
/// a 4-byte big-endian index after the suffix). The seed parameter
/// gives application-level domain separation: two Hyrax instances over
/// the same vector length but with different seeds receive different
/// generator points and therefore disjoint commitment spaces.
/// </para>
/// <para>
/// The canonical seed for the batch-E reference is
/// <see cref="CanonicalSeedV1"/>. Tests that compare against known
/// answers fix this seed; tests that exercise seed-driven domain
/// separation construct distinct strings explicitly.
/// </para>
/// <para>
/// The DST supplied to hash-to-curve is <see cref="CommitmentKeyDst"/>
/// following the RFC 9380 <c>NAME-VERSION-RO_</c> shape.
/// </para>
/// </remarks>
public static class WellKnownHyraxDomainLabels
{
    /// <summary>The canonical seed value for the batch-E v1 Hyrax derivation. Protocols and tests pin this exact string.</summary>
    public const string CanonicalSeedV1 = "veridical.hyrax.v1";

    /// <summary>Suffix appended to the seed for vector-generator derivation. The full hash-to-curve input is <c>seed || GeneratorSuffix || i_BE</c> where <c>i_BE</c> is the 4-byte big-endian generator index.</summary>
    public const string GeneratorSuffix = ".generator";

    /// <summary>Suffix appended to the seed for Pedersen blinding-generator derivation.</summary>
    public const string BlindingSuffix = ".blinding";

    /// <summary>Suffix appended to the seed for IPA value-generator derivation. The value generator <c>U</c> binds the inner-product value into the IPA commitment.</summary>
    public const string ValueSuffix = ".value";

    /// <summary>The Fiat-Shamir domain label every Hyrax transcript carries.</summary>
    public const string TranscriptV1 = "veridical.hyrax.v1";

    /// <summary>The domain separation tag passed to hash-to-curve when deriving the commitment-key generators per RFC 9380.</summary>
    public const string CommitmentKeyDst = "VERIDICAL-HYRAX-V1-RO_";
}