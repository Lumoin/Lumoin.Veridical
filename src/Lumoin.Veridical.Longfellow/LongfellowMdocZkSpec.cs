namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// One row of the reference proof-specification registry (the google/longfellow-zk <c>kZkSpecs</c> table):
/// the circuit-shape and Ligero-encoding constants a dual-field mdoc prove or verify is parameterized by.
/// Every supported (version, attribute-count) pair is a pinned static instance; the upstream-pin tests
/// assert each instance against the reference dump, so a regeneration from a different upstream state
/// fails the suite.
/// </summary>
/// <remarks>
/// <para>
/// The hash circuit's public-input column is laid out as <c>[template ‖ six MACs ‖ shared key]</c>, so the
/// template element count is also the first public MAC wire index (<see cref="HashMacIndex"/>) and the
/// circuit's <c>npub_in</c> equals it plus <see cref="MacAndSharedKeyElementCount"/>. The facade checks that
/// relation against the parsed circuit, so a statement built for one specification cannot be verified
/// against another specification's circuit bytes.
/// </para>
/// <para>
/// <see cref="HashSubfieldBoundary"/> is the reference prover's REBASED boundary: the raw circuit's
/// <c>subfield_boundary</c> minus its <c>npub_in</c>, because the committed witness column excludes the
/// public inputs. The block-encoding lengths are the reference's pinned per-specification Reed-Solomon
/// row widths; the signature-side width is shared by every version-7 specification.
/// </para>
/// </remarks>
public sealed class LongfellowMdocZkSpec
{
    /// <summary>The six cross-field MAC elements plus the shared MAC key element that follow the hash template in the public-input column.</summary>
    public const int MacAndSharedKeyElementCount = 7;

    /// <summary>The signature circuit's first public MAC wire index, <c>[one, pkX, pkY, e2]</c> preceding it; version-independent in the reference.</summary>
    public const int SignatureMacIndex = 4;


    private LongfellowMdocZkSpec(
        int proofSpecVersion,
        int attributeCount,
        int hashBlockEncoded,
        int signatureBlockEncoded,
        int hashTemplateElementCount,
        int hashSubfieldBoundary)
    {
        ProofSpecVersion = proofSpecVersion;
        AttributeCount = attributeCount;
        HashBlockEncoded = hashBlockEncoded;
        SignatureBlockEncoded = signatureBlockEncoded;
        HashTemplateElementCount = hashTemplateElementCount;
        HashSubfieldBoundary = hashSubfieldBoundary;
    }


    /// <summary>
    /// The version-7 one-attribute specification (<c>longfellow-libzk-v1</c>, one disclosed attribute):
    /// the reference registry row the committed circuit fixture is pinned to.
    /// </summary>
    public static LongfellowMdocZkSpec Version7OneAttribute { get; } = new(
        proofSpecVersion: 7,
        attributeCount: 1,
        hashBlockEncoded: 4151,
        signatureBlockEncoded: 4096,
        hashTemplateElementCount: 945,
        hashSubfieldBoundary: 85112 - 952);


    /// <summary>The proof-specification version (the reference <c>ZkSpec.version</c>); selects the transcript framing.</summary>
    public int ProofSpecVersion { get; }

    /// <summary>The number of disclosed attributes the circuit proves.</summary>
    public int AttributeCount { get; }

    /// <summary>The hash circuit's Reed-Solomon block-encoding length (the reference <c>block_enc_hash</c>).</summary>
    public int HashBlockEncoded { get; }

    /// <summary>The signature circuit's Reed-Solomon block-encoding length (the reference <c>block_enc_sig</c>).</summary>
    public int SignatureBlockEncoded { get; }

    /// <summary>The element count of the hash public-input template: <c>[constant-one, attribute bits, now bits]</c>.</summary>
    public int HashTemplateElementCount { get; }

    /// <summary>The hash circuit's first public MAC wire index; the MAC region directly follows the template.</summary>
    public int HashMacIndex => HashTemplateElementCount;

    /// <summary>The hash circuit's public-input count (<c>npub_in</c>): the template plus the MAC and shared-key elements.</summary>
    public int HashPublicInputCount => HashTemplateElementCount + MacAndSharedKeyElementCount;

    /// <summary>The hash prover's rebased subfield boundary: the raw circuit's <c>subfield_boundary</c> minus its <c>npub_in</c>.</summary>
    public int HashSubfieldBoundary { get; }
}
