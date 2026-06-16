namespace Lumoin.Veridical.Bbs;

/// <summary>
/// Canonical BBS+ ciphersuite identifier strings per the IETF
/// <c>draft-irtf-cfrg-bbs-signatures</c> revision -10 (January 2026),
/// Section 7.2.
/// </summary>
/// <remarks>
/// The literal value is the ciphersuite's <c>api_id</c> — i.e.
/// <c>ciphersuite_id || "H2G_HM2S_"</c>, where <c>ciphersuite_id</c>
/// names the hash-to-curve suite and <c>"H2G_HM2S_"</c> names the
/// BBS+ Interface (the <c>create_generators</c> and
/// <c>messages_to_scalars</c> identifiers, per the spec's
/// <c>CREATE_GENERATORS_ID</c> and <c>MAP_TO_SCALAR_ID</c>). All
/// per-operation DSTs in <see cref="WellKnownBbsDomainSeparationTags"/>
/// are produced by appending an operation-specific ASCII suffix to
/// the api_id.
/// </remarks>
public static class WellKnownBbsCiphersuites
{
    /// <summary>
    /// The BLS12-381-SHA-256 ciphersuite api_id per
    /// <c>draft-irtf-cfrg-bbs-signatures-10</c> Section 7.2.2.
    /// </summary>
    public const string Bls12Curve381Sha256 = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";


    /// <summary>
    /// The BLS12-381-SHAKE-256 ciphersuite api_id per
    /// <c>draft-irtf-cfrg-bbs-signatures-10</c> Section 7.2.1.
    /// </summary>
    /// <remarks>
    /// Differs from <see cref="Bls12Curve381Sha256"/> only in the
    /// hash-to-curve-suite component (<c>XOF:SHAKE-256</c> instead
    /// of <c>XMD:SHA-256</c>). The Interface-level
    /// <c>H2G_HM2S_</c> suffix is shared because both ciphersuites
    /// use the same <c>create_generators</c> and
    /// <c>messages_to_scalars</c> Interface operations.
    /// </remarks>
    public const string Bls12Curve381Shake256 = "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_";
}