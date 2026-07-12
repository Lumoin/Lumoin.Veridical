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
    /// The BLS12-381-SHA-256 hash-to-curve <c>ciphersuite_id</c> — the
    /// portion of every api_id that precedes the Interface suffix. Defined
    /// by <c>draft-irtf-cfrg-bbs-signatures-10</c> Section 7.2.2 and reused
    /// verbatim as the api_id prefix for every Interface (core, blind,
    /// pseudonym) per <c>draft-irtf-cfrg-bbs-blind-signatures-03</c>
    /// Section 4.2.1 and <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c>
    /// Section 6.
    /// </summary>
    public const string Bls12Curve381Sha256CiphersuiteId = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";

    /// <summary>
    /// The BLS12-381-SHAKE-256 hash-to-curve <c>ciphersuite_id</c> — the
    /// portion of every api_id that precedes the Interface suffix. Defined
    /// by <c>draft-irtf-cfrg-bbs-signatures-10</c> Section 7.2.1 and reused
    /// verbatim as the api_id prefix for every Interface (core, blind,
    /// pseudonym) per <c>draft-irtf-cfrg-bbs-blind-signatures-03</c>
    /// Section 4.2.1 and <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c>
    /// Section 6.
    /// </summary>
    public const string Bls12Curve381Shake256CiphersuiteId = "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_";


    /// <summary>
    /// The core BBS+ Interface suffix (<c>CREATE_GENERATORS_ID</c> /
    /// <c>MAP_TO_SCALAR_ID</c>) appended to <c>ciphersuite_id</c> to form
    /// the api_id, per <c>draft-irtf-cfrg-bbs-signatures-10</c> Section 7.2.
    /// </summary>
    public const string CoreInterfaceSuffix = "H2G_HM2S_";

    /// <summary>
    /// The Blind BBS Interface suffix appended to <c>ciphersuite_id</c> to
    /// form the blind api_id, per
    /// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Section 4.2.1: an
    /// ASCII string composed of 15 bytes, replacing (not extending) the
    /// core <see cref="CoreInterfaceSuffix"/>.
    /// </summary>
    public const string BlindInterfaceSuffix = "BLIND_H2G_HM2S_";

    /// <summary>
    /// The per-verifier-pseudonym Interface suffix appended to
    /// <c>ciphersuite_id</c> to form the pseudonym api_id, per
    /// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section 6:
    /// the core <see cref="CoreInterfaceSuffix"/> with a <c>PSEUDONYM_</c>
    /// tail appended.
    /// </summary>
    public const string PseudonymInterfaceSuffix = "H2G_HM2S_PSEUDONYM_";


    /// <summary>
    /// The BLS12-381-SHA-256 ciphersuite api_id per
    /// <c>draft-irtf-cfrg-bbs-signatures-10</c> Section 7.2.2:
    /// <see cref="Bls12Curve381Sha256CiphersuiteId"/> composed with the
    /// core <see cref="CoreInterfaceSuffix"/>.
    /// </summary>
    public const string Bls12Curve381Sha256 = Bls12Curve381Sha256CiphersuiteId + CoreInterfaceSuffix;


    /// <summary>
    /// The BLS12-381-SHAKE-256 ciphersuite api_id per
    /// <c>draft-irtf-cfrg-bbs-signatures-10</c> Section 7.2.1:
    /// <see cref="Bls12Curve381Shake256CiphersuiteId"/> composed with the
    /// core <see cref="CoreInterfaceSuffix"/>.
    /// </summary>
    /// <remarks>
    /// Differs from <see cref="Bls12Curve381Sha256"/> only in the
    /// hash-to-curve-suite component (<c>XOF:SHAKE-256</c> instead
    /// of <c>XMD:SHA-256</c>). The Interface-level
    /// <c>H2G_HM2S_</c> suffix is shared because both ciphersuites
    /// use the same <c>create_generators</c> and
    /// <c>messages_to_scalars</c> Interface operations.
    /// </remarks>
    public const string Bls12Curve381Shake256 = Bls12Curve381Shake256CiphersuiteId + CoreInterfaceSuffix;


    /// <summary>
    /// The BLS12-381-SHA-256 Blind BBS Interface api_id per
    /// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Section 4.2.1:
    /// <see cref="Bls12Curve381Sha256CiphersuiteId"/> composed with
    /// <see cref="BlindInterfaceSuffix"/>.
    /// </summary>
    public const string Bls12Curve381Sha256Blind = Bls12Curve381Sha256CiphersuiteId + BlindInterfaceSuffix;

    /// <summary>
    /// The BLS12-381-SHAKE-256 Blind BBS Interface api_id per
    /// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Section 4.2.1:
    /// <see cref="Bls12Curve381Shake256CiphersuiteId"/> composed with
    /// <see cref="BlindInterfaceSuffix"/>.
    /// </summary>
    public const string Bls12Curve381Shake256Blind = Bls12Curve381Shake256CiphersuiteId + BlindInterfaceSuffix;

    /// <summary>
    /// The BLS12-381-SHA-256 per-verifier-pseudonym Interface api_id per
    /// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section 6:
    /// <see cref="Bls12Curve381Sha256CiphersuiteId"/> composed with
    /// <see cref="PseudonymInterfaceSuffix"/>.
    /// </summary>
    public const string Bls12Curve381Sha256Pseudonym = Bls12Curve381Sha256CiphersuiteId + PseudonymInterfaceSuffix;

    /// <summary>
    /// The BLS12-381-SHAKE-256 per-verifier-pseudonym Interface api_id per
    /// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section 6:
    /// <see cref="Bls12Curve381Shake256CiphersuiteId"/> composed with
    /// <see cref="PseudonymInterfaceSuffix"/>.
    /// </summary>
    public const string Bls12Curve381Shake256Pseudonym = Bls12Curve381Shake256CiphersuiteId + PseudonymInterfaceSuffix;


    /// <summary>
    /// The generator-seed prefix <c>create_generators</c> is called with
    /// (as <c>"BLIND_" || api_id</c>) to derive the prover-side blind
    /// generators, per <c>draft-irtf-cfrg-bbs-blind-signatures-03</c>
    /// Section 4.2.2 / 4.2.3. Shared verbatim by the per-verifier-pseudonym
    /// Interface (<c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c>
    /// Section 7, <c>CommitWithNym</c> / <c>BlindSignWithNym</c>), which
    /// derives its own blind generators the same way under the pseudonym
    /// api_id.
    /// </summary>
    public const string BlindGeneratorApiIdPrefix = "BLIND_";

    /// <summary>
    /// The generator-seed prefix <c>create_generators</c> is called with
    /// (as <c>"COM_DIS_" || api_id</c>) to derive the two fixed
    /// committed-disclosure bases <c>(Y_0, Y_1)</c>, per
    /// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Section 4.3.4.
    /// </summary>
    public const string CommittedDisclosureGeneratorApiIdPrefix = "COM_DIS_";
}