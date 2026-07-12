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


    /// <summary>
    /// The pseudonym polynomial-evaluation-point DST suffix: appended to
    /// the pseudonym api_id (<see cref="WellKnownBbsCiphersuites.Bls12Curve381Sha256Pseudonym"/>
    /// / <see cref="WellKnownBbsCiphersuites.Bls12Curve381Shake256Pseudonym"/>) per
    /// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section 7.3.1
    /// step 2 (<c>PseudonymProofInit</c>) and Section 7.3.2 step 2
    /// (<c>PseudonymProofVerifyInit</c>): <c>z = hash_to_scalar(context_id,
    /// api_id || "VECT_NYM_SECRETS")</c>. Unlike every other DST suffix in
    /// this class, the draft does not append a trailing underscore — the
    /// suffix is exactly the 16 ASCII bytes below.
    /// </summary>
    public const string PseudonymSecretsVectorDstSuffix = "VECT_NYM_SECRETS";

    /// <summary>
    /// The mock-random-scalar DST suffix for the blind-commitment fixture
    /// vectors, composed onto the CORE Interface api_id
    /// (<see cref="WellKnownBbsCiphersuites.Bls12Curve381Sha256"/> /
    /// <see cref="WellKnownBbsCiphersuites.Bls12Curve381Shake256"/>) — NOT
    /// the blind or pseudonym extension api_id, verified against both the
    /// blind -02 Section 9 commitment fixtures (still valid for -03) and
    /// the per-verifier-pseudonym -03 Section 12 commit fixtures, which use
    /// the identical composition rule.
    /// </summary>
    public const string CommitMockRandomScalarsDstSuffix = "COMMIT_MOCK_RANDOM_SCALARS_DST_";

    /// <summary>
    /// The mock-random-scalar DST suffix for the blind-proof fixture
    /// vectors, composed onto the CORE Interface api_id — see
    /// <see cref="CommitMockRandomScalarsDstSuffix"/> for the same
    /// core-vs-extension api_id caveat (blind -02 Section 9 / nym -03
    /// Section 12 proof fixtures).
    /// </summary>
    public const string ProofMockRandomScalarsDstSuffix = "PROOF_MOCK_RANDOM_SCALARS_DST_";
}