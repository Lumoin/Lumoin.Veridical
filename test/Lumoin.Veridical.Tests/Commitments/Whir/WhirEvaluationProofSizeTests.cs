using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Whir;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Size gates for the WHIR evaluation proof. The serialized length is a pure
/// function of the parameter schedule and the digest size — no commitment and
/// no opening are computed — so these are exact figures rather than samples,
/// and any unintended change to the schedule derivation or the wire codec
/// moves them. The pinned numbers are the regression surface; the ordering
/// tests state the properties the pins are supposed to exhibit, so a pin that
/// is updated for a real reason still has to keep the shape of the design.
/// </summary>
/// <remarks>
/// <para>
/// Published WHIR proof sizes are deliberately not asserted against here, and
/// the reason is not the folding parameter: the published parameter tables
/// report a folding factor of 4, which is exactly the wired default. The
/// blocker that applies to every published figure is proof-of-work. Those
/// figures are produced with 28 to 30 grinding bits, and grinding lets a
/// verifier accept fewer query repetitions at the same nominal security
/// target. This library wires no grinding at all, so
/// <see cref="WellKnownWhirParameters.ComputeQueryCount"/> derives its
/// repetition count from the security target alone and can only ever sit at or
/// above a grinding-assisted count. Query repetitions drive the authentication
/// paths that dominate the serialized length, so the gap is structural and no
/// choice of argument closes it.
/// </para>
/// <para>
/// Two further blockers apply to particular figures. Those measured over a
/// 31-bit field with an extension tower cannot be matched because
/// <see cref="Scalar"/> is a fixed 32-byte value and no such field is wired
/// here. The figure measured in the capacity regime cannot be matched because
/// <see cref="WhirParameterSchedule.Create"/> refuses that regime, and the
/// schedule type has no other public constructor. Note the precise scope of
/// that refusal: the raw derivations in
/// <see cref="WellKnownWhirParameters"/> do accept the capacity regime, so its
/// query counts remain reproducible for comparison — only a schedule, and
/// therefore only a serialized length, is out of reach.
/// </para>
/// <para>
/// A length comparison becomes meaningful once a published figure states its
/// field, grinding bits, soundness regime and digest size, and a configuration
/// exists here that matches all four. The digest size is free — it is an
/// argument in [1, 64] rather than the hash's native width — so that one is
/// never the obstacle.
/// </para>
/// </remarks>
[TestClass]
internal sealed class WhirEvaluationProofSizeTests
{
    /// <summary>
    /// The pinned shape's variable count: a 2^20-coefficient message, large
    /// enough that the folded oracles and their query openings dominate the
    /// length the way they do at deployment sizes.
    /// </summary>
    private const int PinnedVariableCount = 20;

    /// <summary>
    /// The pinned shape's initial inverse-rate exponent: rate 1/16, the rate
    /// the WHIR paper's own experiments and the published implementations
    /// configure, so the pinned figures sit at a deployment-shaped point
    /// rather than an arbitrary one.
    /// </summary>
    private const int PinnedInitialRateLog2 = 4;

    /// <summary>
    /// The plain evaluation proof's serialized length at the pinned shape and
    /// the wired defaults. Dominated by the per-round query openings: each
    /// opened position carries its coset values and an authentication path of
    /// one digest per remaining tree level.
    /// </summary>
    private const int PinnedPlainSizeBytes = 718272;

    /// <summary>
    /// The plain evaluation proof's serialized length at the pinned shape in
    /// the Johnson regime. Its larger proximity radius prices fewer query
    /// repetitions than unique decoding at the same target, and the saving is
    /// carried almost entirely by the authentication paths that are no longer
    /// sent.
    /// </summary>
    private const int PinnedJohnsonPlainSizeBytes = 188128;

    /// <summary>
    /// The hiding evaluation proof's serialized length at the same shape. The
    /// excess over the plain figure is the mask oracles, their roots, their
    /// blinded openings and the mask totals.
    /// </summary>
    private const int PinnedHidingSizeBytes = 3386048;

    /// <summary>
    /// The proven-Johnson profile's serialized length at the pinned shape:
    /// the concrete benefit the profile buys over the wired default, in the
    /// unit a verifier actually pays.
    /// </summary>
    private const int PinnedProvenJohnsonSizeBytes = 148128;

    /// <summary>The wired Merkle digest size: BLAKE3's 32 bytes.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>
    /// A truncated Merkle digest size. Deployed verifiers that pay for proof
    /// bytes on-chain commonly truncate digests to 80 bits; this library ships
    /// full digests, and the contrast is what the digest-scaling gate below
    /// measures.
    /// </summary>
    private const int TruncatedDigestSizeBytes = 10;

    /// <summary>The BLS12-381 curve the pinned shapes are built over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>
    /// The plain evaluation proof's serialized length at the pinned shape,
    /// under the wired defaults: 128-bit per-round soundness in the unique
    /// decoding regime at the paper's folding parameter.
    /// </summary>
    [TestMethod]
    public void PlainEvaluationProofSizeMatchesThePinnedFigure()
    {
        int sizeBytes = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            PinnedVariableCount,
            Curve,
            PinnedInitialRateLog2,
            digestSizeBytes: DigestSizeBytes);

        Assert.AreEqual(PinnedPlainSizeBytes, sizeBytes, "The plain evaluation proof's serialized length moved.");
    }


    /// <summary>
    /// The hiding evaluation proof's serialized length at the same shape and
    /// the wired mask defaults.
    /// </summary>
    [TestMethod]
    public void HidingEvaluationProofSizeMatchesThePinnedFigure()
    {
        int sizeBytes = WhirPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
            PinnedVariableCount,
            Curve,
            PinnedInitialRateLog2,
            digestSizeBytes: DigestSizeBytes);

        Assert.AreEqual(PinnedHidingSizeBytes, sizeBytes, "The hiding evaluation proof's serialized length moved.");
    }


    /// <summary>
    /// The plain evaluation proof's serialized length at the pinned shape in
    /// the Johnson regime, which is the regime a deployment picks when it
    /// wants the shortest theorem-backed proof.
    /// </summary>
    [TestMethod]
    public void JohnsonRegimeEvaluationProofSizeMatchesThePinnedFigure()
    {
        int sizeBytes = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            PinnedVariableCount,
            Curve,
            PinnedInitialRateLog2,
            regime: WhirSoundnessRegime.ListDecodingJohnson,
            digestSizeBytes: DigestSizeBytes);

        Assert.AreEqual(PinnedJohnsonPlainSizeBytes, sizeBytes, "The Johnson-regime evaluation proof's serialized length moved.");
    }


    /// <summary>
    /// The proven-Johnson profile's serialized length at the pinned shape.
    /// This is the figure the profile exists to produce, so it is pinned
    /// rather than merely bounded.
    /// </summary>
    [TestMethod]
    public void ProvenJohnsonProfileEvaluationProofSizeMatchesThePinnedFigure()
    {
        int sizeBytes = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            PinnedVariableCount,
            Curve,
            PinnedInitialRateLog2,
            securityLevelBits: WellKnownWhirParameters.ProvenJohnsonSecurityLevelBits,
            regime: WellKnownWhirParameters.ProvenJohnsonSecurityRegime,
            digestSizeBytes: DigestSizeBytes);

        Assert.AreEqual(PinnedProvenJohnsonSizeBytes, sizeBytes, "The proven-Johnson profile's serialized length moved.");
    }


    /// <summary>
    /// The profile lowers the soundness target and widens the proximity
    /// radius at once, so it must come in shorter than the wired default on
    /// both counts. A profile that did not would have no reason to exist.
    /// </summary>
    [TestMethod]
    public void ProvenJohnsonProfileIsShorterThanTheWiredDefault()
    {
        int defaultSizeBytes = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            PinnedVariableCount,
            Curve,
            PinnedInitialRateLog2,
            digestSizeBytes: DigestSizeBytes);

        int profileSizeBytes = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            PinnedVariableCount,
            Curve,
            PinnedInitialRateLog2,
            securityLevelBits: WellKnownWhirParameters.ProvenJohnsonSecurityLevelBits,
            regime: WellKnownWhirParameters.ProvenJohnsonSecurityRegime,
            digestSizeBytes: DigestSizeBytes);

        Assert.IsLessThan(defaultSizeBytes, profileSizeBytes, "The proven-Johnson profile must produce a shorter proof than the wired default.");
    }


    /// <summary>
    /// The hiding extension imposes a fit condition the plain schedule does
    /// not: every oracle's codeword needs spare rows to carry the randomness
    /// that hides its openings, and a shape can satisfy the plain schedule
    /// while failing that. The profile is only usable for hiding proofs if it
    /// clears the condition, so this states that it does at the pinned shape.
    /// </summary>
    [TestMethod]
    public void ProvenJohnsonProfileAlsoCarriesAHidingSchedule()
    {
        int sizeBytes = WhirPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
            PinnedVariableCount,
            Curve,
            PinnedInitialRateLog2,
            securityLevelBits: WellKnownWhirParameters.ProvenJohnsonSecurityLevelBits,
            regime: WellKnownWhirParameters.ProvenJohnsonSecurityRegime,
            digestSizeBytes: DigestSizeBytes);

        Assert.IsGreaterThan(0, sizeBytes, "The proven-Johnson profile must admit a hiding schedule at the pinned shape.");
    }


    /// <summary>
    /// Hiding costs bytes. The mask oracles, their roots and their openings
    /// are carried in addition to everything the plain proof carries, so the
    /// hiding proof is strictly the larger of the two at one shape.
    /// </summary>
    [TestMethod]
    public void HidingProofIsLargerThanThePlainProof()
    {
        int plainSizeBytes = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            PinnedVariableCount,
            Curve,
            PinnedInitialRateLog2,
            digestSizeBytes: DigestSizeBytes);

        int hidingSizeBytes = WhirPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
            PinnedVariableCount,
            Curve,
            PinnedInitialRateLog2,
            digestSizeBytes: DigestSizeBytes);

        Assert.IsGreaterThan(plainSizeBytes, hidingSizeBytes, "The hiding proof must carry the mask material the plain proof omits.");
    }


    /// <summary>
    /// The Johnson regime prices a larger proximity radius, so it needs fewer
    /// query repetitions than unique decoding at the same target, and fewer
    /// queries mean fewer authentication paths on the wire. The regime's whole
    /// reason for existing is therefore visible in the serialized length.
    /// </summary>
    [TestMethod]
    public void JohnsonRegimeProducesAShorterProofThanUniqueDecoding()
    {
        int uniqueDecodingSizeBytes = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            PinnedVariableCount,
            Curve,
            PinnedInitialRateLog2,
            regime: WhirSoundnessRegime.UniqueDecoding,
            digestSizeBytes: DigestSizeBytes);

        int johnsonSizeBytes = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            PinnedVariableCount,
            Curve,
            PinnedInitialRateLog2,
            regime: WhirSoundnessRegime.ListDecodingJohnson,
            digestSizeBytes: DigestSizeBytes);

        Assert.IsLessThan(uniqueDecodingSizeBytes, johnsonSizeBytes, "The Johnson regime's larger proximity radius must buy a shorter proof.");
    }


    /// <summary>
    /// Merkle authentication paths carry one digest per level per opened
    /// position, so the digest size is a direct multiplier on the dominant
    /// part of the proof. Truncating digests to 80 bits shortens the proof;
    /// this states that the codec actually scales with the parameter rather
    /// than embedding the wired size.
    /// </summary>
    [TestMethod]
    public void ProofLengthScalesWithTheDigestSize()
    {
        int fullDigestSizeBytes = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            PinnedVariableCount,
            Curve,
            PinnedInitialRateLog2,
            digestSizeBytes: DigestSizeBytes);

        int truncatedDigestSizeBytes = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            PinnedVariableCount,
            Curve,
            PinnedInitialRateLog2,
            digestSizeBytes: TruncatedDigestSizeBytes);

        Assert.IsLessThan(fullDigestSizeBytes, truncatedDigestSizeBytes, "A shorter digest must shorten the authentication paths the proof carries.");
    }


    /// <summary>
    /// A larger committed polynomial runs more folding iterations and opens
    /// more positions, so the proof grows with the variable count. Monotonicity
    /// is the property a size pin at one shape cannot express on its own.
    /// </summary>
    [TestMethod]
    [DataRow(12, 16)]
    [DataRow(16, 20)]
    [DataRow(20, 24)]
    public void ProofLengthGrowsWithTheVariableCount(int smallerVariableCount, int largerVariableCount)
    {
        int smallerSizeBytes = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            smallerVariableCount,
            Curve,
            PinnedInitialRateLog2,
            digestSizeBytes: DigestSizeBytes);

        int largerSizeBytes = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            largerVariableCount,
            Curve,
            PinnedInitialRateLog2,
            digestSizeBytes: DigestSizeBytes);

        Assert.IsLessThan(largerSizeBytes, smallerSizeBytes, $"A polynomial in {largerVariableCount} variables must not serialize shorter than one in {smallerVariableCount}.");
    }
}
