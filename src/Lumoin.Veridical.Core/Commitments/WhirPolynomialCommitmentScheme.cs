using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Whir;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Adapts the WHIR IOPP to the scheme-agnostic
/// <see cref="PolynomialCommitmentProvider"/> surface. The factory captures
/// the curve, the rate and schedule figures, and the algebraic / transcript /
/// Merkle backends once; the returned operations close over them, so a
/// consumer supplies only the per-call arguments (polynomial, point,
/// transcript) and never names a WHIR type. An evaluation claim is the IOPP
/// statement <c>ŵ = Z·eq(z, ·)</c> with target <c>σ = f̂(z)</c>: the
/// commitment is the input oracle's Merkle root and the opening is the
/// serialized IOPP proof.
/// </summary>
/// <remarks>
/// <para>
/// WHIR is a transparent, hash-based, post-quantum-resistant commitment: no
/// structured reference string and no group operations, only smooth
/// Reed-Solomon codes over the scalar field's two-adic subgroups, Merkle
/// commitments and field arithmetic. It differs from the BaseFold sibling in
/// its round-by-round rate improvement, which prices markedly fewer queries
/// in later rounds; the schedule derivation requires the polynomial's
/// variable count plus the rate exponent to fit the field's two-adicity, and
/// at least one whole folding step.
/// </para>
/// <para>
/// Plain WHIR is <em>not hiding</em>: the commitment is a deterministic
/// Merkle root over the codeword and openings reveal queried coset blocks.
/// The blind on the surface is therefore a placeholder with no secret state.
/// <see cref="CreateZeroKnowledge"/> is the hiding sibling — HVZK-WHIR's
/// randomized encoding with the encoding randomness as the blind. The
/// weighted-opening quartet is not supplied by either factory — the wired
/// IOPP statement carries equality-kernel weights only, so both providers
/// are refused by masked Spartan; a dense-weight statement extension remains
/// future work.
/// </para>
/// <para>
/// The schedule is re-derived per call from the captured figures and the
/// polynomial's variable count, matching the correctness-first stance —
/// caching the derived schedule per size is a later performance refinement.
/// </para>
/// </remarks>
public static class WhirPolynomialCommitmentScheme
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>
    /// The blind a WHIR commitment carries: a single zero byte. Plain WHIR
    /// has no hiding randomness, but the surface's blind must be non-empty,
    /// so this is a placeholder the open operation never reads.
    /// </summary>
    private const int PlaceholderBlindLengthBytes = 1;


    /// <summary>
    /// Builds a WHIR-backed provider at the given rate and schedule figures.
    /// The returned provider's scheme is <see cref="CommitmentScheme.Whir"/>
    /// and its curve is <paramref name="curve"/>.
    /// </summary>
    /// <param name="curve">The curve every produced artifact is tagged with.</param>
    /// <param name="initialRateLog2">The initial inverse-rate exponent <c>c ≥ 1</c>: the input oracle's rate is <c>2^-c</c>.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hash">Fiat-Shamir absorb backend.</param>
    /// <param name="squeeze">Fiat-Shamir squeeze backend.</param>
    /// <param name="reduce">Scalar reduction backend.</param>
    /// <param name="add">Scalar addition backend.</param>
    /// <param name="subtract">Scalar subtraction backend.</param>
    /// <param name="multiply">Scalar multiplication backend.</param>
    /// <param name="invert">Scalar inversion backend (for the verifier's fold recomputation).</param>
    /// <param name="foldingParameter">The folding parameter <c>k</c>; defaults to <see cref="WellKnownWhirParameters.DefaultFoldingParameter"/>.</param>
    /// <param name="securityLevelBits">The per-round soundness target <c>λ</c>; defaults to <see cref="WellKnownWhirParameters.ClassicalSecurityLevelBits"/>.</param>
    /// <param name="regime">The soundness regime; defaults to the fully-proven <see cref="WhirSoundnessRegime.UniqueDecoding"/>.</param>
    /// <param name="digestSizeBytes">The Merkle node digest size <paramref name="merkleHash"/> produces; defaults to <see cref="WellKnownMerkleHashParameters.DefaultDigestSizeBytes"/>.</param>
    /// <returns>A provider whose commit / open / verify route to the WHIR IOPP.</returns>
    /// <exception cref="ArgumentNullException">When any reference argument is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    public static PolynomialCommitmentProvider Create(
        CurveParameterSet curve,
        int initialRateLog2,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        int foldingParameter = WellKnownWhirParameters.DefaultFoldingParameter,
        int securityLevelBits = WellKnownWhirParameters.ClassicalSecurityLevelBits,
        WhirSoundnessRegime regime = WellKnownWhirParameters.ClassicalSecurityRegime,
        int digestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes)
    {
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentOutOfRangeException.ThrowIfLessThan(initialRateLog2, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(foldingParameter, 1);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(securityLevelBits);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(digestSizeBytes, WellKnownMerkleHashParameters.MaximumDigestSizeBytes);

        WhirParameterSchedule DeriveSchedule(int variableCount)
        {
            return WhirParameterSchedule.Create(curve, variableCount, initialRateLog2, foldingParameter, securityLevelBits, regime);
        }

        PolynomialCommitDelegate commit = (polynomial, pool) =>
        {
            WhirParameterSchedule schedule = DeriveSchedule(polynomial.VariableCount);
            int messageBytes = (1 << polynomial.VariableCount) * ScalarSize;

            using IMemoryOwner<byte> coefficientsOwner = pool.Rent(messageBytes);
            Span<byte> coefficients = coefficientsOwner.Memory.Span[..messageBytes];
            polynomial.InterpolateToCoefficients(coefficients, subtract);

            using MerkleRoot root = WhirIoppProver.ComputeInputCommitment(schedule, coefficients, merkleHash, add, subtract, multiply, pool);

            PolynomialCommitment commitment = PolynomialCommitment.FromBytes(
                root.AsReadOnlySpan(), curve, CommitmentScheme.Whir, pool);
            PolynomialCommitmentBlind blind = PolynomialCommitmentBlind.CreateZero(
                PlaceholderBlindLengthBytes, curve, CommitmentScheme.Whir, pool);

            return (commitment, blind);
        };

        PolynomialOpenDelegate open = (commitment, blind, polynomial, evaluationPoint, transcript, pool) =>
        {
            int variableCount = polynomial.VariableCount;
            WhirParameterSchedule schedule = DeriveSchedule(variableCount);
            int messageBytes = (1 << variableCount) * ScalarSize;
            int pointBytes = variableCount * ScalarSize;

            using IMemoryOwner<byte> workOwner = pool.Rent(messageBytes + pointBytes + (2 * ScalarSize));
            Span<byte> work = workOwner.Memory.Span[..(messageBytes + pointBytes + (2 * ScalarSize))];
            Span<byte> coefficients = work[..messageBytes];
            Span<byte> point = work.Slice(messageBytes, pointBytes);
            Span<byte> scale = work.Slice(messageBytes + pointBytes, ScalarSize);
            Span<byte> target = work.Slice(messageBytes + pointBytes + ScalarSize, ScalarSize);

            polynomial.InterpolateToCoefficients(coefficients, subtract);
            CopyEvaluationPoint(evaluationPoint, point);
            scale.Clear();
            scale[ScalarSize - 1] = 0x01;
            WhirMultilinear.EvaluateCoefficientsAtPoint(coefficients, point, variableCount, target, add, multiply, curve, pool);

            (WhirIoppProof proof, MerkleRoot root) = WhirIoppProver.Prove(
                schedule,
                coefficients,
                scale,
                point,
                target,
                transcript,
                merkleHash,
                hash,
                squeeze,
                reduce,
                add,
                subtract,
                multiply,
                pool);

            using(proof)
            using(root)
            {
                (IMemoryOwner<byte> bytesOwner, int length) = WhirProofSerialization.ToBytes(proof, digestSizeBytes, pool);
                using(bytesOwner)
                {
                    PolynomialOpening opening = PolynomialOpening.FromBytes(
                        bytesOwner.Memory.Span[..length], curve, CommitmentScheme.Whir, pool);

                    return (opening, WrapScalar(target, curve, pool));
                }
            }
        };

        PolynomialVerifyEvaluationDelegate verifyEvaluation = (commitment, evaluationPoint, claimedValue, opening, transcript, pool) =>
        {
            int variableCount = evaluationPoint.Length;
            WhirParameterSchedule schedule = DeriveSchedule(variableCount);

            WhirIoppProof? proof = null;
            try
            {
                proof = WhirProofSerialization.FromBytes(opening.AsReadOnlySpan(), schedule, digestSizeBytes, pool);
            }
            catch(ArgumentException)
            {
                //Malformed opening bytes are a rejection, not a fault.
                return false;
            }

            int pointBytes = variableCount * ScalarSize;
            using(proof)
            using(MerkleRoot root = MerkleRoot.FromBytes(commitment.AsReadOnlySpan(), pool))
            using(IMemoryOwner<byte> workOwner = pool.Rent(pointBytes + ScalarSize))
            {
                Span<byte> work = workOwner.Memory.Span[..(pointBytes + ScalarSize)];
                Span<byte> point = work[..pointBytes];
                Span<byte> scale = work.Slice(pointBytes, ScalarSize);
                CopyEvaluationPoint(evaluationPoint, point);
                scale.Clear();
                scale[ScalarSize - 1] = 0x01;

                return WhirIoppVerifier.Verify(
                    schedule,
                    root,
                    proof,
                    scale,
                    point,
                    claimedValue.AsReadOnlySpan(),
                    transcript,
                    merkleHash,
                    hash,
                    squeeze,
                    reduce,
                    add,
                    subtract,
                    multiply,
                    invert,
                    pool);
            }
        };

        return new PolynomialCommitmentProvider(
            CommitmentScheme.Whir, curve, commit, open, verifyEvaluation,
            ownedResource: null,
            //WHIR's query counts vary per round and per polynomial size, so no
            //single repetition count describes the scheme; consumers size
            //openings via WhirProofSerialization.ComputeLength instead.
            queryCount: null, digestSizeBytes: digestSizeBytes,
            //The commitment is a Merkle root over the codeword — binding but
            //not additively homomorphic, so it cannot back Nova-style folding;
            //and not hiding (the root is a deterministic fingerprint of the
            //witness, openings reveal queried coset blocks).
            isAdditivelyHomomorphic: false, isHiding: false,
            extraVariableCount: null,
            //Binding-only: no weighted-opening path (the Ligero precedent), so
            //masked Spartan's SupportsWeightedOpening check refuses this
            //provider rather than discovering the gap mid-proof.
            commitVector: null, openWeightedSum: null, verifyWeightedSum: null,
            resolveStatisticalMaskShape: null,
            inverseRate: 1 << initialRateLog2);
    }


    /// <summary>
    /// Builds a hiding WHIR-backed provider (HVZK-WHIR, eprint 2026/391
    /// Construction 9.7) at the given rate, schedule and mask figures. The
    /// commitment is the zero-knowledge encoding's Merkle root — randomized
    /// by fresh per-commit encoding randomness, which travels as the
    /// commitment's blind — and the opening is the serialized hiding IOPP
    /// proof, whose queried blocks are simulatable within the derived
    /// budgets. The returned provider reports
    /// <see cref="PolynomialCommitmentProvider.IsHiding"/> as
    /// <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// The weighted-opening quartet is still not supplied: the hiding path
    /// changes the commitment and the opening, not the wired
    /// equality-kernel statement, so masked Spartan refuses this provider
    /// exactly as it refuses the plain one. The zero-knowledge extension is
    /// re-derived per call from the captured figures and the polynomial's
    /// variable count, like the plain factory.
    /// </remarks>
    /// <param name="curve">The curve every produced artifact is tagged with.</param>
    /// <param name="initialRateLog2">The initial inverse-rate exponent <c>c ≥ 1</c>: the input oracle's rate is <c>2^-c</c>.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hash">Fiat-Shamir absorb backend.</param>
    /// <param name="squeeze">Fiat-Shamir squeeze backend.</param>
    /// <param name="reduce">Scalar reduction backend.</param>
    /// <param name="add">Scalar addition backend.</param>
    /// <param name="subtract">Scalar subtraction backend.</param>
    /// <param name="multiply">Scalar multiplication backend.</param>
    /// <param name="invert">Scalar inversion backend (for the fold recomputations on both sides).</param>
    /// <param name="maskRandom">The entropy-sourced sampler behind every hiding ingredient: encoding randomness, masks, pads and blinds.</param>
    /// <param name="foldingParameter">The folding parameter <c>k</c>; defaults to <see cref="WellKnownWhirParameters.DefaultFoldingParameter"/>.</param>
    /// <param name="securityLevelBits">The per-round soundness target <c>λ</c>; defaults to <see cref="WellKnownWhirParameters.ClassicalSecurityLevelBits"/>.</param>
    /// <param name="regime">The soundness regime; defaults to the fully-proven <see cref="WhirSoundnessRegime.UniqueDecoding"/>.</param>
    /// <param name="digestSizeBytes">The Merkle node digest size <paramref name="merkleHash"/> produces; defaults to <see cref="WellKnownMerkleHashParameters.DefaultDigestSizeBytes"/>.</param>
    /// <param name="maskMessageLength">The mask message length <c>ℓ_zk</c>; defaults to <see cref="WhirZkParameters.DefaultMaskMessageLength"/>.</param>
    /// <param name="maskRateLog2">The mask codes' inverse-rate exponent; defaults to <see cref="WhirZkParameters.DefaultMaskRateLog2"/>.</param>
    /// <returns>A hiding provider whose commit / open / verify route to the HVZK-WHIR IOPP.</returns>
    /// <exception cref="ArgumentNullException">When any reference argument is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    public static PolynomialCommitmentProvider CreateZeroKnowledge(
        CurveParameterSet curve,
        int initialRateLog2,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarRandomDelegate maskRandom,
        int foldingParameter = WellKnownWhirParameters.DefaultFoldingParameter,
        int securityLevelBits = WellKnownWhirParameters.ClassicalSecurityLevelBits,
        WhirSoundnessRegime regime = WellKnownWhirParameters.ClassicalSecurityRegime,
        int digestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes,
        int maskMessageLength = WhirZkParameters.DefaultMaskMessageLength,
        int maskRateLog2 = WhirZkParameters.DefaultMaskRateLog2)
    {
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(maskRandom);
        ArgumentOutOfRangeException.ThrowIfLessThan(initialRateLog2, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(foldingParameter, 1);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(securityLevelBits);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(digestSizeBytes, WellKnownMerkleHashParameters.MaximumDigestSizeBytes);
        ArgumentOutOfRangeException.ThrowIfLessThan(maskMessageLength, WhirZkParameters.MinimumMaskMessageLength);
        ArgumentOutOfRangeException.ThrowIfLessThan(maskRateLog2, 1);

        WhirZkParameters DeriveParameters(int variableCount)
        {
            return WhirZkParameters.Create(
                WhirParameterSchedule.Create(curve, variableCount, initialRateLog2, foldingParameter, securityLevelBits, regime),
                maskMessageLength,
                maskRateLog2);
        }

        PolynomialCommitDelegate commit = (polynomial, pool) =>
        {
            WhirZkParameters parameters = DeriveParameters(polynomial.VariableCount);
            int messageBytes = (1 << polynomial.VariableCount) * ScalarSize;
            int randomnessBytes = parameters.OracleRandomnessElementCount(0) * ScalarSize;

            using IMemoryOwner<byte> workOwner = pool.Rent(messageBytes + randomnessBytes);
            Span<byte> work = workOwner.Memory.Span[..(messageBytes + randomnessBytes)];
            Span<byte> coefficients = work[..messageBytes];
            Span<byte> randomness = work.Slice(messageBytes, randomnessBytes);
            polynomial.InterpolateToCoefficients(coefficients, subtract);
            ZkWhirIoppProver.FillWithScalars(randomness, maskRandom, curve);

            using MerkleRoot root = ZkWhirIoppProver.ComputeInputCommitment(
                parameters, coefficients, randomness, merkleHash, add, subtract, multiply, pool);

            PolynomialCommitment commitment = PolynomialCommitment.FromBytes(
                root.AsReadOnlySpan(), curve, CommitmentScheme.Whir, pool);

            //The encoding randomness is the commitment's secret state: the
            //open operation must encode the same randomized codeword the
            //root fingerprints, so it travels as the blind.
            PolynomialCommitmentBlind blind = PolynomialCommitmentBlind.FromCanonical(
                randomness, curve, CommitmentScheme.Whir, pool);

            return (commitment, blind);
        };

        PolynomialOpenDelegate open = (commitment, blind, polynomial, evaluationPoint, transcript, pool) =>
        {
            int variableCount = polynomial.VariableCount;
            WhirZkParameters parameters = DeriveParameters(variableCount);
            int messageBytes = (1 << variableCount) * ScalarSize;
            int pointBytes = variableCount * ScalarSize;

            using IMemoryOwner<byte> workOwner = pool.Rent(messageBytes + pointBytes + (2 * ScalarSize));
            Span<byte> work = workOwner.Memory.Span[..(messageBytes + pointBytes + (2 * ScalarSize))];
            Span<byte> coefficients = work[..messageBytes];
            Span<byte> point = work.Slice(messageBytes, pointBytes);
            Span<byte> scale = work.Slice(messageBytes + pointBytes, ScalarSize);
            Span<byte> target = work.Slice(messageBytes + pointBytes + ScalarSize, ScalarSize);

            polynomial.InterpolateToCoefficients(coefficients, subtract);
            CopyEvaluationPoint(evaluationPoint, point);
            scale.Clear();
            scale[ScalarSize - 1] = 0x01;
            WhirMultilinear.EvaluateCoefficientsAtPoint(coefficients, point, variableCount, target, add, multiply, curve, pool);

            (ZkWhirIoppProof proof, MerkleRoot root) = ZkWhirIoppProver.Prove(
                parameters,
                coefficients,
                blind.AsReadOnlySpan(),
                scale,
                point,
                target,
                transcript,
                merkleHash,
                hash,
                squeeze,
                reduce,
                add,
                subtract,
                multiply,
                invert,
                maskRandom,
                pool);

            using(proof)
            using(root)
            {
                (IMemoryOwner<byte> bytesOwner, int length) = ZkWhirProofSerialization.ToBytes(proof, digestSizeBytes, pool);
                using(bytesOwner)
                {
                    PolynomialOpening opening = PolynomialOpening.FromBytes(
                        bytesOwner.Memory.Span[..length], curve, CommitmentScheme.Whir, pool);

                    return (opening, WrapScalar(target, curve, pool));
                }
            }
        };

        PolynomialVerifyEvaluationDelegate verifyEvaluation = (commitment, evaluationPoint, claimedValue, opening, transcript, pool) =>
        {
            int variableCount = evaluationPoint.Length;
            WhirZkParameters parameters = DeriveParameters(variableCount);

            ZkWhirIoppProof? proof = null;
            try
            {
                proof = ZkWhirProofSerialization.FromBytes(opening.AsReadOnlySpan(), parameters, digestSizeBytes, pool);
            }
            catch(ArgumentException)
            {
                //Malformed opening bytes are a rejection, not a fault.
                return false;
            }

            int pointBytes = variableCount * ScalarSize;
            using(proof)
            using(MerkleRoot root = MerkleRoot.FromBytes(commitment.AsReadOnlySpan(), pool))
            using(IMemoryOwner<byte> workOwner = pool.Rent(pointBytes + ScalarSize))
            {
                Span<byte> work = workOwner.Memory.Span[..(pointBytes + ScalarSize)];
                Span<byte> point = work[..pointBytes];
                Span<byte> scale = work.Slice(pointBytes, ScalarSize);
                CopyEvaluationPoint(evaluationPoint, point);
                scale.Clear();
                scale[ScalarSize - 1] = 0x01;

                return ZkWhirIoppVerifier.Verify(
                    parameters,
                    root,
                    proof,
                    scale,
                    point,
                    claimedValue.AsReadOnlySpan(),
                    transcript,
                    merkleHash,
                    hash,
                    squeeze,
                    reduce,
                    add,
                    subtract,
                    multiply,
                    invert,
                    pool);
            }
        };

        return new PolynomialCommitmentProvider(
            CommitmentScheme.Whir, curve, commit, open, verifyEvaluation,
            ownedResource: null,
            queryCount: null, digestSizeBytes: digestSizeBytes,
            //Still a Merkle-root commitment — binding, not additively
            //homomorphic — but hiding: the root fingerprints a randomized
            //codeword and every scheduled opening is simulatable within the
            //derived per-oracle budgets.
            isAdditivelyHomomorphic: false, isHiding: true,
            extraVariableCount: null,
            commitVector: null, openWeightedSum: null, verifyWeightedSum: null,
            resolveStatisticalMaskShape: null,
            inverseRate: 1 << initialRateLog2);
    }


    /// <summary>
    /// Returns the byte size of the serialized WHIR evaluation proof (the
    /// opening) for a multilinear polynomial in
    /// <paramref name="variableCount"/> variables under the given schedule
    /// figures. A consumer that embeds WHIR openings in a larger proof uses
    /// this to lay out and recover the variable-length opening sections
    /// without naming the internal serializer.
    /// </summary>
    /// <param name="variableCount">The committed polynomial's variable count.</param>
    /// <param name="curve">The curve the codes are over.</param>
    /// <param name="initialRateLog2">The initial inverse-rate exponent the provider was built with.</param>
    /// <param name="foldingParameter">The folding parameter the provider was built with.</param>
    /// <param name="securityLevelBits">The per-round soundness target the provider was built with.</param>
    /// <param name="regime">The soundness regime the provider was built with.</param>
    /// <param name="digestSizeBytes">The Merkle digest size the provider was built with.</param>
    /// <returns>The opening's serialized byte length.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    /// <exception cref="ArgumentException">When the shape cannot carry a schedule at the given figures.</exception>
    public static int GetEvaluationProofSizeBytes(
        int variableCount,
        CurveParameterSet curve,
        int initialRateLog2,
        int foldingParameter = WellKnownWhirParameters.DefaultFoldingParameter,
        int securityLevelBits = WellKnownWhirParameters.ClassicalSecurityLevelBits,
        WhirSoundnessRegime regime = WellKnownWhirParameters.ClassicalSecurityRegime,
        int digestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes)
    {
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(curve, variableCount, initialRateLog2, foldingParameter, securityLevelBits, regime);

        return WhirProofSerialization.ComputeLength(schedule, digestSizeBytes);
    }


    /// <summary>
    /// Returns the byte size of the serialized hiding WHIR evaluation proof
    /// (the opening a <see cref="CreateZeroKnowledge"/> provider produces)
    /// for a multilinear polynomial in <paramref name="variableCount"/>
    /// variables under the given schedule and mask figures.
    /// </summary>
    /// <param name="variableCount">The committed polynomial's variable count.</param>
    /// <param name="curve">The curve the codes are over.</param>
    /// <param name="initialRateLog2">The initial inverse-rate exponent the provider was built with.</param>
    /// <param name="foldingParameter">The folding parameter the provider was built with.</param>
    /// <param name="securityLevelBits">The per-round soundness target the provider was built with.</param>
    /// <param name="regime">The soundness regime the provider was built with.</param>
    /// <param name="digestSizeBytes">The Merkle digest size the provider was built with.</param>
    /// <param name="maskMessageLength">The mask message length the provider was built with.</param>
    /// <param name="maskRateLog2">The mask-code inverse-rate exponent the provider was built with.</param>
    /// <returns>The opening's serialized byte length.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    /// <exception cref="ArgumentException">When the shape cannot carry a schedule or its hiding extension at the given figures.</exception>
    public static int GetZeroKnowledgeEvaluationProofSizeBytes(
        int variableCount,
        CurveParameterSet curve,
        int initialRateLog2,
        int foldingParameter = WellKnownWhirParameters.DefaultFoldingParameter,
        int securityLevelBits = WellKnownWhirParameters.ClassicalSecurityLevelBits,
        WhirSoundnessRegime regime = WellKnownWhirParameters.ClassicalSecurityRegime,
        int digestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes,
        int maskMessageLength = WhirZkParameters.DefaultMaskMessageLength,
        int maskRateLog2 = WhirZkParameters.DefaultMaskRateLog2)
    {
        WhirZkParameters parameters = WhirZkParameters.Create(
            WhirParameterSchedule.Create(curve, variableCount, initialRateLog2, foldingParameter, securityLevelBits, regime),
            maskMessageLength,
            maskRateLog2);

        return ZkWhirProofSerialization.ComputeLength(parameters, digestSizeBytes);
    }


    /// <summary>
    /// Concatenates the evaluation point's coordinates, first variable
    /// first, into the flat span the IOPP statement consumes.
    /// </summary>
    /// <param name="evaluationPoint">The evaluation point, one scalar per variable.</param>
    /// <param name="destination">The destination span, one element per coordinate.</param>
    private static void CopyEvaluationPoint(ReadOnlySpan<Scalar> evaluationPoint, Span<byte> destination)
    {
        for(int coordinate = 0; coordinate < evaluationPoint.Length; coordinate++)
        {
            evaluationPoint[coordinate].AsReadOnlySpan().CopyTo(destination.Slice(coordinate * ScalarSize, ScalarSize));
        }
    }


    /// <summary>
    /// Copies a computed value into a pool-owned <see cref="Scalar"/>.
    /// </summary>
    /// <param name="value">The value's bytes, one element.</param>
    /// <param name="curve">The curve identifying the scalar field.</param>
    /// <param name="pool">The pool to rent the scalar's buffer from.</param>
    /// <returns>The scalar; ownership transfers to the caller.</returns>
    private static Scalar WrapScalar(ReadOnlySpan<byte> value, CurveParameterSet curve, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        value.CopyTo(owner.Memory.Span[..ScalarSize]);

        return new Scalar(owner, curve, WellKnownAlgebraicTags.ScalarFor(curve));
    }
}
