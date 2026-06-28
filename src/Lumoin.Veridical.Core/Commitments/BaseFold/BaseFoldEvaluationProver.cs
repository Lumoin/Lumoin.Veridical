using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// The BaseFold evaluation-protocol prover: proves that the committed
/// multilinear polynomial <c>f</c> evaluates to <c>y = f(z)</c> at a point
/// <c>z</c>. It interleaves a sumcheck for <c>Σ_b f(b)·eq_z(b) = y</c> with the
/// BaseFold IOPP, where the sumcheck round challenge of each round IS the IOPP
/// fold challenge of that round. Produces a <see cref="BaseFoldEvaluationProof"/>
/// and returns the claimed value <c>y</c>.
/// </summary>
/// <remarks>
/// <para>
/// Implements the prover side of Protocol 4 / Fig. 3 (Zeilberger, Chen, Fisch,
/// CRYPTO 2024, IACR ePrint 2023/1705). Structural inspiration only, no code
/// dependency.
/// </para>
/// <para>
/// Three reductions advance in lockstep under the shared per-round challenges,
/// binding the highest remaining variable first (the order
/// <see cref="FoldableCodeExtensions.Encode"/> collapses, since it splits the
/// coefficient vector on the high index bit):
/// </para>
/// <list type="bullet">
///   <item><description>the codeword <c>π_ℓ</c> folds to <c>π_{ℓ-1}</c> via <see cref="FoldableCodeExtensions.Fold"/>, Merkle-committed each layer — the IOPP;</description></item>
///   <item><description>the dense evaluation table of <c>f</c> and of <c>eq_z</c> fold on the high bit, yielding each round's degree-2 polynomial <c>h_i</c> of the product — the sumcheck.</description></item>
/// </list>
/// <para>
/// Because the codeword fold of <c>Enc_d(coeffs)</c> under the challenges
/// computes the same evaluation <c>f(r_0, …, r_{d-1})</c> the sumcheck reduces
/// to, the fully folded base codeword <c>π_0 = Enc_0(f(r))</c> ties the two
/// reductions; the verifier checks that tie.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BaseFoldEvaluationProver
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The degree of every sumcheck round polynomial: f·eq_z is a product of two
    //multilinears, so each round polynomial is quadratic in the bound variable.
    private const int RoundPolynomialDegree = 2;

    //Pairs per batched block, matching the sumcheck convention: bounds the
    //pooled column scratch while keeping each BatchMultiply call long enough
    //to amortise its lane setup.
    private const int BatchBlockPairCount = 1024;


    /// <summary>
    /// Proves the evaluation of <paramref name="polynomial"/> at
    /// <paramref name="evaluationPoint"/> under the foldable
    /// <paramref name="code"/>, performing <paramref name="queryCount"/>
    /// independent IOPP queries. Returns the proof and the claimed value
    /// <c>y = f(z)</c>.
    /// </summary>
    /// <param name="code">The foldable code; its layer count must equal the polynomial's variable count, and it is reconstructed from the same seed the verifier uses.</param>
    /// <param name="polynomial">The committed multilinear polynomial <c>f</c>.</param>
    /// <param name="evaluationPoint">The point <c>z</c>; one scalar per variable, the i-th binding variable <c>X_{i+1}</c> (the MLE storage convention).</param>
    /// <param name="queryCount">The number of IOPP query repetitions.</param>
    /// <param name="transcript">The live Fiat-Shamir transcript.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hash">The transcript's fixed-output hash backend.</param>
    /// <param name="squeeze">The transcript's XOF backend.</param>
    /// <param name="reduce">The scalar-reduce backend for deriving challenges.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend (the fold uses it).</param>
    /// <param name="pool">The pool to rent working and proof buffers from.</param>
    /// <param name="batch">The optional batched scalar-arithmetic backend.</param>
    /// <returns>The evaluation proof (caller owns its disposal) and the claimed value <c>y</c> (caller owns its disposal).</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="queryCount"/> is non-positive or the code has no foldable layers.</exception>
    /// <exception cref="ArgumentException">When the polynomial's variable count does not match the code or the evaluation point length.</exception>
    public static (BaseFoldEvaluationProof Proof, Scalar ClaimedValue) Prove(
        FoldableCode code,
        MultilinearExtension polynomial,
        ReadOnlySpan<Scalar> evaluationPoint,
        int queryCount,
        FiatShamirTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        BaseMemoryPool pool,
        ScalarArithmeticBackend? batch = null)
    {
        return ProveCore(code, polynomial, evaluationPoint, queryCount, transcript, merkleHash, hash, squeeze, reduce, add, subtract, multiply, invert, topLayerSalts: default, saltRandom: null, maskRandom: null, pool, batch: batch);
    }


    /// <summary>
    /// Proves the evaluation as <see cref="Prove"/> does, but over a hiding
    /// (salted-Merkle) commitment: every fold-layer Merkle tree is built over
    /// salted leaves <c>hash(value ‖ salt)</c>, so the committed root and every
    /// in-proof fold root reveal nothing about the codeword given secret uniform
    /// salts. The opening carries the two salts of each revealed fold pair so the
    /// verifier can recompute the authenticated leaf. The top-layer (<c>π_d</c>)
    /// salts are supplied by the caller — they fixed the public commitment at
    /// commit time and so must match here — while the lower fold layers are
    /// salted with fresh salts drawn from <paramref name="saltRandom"/>.
    /// </summary>
    /// <param name="code">The foldable code; its layer count must equal the polynomial's variable count, and it is reconstructed from the same seed the verifier uses.</param>
    /// <param name="polynomial">The committed multilinear polynomial <c>f</c>.</param>
    /// <param name="evaluationPoint">The point <c>z</c>; one scalar per variable, the i-th binding variable <c>X_{i+1}</c> (the MLE storage convention).</param>
    /// <param name="queryCount">The number of IOPP query repetitions.</param>
    /// <param name="transcript">The Fiat-Shamir transcript.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hash">The Fiat-Shamir hash.</param>
    /// <param name="squeeze">The Fiat-Shamir squeeze.</param>
    /// <param name="reduce">Backend scalar reduction.</param>
    /// <param name="add">Backend scalar addition.</param>
    /// <param name="subtract">Backend scalar subtraction.</param>
    /// <param name="multiply">Backend scalar multiplication.</param>
    /// <param name="invert">Backend scalar inversion.</param>
    /// <param name="topLayerSalts">The <c>π_d</c> leaf salts that fixed the commitment, one digest-wide salt per codeword position, in position order.</param>
    /// <param name="saltRandom">The entropy-sourced sampler for the lower fold layers' salts.</param>
    /// <param name="pool">The pool to rent working and proof buffers from.</param>
    /// <param name="batch">The optional batched scalar-arithmetic backend.</param>
    /// <inheritdoc cref="Prove"/>
    /// <exception cref="ArgumentException">When <paramref name="topLayerSalts"/> does not carry exactly one salt per top-layer codeword position, in addition to the base exceptions.</exception>
    public static (BaseFoldEvaluationProof Proof, Scalar ClaimedValue) ProveHiding(
        FoldableCode code,
        MultilinearExtension polynomial,
        ReadOnlySpan<Scalar> evaluationPoint,
        int queryCount,
        FiatShamirTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ReadOnlySpan<byte> topLayerSalts,
        ScalarRandomDelegate saltRandom,
        BaseMemoryPool pool,
        ScalarArithmeticBackend? batch = null)
    {
        ArgumentNullException.ThrowIfNull(saltRandom);

        return ProveCore(code, polynomial, evaluationPoint, queryCount, transcript, merkleHash, hash, squeeze, reduce, add, subtract, multiply, invert, topLayerSalts, saltRandom, maskRandom: null, pool, batch: batch);
    }


    /// <summary>
    /// Proves the evaluation as <see cref="ProveHiding"/> does, but additionally
    /// masks the interleaved sumcheck's round polynomials so the opening is a
    /// statistically zero-knowledge argument in the ROM (the Libra
    /// sum-of-univariates mask, IACR ePrint 2019/317 §4.1, with the v3 binding of
    /// <c>ZK-STATMASK-DESIGN.md</c>). A fresh mask <c>s</c> with
    /// <c>2d + 1</c> random coefficients is sampled; its coefficient vector,
    /// extended by laundering filler, is committed salted-and-lifted under
    /// <paramref name="maskCommitmentCode"/>; <c>com(C*)</c>, <c>σ = Σ_b s(b)</c>,
    /// and the filler sum <c>σ_F</c> are absorbed; a blend scalar <c>ρ</c> is
    /// squeezed; and each sent round polynomial becomes <c>h_k + ρ·s_k</c> via
    /// the mask's closed-form blends — every revealed coefficient uniform,
    /// including the degree-two one. The terminal mask evaluation is bound by a
    /// nested hiding weighted opening of <c>C*</c> against the claim
    /// <c>s(r) + σ_F</c> the verifier derives from the masked chain.
    /// </summary>
    /// <param name="code">The foldable code; its layer count must equal the polynomial's variable count, and it is reconstructed from the same seed the verifier uses.</param>
    /// <param name="polynomial">The committed multilinear polynomial <c>f</c>.</param>
    /// <param name="evaluationPoint">The point <c>z</c>; one scalar per variable, the i-th binding variable <c>X_{i+1}</c> (the MLE storage convention).</param>
    /// <param name="queryCount">The number of IOPP query repetitions.</param>
    /// <param name="transcript">The Fiat-Shamir transcript.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hash">The Fiat-Shamir hash.</param>
    /// <param name="squeeze">The Fiat-Shamir squeeze.</param>
    /// <param name="reduce">Backend scalar reduction.</param>
    /// <param name="add">Backend scalar addition.</param>
    /// <param name="subtract">Backend scalar subtraction.</param>
    /// <param name="multiply">Backend scalar multiplication.</param>
    /// <param name="invert">Backend scalar inversion.</param>
    /// <param name="topLayerSalts">The <c>π_d</c> leaf salts that fixed the commitment, one digest-wide salt per codeword position, in position order.</param>
    /// <param name="saltRandom">The entropy-sourced sampler for the lower fold layers' salts.</param>
    /// <param name="maskRandom">The entropy-sourced sampler for the mask coefficients, the filler, and the commitment's lift block.</param>
    /// <param name="maskCommitmentCode">The foldable code the mask's coefficient commitment lives under: derived from the same seed as <paramref name="code"/> at the lifted layer count of <see cref="WellKnownStatisticalMaskParameters.CreateClassicalSecurity"/> for this protocol's shape.</param>
    /// <param name="pool">The pool to rent working and proof buffers from.</param>
    /// <param name="batch">The optional batched scalar-arithmetic backend.</param>
    /// <inheritdoc cref="ProveHiding"/>
    /// <exception cref="ArgumentException">When <paramref name="maskCommitmentCode"/> does not match the deterministic mask-commitment shape, in addition to the base exceptions.</exception>
    public static (BaseFoldEvaluationProof Proof, Scalar ClaimedValue) ProveZeroKnowledge(
        FoldableCode code,
        MultilinearExtension polynomial,
        ReadOnlySpan<Scalar> evaluationPoint,
        int queryCount,
        FiatShamirTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ReadOnlySpan<byte> topLayerSalts,
        ScalarRandomDelegate saltRandom,
        ScalarRandomDelegate maskRandom,
        FoldableCode maskCommitmentCode,
        BaseMemoryPool pool,
        ScalarArithmeticBackend? batch = null)
    {
        ArgumentNullException.ThrowIfNull(saltRandom);
        ArgumentNullException.ThrowIfNull(maskRandom);
        ArgumentNullException.ThrowIfNull(maskCommitmentCode);

        return ProveCore(code, polynomial, evaluationPoint, queryCount, transcript, merkleHash, hash, squeeze, reduce, add, subtract, multiply, invert, topLayerSalts, saltRandom, maskRandom, pool, multiplier: null, maskCommitmentCode, batch);
    }


    /// <summary>
    /// Proves the weighted sum <c>v = Σ_b f(b)·W(b)</c> of the committed
    /// polynomial <c>f</c> against a <em>public</em> multiplier multilinear
    /// <c>W</c> — the evaluation protocol of <see cref="Prove"/> with the
    /// <c>eq_z</c> multiplier generalised to an arbitrary multiplier table. An
    /// evaluation opening is the special case <c>W = eq_z</c> (byte-identical
    /// transcript and proof); a general <c>W</c> proves any public linear
    /// functional of <c>f</c>'s hypercube evaluations, which is how the
    /// statistical-mask construction binds its mask coefficients
    /// (<c>ZK-STATMASK-DESIGN.md</c> levels 2 and 3).
    /// </summary>
    /// <remarks>
    /// The multiplier must be public and known to the verifier — the protocol
    /// neither commits nor transmits it, exactly as the evaluation point is the
    /// consumer's to bind. As with the evaluation entries, the caller is
    /// responsible for the transcript already being bound to the statement
    /// (the multiplier's identity and the claimed value's role) before opening.
    /// </remarks>
    /// <param name="code">The foldable code; its layer count must equal the polynomial's variable count, and it is reconstructed from the same seed the verifier uses.</param>
    /// <param name="polynomial">The committed multilinear polynomial <c>f</c>.</param>
    /// <param name="multiplier">The public multiplier multilinear <c>W</c>; its variable count must equal the code's layer count.</param>
    /// <param name="queryCount">The number of IOPP query repetitions.</param>
    /// <param name="transcript">The Fiat-Shamir transcript.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hash">The Fiat-Shamir hash.</param>
    /// <param name="squeeze">The Fiat-Shamir squeeze.</param>
    /// <param name="reduce">Backend scalar reduction.</param>
    /// <param name="add">Backend scalar addition.</param>
    /// <param name="subtract">Backend scalar subtraction.</param>
    /// <param name="multiply">Backend scalar multiplication.</param>
    /// <param name="invert">Backend scalar inversion.</param>
    /// <param name="pool">The pool to rent working and proof buffers from.</param>
    /// <param name="batch">The optional batched scalar-arithmetic backend.</param>
    /// <inheritdoc cref="Prove"/>
    /// <exception cref="ArgumentException">When the polynomial's or multiplier's variable count does not match the code.</exception>
    public static (BaseFoldEvaluationProof Proof, Scalar ClaimedValue) ProveWeightedSum(
        FoldableCode code,
        MultilinearExtension polynomial,
        MultilinearExtension multiplier,
        int queryCount,
        FiatShamirTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        BaseMemoryPool pool,
        ScalarArithmeticBackend? batch = null)
    {
        ArgumentNullException.ThrowIfNull(multiplier);

        return ProveCore(code, polynomial, evaluationPoint: default, queryCount, transcript, merkleHash, hash, squeeze, reduce, add, subtract, multiply, invert, topLayerSalts: default, saltRandom: null, maskRandom: null, pool, multiplier, batch: batch);
    }


    /// <summary>
    /// Proves the weighted sum as <see cref="ProveWeightedSum"/> does, but over a
    /// hiding (salted-Merkle) commitment, exactly as <see cref="ProveHiding"/>
    /// relates to <see cref="Prove"/>: the top-layer salts that fixed the public
    /// commitment are replayed and the lower fold layers draw fresh salts.
    /// </summary>
    /// <inheritdoc cref="ProveWeightedSum"/>
    /// <inheritdoc cref="ProveHiding"/>
    public static (BaseFoldEvaluationProof Proof, Scalar ClaimedValue) ProveWeightedSumHiding(
        FoldableCode code,
        MultilinearExtension polynomial,
        MultilinearExtension multiplier,
        int queryCount,
        FiatShamirTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ReadOnlySpan<byte> topLayerSalts,
        ScalarRandomDelegate saltRandom,
        BaseMemoryPool pool,
        ScalarArithmeticBackend? batch = null)
    {
        ArgumentNullException.ThrowIfNull(multiplier);
        ArgumentNullException.ThrowIfNull(saltRandom);

        return ProveCore(code, polynomial, evaluationPoint: default, queryCount, transcript, merkleHash, hash, squeeze, reduce, add, subtract, multiply, invert, topLayerSalts, saltRandom, maskRandom: null, pool, multiplier, batch: batch);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Working codewords, trees, salt buffers, and the f/eq tables are disposed in the finally block; the round polynomials, fold roots, final oracle, and query steps the proof keeps are owned by the returned proof.")]
    private static (BaseFoldEvaluationProof Proof, Scalar ClaimedValue) ProveCore(
        FoldableCode code,
        MultilinearExtension polynomial,
        ReadOnlySpan<Scalar> evaluationPoint,
        int queryCount,
        FiatShamirTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ReadOnlySpan<byte> topLayerSalts,
        ScalarRandomDelegate? saltRandom,
        ScalarRandomDelegate? maskRandom,
        BaseMemoryPool pool,
        MultilinearExtension? multiplier = null,
        FoldableCode? maskCommitmentCode = null,
        ScalarArithmeticBackend? batch = null)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(polynomial);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);

        FoldableCodeParameters parameters = code.Parameters;
        int d = parameters.LayerCount;
        ArgumentOutOfRangeException.ThrowIfLessThan(d, 1);

        CurveParameterSet curve = parameters.Curve;
        WellKnownCurves.ThrowIfCurveNotWired(curve);
        if(polynomial.VariableCount != d)
        {
            throw new ArgumentException(
                $"Polynomial variable count {polynomial.VariableCount} must equal the code's layer count {d}.",
                nameof(polynomial));
        }

        //An evaluation opening derives its eq_z multiplier from the point; a
        //weighted opening carries the multiplier itself and no point.
        if(multiplier is null && evaluationPoint.Length != d)
        {
            throw new ArgumentException(
                $"Evaluation point must carry {d} scalar(s) (one per variable); received {evaluationPoint.Length}.",
                nameof(evaluationPoint));
        }

        if(multiplier is not null && multiplier.VariableCount != d)
        {
            throw new ArgumentException(
                $"Multiplier variable count {multiplier.VariableCount} must equal the code's layer count {d}.",
                nameof(multiplier));
        }

        int baseUnit = parameters.InverseRate * parameters.BaseDimension;
        int evaluationCount = polynomial.EvaluationCount;

        //Working storage. codewords[ℓ] holds π_ℓ; trees[ℓ] its Merkle tree (π_0
        //is cleartext). fTable / eqTable are the dense evaluation tables of f
        //and eq_z that the sumcheck folds on the high bit in lockstep.
        var codewords = new IMemoryOwner<byte>?[d + 1];
        var trees = new MerkleTree?[d + 1];
        var disposables = new List<IDisposable>();

        //Per-layer leaf salts for the hiding (ZK) commitment: saltsByLayer[ℓ]
        //holds one digest-wide salt per π_ℓ position (π_0 is cleartext, so it is
        //unused). The top layer reuses the salts that fixed the commitment at
        //commit time; the lower fold layers are salted with fresh randomness.
        bool hiding = saltRandom is not null;
        var saltsByLayer = hiding ? new IMemoryOwner<byte>?[d + 1] : null;

        //Statistical-ZK sumcheck mask (design doc §2 v3): a sum-of-univariates
        //mask blended closed-form into the rounds; its coefficient vector plus
        //laundering filler is committed salted-and-lifted under
        //maskCommitmentCode, and the terminal evaluation is bound by a nested
        //weighted opening after the witness protocol completes. The per-round
        //challenges are recorded (one-based registry) for the blends and the
        //terminal mask evaluation.
        bool zeroKnowledge = maskRandom is not null;
        if(zeroKnowledge && maskCommitmentCode is null)
        {
            throw new ArgumentException("A zero-knowledge opening needs the mask-commitment code.", nameof(maskCommitmentCode));
        }

        var challengesForVariable = zeroKnowledge ? new Scalar[d + 1] : null;

        var roundPolynomials = new CompressedRoundPolynomial[d];
        bool success = false;

        try
        {
            //Coefficients of f in the ordering Encode consumes, then π_d.
            IMemoryOwner<byte> coeffsOwner = pool.Rent(evaluationCount * ScalarSize);
            disposables.Add(coeffsOwner);
            Span<byte> coeffs = coeffsOwner.Memory.Span[..(evaluationCount * ScalarSize)];
            polynomial.InterpolateToCoefficients(coeffs, subtract);

            int topLength = BaseFoldQueryPhase.LayerLength(baseUnit, d);
            codewords[d] = pool.Rent(topLength * ScalarSize);
            disposables.Add(codewords[d]!);
            Span<byte> topCodeword = codewords[d]!.Memory.Span[..(topLength * ScalarSize)];
            code.Encode(coeffs, topCodeword, add, subtract, multiply, pool, batch);

            if(hiding)
            {
                if(topLayerSalts.Length != topLength * ScalarSize)
                {
                    throw new ArgumentException(
                        $"Top-layer salts must carry one {ScalarSize}-byte salt per π_d position ({topLength * ScalarSize}); received {topLayerSalts.Length}.",
                        nameof(topLayerSalts));
                }

                saltsByLayer![d] = CopySalts(topLayerSalts, pool, disposables);
                trees[d] = BuildSaltedTree(codewords[d]!, saltsByLayer[d]!.Memory.Span[..(topLength * ScalarSize)], topLength, merkleHash, pool, disposables);
            }
            else
            {
                trees[d] = BuildTree(codewords[d]!, topLength, merkleHash, pool, disposables);
            }

            //Dense evaluation tables f and the multiplier over the hypercube: the
            //derived eq_z table for an evaluation opening, the supplied public
            //multiplier W for a weighted opening. The sumcheck below is identical
            //either way — eq_z is just the multiplier an evaluation uses.
            IMemoryOwner<byte> fTableOwner = pool.Rent(evaluationCount * ScalarSize);
            disposables.Add(fTableOwner);
            Span<byte> fTable = fTableOwner.Memory.Span[..(evaluationCount * ScalarSize)];
            polynomial.AsReadOnlySpan().CopyTo(fTable);

            IMemoryOwner<byte> eqTableOwner = pool.Rent(evaluationCount * ScalarSize);
            disposables.Add(eqTableOwner);
            Span<byte> eqTable = eqTableOwner.Memory.Span[..(evaluationCount * ScalarSize)];
            if(multiplier is null)
            {
                using MultilinearExtension eqMle = SumcheckRoundComputation.BuildEqEvaluations(evaluationPoint, subtract, multiply, curve, pool, batch);
                eqMle.AsReadOnlySpan().CopyTo(eqTable);
            }
            else
            {
                multiplier.AsReadOnlySpan().CopyTo(eqTable);
            }

            //The claimed value and the round-0 claim: y = Σ_b f(b)·eq_z(b) = f(z)
            //for an evaluation opening, v = Σ_b f(b)·W(b) for a weighted one.
            Scalar claimedValue = ComputeWeightedSum(fTable, eqTable, evaluationCount, add, multiply, curve, pool);

            //Statistical-ZK mask setup (design doc §2 v3): sample the
            //sum-of-univariates mask, build C* = (coefficients ‖ random filler),
            //compute σ and σ_F, and commit C* salted-and-lifted under the
            //mask-commitment code. The lifted table and salts stay alive for the
            //terminal weighted opening after the witness protocol completes.
            MonomialBasisMask? mask = null;
            MonomialBasis? maskBasis = null;
            Scalar? sigma = null;
            Scalar? fillerSum = null;
            Scalar? rho = null;
            MultilinearExtension? maskLiftedMle = null;
            Span<byte> maskTopSalts = default;
            MerkleTree? maskTree = null;
            StatisticalMaskParameters maskParameters = default;
            if(zeroKnowledge)
            {
                maskParameters = WellKnownStatisticalMaskParameters.CreateClassicalSecurity(d, curve, queryCount);
                FoldableCodeParameters expectedMaskParameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(maskParameters.LiftedVariableCount, curve);
                if(maskCommitmentCode!.Parameters != expectedMaskParameters)
                {
                    throw new ArgumentException(
                        $"The mask-commitment code must carry {maskParameters.LiftedVariableCount} layer(s) under the classical-security shape for d = {d}, queryCount = {queryCount}.",
                        nameof(maskCommitmentCode));
                }

                maskBasis = MonomialBasis.SumOfUnivariatesWithPad(d, padPairCount: 0);
                mask = MonomialBasisMask.Sample(maskBasis, maskRandom!, curve, pool);
                disposables.Add(mask);

                sigma = mask.ComputeSigma(add, multiply, pool);
                disposables.Add(sigma);

                //The lifted C* table: mask coefficients, then the laundering
                //filler (every remaining real coordinate), then the lift block.
                int coefficientBytes = maskParameters.CoefficientCount * ScalarSize;
                int liftedEvaluations = 1 << maskParameters.LiftedVariableCount;
                IMemoryOwner<byte> liftedTableOwner = pool.Rent(liftedEvaluations * ScalarSize);
                disposables.Add(liftedTableOwner);
                Span<byte> liftedTable = liftedTableOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
                mask.CopyCoefficientsTo(liftedTable[..coefficientBytes]);

                Tag scalarTag = WellKnownAlgebraicTags.ScalarFor(curve);
                int fillerStart = maskParameters.MaskCoefficientCount * ScalarSize;
                for(int i = maskParameters.MaskCoefficientCount; i < maskParameters.CoefficientCount; i++)
                {
                    _ = maskRandom!(liftedTable.Slice(i * ScalarSize, ScalarSize), curve, scalarTag);
                }

                fillerSum = SumTable(liftedTable.Slice(fillerStart, coefficientBytes - fillerStart), maskParameters.FillerCount, add, curve, pool);
                disposables.Add(fillerSum);

                for(int i = maskParameters.CoefficientCount; i < liftedEvaluations; i++)
                {
                    _ = maskRandom!(liftedTable.Slice(i * ScalarSize, ScalarSize), curve, scalarTag);
                }

                maskLiftedMle = MultilinearExtension.FromEvaluations(liftedTable, maskParameters.LiftedVariableCount, curve, pool);
                disposables.Add(maskLiftedMle);

                IMemoryOwner<byte> maskCoeffsOwner = pool.Rent(liftedEvaluations * ScalarSize);
                disposables.Add(maskCoeffsOwner);
                Span<byte> maskCoeffs = maskCoeffsOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
                maskLiftedMle.InterpolateToCoefficients(maskCoeffs, subtract);

                int maskCodewordLength = maskCommitmentCode.Parameters.CodewordLength;
                IMemoryOwner<byte> maskCodewordOwner = pool.Rent(maskCodewordLength * ScalarSize);
                disposables.Add(maskCodewordOwner);
                Span<byte> maskCodeword = maskCodewordOwner.Memory.Span[..(maskCodewordLength * ScalarSize)];
                maskCommitmentCode.Encode(maskCoeffs, maskCodeword, add, subtract, multiply, pool, batch);

                IMemoryOwner<byte> maskSaltsOwner = GenerateLayerSalts(maskCodewordLength, saltRandom!, curve, pool, disposables);
                maskTopSalts = maskSaltsOwner.Memory.Span[..(maskCodewordLength * ScalarSize)];
                maskTree = BuildSaltedTree(maskCodewordOwner, maskTopSalts, maskCodewordLength, merkleHash, pool, disposables);
            }

            //Commit phase. Absorb the public commitment (root of π_d). For a ZK
            //opening, also absorb com(C*), σ, and σ_F, then squeeze the blend
            //scalar ρ, before the first round polynomial (every round polynomial
            //carries the ρ·s blend).
            transcript.AbsorbBaseFoldFoldRoot(trees[d]!.Root, hash);
            if(zeroKnowledge)
            {
                transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBaseFoldEvaluationParameters.MaskCommitmentRoot), maskTree!.Root.AsReadOnlySpan(), hash);
                transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBaseFoldEvaluationParameters.MaskSum), sigma!.AsReadOnlySpan(), hash);
                transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBaseFoldEvaluationParameters.MaskFillerSum), fillerSum!.AsReadOnlySpan(), hash);
                rho = transcript.SqueezeScalar(new FiatShamirOperationLabel(WellKnownBaseFoldEvaluationParameters.MaskBlendChallenge), squeeze, hash, reduce, curve, pool);
                disposables.Add(rho);
            }

            //First round polynomial h_d (blended with ρ·s_d when zero-knowledge),
            //before any fold challenge is squeezed. The first round binds the
            //high variable X_d, matching the fold order.
            ReadOnlySpan<byte> rhoSpan = zeroKnowledge ? rho!.AsReadOnlySpan() : default;
            roundPolynomials[0] = ComputeRoundPolynomial(fTable, eqTable, evaluationCount, add, subtract, multiply, curve, pool, mask, boundVariable: d, challengesForVariable, rhoSpan, batch);
            transcript.AbsorbRoundPolynomial(RoundPolynomialLabel, roundPolynomials[0], hash);

            int currentSize = evaluationCount;
            for(int level = d; level >= 1; level--)
            {
                Scalar challenge = transcript.SqueezeBaseFoldFoldChallenge(squeeze, hash, reduce, curve, pool);
                disposables.Add(challenge);
                if(zeroKnowledge)
                {
                    //The registry entry for X_level, read by the later rounds'
                    //blends and the terminal mask evaluation.
                    challengesForVariable![level] = challenge;
                }

                ReadOnlySpan<byte> r = challenge.AsReadOnlySpan();

                //IOPP fold π_level → π_{level-1}.
                int lowerLength = BaseFoldQueryPhase.LayerLength(baseUnit, level - 1);
                codewords[level - 1] = pool.Rent(lowerLength * ScalarSize);
                disposables.Add(codewords[level - 1]!);
                Span<byte> lower = codewords[level - 1]!.Memory.Span[..(lowerLength * ScalarSize)];
                code.Fold(
                    codewords[level]!.Memory.Span[..(BaseFoldQueryPhase.LayerLength(baseUnit, level) * ScalarSize)],
                    level,
                    r,
                    lower,
                    add,
                    subtract,
                    multiply,
                    invert,
                    batch,
                    pool);

                //Sumcheck fold of f and eq_z on the high bit by the same r. The
                //statistical mask needs no fold — its round contributions are
                //closed-form over the recorded challenges.
                FoldHighBitInPlace(fTable, currentSize, r, add, subtract, multiply, curve, batch, pool);
                FoldHighBitInPlace(eqTable, currentSize, r, add, subtract, multiply, curve, batch, pool);

                currentSize >>= 1;

                if(level - 1 >= 1)
                {
                    if(hiding)
                    {
                        saltsByLayer![level - 1] = GenerateLayerSalts(lowerLength, saltRandom!, curve, pool, disposables);
                        trees[level - 1] = BuildSaltedTree(codewords[level - 1]!, saltsByLayer[level - 1]!.Memory.Span[..(lowerLength * ScalarSize)], lowerLength, merkleHash, pool, disposables);
                    }
                    else
                    {
                        trees[level - 1] = BuildTree(codewords[level - 1]!, lowerLength, merkleHash, pool, disposables);
                    }

                    transcript.AbsorbBaseFoldFoldRoot(trees[level - 1]!.Root, hash);

                    //Next round polynomial h_{level-1} (blended when zero-knowledge)
                    //over the folded tables, placed in send order (index d-level+1).
                    CompressedRoundPolynomial next = ComputeRoundPolynomial(fTable, eqTable, currentSize, add, subtract, multiply, curve, pool, mask, boundVariable: level - 1, challengesForVariable, rhoSpan, batch);
                    roundPolynomials[d - level + 1] = next;
                    transcript.AbsorbRoundPolynomial(RoundPolynomialLabel, next, hash);
                }
            }

            //Absorb the cleartext base codeword π_0 before squeezing queries.
            int finalLength = BaseFoldQueryPhase.LayerLength(baseUnit, 0) * ScalarSize;
            ReadOnlySpan<byte> finalOracleSpan = codewords[0]!.Memory.Span[..finalLength];
            transcript.AbsorbBaseFoldFinalOracle(finalOracleSpan, hash);

            //Query phase over the witness codeword.
            int queryDomainSize = BaseFoldQueryPhase.LayerLength(baseUnit, d - 1);
            var openings = new BaseFoldQueryStep[queryCount][];
            for(int q = 0; q < queryCount; q++)
            {
                int j0 = transcript.SqueezeBaseFoldQueryIndex(queryDomainSize, squeeze, hash);
                openings[q] = BaseFoldQueryPhase.BuildOpening(trees, codewords, baseUnit, d, j0, pool, saltsByLayer);
            }

            MerkleRoot[] foldRoots = CopyFoldRoots(trees, d, pool);
            IMemoryOwner<byte> finalOracle = pool.Rent(finalLength);
            finalOracleSpan.CopyTo(finalOracle.Memory.Span[..finalLength]);

            //Terminal mask binding (design doc §2 v3): the nested hiding weighted
            //opening of C* against the public weights w⁺ = (basis weights at the
            //bound challenges ‖ 1s on the filler ‖ 0s on the lift block), proving
            //⟨C*, w⁺⟩ = s(r) + σ_F — the claim the verifier derives from the
            //masked chain and the precommitted σ_F.
            BaseFoldMaskOpening? maskOpening = null;
            if(zeroKnowledge)
            {
                ReadOnlySpan<Scalar> terminalPoint = challengesForVariable.AsSpan(1, d);

                int liftedEvaluations = 1 << maskParameters.LiftedVariableCount;
                int coefficientBytes = maskParameters.CoefficientCount * ScalarSize;
                IMemoryOwner<byte> weightsOwner = pool.Rent(liftedEvaluations * ScalarSize);
                disposables.Add(weightsOwner);
                Span<byte> weights = weightsOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
                MonomialBasisMask.BuildWeightVector(maskBasis!, terminalPoint, weights, multiply, curve);

                //Field one on every filler coordinate; the lift block stays zero.
                for(int i = maskParameters.MaskCoefficientCount; i < maskParameters.CoefficientCount; i++)
                {
                    Span<byte> weight = weights.Slice(i * ScalarSize, ScalarSize);
                    weight.Clear();
                    weight[ScalarSize - 1] = 0x01;
                }

                using MultilinearExtension weightsMle = MultilinearExtension.FromEvaluations(weights, maskParameters.LiftedVariableCount, curve, pool);

                (BaseFoldEvaluationProof weightedOpening, Scalar weightedClaim) = ProveCore(
                    maskCommitmentCode!, maskLiftedMle!, evaluationPoint: default, queryCount, transcript,
                    merkleHash, hash, squeeze, reduce, add, subtract, multiply, invert,
                    maskTopSalts, saltRandom, maskRandom: null, pool, weightsMle, batch: batch);
                disposables.Add(weightedClaim);

                maskOpening = BuildMaskOpening(maskTree!, sigma!, fillerSum!, weightedOpening, pool);
            }

            var proof = new BaseFoldEvaluationProof(parameters, queryCount, roundPolynomials, foldRoots, finalOracle, finalLength, openings, maskOpening);
            success = true;

            return (proof, claimedValue);
        }
        finally
        {
            //On the failure path the proof-owned round polynomials never reached
            //a proof, so release them; on success the proof owns them.
            if(!success)
            {
                foreach(CompressedRoundPolynomial polynomial2 in roundPolynomials)
                {
                    polynomial2?.Dispose();
                }
            }

            for(int i = disposables.Count - 1; i >= 0; i--)
            {
                disposables[i].Dispose();
            }
        }
    }


    //y = Σ_i fTable[i]·eqTable[i] over the full hypercube; equals f(z).
    private static Scalar ComputeWeightedSum(
        ReadOnlySpan<byte> fTable,
        ReadOnlySpan<byte> eqTable,
        int count,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarArithmeticBackend? batch = null)
    {
        IMemoryOwner<byte> sumOwner = pool.Rent(ScalarSize);
        Span<byte> sum = sumOwner.Memory.Span[..ScalarSize];
        sum.Clear();

        Span<byte> product = stackalloc byte[ScalarSize];
        for(int i = 0; i < count; i++)
        {
            multiply(fTable.Slice(i * ScalarSize, ScalarSize), eqTable.Slice(i * ScalarSize, ScalarSize), product, curve);
            add(sum, product, sum, curve);
        }

        return new Scalar(sumOwner, curve, WellKnownAlgebraicTags.ScalarFor(curve));
    }


    //The degree-2 round polynomial of f·eq_z in the high (current) variable,
    //compressed to (c_0, c_2). Pairs (i, i + half): f0 = f[i] (X = 0),
    //f1 = f[i+half] (X = 1), and likewise for eq. With fd = f1 − f0,
    //eqd = eq1 − eq0, the product (f0 + X·fd)(eq0 + X·eqd) has
    //c_0 = Σ f0·eq0 and c_2 = Σ fd·eqd; c_1 is elided (the verifier
    //reconstructs it from the running claim).
    //
    //For a zero-knowledge opening the statistical mask and the blend ρ are
    //supplied: the round polynomial becomes h_k + ρ·s_k via the mask's
    //closed-form blends into c_0 and c_2 (the c_1 share lands in the elided
    //linear term, which the verifier reconstructs from the running claim
    //started at y + ρ·σ).
    private static CompressedRoundPolynomial ComputeRoundPolynomial(
        ReadOnlySpan<byte> fTable,
        ReadOnlySpan<byte> eqTable,
        int size,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        MonomialBasisMask? mask,
        int boundVariable,
        ReadOnlySpan<Scalar> challengesForVariable,
        ReadOnlySpan<byte> rho,
        ScalarArithmeticBackend? batch)
    {
        int half = size >> 1;

        Span<byte> compressed = stackalloc byte[RoundPolynomialDegree * ScalarSize];
        compressed.Clear();
        Span<byte> c0 = compressed[..ScalarSize];
        Span<byte> c2 = compressed.Slice(ScalarSize, ScalarSize);

        if(batch is not null)
        {
            //The pair halves are contiguous (low half, high half), so the two
            //per-pair products batch with only the slope columns formed —
            //byte-identical by exact field ops and commutative accumulation.
            ComputeRoundPolynomialBatched(fTable, eqTable, half, c0, c2, add, subtract, batch, curve, pool);
        }
        else
        {
            ComputeRoundPolynomialPerElement(fTable, eqTable, half, c0, c2, add, subtract, multiply, curve);
        }

        mask?.AddRoundBlend(boundVariable, challengesForVariable, rho, c0, c2, add, multiply);

        return CompressedRoundPolynomial.FromCompressedBytes(compressed, RoundPolynomialDegree, curve, pool);
    }


    private static void ComputeRoundPolynomialPerElement(
        ReadOnlySpan<byte> fTable,
        ReadOnlySpan<byte> eqTable,
        int half,
        Span<byte> c0,
        Span<byte> c2,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> fd = stackalloc byte[ScalarSize];
        Span<byte> eqd = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];

        for(int i = 0; i < half; i++)
        {
            ReadOnlySpan<byte> f0 = fTable.Slice(i * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> f1 = fTable.Slice((i + half) * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> eq0 = eqTable.Slice(i * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> eq1 = eqTable.Slice((i + half) * ScalarSize, ScalarSize);

            //c_0 += f0·eq0.
            multiply(f0, eq0, product, curve);
            add(c0, product, c0, curve);

            //c_2 += (f1 − f0)·(eq1 − eq0).
            subtract(f1, f0, fd, curve);
            subtract(eq1, eq0, eqd, curve);
            multiply(fd, eqd, product, curve);
            add(c2, product, c2, curve);
        }
    }


    //The batched twin: f0/eq0 columns are the tables' low halves verbatim and
    //f1/eq1 the high halves, so only the slope columns are formed before the
    //two batched products per block.
    private static void ComputeRoundPolynomialBatched(
        ReadOnlySpan<byte> fTable,
        ReadOnlySpan<byte> eqTable,
        int half,
        Span<byte> c0,
        Span<byte> c2,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarArithmeticBackend batch,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int halfBytes = half * ScalarSize;
        ReadOnlySpan<byte> fLow = fTable[..halfBytes];
        ReadOnlySpan<byte> fHigh = fTable.Slice(halfBytes, halfBytes);
        ReadOnlySpan<byte> eqLow = eqTable[..halfBytes];
        ReadOnlySpan<byte> eqHigh = eqTable.Slice(halfBytes, halfBytes);

        int blockSize = Math.Min(half, BatchBlockPairCount);
        int columnBytes = blockSize * ScalarSize;
        using IMemoryOwner<byte> columnsOwner = pool.Rent(3 * columnBytes);
        Span<byte> columns = columnsOwner.Memory.Span[..(3 * columnBytes)];
        Span<byte> fd = columns[..columnBytes];
        Span<byte> eqd = columns.Slice(1 * columnBytes, columnBytes);
        Span<byte> products = columns.Slice(2 * columnBytes, columnBytes);

        for(int blockStart = 0; blockStart < half; blockStart += blockSize)
        {
            int n = Math.Min(blockSize, half - blockStart);
            int usedBytes = n * ScalarSize;
            int sourceOffset = blockStart * ScalarSize;

            //c_0 += Σ f0·eq0 over the block.
            batch.BatchMultiply(fLow.Slice(sourceOffset, usedBytes), eqLow.Slice(sourceOffset, usedBytes), products[..usedBytes], n, curve);
            for(int j = 0; j < n; j++)
            {
                add(c0, products.Slice(j * ScalarSize, ScalarSize), c0, curve);
            }

            //c_2 += Σ (f1 − f0)·(eq1 − eq0) over the block: the halves are
            //contiguous, so the slopes are whole-block batch subtracts.
            batch.BatchSubtract(fHigh.Slice(sourceOffset, usedBytes), fLow.Slice(sourceOffset, usedBytes), fd[..usedBytes], n, curve);
            batch.BatchSubtract(eqHigh.Slice(sourceOffset, usedBytes), eqLow.Slice(sourceOffset, usedBytes), eqd[..usedBytes], n, curve);

            batch.BatchMultiply(fd[..usedBytes], eqd[..usedBytes], products[..usedBytes], n, curve);
            for(int j = 0; j < n; j++)
            {
                add(c2, products.Slice(j * ScalarSize, ScalarSize), c2, curve);
            }
        }
    }


    //Σ_i table[i] over all `count` entries; the mask sum σ = Σ_b s(b).
    private static Scalar SumTable(
        ReadOnlySpan<byte> table,
        int count,
        ScalarAddDelegate add,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        IMemoryOwner<byte> sumOwner = pool.Rent(ScalarSize);
        Span<byte> sum = sumOwner.Memory.Span[..ScalarSize];
        sum.Clear();
        for(int i = 0; i < count; i++)
        {
            add(sum, table.Slice(i * ScalarSize, ScalarSize), sum, curve);
        }

        return new Scalar(sumOwner, curve, WellKnownAlgebraicTags.ScalarFor(curve));
    }


    //Folds a dense evaluation table on its high bit in place: for i in
    //[0, size/2), table[i] ← table[i] + r·(table[i + size/2] − table[i]),
    //which is (1 − r)·table[i] + r·table[i + size/2]. The folded table
    //occupies the first half. Internal so the weighted-opening verifier can
    //evaluate the public multiplier at the squeezed challenges the same way
    //the prover's tables collapse.
    internal static void FoldHighBitInPlace(
        Span<byte> table,
        int size,
        ReadOnlySpan<byte> r,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        ScalarArithmeticBackend? batch = null,
        BaseMemoryPool? batchPool = null)
    {
        int half = size >> 1;

        if(batch is not null)
        {
            //The halves are contiguous: form the difference column, broadcast
            //the constant r, and run the per-level products as batched calls.
            BaseMemoryPool columnPool = batchPool ?? throw new ArgumentNullException(nameof(batchPool));
            int blockSize = Math.Min(half, BatchBlockPairCount);
            int columnBytes = blockSize * ScalarSize;
            using IMemoryOwner<byte> columnsOwner = columnPool.Rent(2 * columnBytes);
            Span<byte> columns = columnsOwner.Memory.Span[..(2 * columnBytes)];
            Span<byte> differences = columns[..columnBytes];
            Span<byte> broadcast = columns.Slice(columnBytes, columnBytes);
            for(int j = 0; j < blockSize; j++)
            {
                r.CopyTo(broadcast.Slice(j * ScalarSize, ScalarSize));
            }

            int halfBytes = half * ScalarSize;
            for(int blockStart = 0; blockStart < half; blockStart += blockSize)
            {
                int n = Math.Min(blockSize, half - blockStart);
                int usedBytes = n * ScalarSize;
                int sourceOffset = blockStart * ScalarSize;
                Span<byte> lows = table.Slice(sourceOffset, usedBytes);
                ReadOnlySpan<byte> highs = table.Slice(halfBytes + sourceOffset, usedBytes);

                //The halves are contiguous: whole-block subtract, broadcast
                //multiply, and an in-place elementwise add back onto the lows.
                batch.BatchSubtract(highs, lows, differences[..usedBytes], n, curve);
                batch.BatchMultiply(broadcast[..usedBytes], differences[..usedBytes], differences[..usedBytes], n, curve);
                batch.BatchAdd(lows, differences[..usedBytes], lows, n, curve);
            }

            return;
        }

        Span<byte> difference = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];

        for(int i = 0; i < half; i++)
        {
            Span<byte> low = table.Slice(i * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> high = table.Slice((i + half) * ScalarSize, ScalarSize);

            subtract(high, low, difference, curve);
            multiply(r, difference, term, curve);
            add(low, term, low, curve);
        }
    }


    //Assembles the proof-owned statistical-mask side: copies of com(C*)'s root,
    //σ, and σ_F, plus the (already caller-owned) nested weighted opening.
    [SuppressMessage("Reliability", "CA2000", Justification = "The copied root and the σ/σ_F buffers transfer ownership to the returned BaseFoldMaskOpening, which the proof owns and disposes alongside the nested weighted opening.")]
    private static BaseFoldMaskOpening BuildMaskOpening(
        MerkleTree maskTree,
        Scalar sigma,
        Scalar fillerSum,
        BaseFoldEvaluationProof weightedOpening,
        BaseMemoryPool pool)
    {
        MerkleRoot rootCopy = MerkleRoot.FromBytes(maskTree.Root.AsReadOnlySpan(), pool);

        IMemoryOwner<byte> sigmaOwner = pool.Rent(ScalarSize);
        sigma.AsReadOnlySpan().CopyTo(sigmaOwner.Memory.Span[..ScalarSize]);

        IMemoryOwner<byte> fillerSumOwner = pool.Rent(ScalarSize);
        fillerSum.AsReadOnlySpan().CopyTo(fillerSumOwner.Memory.Span[..ScalarSize]);

        return new BaseFoldMaskOpening(rootCopy, sigmaOwner, fillerSumOwner, ScalarSize, weightedOpening);
    }


    //Copies the fold-layer roots π_{d-1} … π_1 (commit order) into standalone
    //proof-owned roots so the working trees can be disposed.
    [SuppressMessage("Reliability", "CA2000", Justification = "Each copied root transfers ownership to the returned array, which the proof owns and disposes.")]
    private static MerkleRoot[] CopyFoldRoots(MerkleTree?[] trees, int d, BaseMemoryPool pool)
    {
        var foldRoots = new MerkleRoot[d - 1];
        for(int i = 0; i < d - 1; i++)
        {
            //Commit order: index 0 is π_{d-1}, last is π_1.
            int level = d - 1 - i;
            foldRoots[i] = MerkleRoot.FromBytes(trees[level]!.Root.AsReadOnlySpan(), pool);
        }

        return foldRoots;
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The tree is tracked in the disposables list and released in the prover's finally block.")]
    private static MerkleTree BuildTree(
        IMemoryOwner<byte> codeword,
        int leafCount,
        MerkleHashDelegate merkleHash,
        BaseMemoryPool pool,
        List<IDisposable> disposables)
    {
        MerkleTree tree = MerkleTree.Build(codeword.Memory.Span[..(leafCount * ScalarSize)], leafCount, merkleHash, pool);
        disposables.Add(tree);

        return tree;
    }


    //Builds the layer tree over salted leaves hash(value ‖ salt) for the hiding
    //commitment; the salts span carries one digest-wide salt per leaf.
    [SuppressMessage("Reliability", "CA2000", Justification = "The tree is tracked in the disposables list and released in the prover's finally block.")]
    private static MerkleTree BuildSaltedTree(
        IMemoryOwner<byte> codeword,
        ReadOnlySpan<byte> salts,
        int leafCount,
        MerkleHashDelegate merkleHash,
        BaseMemoryPool pool,
        List<IDisposable> disposables)
    {
        MerkleTree tree = MerkleTree.BuildSalted(codeword.Memory.Span[..(leafCount * ScalarSize)], salts, leafCount, merkleHash, pool);
        disposables.Add(tree);

        return tree;
    }


    //Copies the commitment-time top-layer salts into a tracked working buffer so
    //the openings can read them alongside the other per-layer salt arrays.
    private static IMemoryOwner<byte> CopySalts(
        ReadOnlySpan<byte> salts,
        BaseMemoryPool pool,
        List<IDisposable> disposables)
    {
        IMemoryOwner<byte> owner = pool.Rent(salts.Length);
        disposables.Add(owner);
        salts.CopyTo(owner.Memory.Span[..salts.Length]);

        return owner;
    }


    //Draws one fresh digest-wide salt per leaf for a lower fold layer. A scalar's
    //canonical bytes carry ample min-entropy for the ROM hiding argument and are
    //exactly digest-wide for the wired curves, so the scalar sampler doubles as
    //the salt source (its returned tag is irrelevant for raw salt bytes).
    private static IMemoryOwner<byte> GenerateLayerSalts(
        int leafCount,
        ScalarRandomDelegate saltRandom,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        List<IDisposable> disposables)
    {
        int length = leafCount * ScalarSize;
        IMemoryOwner<byte> owner = pool.Rent(length);
        disposables.Add(owner);
        Span<byte> span = owner.Memory.Span[..length];
        for(int i = 0; i < leafCount; i++)
        {
            _ = saltRandom(span.Slice(i * ScalarSize, ScalarSize), curve, WellKnownAlgebraicTags.ScalarFor(curve));
        }

        return owner;
    }


    private static FiatShamirOperationLabel RoundPolynomialLabel =>
        new(WellKnownBaseFoldEvaluationParameters.RoundPolynomial);
}
