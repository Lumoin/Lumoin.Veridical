using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// The hiding (zero-knowledge) sibling of
/// <see cref="BaseFoldPolynomialCommitmentScheme"/>: adapts a salted-Merkle
/// BaseFold commitment to the scheme-agnostic
/// <see cref="PolynomialCommitmentProvider"/> surface. Every fold-layer Merkle
/// tree is built over salted leaves <c>hash(value ‖ salt)</c> rather than the
/// codeword values verbatim, so the commitment root — and every in-proof fold
/// root — is hiding given secret uniform salts. The factory captures the same
/// non-moving parts the non-hiding scheme does plus a
/// <see cref="ScalarRandomDelegate"/> for the salts.
/// </summary>
/// <remarks>
/// <para>
/// The construction adds exactly one thing to the non-hiding BaseFold protocol:
/// a per-leaf salt under the Merkle leaf hash. The fold-consistency relation is
/// still checked on the cleartext codeword values, the IOPP query count is
/// unchanged, and binding is preserved (the salted tree binds the
/// <c>(value, salt)</c> pairs, the fold check binds the values). What changes is
/// that the root no longer fingerprints the witness: committing the same
/// polynomial twice draws fresh salts and yields different roots.
/// </para>
/// <para>
/// The top-layer (<c>π_d</c>) salts fix the public commitment, so they are
/// retained in the <see cref="PolynomialCommitmentBlind"/> and replayed by the
/// matching <see cref="PolynomialCommitmentProvider.Open"/>; the lower fold
/// layers, whose roots live in the proof, are salted with fresh randomness
/// inside the open. The open's evaluation proof additionally carries the two
/// leaf salts of each revealed fold pair so the verifier can recompute the
/// salted leaf.
/// </para>
/// <para>
/// This scheme makes the BaseFold <em>commitment</em> hiding — it flips the
/// commitment-recoverability leak. It does not by itself make the evaluation
/// proof simulatable (the queried entries, round polynomials, and base oracle
/// are still deterministic in <c>f</c>); that is the separate zero-knowledge
/// evaluation construction. The provider's <see cref="PolynomialCommitmentProvider.IsHiding"/>
/// is <see langword="true"/>, signalling the hiding commitment.
/// </para>
/// </remarks>
public static class ZkBaseFoldPolynomialCommitmentScheme
{
    private const int ScalarSize = Scalar.SizeBytes;

    //Above this lift total the mask degrees of freedom (≥ 2^(d + t)) no longer fit
    //a long and dwarf any realisable query count, so the budget is trivially met;
    //it also bounds the GetMinimumExtraVariableCount search.
    private const int LiftedVariableCountBudgetCeiling = 62;


    /// <summary>
    /// Builds a hiding BaseFold-backed provider over the code derived from
    /// <paramref name="seed"/>. The returned provider's
    /// <see cref="PolynomialCommitmentProvider.Scheme"/> is
    /// <see cref="CommitmentScheme.BaseFold"/>, its curve is
    /// <paramref name="curve"/>, and its
    /// <see cref="PolynomialCommitmentProvider.IsHiding"/> is
    /// <see langword="true"/>.
    /// </summary>
    /// <param name="seed">The seed binding the random foldable code; commit, open, and verify must share it.</param>
    /// <param name="curve">The curve every produced artifact is tagged with.</param>
    /// <param name="queryCount">The IOPP query repetition count (see <see cref="WellKnownBaseFoldIoppParameters.ClassicalSecurityDefaultQueryCount"/>).</param>
    /// <param name="merkleHash">The two-to-one Merkle compression, used both to salt the leaves and to compress internal nodes.</param>
    /// <param name="hash">Fiat-Shamir absorb backend.</param>
    /// <param name="squeeze">Fiat-Shamir squeeze backend.</param>
    /// <param name="reduce">Scalar reduction backend.</param>
    /// <param name="add">Scalar addition backend.</param>
    /// <param name="subtract">Scalar subtraction backend.</param>
    /// <param name="multiply">Scalar multiplication backend.</param>
    /// <param name="invert">Scalar inversion backend.</param>
    /// <param name="scalarRandom">The entropy-sourced sampler for the per-leaf hiding salts.</param>
    /// <param name="hashToScalar">Hash-to-scalar backend the code derivation uses for its diagonal entries.</param>
    /// <param name="digestSizeBytes">The Merkle node digest size <paramref name="merkleHash"/> produces; defaults to <see cref="WellKnownMerkleHashParameters.DefaultDigestSizeBytes"/>.</param>
    /// <param name="batch">The optional batched scalar-arithmetic backend.</param>
    /// <returns>A hiding provider whose commit / open / verify route to the salted BaseFold evaluation protocol.</returns>
    /// <exception cref="ArgumentNullException">When any reference argument is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="queryCount"/> or <paramref name="digestSizeBytes"/> is non-positive.</exception>
    public static PolynomialCommitmentProvider Create(
        ReadOnlySpan<byte> seed,
        CurveParameterSet curve,
        int queryCount,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarRandomDelegate scalarRandom,
        ScalarHashToScalarDelegate hashToScalar,
        int digestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes,
        ScalarArithmeticBackend? batch = null)
    {
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(scalarRandom);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);

        //Copy the seed: the closures outlive the caller's span.
        byte[] seedCopy = seed.ToArray();

        FoldableCode DeriveCode(int variableCount, BaseMemoryPool pool)
        {
            FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(variableCount, curve);
            return FoldableCode.Derive(parameters, seedCopy, hashToScalar, pool);
        }

        PolynomialCommitDelegate commit = (polynomial, pool) =>
        {
            using FoldableCode code = DeriveCode(polynomial.VariableCount, pool);
            FoldableCodeParameters parameters = code.Parameters;

            int messageElements = parameters.MessageLength;
            int codewordElements = parameters.CodewordLength;

            using IMemoryOwner<byte> coeffsOwner = pool.Rent(messageElements * ScalarSize);
            Span<byte> coeffs = coeffsOwner.Memory.Span[..(messageElements * ScalarSize)];
            polynomial.InterpolateToCoefficients(coeffs, subtract);

            using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
            Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
            code.Encode(coeffs, codeword, add, subtract, multiply, pool, batch);

            //One fresh salt per codeword position; the blind retains them so the
            //matching open rebuilds π_d's salted tree identically, while the
            //commitment root over hash(value ‖ salt) reveals nothing about the
            //codeword.
            int saltBytes = codewordElements * ScalarSize;
            using IMemoryOwner<byte> saltOwner = pool.Rent(saltBytes);
            Span<byte> salts = saltOwner.Memory.Span[..saltBytes];
            GenerateScalars(salts, codewordElements, scalarRandom, curve);

            using MerkleTree tree = MerkleTree.BuildSalted(codeword, salts, codewordElements, merkleHash, pool);

            PolynomialCommitment commitment = PolynomialCommitment.FromBytes(
                tree.Root.AsReadOnlySpan(), curve, CommitmentScheme.BaseFold, pool);
            PolynomialCommitmentBlind blind = PolynomialCommitmentBlind.FromCanonical(
                salts, curve, CommitmentScheme.BaseFold, pool);

            return (commitment, blind);
        };

        PolynomialOpenDelegate open = (commitment, blind, polynomial, evaluationPoint, transcript, pool) =>
        {
            using FoldableCode code = DeriveCode(polynomial.VariableCount, pool);

            (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.ProveHiding(
                code,
                polynomial,
                evaluationPoint,
                queryCount,
                transcript,
                merkleHash,
                hash,
                squeeze,
                reduce,
                add,
                subtract,
                multiply,
                invert,
                blind.AsReadOnlySpan(),
                scalarRandom,
                pool,
                batch);

            using(proof)
            {
                (IMemoryOwner<byte> bytesOwner, int length) = BaseFoldEvaluationProofSerialization.ToBytes(proof, digestSizeBytes, BaseFoldOpeningMode.Hiding, pool);
                using(bytesOwner)
                {
                    PolynomialOpening opening = PolynomialOpening.FromBytes(
                        bytesOwner.Memory.Span[..length], curve, CommitmentScheme.BaseFold, pool);

                    return (opening, claimedValue);
                }
            }
        };

        PolynomialVerifyEvaluationDelegate verifyEvaluation = (commitment, evaluationPoint, claimedValue, opening, transcript, pool) =>
        {
            using FoldableCode code = DeriveCode(evaluationPoint.Length, pool);

            BaseFoldEvaluationProof? proof = null;
            try
            {
                proof = BaseFoldEvaluationProofSerialization.FromBytes(
                    opening.AsReadOnlySpan(), code.Parameters, queryCount, digestSizeBytes, BaseFoldOpeningMode.Hiding, pool);
            }
            catch(ArgumentException)
            {
                //Malformed opening bytes are a rejection, not a fault.
                return false;
            }

            using(proof)
            using(MerkleRoot commitmentRoot = MerkleRoot.FromBytes(commitment.AsReadOnlySpan(), pool))
            {
                return BaseFoldEvaluationVerifier.Verify(
                    code,
                    commitmentRoot,
                    evaluationPoint,
                    claimedValue,
                    proof,
                    queryCount,
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
            CommitmentScheme.BaseFold, curve, commit, open, verifyEvaluation,
            ownedResource: null, queryCount: queryCount, digestSizeBytes: digestSizeBytes,
            //Salted leaves are still hash-based — binding but not additively
            //homomorphic, so this cannot back Nova-style folding — yet the secret
            //salts make the commitment hiding, which the non-hiding sibling is not.
            isAdditivelyHomomorphic: false, isHiding: true);
    }


    /// <summary>
    /// Builds a hiding provider whose <em>evaluation opening</em> is additionally
    /// query/base-oracle hiding via the dimension-lift construction (ZK.2b, design
    /// fork resolved for dimension lifting; <c>BaseFold/BASEFOLD.md</c>,
    /// <em>Zero-knowledge BaseFold</em>). The real
    /// <c>d</c>-variable witness <c>f</c> is committed as the <c>Y = 0</c> slice of
    /// a <c>(d + extraVariableCount)</c>-variable polynomial <c>f'</c> whose
    /// <c>Y != 0</c> evaluations are entropy mask, and every opening is evaluated at
    /// the protocol-fixed point <c>(z, 0…0)</c>. By the multilinear <c>eq</c>
    /// factorisation <c>f'(z, 0…0) = f(z)</c> for any mask, so the proven value is
    /// the true witness value, while the mask spreads through the linear encoder to
    /// randomise the queried codeword positions and the folded base oracle.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The consumer keeps the ordinary <c>Commit(f)</c> / <c>Open(f, z)</c> surface
    /// with a <c>d</c>-variable polynomial and a <c>d</c>-coordinate point; the lift
    /// and the trailing zero coordinates are entirely internal. The committed
    /// codeword is an honest codeword of the same random foldable code at
    /// <c>d + extraVariableCount</c> layers, so BaseFold's knowledge soundness
    /// (Theorem 4) and the code's minimum-distance bound apply unchanged — there is
    /// no code modification and no distance re-proof.
    /// </para>
    /// <para>
    /// This variant closes the query and base-oracle leakage channels. It does not
    /// by itself mask the sumcheck round polynomials (channel 2); that is the
    /// CFS-2017 sumcheck mask added in a following sub-batch. The mask
    /// degrees-of-freedom are <c>(2^extraVariableCount − 1)·2^d</c> and must meet
    /// the bounded-independence budget for the provider's query count; the
    /// provider <em>enforces</em> this on every commit and open, throwing
    /// <see cref="InvalidOperationException"/> for an under-budget witness rather
    /// than silently delivering less hiding than <c>IsHiding</c> advertises. Use
    /// <see cref="GetMinimumExtraVariableCount"/> to size the lift and
    /// <see cref="MeetsHidingBudget"/> to check a chosen one. Hiding of the
    /// codeword positions is additionally validated empirically in ZK.4.
    /// </para>
    /// </remarks>
    /// <param name="seed">The seed binding the random foldable code; commit, open, and verify must share it.</param>
    /// <param name="curve">The curve every produced artifact is tagged with.</param>
    /// <param name="queryCount">The IOPP query repetition count (see <see cref="WellKnownBaseFoldIoppParameters.ClassicalSecurityDefaultQueryCount"/>).</param>
    /// <param name="merkleHash">The two-to-one Merkle compression, used both to salt the leaves and to compress internal nodes.</param>
    /// <param name="hash">The Fiat-Shamir hash.</param>
    /// <param name="squeeze">The Fiat-Shamir squeeze.</param>
    /// <param name="reduce">Backend scalar reduction.</param>
    /// <param name="add">Backend scalar addition.</param>
    /// <param name="subtract">Backend scalar subtraction.</param>
    /// <param name="multiply">Backend scalar multiplication.</param>
    /// <param name="invert">Backend scalar inversion.</param>
    /// <param name="scalarRandom">Backend random scalar generation.</param>
    /// <param name="hashToScalar">Hash-to-scalar backend the code derivation uses for its diagonal entries.</param>
    /// <param name="extraVariableCount">The number of extra (mask) variables <c>t</c> the witness is lifted by; must be positive.</param>
    /// <param name="digestSizeBytes">The Merkle node digest size <paramref name="merkleHash"/> produces; defaults to <see cref="WellKnownMerkleHashParameters.DefaultDigestSizeBytes"/>.</param>
    /// <param name="batch">The optional batched scalar-arithmetic backend.</param>
    /// <inheritdoc cref="Create"/>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="extraVariableCount"/> is non-positive, in addition to the base exceptions.</exception>
    public static PolynomialCommitmentProvider CreateZeroKnowledge(
        ReadOnlySpan<byte> seed,
        CurveParameterSet curve,
        int queryCount,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarRandomDelegate scalarRandom,
        ScalarHashToScalarDelegate hashToScalar,
        int extraVariableCount,
        int digestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes,
        ScalarArithmeticBackend? batch = null)
    {
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(scalarRandom);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(extraVariableCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);

        byte[] seedCopy = seed.ToArray();
        int t = extraVariableCount;

        FoldableCode DeriveCode(int variableCount, BaseMemoryPool pool)
        {
            FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(variableCount, curve);
            return FoldableCode.Derive(parameters, seedCopy, hashToScalar, pool);
        }

        PolynomialCommitDelegate commit = (polynomial, pool) =>
        {
            ThrowIfHidingBudgetUnmet(polynomial.VariableCount, t, curve, queryCount);

            int liftedVariableCount = polynomial.VariableCount + t;
            int realEvaluations = polynomial.EvaluationCount;
            int liftedEvaluations = 1 << liftedVariableCount;
            int maskScalars = liftedEvaluations - realEvaluations;

            using FoldableCode code = DeriveCode(liftedVariableCount, pool);
            FoldableCodeParameters parameters = code.Parameters;
            int codewordElements = parameters.CodewordLength;

            //f' evaluations: the real witness in the Y = 0 slice (first 2^d
            //entries), entropy mask in the rest.
            using IMemoryOwner<byte> liftedEvalsOwner = pool.Rent(liftedEvaluations * ScalarSize);
            Span<byte> liftedEvals = liftedEvalsOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
            polynomial.AsReadOnlySpan().CopyTo(liftedEvals[..(realEvaluations * ScalarSize)]);
            GenerateScalars(liftedEvals.Slice(realEvaluations * ScalarSize, maskScalars * ScalarSize), maskScalars, scalarRandom, curve);

            using MultilinearExtension lifted = MultilinearExtension.FromEvaluations(liftedEvals, liftedVariableCount, curve, pool);

            using IMemoryOwner<byte> coeffsOwner = pool.Rent(liftedEvaluations * ScalarSize);
            Span<byte> coeffs = coeffsOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
            lifted.InterpolateToCoefficients(coeffs, subtract);

            using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
            Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
            code.Encode(coeffs, codeword, add, subtract, multiply, pool, batch);

            //Top-layer salts for the lifted codeword.
            using IMemoryOwner<byte> saltsOwner = pool.Rent(codewordElements * ScalarSize);
            Span<byte> salts = saltsOwner.Memory.Span[..(codewordElements * ScalarSize)];
            GenerateScalars(salts, codewordElements, scalarRandom, curve);

            using MerkleTree tree = MerkleTree.BuildSalted(codeword, salts, codewordElements, merkleHash, pool);

            PolynomialCommitment commitment = PolynomialCommitment.FromBytes(
                tree.Root.AsReadOnlySpan(), curve, CommitmentScheme.BaseFold, pool);

            //Blind = [mask Y-block evaluations ‖ top-layer salts]; the matching
            //open reuses both to rebuild f' and its salted tree identically.
            using IMemoryOwner<byte> blindOwner = pool.Rent((maskScalars + codewordElements) * ScalarSize);
            Span<byte> blindBytes = blindOwner.Memory.Span[..((maskScalars + codewordElements) * ScalarSize)];
            liftedEvals.Slice(realEvaluations * ScalarSize, maskScalars * ScalarSize).CopyTo(blindBytes[..(maskScalars * ScalarSize)]);
            salts.CopyTo(blindBytes.Slice(maskScalars * ScalarSize, codewordElements * ScalarSize));
            PolynomialCommitmentBlind blind = PolynomialCommitmentBlind.FromCanonical(
                blindBytes, curve, CommitmentScheme.BaseFold, pool);

            return (commitment, blind);
        };

        PolynomialOpenDelegate open = (commitment, blind, polynomial, evaluationPoint, transcript, pool) =>
        {
            ThrowIfHidingBudgetUnmet(polynomial.VariableCount, t, curve, queryCount);

            int liftedVariableCount = polynomial.VariableCount + t;
            int realEvaluations = polynomial.EvaluationCount;
            int liftedEvaluations = 1 << liftedVariableCount;
            int maskScalars = liftedEvaluations - realEvaluations;

            using FoldableCode code = DeriveCode(liftedVariableCount, pool);
            int codewordElements = code.Parameters.CodewordLength;

            ReadOnlySpan<byte> blindBytes = blind.AsReadOnlySpan();
            ReadOnlySpan<byte> maskBlock = blindBytes[..(maskScalars * ScalarSize)];
            ReadOnlySpan<byte> topSalts = blindBytes.Slice(maskScalars * ScalarSize, codewordElements * ScalarSize);

            //Rebuild the exact f' committed: real witness ‖ the blind's mask block.
            using IMemoryOwner<byte> liftedEvalsOwner = pool.Rent(liftedEvaluations * ScalarSize);
            Span<byte> liftedEvals = liftedEvalsOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
            polynomial.AsReadOnlySpan().CopyTo(liftedEvals[..(realEvaluations * ScalarSize)]);
            maskBlock.CopyTo(liftedEvals.Slice(realEvaluations * ScalarSize, maskScalars * ScalarSize));

            using MultilinearExtension lifted = MultilinearExtension.FromEvaluations(liftedEvals, liftedVariableCount, curve, pool);

            Scalar[] liftedPoint = BuildLiftedPoint(evaluationPoint, t, curve, pool);
            try
            {
                (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.ProveHiding(
                    code, lifted, liftedPoint, queryCount, transcript, merkleHash, hash, squeeze,
                    reduce, add, subtract, multiply, invert, topSalts, scalarRandom, pool, batch);

                using(proof)
                {
                    (IMemoryOwner<byte> bytesOwner, int length) = BaseFoldEvaluationProofSerialization.ToBytes(proof, digestSizeBytes, BaseFoldOpeningMode.Hiding, pool);
                    using(bytesOwner)
                    {
                        PolynomialOpening opening = PolynomialOpening.FromBytes(
                            bytesOwner.Memory.Span[..length], curve, CommitmentScheme.BaseFold, pool);

                        return (opening, claimedValue);
                    }
                }
            }
            finally
            {
                foreach(Scalar coordinate in liftedPoint)
                {
                    coordinate.Dispose();
                }
            }
        };

        PolynomialVerifyEvaluationDelegate verifyEvaluation = (commitment, evaluationPoint, claimedValue, opening, transcript, pool) =>
        {
            int liftedVariableCount = evaluationPoint.Length + t;
            using FoldableCode code = DeriveCode(liftedVariableCount, pool);

            BaseFoldEvaluationProof? proof = null;
            try
            {
                proof = BaseFoldEvaluationProofSerialization.FromBytes(
                    opening.AsReadOnlySpan(), code.Parameters, queryCount, digestSizeBytes, BaseFoldOpeningMode.Hiding, pool);
            }
            catch(ArgumentException)
            {
                return false;
            }

            Scalar[] liftedPoint = BuildLiftedPoint(evaluationPoint, t, curve, pool);
            try
            {
                using(proof)
                using(MerkleRoot commitmentRoot = MerkleRoot.FromBytes(commitment.AsReadOnlySpan(), pool))
                {
                    return BaseFoldEvaluationVerifier.Verify(
                        code, commitmentRoot, liftedPoint, claimedValue, proof, queryCount, transcript,
                        merkleHash, hash, squeeze, reduce, add, subtract, multiply, invert, pool);
                }
            }
            finally
            {
                foreach(Scalar coordinate in liftedPoint)
                {
                    coordinate.Dispose();
                }
            }
        };

        return new PolynomialCommitmentProvider(
            CommitmentScheme.BaseFold, curve, commit, open, verifyEvaluation,
            ownedResource: null, queryCount: queryCount, digestSizeBytes: digestSizeBytes,
            isAdditivelyHomomorphic: false, isHiding: true, extraVariableCount: t);
    }


    /// <summary>
    /// Builds a genuinely zero-knowledge provider: the dimension lift of
    /// <see cref="CreateZeroKnowledge"/> (closing the query and base-oracle
    /// channels) <em>plus</em> the CFS-2017 sumcheck mask (closing the
    /// round-polynomial channel), so the evaluation opening is simulatable from the
    /// public statement alone. The witness is committed exactly as in
    /// <see cref="CreateZeroKnowledge"/> — the commitment bytes and blind layout are
    /// identical — but the opening additionally folds a fresh masking codeword
    /// <c>s</c> in lockstep, blends the round polynomials by a squeezed <c>ρ</c>,
    /// and carries <c>σ = Σ_b s(b)</c>, the mask roots, the mask base oracle, and
    /// the mask query openings (see
    /// <see cref="BaseFoldEvaluationProver.ProveZeroKnowledge"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the provider the masked-Spartan-over-ZK-BaseFold integration (ZK.3)
    /// wires its polynomial opening to; only here is masked-Spartan-over-BaseFold
    /// genuinely zero-knowledge rather than merely sound. The single entropy sampler
    /// <paramref name="scalarRandom"/> sources both the hiding salts and the mask
    /// multilinear; they are independent draws.
    /// </para>
    /// <para>
    /// The mask doubles the opening's IOPP work and roughly its byte size; the
    /// <see cref="GetFullZeroKnowledgeEvaluationProofSizeBytes"/> helper reports the
    /// exact size. As in <see cref="CreateZeroKnowledge"/> the bounded-independence
    /// hiding budget is enforced on every commit and open (size the lift with
    /// <see cref="GetMinimumExtraVariableCount"/>); it is additionally validated
    /// empirically in ZK.4.
    /// </para>
    /// </remarks>
    /// <inheritdoc cref="CreateZeroKnowledge"/>
    public static PolynomialCommitmentProvider CreateFullZeroKnowledge(
        ReadOnlySpan<byte> seed,
        CurveParameterSet curve,
        int queryCount,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarRandomDelegate scalarRandom,
        ScalarHashToScalarDelegate hashToScalar,
        int extraVariableCount,
        int digestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes,
        ScalarArithmeticBackend? batch = null)
    {
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(scalarRandom);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(extraVariableCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);

        byte[] seedCopy = seed.ToArray();
        int t = extraVariableCount;

        FoldableCode DeriveCode(int variableCount, BaseMemoryPool pool)
        {
            FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(variableCount, curve);
            return FoldableCode.Derive(parameters, seedCopy, hashToScalar, pool);
        }

        PolynomialCommitDelegate commit = (polynomial, pool) =>
        {
            ThrowIfHidingBudgetUnmet(polynomial.VariableCount, t, curve, queryCount);

            int liftedVariableCount = polynomial.VariableCount + t;
            int realEvaluations = polynomial.EvaluationCount;
            int liftedEvaluations = 1 << liftedVariableCount;
            int maskScalars = liftedEvaluations - realEvaluations;

            using FoldableCode code = DeriveCode(liftedVariableCount, pool);
            FoldableCodeParameters parameters = code.Parameters;
            int codewordElements = parameters.CodewordLength;

            //f' evaluations: the real witness in the Y = 0 slice, entropy mask in
            //the rest — identical to CreateZeroKnowledge's commitment.
            using IMemoryOwner<byte> liftedEvalsOwner = pool.Rent(liftedEvaluations * ScalarSize);
            Span<byte> liftedEvals = liftedEvalsOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
            polynomial.AsReadOnlySpan().CopyTo(liftedEvals[..(realEvaluations * ScalarSize)]);
            GenerateScalars(liftedEvals.Slice(realEvaluations * ScalarSize, maskScalars * ScalarSize), maskScalars, scalarRandom, curve);

            using MultilinearExtension lifted = MultilinearExtension.FromEvaluations(liftedEvals, liftedVariableCount, curve, pool);

            using IMemoryOwner<byte> coeffsOwner = pool.Rent(liftedEvaluations * ScalarSize);
            Span<byte> coeffs = coeffsOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
            lifted.InterpolateToCoefficients(coeffs, subtract);

            using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
            Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
            code.Encode(coeffs, codeword, add, subtract, multiply, pool, batch);

            using IMemoryOwner<byte> saltsOwner = pool.Rent(codewordElements * ScalarSize);
            Span<byte> salts = saltsOwner.Memory.Span[..(codewordElements * ScalarSize)];
            GenerateScalars(salts, codewordElements, scalarRandom, curve);

            using MerkleTree tree = MerkleTree.BuildSalted(codeword, salts, codewordElements, merkleHash, pool);

            PolynomialCommitment commitment = PolynomialCommitment.FromBytes(
                tree.Root.AsReadOnlySpan(), curve, CommitmentScheme.BaseFold, pool);

            using IMemoryOwner<byte> blindOwner = pool.Rent((maskScalars + codewordElements) * ScalarSize);
            Span<byte> blindBytes = blindOwner.Memory.Span[..((maskScalars + codewordElements) * ScalarSize)];
            liftedEvals.Slice(realEvaluations * ScalarSize, maskScalars * ScalarSize).CopyTo(blindBytes[..(maskScalars * ScalarSize)]);
            salts.CopyTo(blindBytes.Slice(maskScalars * ScalarSize, codewordElements * ScalarSize));
            PolynomialCommitmentBlind blind = PolynomialCommitmentBlind.FromCanonical(
                blindBytes, curve, CommitmentScheme.BaseFold, pool);

            return (commitment, blind);
        };

        PolynomialOpenDelegate open = (commitment, blind, polynomial, evaluationPoint, transcript, pool) =>
        {
            ThrowIfHidingBudgetUnmet(polynomial.VariableCount, t, curve, queryCount);

            int liftedVariableCount = polynomial.VariableCount + t;
            int realEvaluations = polynomial.EvaluationCount;
            int liftedEvaluations = 1 << liftedVariableCount;
            int maskScalars = liftedEvaluations - realEvaluations;

            using FoldableCode code = DeriveCode(liftedVariableCount, pool);
            int codewordElements = code.Parameters.CodewordLength;

            ReadOnlySpan<byte> blindBytes = blind.AsReadOnlySpan();
            ReadOnlySpan<byte> maskBlock = blindBytes[..(maskScalars * ScalarSize)];
            ReadOnlySpan<byte> topSalts = blindBytes.Slice(maskScalars * ScalarSize, codewordElements * ScalarSize);

            using IMemoryOwner<byte> liftedEvalsOwner = pool.Rent(liftedEvaluations * ScalarSize);
            Span<byte> liftedEvals = liftedEvalsOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
            polynomial.AsReadOnlySpan().CopyTo(liftedEvals[..(realEvaluations * ScalarSize)]);
            maskBlock.CopyTo(liftedEvals.Slice(realEvaluations * ScalarSize, maskScalars * ScalarSize));

            using MultilinearExtension lifted = MultilinearExtension.FromEvaluations(liftedEvals, liftedVariableCount, curve, pool);

            //The mask's coefficient commitment lives under its own code from the
            //same seed, at the deterministic policy shape for this sumcheck.
            StatisticalMaskParameters maskParameters = WellKnownStatisticalMaskParameters.CreateClassicalSecurity(liftedVariableCount, curve, queryCount);
            using FoldableCode maskCommitmentCode = DeriveCode(maskParameters.LiftedVariableCount, pool);

            Scalar[] liftedPoint = BuildLiftedPoint(evaluationPoint, t, curve, pool);
            try
            {
                //The witness salts source the hiding side; the same entropy sampler
                //sources the sumcheck mask, the filler, and the mask commitment's
                //lift block (independent draws).
                (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.ProveZeroKnowledge(
                    code, lifted, liftedPoint, queryCount, transcript, merkleHash, hash, squeeze,
                    reduce, add, subtract, multiply, invert, topSalts, scalarRandom, scalarRandom, maskCommitmentCode, pool, batch);

                using(proof)
                {
                    (IMemoryOwner<byte> bytesOwner, int length) = BaseFoldEvaluationProofSerialization.ToBytes(proof, digestSizeBytes, BaseFoldOpeningMode.ZeroKnowledge, pool);
                    using(bytesOwner)
                    {
                        PolynomialOpening opening = PolynomialOpening.FromBytes(
                            bytesOwner.Memory.Span[..length], curve, CommitmentScheme.BaseFold, pool);

                        return (opening, claimedValue);
                    }
                }
            }
            finally
            {
                foreach(Scalar coordinate in liftedPoint)
                {
                    coordinate.Dispose();
                }
            }
        };

        PolynomialVerifyEvaluationDelegate verifyEvaluation = (commitment, evaluationPoint, claimedValue, opening, transcript, pool) =>
        {
            int liftedVariableCount = evaluationPoint.Length + t;
            using FoldableCode code = DeriveCode(liftedVariableCount, pool);

            BaseFoldEvaluationProof? proof = null;
            try
            {
                proof = BaseFoldEvaluationProofSerialization.FromBytes(
                    opening.AsReadOnlySpan(), code.Parameters, queryCount, digestSizeBytes, BaseFoldOpeningMode.ZeroKnowledge, pool);
            }
            catch(ArgumentException)
            {
                return false;
            }

            StatisticalMaskParameters maskParameters = WellKnownStatisticalMaskParameters.CreateClassicalSecurity(liftedVariableCount, curve, queryCount);
            using FoldableCode maskCommitmentCode = DeriveCode(maskParameters.LiftedVariableCount, pool);

            Scalar[] liftedPoint = BuildLiftedPoint(evaluationPoint, t, curve, pool);
            try
            {
                using(proof)
                using(MerkleRoot commitmentRoot = MerkleRoot.FromBytes(commitment.AsReadOnlySpan(), pool))
                {
                    return BaseFoldEvaluationVerifier.VerifyZeroKnowledge(
                        code, commitmentRoot, liftedPoint, claimedValue, proof, queryCount, transcript,
                        merkleHash, hash, squeeze, reduce, add, subtract, multiply, invert, maskCommitmentCode, pool);
                }
            }
            finally
            {
                foreach(Scalar coordinate in liftedPoint)
                {
                    coordinate.Dispose();
                }
            }
        };

        //The weighted-opening path (the statistical sumcheck mask's binding,
        //SM.7b): the vector is committed salted-and-lifted at its OWN minimum
        //lift (recomputed from the vector's variable count — the provider's
        //witness lift t is sized for a different shape), and the weighted
        //opening is the SM.1 multiplier-generic protocol in hiding mode with
        //the weights zero-extended over the lift block, so the claimed value
        //stays the inner product over the caller's coordinates.
        PolynomialCommitDelegate commitVector = (vector, pool) =>
        {
            int vectorLift = GetMinimumExtraVariableCount(vector.VariableCount, curve, queryCount);
            ThrowIfHidingBudgetUnmet(vector.VariableCount, vectorLift, curve, queryCount);

            int liftedVariableCount = vector.VariableCount + vectorLift;
            int realEvaluations = vector.EvaluationCount;
            int liftedEvaluations = 1 << liftedVariableCount;
            int maskScalars = liftedEvaluations - realEvaluations;

            using FoldableCode code = DeriveCode(liftedVariableCount, pool);
            int codewordElements = code.Parameters.CodewordLength;

            using IMemoryOwner<byte> liftedEvalsOwner = pool.Rent(liftedEvaluations * ScalarSize);
            Span<byte> liftedEvals = liftedEvalsOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
            vector.AsReadOnlySpan().CopyTo(liftedEvals[..(realEvaluations * ScalarSize)]);
            GenerateScalars(liftedEvals.Slice(realEvaluations * ScalarSize, maskScalars * ScalarSize), maskScalars, scalarRandom, curve);

            using MultilinearExtension lifted = MultilinearExtension.FromEvaluations(liftedEvals, liftedVariableCount, curve, pool);

            using IMemoryOwner<byte> coeffsOwner = pool.Rent(liftedEvaluations * ScalarSize);
            Span<byte> coeffs = coeffsOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
            lifted.InterpolateToCoefficients(coeffs, subtract);

            using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
            Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
            code.Encode(coeffs, codeword, add, subtract, multiply, pool, batch);

            using IMemoryOwner<byte> saltsOwner = pool.Rent(codewordElements * ScalarSize);
            Span<byte> salts = saltsOwner.Memory.Span[..(codewordElements * ScalarSize)];
            GenerateScalars(salts, codewordElements, scalarRandom, curve);

            using MerkleTree tree = MerkleTree.BuildSalted(codeword, salts, codewordElements, merkleHash, pool);

            PolynomialCommitment commitment = PolynomialCommitment.FromBytes(
                tree.Root.AsReadOnlySpan(), curve, CommitmentScheme.BaseFold, pool);

            //Blind = [lift block ‖ top-layer salts], the witness commit's layout.
            using IMemoryOwner<byte> blindOwner = pool.Rent((maskScalars + codewordElements) * ScalarSize);
            Span<byte> blindBytes = blindOwner.Memory.Span[..((maskScalars + codewordElements) * ScalarSize)];
            liftedEvals.Slice(realEvaluations * ScalarSize, maskScalars * ScalarSize).CopyTo(blindBytes[..(maskScalars * ScalarSize)]);
            salts.CopyTo(blindBytes.Slice(maskScalars * ScalarSize, codewordElements * ScalarSize));
            PolynomialCommitmentBlind blind = PolynomialCommitmentBlind.FromCanonical(
                blindBytes, curve, CommitmentScheme.BaseFold, pool);

            return (commitment, blind);
        };

        PolynomialOpenWeightedSumDelegate openWeightedSum = (commitment, blind, vector, weights, transcript, pool) =>
        {
            int vectorLift = GetMinimumExtraVariableCount(vector.VariableCount, curve, queryCount);
            ThrowIfHidingBudgetUnmet(vector.VariableCount, vectorLift, curve, queryCount);

            int liftedVariableCount = vector.VariableCount + vectorLift;
            int realEvaluations = vector.EvaluationCount;
            int liftedEvaluations = 1 << liftedVariableCount;
            int maskScalars = liftedEvaluations - realEvaluations;

            using FoldableCode code = DeriveCode(liftedVariableCount, pool);
            int codewordElements = code.Parameters.CodewordLength;

            ReadOnlySpan<byte> blindBytes = blind.AsReadOnlySpan();
            ReadOnlySpan<byte> maskBlock = blindBytes[..(maskScalars * ScalarSize)];
            ReadOnlySpan<byte> topSalts = blindBytes.Slice(maskScalars * ScalarSize, codewordElements * ScalarSize);

            //Rebuild the exact lifted vector committed: the caller's coordinates
            //followed by the blind's lift block.
            using IMemoryOwner<byte> liftedEvalsOwner = pool.Rent(liftedEvaluations * ScalarSize);
            Span<byte> liftedEvals = liftedEvalsOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
            vector.AsReadOnlySpan().CopyTo(liftedEvals[..(realEvaluations * ScalarSize)]);
            maskBlock.CopyTo(liftedEvals.Slice(realEvaluations * ScalarSize, maskScalars * ScalarSize));

            using MultilinearExtension lifted = MultilinearExtension.FromEvaluations(liftedEvals, liftedVariableCount, curve, pool);
            using MultilinearExtension liftedWeights = BuildLiftedWeights(weights, liftedVariableCount, curve, pool);

            (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.ProveWeightedSumHiding(
                code, lifted, liftedWeights, queryCount, transcript, merkleHash, hash, squeeze,
                reduce, add, subtract, multiply, invert, topSalts, scalarRandom, pool, batch);

            using(proof)
            {
                (IMemoryOwner<byte> bytesOwner, int length) = BaseFoldEvaluationProofSerialization.ToBytes(proof, digestSizeBytes, BaseFoldOpeningMode.Hiding, pool);
                using(bytesOwner)
                {
                    PolynomialOpening opening = PolynomialOpening.FromBytes(
                        bytesOwner.Memory.Span[..length], curve, CommitmentScheme.BaseFold, pool);

                    return (opening, claimedValue);
                }
            }
        };

        PolynomialVerifyWeightedSumDelegate verifyWeightedSum = (commitment, weights, claimedValue, opening, transcript, pool) =>
        {
            int vectorLift = GetMinimumExtraVariableCount(weights.VariableCount, curve, queryCount);
            int liftedVariableCount = weights.VariableCount + vectorLift;
            using FoldableCode code = DeriveCode(liftedVariableCount, pool);

            BaseFoldEvaluationProof? proof = null;
            try
            {
                proof = BaseFoldEvaluationProofSerialization.FromBytes(
                    opening.AsReadOnlySpan(), code.Parameters, queryCount, digestSizeBytes, BaseFoldOpeningMode.Hiding, pool);
            }
            catch(ArgumentException)
            {
                return false;
            }

            using MultilinearExtension liftedWeights = BuildLiftedWeights(weights, liftedVariableCount, curve, pool);

            using(proof)
            using(MerkleRoot commitmentRoot = MerkleRoot.FromBytes(commitment.AsReadOnlySpan(), pool))
            {
                return BaseFoldEvaluationVerifier.VerifyWeightedSum(
                    code, commitmentRoot, liftedWeights, claimedValue, proof, queryCount, transcript,
                    merkleHash, hash, squeeze, reduce, add, subtract, multiply, invert, pool);
            }
        };

        return new PolynomialCommitmentProvider(
            CommitmentScheme.BaseFold, curve, commit, open, verifyEvaluation,
            ownedResource: null, queryCount: queryCount, digestSizeBytes: digestSizeBytes,
            isAdditivelyHomomorphic: false, isHiding: true, extraVariableCount: t,
            commitVector, openWeightedSum, verifyWeightedSum,
            //The lifted-and-filled BaseFold mask-shape ledger at this provider's
            //query count.
            resolveStatisticalMaskShape: (d, degree) => WellKnownStatisticalMaskParameters.CreateClassicalSecurity(d, curve, queryCount, degree));
    }


    //The weight table zero-extended over the lift block: the caller's weights on
    //the real coordinates (the first 2^d entries — the lift adds HIGH variables),
    //field zero everywhere the internal lift entropy lives, so the weighted sum
    //ranges over exactly the caller's coordinates.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000", Justification = "The rented buffer transfers ownership to the returned MLE.")]
    private static MultilinearExtension BuildLiftedWeights(
        MultilinearExtension weights,
        int liftedVariableCount,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int liftedEvaluations = 1 << liftedVariableCount;
        using IMemoryOwner<byte> liftedOwner = pool.Rent(liftedEvaluations * ScalarSize);
        Span<byte> lifted = liftedOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
        lifted.Clear();
        weights.AsReadOnlySpan().CopyTo(lifted[..(weights.EvaluationCount * ScalarSize)]);

        return MultilinearExtension.FromEvaluations(lifted, liftedVariableCount, curve, pool);
    }


    //Fills a span with count fresh uniform scalars from the entropy sampler.
    //Every caller draws hiding material — the per-leaf Merkle salts or a
    //dimension-lift mask block — so an identically-zero block voids the hiding
    //property while every proof still verifies. A healthy sampler produces a
    //zero block with probability at most 2^-255 per scalar, so the post-check
    //only ever fires on a broken entropy delegate; reject at generation, the
    //one place the drawn bytes are visible.
    private static void GenerateScalars(Span<byte> destination, int count, ScalarRandomDelegate scalarRandom, CurveParameterSet curve)
    {
        Tag scalarTag = WellKnownAlgebraicTags.ScalarFor(curve);
        for(int i = 0; i < count; i++)
        {
            _ = scalarRandom(destination.Slice(i * ScalarSize, ScalarSize), curve, scalarTag);
        }

        if(count > 0 && destination[..(count * ScalarSize)].IndexOfAnyExcept((byte)0) < 0)
        {
            throw new InvalidOperationException(
                "The sampled hiding block (salts or dimension-lift mask) is identically zero. A zero block voids "
                + "the hiding property while the commitment and proof remain sound, and can only come from a broken "
                + "entropy source; check the ScalarRandomDelegate wiring supplied to the provider factory.");
        }
    }


    //Builds the protocol-fixed lifted point (z, 0…0): the supplied real point
    //coordinates followed by t field-zero coordinates (the extra mask variables).
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000", Justification = "Each coordinate scalar is owned by the returned array; the caller disposes the array in a finally block.")]
    private static Scalar[] BuildLiftedPoint(ReadOnlySpan<Scalar> point, int extraVariableCount, CurveParameterSet curve, BaseMemoryPool pool)
    {
        Tag scalarTag = WellKnownAlgebraicTags.ScalarFor(curve);
        var lifted = new Scalar[point.Length + extraVariableCount];
        for(int i = 0; i < point.Length; i++)
        {
            IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
            point[i].AsReadOnlySpan().CopyTo(owner.Memory.Span[..ScalarSize]);
            lifted[i] = new Scalar(owner, curve, scalarTag);
        }

        for(int i = 0; i < extraVariableCount; i++)
        {
            IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
            owner.Memory.Span[..ScalarSize].Clear();
            lifted[point.Length + i] = new Scalar(owner, curve, scalarTag);
        }

        return lifted;
    }


    /// <summary>
    /// Determines whether the lift <paramref name="extraVariableCount"/> meets the
    /// bounded-independence hiding budget for a <paramref name="variableCount"/>-variable
    /// witness at <paramref name="queryCount"/> IOPP queries: the mask degrees of
    /// freedom <c>(2^t − 1)·2^d</c> (the entropy <c>Y ≠ 0</c> block of the lifted
    /// polynomial) must cover every codeword position an opening can reveal. The
    /// reveal bound counts, per query, the two top-layer fold-pair entries plus one
    /// new sibling per lower layer (the folded partner is determined by the layer
    /// above), and the cleartext base oracle sent in full — see the design notes in
    /// <c>BaseFold/BASEFOLD.md</c>.
    /// </summary>
    /// <param name="variableCount">The real witness's variable count <c>d</c>.</param>
    /// <param name="extraVariableCount">The lift <c>t</c> under consideration; must be positive.</param>
    /// <param name="curve">The curve the wired classical-security code shape is over.</param>
    /// <param name="queryCount">The IOPP query repetition count.</param>
    /// <returns><see langword="true"/> when the budget is met; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    public static bool MeetsHidingBudget(int variableCount, int extraVariableCount, CurveParameterSet curve, int queryCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(variableCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(extraVariableCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);

        int liftedVariableCount = variableCount + extraVariableCount;
        if(liftedVariableCount >= LiftedVariableCountBudgetCeiling)
        {
            return true;
        }

        long degreesOfFreedom = ((1L << extraVariableCount) - 1) << variableCount;

        return degreesOfFreedom >= ComputeRevealedPositionBound(liftedVariableCount, curve, queryCount);
    }


    /// <summary>
    /// Returns the smallest lift <c>t</c> for which
    /// <see cref="MeetsHidingBudget"/> holds — the minimum
    /// <c>extraVariableCount</c> a <see cref="CreateZeroKnowledge"/> /
    /// <see cref="CreateFullZeroKnowledge"/> provider needs to commit a
    /// <paramref name="variableCount"/>-variable witness at
    /// <paramref name="queryCount"/> queries. Each unit of <c>t</c> doubles the
    /// lifted codeword (and so the commit/open cost), so callers want exactly
    /// this value unless they have a reason to over-provision.
    /// </summary>
    /// <param name="variableCount">The real witness's variable count <c>d</c>.</param>
    /// <param name="curve">The curve the wired classical-security code shape is over.</param>
    /// <param name="queryCount">The IOPP query repetition count.</param>
    /// <returns>The smallest budget-meeting <c>extraVariableCount</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    public static int GetMinimumExtraVariableCount(int variableCount, CurveParameterSet curve, int queryCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(variableCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);

        //The degrees of freedom grow as 2^t while the reveal bound grows linearly
        //in t, so the search always terminates well below the ceiling.
        for(int t = 1; variableCount + t < LiftedVariableCountBudgetCeiling; t++)
        {
            if(MeetsHidingBudget(variableCount, t, curve, queryCount))
            {
                return t;
            }
        }

        return LiftedVariableCountBudgetCeiling - variableCount;
    }


    //The upper bound on distinct codeword positions one opening reveals (the Q* of
    //design doc §3.3): per query, the top layer's fold pair is two entries and each
    //lower layer adds one new sibling (its other entry is the fold of the pair
    //above, so it carries no new information), giving liftedVariableCount + 1 per
    //query; the base oracle is sent in cleartext in full. Cross-query coincidences
    //only shrink the true count, so the bound is safe.
    private static long ComputeRevealedPositionBound(int liftedVariableCount, CurveParameterSet curve, int queryCount)
    {
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(liftedVariableCount, curve);
        long baseOracleLength = (long)parameters.InverseRate * parameters.BaseDimension;

        return ((long)queryCount * (liftedVariableCount + 1)) + baseOracleLength;
    }


    //The budget guard the lift factories run on every commit and open: a provider
    //advertising IsHiding must not silently deliver less hiding than the §3.3
    //bounded-independence argument supports — refuse loudly instead.
    private static void ThrowIfHidingBudgetUnmet(int variableCount, int extraVariableCount, CurveParameterSet curve, int queryCount)
    {
        if(!MeetsHidingBudget(variableCount, extraVariableCount, curve, queryCount))
        {
            long degreesOfFreedom = ((1L << extraVariableCount) - 1) << variableCount;
            long revealed = ComputeRevealedPositionBound(variableCount + extraVariableCount, curve, queryCount);
            int minimum = GetMinimumExtraVariableCount(variableCount, curve, queryCount);

            throw new InvalidOperationException(
                $"The bounded-independence hiding budget is unmet: extraVariableCount = {extraVariableCount} gives "
                + $"(2^{extraVariableCount} − 1)·2^{variableCount} = {degreesOfFreedom} mask degrees of freedom, but an opening at "
                + $"queryCount = {queryCount} can reveal up to {revealed} codeword positions. The smallest sufficient "
                + $"extraVariableCount for a {variableCount}-variable witness is {minimum} "
                + $"(ZkBaseFoldPolynomialCommitmentScheme.GetMinimumExtraVariableCount).");
        }
    }


    /// <summary>
    /// Returns the byte size of the serialized hiding BaseFold evaluation proof
    /// (the opening) for a multilinear polynomial in
    /// <paramref name="variableCount"/> variables, under the wired
    /// classical-security code shape, the given query count, and digest size.
    /// The hiding opening is larger than the non-hiding one by the two leaf salts
    /// carried per fold-pair step.
    /// </summary>
    /// <param name="variableCount">The committed polynomial's variable count (= the code's layer count).</param>
    /// <param name="curve">The curve the code is over.</param>
    /// <param name="queryCount">The IOPP query repetition count the provider was built with.</param>
    /// <param name="digestSizeBytes">The Merkle digest size the provider was built with.</param>
    /// <returns>The opening's serialized byte length.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is non-positive or negative.</exception>
    public static int GetEvaluationProofSizeBytes(int variableCount, CurveParameterSet curve, int queryCount, int digestSizeBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(variableCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);

        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(variableCount, curve);
        return BaseFoldEvaluationProofSerialization.ComputeLength(parameters, queryCount, digestSizeBytes, BaseFoldOpeningMode.Hiding);
    }


    /// <summary>
    /// Returns the serialized opening size for a provider built via
    /// <see cref="CreateZeroKnowledge"/>: the dimension-lift commits a
    /// <c>d</c>-variable witness at <c>d + extraVariableCount</c> layers, so the
    /// opening is the hiding proof size at the lifted variable count. A consumer
    /// (the masked-Spartan-over-ZK-BaseFold integration) uses this to lay out the
    /// variable-length opening sections.
    /// </summary>
    /// <param name="variableCount">The real witness's variable count <c>d</c>.</param>
    /// <param name="extraVariableCount">The lift <c>t</c> the provider was built with.</param>
    /// <param name="curve">The curve the code is over.</param>
    /// <param name="queryCount">The IOPP query repetition count the provider was built with.</param>
    /// <param name="digestSizeBytes">The Merkle digest size the provider was built with.</param>
    /// <returns>The lifted opening's serialized byte length.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    public static int GetZeroKnowledgeEvaluationProofSizeBytes(int variableCount, int extraVariableCount, CurveParameterSet curve, int queryCount, int digestSizeBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(variableCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(extraVariableCount);

        return GetEvaluationProofSizeBytes(variableCount + extraVariableCount, curve, queryCount, digestSizeBytes);
    }


    /// <summary>
    /// Returns the serialized opening size for a provider built via
    /// <see cref="CreateFullZeroKnowledge"/>: the lifted hiding witness proof plus
    /// the CFS-2017 mask side (<c>σ</c>, the mask top root, the mask fold roots,
    /// the mask base oracle, and the mask query openings) — roughly twice
    /// <see cref="GetZeroKnowledgeEvaluationProofSizeBytes"/>.
    /// </summary>
    /// <param name="variableCount">The real witness's variable count <c>d</c>.</param>
    /// <param name="extraVariableCount">The lift <c>t</c> the provider was built with.</param>
    /// <param name="curve">The curve the code is over.</param>
    /// <param name="queryCount">The IOPP query repetition count the provider was built with.</param>
    /// <param name="digestSizeBytes">The Merkle digest size the provider was built with.</param>
    /// <returns>The full zero-knowledge opening's serialized byte length.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    public static int GetFullZeroKnowledgeEvaluationProofSizeBytes(int variableCount, int extraVariableCount, CurveParameterSet curve, int queryCount, int digestSizeBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(variableCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(extraVariableCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);

        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(variableCount + extraVariableCount, curve);
        return BaseFoldEvaluationProofSerialization.ComputeLength(parameters, queryCount, digestSizeBytes, BaseFoldOpeningMode.ZeroKnowledge);
    }
}
