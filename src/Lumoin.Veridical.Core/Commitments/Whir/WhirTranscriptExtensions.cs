using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// Fiat-Shamir transcript operations for the WHIR IOPP, in the protocol's
/// message order: the statement and input-oracle root, then per iteration the
/// folded oracle's root, the out-of-domain sample and reply, the shift-query
/// indices and combination challenge, and the sumcheck round polynomials and
/// folding challenges; finally the cleartext final polynomial and the final
/// query indices, and, on the hiding path, the masked-sumcheck, code-switch
/// and masked base-case messages. Prover and verifier call these in the same
/// order so they reach identical transcript states and therefore identical
/// challenges and query indices.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class WhirTranscriptExtensions
{
    /// <summary>
    /// Bytes squeezed for a query index. Eight bytes give a 64-bit value; the
    /// query domain is a power of two, so the low-bit mask is unbiased
    /// regardless of the byte count, and eight bytes comfortably cover any
    /// practical domain size.
    /// </summary>
    private const int QueryIndexSqueezeBytes = sizeof(ulong);


    extension(FiatShamirTranscript transcript)
    {
        /// <summary>
        /// Absorbs the public statement — the sumcheck target <c>σ</c>
        /// followed by every constraint's coefficient and point — under the
        /// <see cref="WellKnownWhirTranscriptLabels.Statement"/> label, as one
        /// operation so the challenge stream is bound to the whole claim.
        /// </summary>
        /// <param name="target">The sumcheck target <c>σ</c>, one element.</param>
        /// <param name="constraintCoefficients">The constraint coefficients, one element per constraint.</param>
        /// <param name="constraintPoints">The concatenated constraint points.</param>
        /// <param name="hash">The transcript's fixed-output hash backend.</param>
        /// <exception cref="ArgumentNullException">When <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbWhirStatement(
            ReadOnlySpan<byte> target,
            ReadOnlySpan<byte> constraintCoefficients,
            ReadOnlySpan<byte> constraintPoints,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            var label = new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.Statement);
            transcript.AbsorbBytes(label, target, hash);
            transcript.AbsorbBytes(label, constraintCoefficients, hash);
            transcript.AbsorbBytes(label, constraintPoints, hash);
        }


        /// <summary>
        /// Absorbs an oracle's Merkle root under the
        /// <see cref="WellKnownWhirTranscriptLabels.OracleRoot"/> label.
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="root"/> or <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbWhirOracleRoot(MerkleRoot root, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(root);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.OracleRoot),
                root.AsReadOnlySpan(),
                hash);
        }


        /// <summary>
        /// Absorbs a compressed sumcheck round polynomial under the
        /// <see cref="WellKnownWhirTranscriptLabels.SumcheckPolynomial"/> label.
        /// </summary>
        /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
        public void AbsorbWhirSumcheckPolynomial(CompressedRoundPolynomial roundPolynomial, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            transcript.AbsorbRoundPolynomial(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.SumcheckPolynomial),
                roundPolynomial,
                hash);
        }


        /// <summary>
        /// Squeezes a sumcheck folding challenge <c>α</c> as a canonical
        /// scalar under the
        /// <see cref="WellKnownWhirTranscriptLabels.FoldChallenge"/> label.
        /// </summary>
        /// <returns>The challenge; the caller owns its disposal.</returns>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        public Scalar SqueezeWhirFoldChallenge(
            FiatShamirSqueezeDelegate squeeze,
            FiatShamirHashDelegate hash,
            ScalarReduceDelegate reduce,
            CurveParameterSet curve,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            return transcript.SqueezeScalar(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.FoldChallenge),
                squeeze,
                hash,
                reduce,
                curve,
                pool);
        }


        /// <summary>
        /// Squeezes an out-of-domain sample <c>z_(i,0)</c> as a canonical
        /// scalar under the
        /// <see cref="WellKnownWhirTranscriptLabels.OutOfDomainPoint"/> label.
        /// </summary>
        /// <returns>The sample; the caller owns its disposal.</returns>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        public Scalar SqueezeWhirOutOfDomainPoint(
            FiatShamirSqueezeDelegate squeeze,
            FiatShamirHashDelegate hash,
            ScalarReduceDelegate reduce,
            CurveParameterSet curve,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            return transcript.SqueezeScalar(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.OutOfDomainPoint),
                squeeze,
                hash,
                reduce,
                curve,
                pool);
        }


        /// <summary>
        /// Absorbs an out-of-domain reply <c>y_(i,0)</c> under the
        /// <see cref="WellKnownWhirTranscriptLabels.OutOfDomainReply"/> label.
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbWhirOutOfDomainReply(ReadOnlySpan<byte> reply, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.OutOfDomainReply),
                reply,
                hash);
        }


        /// <summary>
        /// Squeezes a combination challenge <c>γ</c> as a canonical scalar
        /// under the
        /// <see cref="WellKnownWhirTranscriptLabels.CombinationChallenge"/> label.
        /// </summary>
        /// <returns>The challenge; the caller owns its disposal.</returns>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        public Scalar SqueezeWhirCombinationChallenge(
            FiatShamirSqueezeDelegate squeeze,
            FiatShamirHashDelegate hash,
            ScalarReduceDelegate reduce,
            CurveParameterSet curve,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            return transcript.SqueezeScalar(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.CombinationChallenge),
                squeeze,
                hash,
                reduce,
                curve,
                pool);
        }


        /// <summary>
        /// Absorbs the final polynomial's cleartext coefficients under the
        /// <see cref="WellKnownWhirTranscriptLabels.FinalPolynomial"/> label.
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbWhirFinalPolynomial(ReadOnlySpan<byte> coefficients, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.FinalPolynomial),
                coefficients,
                hash);
        }


        /// <summary>
        /// Absorbs a public batch statement — every claim's target and
        /// constraint list, prefixed by an explicit fixed-width encoding of
        /// the claim boundaries — under the
        /// <see cref="WellKnownWhirTranscriptLabels.BatchStatement"/> label.
        /// Absorbing the boundary encoding pins how the flat spans split
        /// into claims, so two different batches can never absorb identical
        /// bytes. The batch combination challenge is bound to this statement
        /// and to the input oracle's root absorbed after it.
        /// </summary>
        /// <param name="claimTargets">The claim targets <c>σ_i</c>, one element per claim.</param>
        /// <param name="claimConstraintCounts">The per-claim constraint counts splitting the flat constraint spans.</param>
        /// <param name="constraintCoefficients">Every claim's constraint coefficients, concatenated in claim order.</param>
        /// <param name="constraintPoints">Every claim's constraint points, concatenated in claim order.</param>
        /// <param name="hash">The transcript's fixed-output hash backend.</param>
        /// <param name="pool">The pool to rent the boundary encoding from.</param>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        public void AbsorbWhirBatchStatement(
            ReadOnlySpan<byte> claimTargets,
            ReadOnlySpan<int> claimConstraintCounts,
            ReadOnlySpan<byte> constraintCoefficients,
            ReadOnlySpan<byte> constraintPoints,
            FiatShamirHashDelegate hash,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(pool);

            var label = new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.BatchStatement);

            int encodedLength = sizeof(int) * (1 + claimConstraintCounts.Length);
            using IMemoryOwner<byte> boundariesOwner = pool.Rent(encodedLength);
            Span<byte> boundaries = boundariesOwner.Memory.Span[..encodedLength];
            BinaryPrimitives.WriteInt32BigEndian(boundaries, claimConstraintCounts.Length);
            for(int claim = 0; claim < claimConstraintCounts.Length; claim++)
            {
                BinaryPrimitives.WriteInt32BigEndian(boundaries.Slice(sizeof(int) * (1 + claim), sizeof(int)), claimConstraintCounts[claim]);
            }

            transcript.AbsorbBytes(label, boundaries, hash);
            transcript.AbsorbBytes(label, claimTargets, hash);
            transcript.AbsorbBytes(label, constraintCoefficients, hash);
            transcript.AbsorbBytes(label, constraintPoints, hash);
        }


        /// <summary>
        /// Squeezes the batch combination challenge <c>γ</c> of WHIR
        /// Construction 5.5 as a canonical scalar under the
        /// <see cref="WellKnownWhirTranscriptLabels.BatchCombinationChallenge"/>
        /// label.
        /// </summary>
        /// <param name="squeeze">The XOF backend.</param>
        /// <param name="hash">The transcript's fixed-output hash backend.</param>
        /// <param name="reduce">The scalar-reduce backend for deriving the challenge.</param>
        /// <param name="curve">The curve whose scalar field the challenge lands in.</param>
        /// <param name="pool">The pool to rent the challenge from.</param>
        /// <returns>The challenge; the caller owns its disposal.</returns>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        public Scalar SqueezeWhirBatchCombinationChallenge(
            FiatShamirSqueezeDelegate squeeze,
            FiatShamirHashDelegate hash,
            ScalarReduceDelegate reduce,
            CurveParameterSet curve,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            return transcript.SqueezeScalar(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.BatchCombinationChallenge),
                squeeze,
                hash,
                reduce,
                curve,
                pool);
        }


        /// <summary>
        /// Absorbs a masked-sumcheck batch's interleaved mask oracle root
        /// under the
        /// <see cref="WellKnownWhirTranscriptLabels.MaskOracleRoot"/> label
        /// (eprint 2026/391 Construction 6.3, step 2).
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="root"/> or <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbWhirMaskOracleRoot(MerkleRoot root, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(root);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.MaskOracleRoot),
                root.AsReadOnlySpan(),
                hash);
        }


        /// <summary>
        /// Absorbs the mask total <c>μ̃</c> under the
        /// <see cref="WellKnownWhirTranscriptLabels.MaskTotal"/> label —
        /// before the combination challenge is squeezed, so the total cannot
        /// depend on it.
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbWhirMaskTotal(ReadOnlySpan<byte> maskTotal, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.MaskTotal),
                maskTotal,
                hash);
        }


        /// <summary>
        /// Squeezes the mask combination challenge <c>ε</c> as a canonical
        /// scalar under the
        /// <see cref="WellKnownWhirTranscriptLabels.MaskCombinationChallenge"/>
        /// label.
        /// </summary>
        /// <returns>The challenge; the caller owns its disposal.</returns>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        public Scalar SqueezeWhirMaskCombinationChallenge(
            FiatShamirSqueezeDelegate squeeze,
            FiatShamirHashDelegate hash,
            ScalarReduceDelegate reduce,
            CurveParameterSet curve,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            return transcript.SqueezeScalar(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.MaskCombinationChallenge),
                squeeze,
                hash,
                reduce,
                curve,
                pool);
        }


        /// <summary>
        /// Squeezes a query block index in <c>[0, queryDomainSize)</c> under
        /// the given label — <see cref="WellKnownWhirTranscriptLabels.ShiftQueryIndex"/>
        /// for the main loop's shift queries,
        /// <see cref="WellKnownWhirTranscriptLabels.FinalQueryIndex"/> for the
        /// final phase. The domain size must be a power of two (every WHIR
        /// folded query domain is), so the reduction is an unbiased low-bit
        /// mask.
        /// </summary>
        /// <param name="label">The operation label naming the query family.</param>
        /// <param name="queryDomainSize">The number of distinct query blocks; a power of two.</param>
        /// <param name="squeeze">The XOF backend.</param>
        /// <param name="hash">The fixed-output hash backend, used by the post-squeeze state update.</param>
        /// <returns>A block index in <c>[0, queryDomainSize)</c>.</returns>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When <paramref name="queryDomainSize"/> is not a positive power of two.</exception>
        public int SqueezeWhirQueryIndex(
            string label,
            int queryDomainSize,
            FiatShamirSqueezeDelegate squeeze,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryDomainSize);

            if(!BitOperations.IsPow2((uint)queryDomainSize))
            {
                throw new ArgumentException($"Query domain size must be a power of two; received {queryDomainSize}.", nameof(queryDomainSize));
            }

            Span<byte> bytes = stackalloc byte[QueryIndexSqueezeBytes];
            transcript.SqueezeBytes(
                new FiatShamirOperationLabel(label),
                bytes,
                squeeze,
                hash);

            ulong value = BinaryPrimitives.ReadUInt64BigEndian(bytes);

            //Power-of-two domain: the low bits are an unbiased uniform sample.
            return (int)(value & (ulong)(queryDomainSize - 1));
        }


        /// <summary>
        /// Absorbs the joint claim (source claim plus mask-claim total) under
        /// the <see cref="WellKnownWhirTranscriptLabels.MaskBatchClaim"/>
        /// label — before the batch's mask oracle root, so every batch
        /// transcript is self-contained.
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbWhirMaskBatchClaim(ReadOnlySpan<byte> jointClaim, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.MaskBatchClaim),
                jointClaim,
                hash);
        }


        /// <summary>
        /// Absorbs a code-switch round's fresh mask oracle root — folded
        /// randomness plus private out-of-domain pad — under the
        /// <see cref="WellKnownWhirTranscriptLabels.CodeSwitchMaskRoot"/>
        /// label.
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="root"/> or <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbWhirCodeSwitchMaskRoot(MerkleRoot root, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(root);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.CodeSwitchMaskRoot),
                root.AsReadOnlySpan(),
                hash);
        }


        /// <summary>
        /// Squeezes a private out-of-domain sample of a code-switch round as
        /// a canonical scalar under the
        /// <see cref="WellKnownWhirTranscriptLabels.PrivateOutOfDomainPoint"/>
        /// label.
        /// </summary>
        /// <returns>The sample; the caller owns its disposal.</returns>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        public Scalar SqueezeWhirPrivateOutOfDomainPoint(
            FiatShamirSqueezeDelegate squeeze,
            FiatShamirHashDelegate hash,
            ScalarReduceDelegate reduce,
            CurveParameterSet curve,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            return transcript.SqueezeScalar(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.PrivateOutOfDomainPoint),
                squeeze,
                hash,
                reduce,
                curve,
                pool);
        }


        /// <summary>
        /// Absorbs the zero-evader-padded reply to a private out-of-domain
        /// sample under the
        /// <see cref="WellKnownWhirTranscriptLabels.PrivateOutOfDomainReply"/>
        /// label.
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbWhirPrivateOutOfDomainReply(ReadOnlySpan<byte> reply, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.PrivateOutOfDomainReply),
                reply,
                hash);
        }


        /// <summary>
        /// Absorbs the masked base case's fresh main-oracle commitment under
        /// the <see cref="WellKnownWhirTranscriptLabels.BaseCaseFreshRoot"/>
        /// label (eprint 2026/391 Construction 7.2, move 1a).
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="root"/> or <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbWhirBaseCaseFreshRoot(MerkleRoot root, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(root);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.BaseCaseFreshRoot),
                root.AsReadOnlySpan(),
                hash);
        }


        /// <summary>
        /// Absorbs one fresh blind commitment for a carried mask group of
        /// the masked base case under the
        /// <see cref="WellKnownWhirTranscriptLabels.BaseCaseMaskRoot"/> label
        /// (eprint 2026/391 Construction 7.2, move 1b).
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="root"/> or <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbWhirBaseCaseMaskRoot(MerkleRoot root, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(root);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.BaseCaseMaskRoot),
                root.AsReadOnlySpan(),
                hash);
        }


        /// <summary>
        /// Absorbs the masked base-case claim μ_g under the
        /// <see cref="WellKnownWhirTranscriptLabels.BaseCaseClaim"/> label —
        /// fixed before the blinding challenge is squeezed, so the claim
        /// cannot depend on it.
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbWhirBaseCaseClaim(ReadOnlySpan<byte> maskedClaim, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.BaseCaseClaim),
                maskedClaim,
                hash);
        }


        /// <summary>
        /// Squeezes the base case's blinding challenge <c>γ</c> as a
        /// canonical scalar under the
        /// <see cref="WellKnownWhirTranscriptLabels.BaseCaseCombinationChallenge"/>
        /// label.
        /// </summary>
        /// <returns>The challenge; the caller owns its disposal.</returns>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        public Scalar SqueezeWhirBaseCaseCombinationChallenge(
            FiatShamirSqueezeDelegate squeeze,
            FiatShamirHashDelegate hash,
            ScalarReduceDelegate reduce,
            CurveParameterSet curve,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            return transcript.SqueezeScalar(
                new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.BaseCaseCombinationChallenge),
                squeeze,
                hash,
                reduce,
                curve,
                pool);
        }


        /// <summary>
        /// Absorbs the blinded source reveals — the message then the
        /// encoding randomness — as one operation under the
        /// <see cref="WellKnownWhirTranscriptLabels.BaseCaseReveal"/> label.
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbWhirBaseCaseReveal(
            ReadOnlySpan<byte> blindedMessage,
            ReadOnlySpan<byte> blindedRandomness,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            var label = new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.BaseCaseReveal);
            transcript.AbsorbBytes(label, blindedMessage, hash);
            transcript.AbsorbBytes(label, blindedRandomness, hash);
        }


        /// <summary>
        /// Absorbs the blinded mask reveals for a group member — the
        /// message then the encoding randomness — as one operation under the
        /// <see cref="WellKnownWhirTranscriptLabels.BaseCaseMaskReveal"/>
        /// label.
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbWhirBaseCaseMaskReveal(
            ReadOnlySpan<byte> blindedMessage,
            ReadOnlySpan<byte> blindedRandomness,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            var label = new FiatShamirOperationLabel(WellKnownWhirTranscriptLabels.BaseCaseMaskReveal);
            transcript.AbsorbBytes(label, blindedMessage, hash);
            transcript.AbsorbBytes(label, blindedRandomness, hash);
        }    }
}
