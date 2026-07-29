using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Lookup;

/// <summary>
/// The LogUp lookup-argument verifier: replays the prover's transcript
/// schedule, checks every sumcheck round's consistency, verifies the
/// polynomial-commitment openings, evaluates the public table itself at the
/// sumcheck point, and reassembles the combined identity there.
/// </summary>
/// <remarks>
/// The verifier performs no field inversions and never runs the fractional
/// arithmetic — zero denominators are a prover-side completeness concern only.
/// Hostile proof content yields <see langword="false"/>; only programmer
/// errors (null arguments, shape mismatches between the proof and the supplied
/// table) throw.
/// </remarks>
public static class LogUpVerifier
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Verifies a LogUp proof against the public
    /// <paramref name="tableEvaluations"/>.
    /// </summary>
    /// <param name="tableEvaluations">The public table column, <c>2^VariableCount × 32</c> canonical bytes — the same bytes the prover absorbed.</param>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="pcs">The polynomial-commitment provider matching the prover's.</param>
    /// <param name="transcript">A fresh transcript over the same domain the prover used.</param>
    /// <param name="hash">The transcript hash backend.</param>
    /// <param name="squeeze">The transcript XOF backend.</param>
    /// <param name="reduce">The wide-bytes-to-scalar reduction backend.</param>
    /// <param name="add">Scalar-add delegate.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="invert">Scalar-invert delegate, used only for the constant Lagrange denominators of the round interpolation.</param>
    /// <param name="mleEvaluate">The multilinear-evaluation backend for the verifier's own table evaluation.</param>
    /// <param name="pool">The pool every buffer is rented from.</param>
    /// <returns><see langword="true"/> when every check passes.</returns>
    public static bool Verify(
        ReadOnlySpan<byte> tableEvaluations,
        LogUpProof proof,
        PolynomialCommitmentProvider pcs,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        MleEvaluateDelegate mleEvaluate,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(pcs);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(mleEvaluate);
        ArgumentNullException.ThrowIfNull(pool);

        int variableCount = proof.VariableCount;
        int witnessColumnCount = proof.WitnessColumnCount;
        long expectedTableBytes = (1L << variableCount) * ScalarSize;
        if(tableEvaluations.Length != expectedTableBytes)
        {
            throw new ArgumentException($"The proof binds a {variableCount}-variable table of {expectedTableBytes} bytes; received {tableEvaluations.Length}.", nameof(tableEvaluations));
        }

        CurveParameterSet curve = pcs.Curve;
        if(curve.Code != proof.Curve.Code)
        {
            throw new ArgumentException($"The proof was produced over {proof.Curve} but the provider works over {curve}.", nameof(pcs));
        }

        //The table is public input the caller vouches for; non-canonical bytes
        //here are a caller bug, not a hostile proof.
        LogUpProver.ThrowIfNonCanonical(tableEvaluations, curve, nameof(tableEvaluations));

        int evaluationCount = LogUpSumcheck.RoundEvaluationCount(witnessColumnCount);

        //Replay the pre-challenge absorbs from the proof's commitments.
        LogUpProver.AbsorbInstanceShape(transcript, variableCount, witnessColumnCount, curve, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.TableEvaluations), tableEvaluations, hash);
        for(int column = 0; column < witnessColumnCount; column++)
        {
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.WitnessCommitment), proof.WitnessCommitments[column].AsReadOnlySpan(), hash);
        }

        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.MultiplicityCommitment), proof.MultiplicityCommitment.AsReadOnlySpan(), hash);

        Span<byte> denominatorChallenge = stackalloc byte[ScalarSize];
        LogUpProver.SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.DenominatorChallenge, denominatorChallenge, squeeze, hash, reduce, curve);

        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.HelperCommitment), proof.HelperCommitment.AsReadOnlySpan(), hash);

        Scalar[] kernelPoint = LogUpProver.SqueezeKernelPoint(transcript, variableCount, squeeze, hash, reduce, curve, pool);
        try
        {
            Span<byte> foldingChallenge = stackalloc byte[ScalarSize];
            LogUpProver.SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.FoldingChallenge, foldingChallenge, squeeze, hash, reduce, curve);

            //Sumcheck replay: the claim starts at zero, each round must split
            //it as s(0) + s(1), and the challenge reduces it by interpolation.
            using IMemoryOwner<byte> inverseDenominatorOwner = pool.Rent(evaluationCount * ScalarSize);
            Span<byte> inverseDenominators = inverseDenominatorOwner.Memory.Span[..(evaluationCount * ScalarSize)];
            SumcheckInterpolation.ComputeInverseDenominators(inverseDenominators, evaluationCount, subtract, multiply, invert, curve);

            using IMemoryOwner<byte> challengesOwner = pool.Rent(variableCount * ScalarSize);
            Span<byte> challenges = challengesOwner.Memory.Span[..(variableCount * ScalarSize)];

            ReadOnlySpan<byte> roundEvaluations = proof.GetRoundEvaluationBytes();
            Span<byte> claim = stackalloc byte[ScalarSize];
            claim.Clear();
            Span<byte> sum = stackalloc byte[ScalarSize];

            bool accepted = true;
            for(int round = 0; round < variableCount; round++)
            {
                ReadOnlySpan<byte> roundMessage = roundEvaluations.Slice(round * evaluationCount * ScalarSize, evaluationCount * ScalarSize);

                add(roundMessage[..ScalarSize], roundMessage.Slice(ScalarSize, ScalarSize), sum, curve);
                if(!sum.SequenceEqual(claim))
                {
                    accepted = false;
                }

                transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.SumcheckRoundPolynomial), roundMessage, hash);
                Span<byte> challenge = challenges.Slice(round * ScalarSize, ScalarSize);
                LogUpProver.SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.SumcheckRoundChallenge, challenge, squeeze, hash, reduce, curve);

                SumcheckInterpolation.Interpolate(roundMessage, evaluationCount, challenge, inverseDenominators, claim, add, subtract, multiply, curve);
            }

            //Absorb the claimed evaluations in the prover's order, then verify
            //every opening against them at the challenge point.
            ReadOnlySpan<byte> claimedEvaluations = proof.GetClaimedEvaluationBytes();
            for(int column = 0; column < witnessColumnCount; column++)
            {
                transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.WitnessEvaluation), claimedEvaluations.Slice(column * ScalarSize, ScalarSize), hash);
            }

            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.MultiplicityEvaluation), claimedEvaluations.Slice(witnessColumnCount * ScalarSize, ScalarSize), hash);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.HelperEvaluation), claimedEvaluations.Slice((witnessColumnCount + 1) * ScalarSize, ScalarSize), hash);

            Scalar[] openingPoint = LogUpProver.ToScalarArray(challenges, variableCount, curve, pool);
            try
            {
                int committedColumnCount = witnessColumnCount + LogUpSumcheck.AuxiliaryColumnCount;
                for(int column = 0; column < committedColumnCount; column++)
                {
                    (PolynomialCommitment commitment, PolynomialOpening opening) = column switch
                    {
                        _ when column < witnessColumnCount => (proof.WitnessCommitments[column], proof.WitnessOpenings[column]),
                        _ when column == witnessColumnCount => (proof.MultiplicityCommitment, proof.MultiplicityOpening),
                        _ => (proof.HelperCommitment, proof.HelperOpening),
                    };

                    using Scalar claimedValue = Scalar.FromCanonical(claimedEvaluations.Slice(column * ScalarSize, ScalarSize), curve, pool);
                    if(!pcs.VerifyEvaluation(commitment, openingPoint, claimedValue, opening, transcript, pool))
                    {
                        accepted = false;
                    }
                }

                //The verifier's own table evaluation at the challenge point.
                using MultilinearExtension tableMle = MultilinearExtension.FromEvaluations(tableEvaluations, variableCount, curve, pool);
                using Scalar tableAtPoint = tableMle.Evaluate(openingPoint, mleEvaluate, pool);

                //Reassemble P(r) from the claimed evaluations and check it
                //against the sumcheck's reduced claim.
                Span<byte> expected = stackalloc byte[ScalarSize];
                ComputeCombinedIdentity(
                    claimedEvaluations,
                    tableAtPoint.AsReadOnlySpan(),
                    denominatorChallenge,
                    foldingChallenge,
                    kernelPoint,
                    challenges,
                    witnessColumnCount,
                    expected,
                    add, subtract, multiply, curve, pool);

                if(!expected.SequenceEqual(claim))
                {
                    accepted = false;
                }

                return accepted;
            }
            finally
            {
                foreach(Scalar coordinate in openingPoint)
                {
                    coordinate.Dispose();
                }
            }
        }
        finally
        {
            foreach(Scalar coordinate in kernelPoint)
            {
                coordinate.Dispose();
            }
        }
    }


    //expected = h(r) + λ·eq(z,r)·( h(r)·Π φ_i − ( m(r)·Π_{j≠0} φ_j − Σ_{i≥1} Π_{j≠i} φ_j ) )
    //with φ_0 = x − t(r) and φ_i = x − w_i(r).
    private static void ComputeCombinedIdentity(
        ReadOnlySpan<byte> claimedEvaluations,
        ReadOnlySpan<byte> tableAtPoint,
        ReadOnlySpan<byte> denominatorChallenge,
        ReadOnlySpan<byte> foldingChallenge,
        ReadOnlySpan<Scalar> kernelPoint,
        ReadOnlySpan<byte> challenges,
        int witnessColumnCount,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int columnCount = witnessColumnCount + 1;
        ReadOnlySpan<byte> multiplicityValue = claimedEvaluations.Slice(witnessColumnCount * ScalarSize, ScalarSize);
        ReadOnlySpan<byte> helperValue = claimedEvaluations.Slice((witnessColumnCount + 1) * ScalarSize, ScalarSize);

        using IMemoryOwner<byte> scratchOwner = pool.Rent((3 * (columnCount + 1)) * ScalarSize);
        Span<byte> scratch = scratchOwner.Memory.Span;
        Span<byte> phis = scratch[..(columnCount * ScalarSize)];
        Span<byte> prefixes = scratch.Slice(columnCount * ScalarSize, (columnCount + 1) * ScalarSize);
        Span<byte> suffixes = scratch.Slice(((2 * columnCount) + 1) * ScalarSize, (columnCount + 1) * ScalarSize);
        Span<byte> temp1 = stackalloc byte[ScalarSize];
        Span<byte> temp2 = stackalloc byte[ScalarSize];

        subtract(denominatorChallenge, tableAtPoint, phis[..ScalarSize], curve);
        for(int column = 0; column < witnessColumnCount; column++)
        {
            subtract(denominatorChallenge, claimedEvaluations.Slice(column * ScalarSize, ScalarSize), phis.Slice((1 + column) * ScalarSize, ScalarSize), curve);
        }

        SumcheckChallenge.EncodeOne(prefixes[..ScalarSize]);
        for(int slot = 0; slot < columnCount; slot++)
        {
            multiply(prefixes.Slice(slot * ScalarSize, ScalarSize), phis.Slice(slot * ScalarSize, ScalarSize), prefixes.Slice((slot + 1) * ScalarSize, ScalarSize), curve);
        }

        SumcheckChallenge.EncodeOne(suffixes.Slice(columnCount * ScalarSize, ScalarSize));
        for(int slot = columnCount - 1; slot >= 0; slot--)
        {
            multiply(phis.Slice(slot * ScalarSize, ScalarSize), suffixes.Slice((slot + 1) * ScalarSize, ScalarSize), suffixes.Slice(slot * ScalarSize, ScalarSize), curve);
        }

        //S = m·Π_{j≠0} φ_j − Σ_{i≥1} Π_{j≠i} φ_j.
        multiply(multiplicityValue, suffixes.Slice(ScalarSize, ScalarSize), temp1, curve);
        for(int slot = 1; slot < columnCount; slot++)
        {
            multiply(prefixes.Slice(slot * ScalarSize, ScalarSize), suffixes.Slice((slot + 1) * ScalarSize, ScalarSize), temp2, curve);
            subtract(temp1, temp2, temp1, curve);
        }

        //inner = h·Πφ − S.
        multiply(helperValue, prefixes.Slice(columnCount * ScalarSize, ScalarSize), temp2, curve);
        subtract(temp2, temp1, temp1, curve);

        //eq(z, r) = Π_k (z_k·r_k + (1 − z_k)·(1 − r_k)), the kernel at the
        //challenge point, one factor per round in round order.
        Span<byte> kernel = stackalloc byte[ScalarSize];
        Span<byte> one = stackalloc byte[ScalarSize];
        SumcheckChallenge.EncodeOne(kernel);
        SumcheckChallenge.EncodeOne(one);
        Span<byte> factor = stackalloc byte[ScalarSize];
        Span<byte> complementZ = stackalloc byte[ScalarSize];
        Span<byte> complementR = stackalloc byte[ScalarSize];
        for(int round = 0; round < kernelPoint.Length; round++)
        {
            ReadOnlySpan<byte> z = kernelPoint[round].AsReadOnlySpan();
            ReadOnlySpan<byte> r = challenges.Slice(round * ScalarSize, ScalarSize);
            multiply(z, r, factor, curve);
            subtract(one, z, complementZ, curve);
            subtract(one, r, complementR, curve);
            multiply(complementZ, complementR, temp2, curve);
            add(factor, temp2, factor, curve);
            multiply(kernel, factor, kernel, curve);
        }

        //expected = h + λ·eq·inner.
        multiply(foldingChallenge, kernel, temp2, curve);
        multiply(temp2, temp1, temp1, curve);
        add(helperValue, temp1, destination, curve);
    }
}
