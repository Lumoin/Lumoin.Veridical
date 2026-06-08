using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Drives the inner (degree-2) sumcheck phase of Spartan: composes the
/// pure round-polynomial computation from
/// <see cref="SumcheckRoundComputation"/> with Fiat-Shamir transcript
/// absorbs and squeezes. The round-polynomial computation is not
/// inlined here; keeping the two responsibilities separated lets each
/// be reasoned about and tested independently.
/// </summary>
/// <remarks>
/// The driver runs <c>log_2(columns)</c> rounds against the batched
/// matrix MLE <c>ABC = A + r·B + r²·C</c> at <c>r_x</c> (a length-cols
/// vector) and the assignment MLE <c>z</c>. Per round: compute
/// <c>g_i</c> from the current folded <c>(ABC, z)</c>, compress, absorb
/// under <see cref="WellKnownSpartanTranscriptLabels.SumcheckRoundPolynomial"/>,
/// squeeze the next challenge under
/// <see cref="WellKnownSpartanTranscriptLabels.SumcheckRoundChallenge"/>,
/// and fold both MLEs against the squeeze.
/// </remarks>
internal static class InnerSumcheckProver
{
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of per-round challenge scalars transfers to the returned InnerSumcheckProverResult, which owns their disposal. Exceptional paths are handled by the try/catch wrapping the loop.")]
    internal static InnerSumcheckProverResult Run(
        MultilinearExtension polyAbc,
        MultilinearExtension polyZ,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        MleFoldDelegate mleFold,
        SensitiveMemoryPool<byte> pool,
        ScalarArithmeticBackend? batch = null)
    {
        ArgumentNullException.ThrowIfNull(polyAbc);
        ArgumentNullException.ThrowIfNull(polyZ);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(mleFold);
        ArgumentNullException.ThrowIfNull(pool);

        if(polyAbc.VariableCount != polyZ.VariableCount)
        {
            throw new ArgumentException(
                $"Inner sumcheck inputs must share variable count; received ABC={polyAbc.VariableCount}, z={polyZ.VariableCount}.");
        }

        int numRounds = polyAbc.VariableCount;
        CurveParameterSet curve = polyAbc.Curve;

        //Copy the input MLEs into pool-rented working buffers so per-round
        //fold-and-dispose never touches the caller's objects.
        MultilinearExtension abcCurrent = MultilinearExtension.FromEvaluations(
            polyAbc.AsReadOnlySpan(), polyAbc.VariableCount, curve, pool);
        MultilinearExtension zCurrent = MultilinearExtension.FromEvaluations(
            polyZ.AsReadOnlySpan(), polyZ.VariableCount, curve, pool);

        List<SumcheckRound> rounds = new(numRounds);
        List<Scalar> challenges = new(numRounds);

        try
        {
            for(int round = 0; round < numRounds; round++)
            {
                int remainingVariables = numRounds - round;

                Polynomial roundPoly = SumcheckRoundComputation.ComputeInnerRoundPolynomial(
                    abcCurrent.AsReadOnlySpan(),
                    zCurrent.AsReadOnlySpan(),
                    remainingVariables,
                    add,
                    subtract,
                    multiply,
                    curve,
                    pool,
                    batch);

                CompressedRoundPolynomial compressed;
                using(roundPoly)
                {
                    compressed = roundPoly.Compress(pool);
                }

                Scalar challenge;
                using(compressed)
                {
                    transcript.AbsorbCompressedRoundPolynomial(compressed, hash);
                    challenge = transcript.SqueezeScalar(
                        new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.SumcheckRoundChallenge),
                        squeeze,
                        hash,
                        reduce,
                        curve,
                        pool);

                    rounds.Add(SumcheckRound.Create(round, compressed, challenge, pool));
                }

                challenges.Add(challenge);

                CryptographicOperationCounters.Increment(CryptographicOperationKind.SumcheckRound, curve);

                MultilinearExtension abcNext = abcCurrent.Fold(challenge, mleFold, pool);
                MultilinearExtension zNext = zCurrent.Fold(challenge, mleFold, pool);

                abcCurrent.Dispose();
                zCurrent.Dispose();

                abcCurrent = abcNext;
                zCurrent = zNext;
            }

            //After numRounds rounds each MLE collapses to a zero-variable MLE
            //holding the single terminating scalar. Surface both as proper
            //leaf-typed handles so the caller can use them in any follow-on
            //identity check.
            Scalar terminatingAbc = Scalar.FromCanonical(abcCurrent.AsReadOnlySpan(), curve, pool);
            Scalar terminatingZ = Scalar.FromCanonical(zCurrent.AsReadOnlySpan(), curve, pool);

            return new InnerSumcheckProverResult(rounds, challenges, terminatingAbc, terminatingZ);
        }
        catch
        {
            foreach(SumcheckRound r in rounds)
            {
                r.Dispose();
            }
            foreach(Scalar c in challenges)
            {
                c.Dispose();
            }
            throw;
        }
        finally
        {
            abcCurrent.Dispose();
            zCurrent.Dispose();
        }
    }
}


/// <summary>
/// The inner sumcheck phase's output: per-round messages, the challenge
/// vector <c>r_y</c>, and the two terminating evaluations
/// <c>(ABC(r_y), z(r_y))</c>.
/// </summary>
internal sealed class InnerSumcheckProverResult: IDisposable
{
    /// <summary>The per-round messages, in round order.</summary>
    public IReadOnlyList<SumcheckRound> Rounds { get; }

    /// <summary>The challenge vector <c>r_y</c>, length equal to <see cref="Rounds"/>.</summary>
    public IReadOnlyList<Scalar> Challenges { get; }

    /// <summary>The terminating <c>ABC(r_y)</c> value.</summary>
    public Scalar TerminatingAbc { get; }

    /// <summary>The terminating <c>z(r_y)</c> value.</summary>
    public Scalar TerminatingZ { get; }


    internal InnerSumcheckProverResult(
        IReadOnlyList<SumcheckRound> rounds,
        IReadOnlyList<Scalar> challenges,
        Scalar terminatingAbc,
        Scalar terminatingZ)
    {
        Rounds = rounds;
        Challenges = challenges;
        TerminatingAbc = terminatingAbc;
        TerminatingZ = terminatingZ;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        foreach(SumcheckRound round in Rounds)
        {
            round.Dispose();
        }
        foreach(Scalar challenge in Challenges)
        {
            challenge.Dispose();
        }
        TerminatingAbc.Dispose();
        TerminatingZ.Dispose();
    }
}