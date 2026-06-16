using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Drives the outer (degree-3) sumcheck phase of Spartan: composes the
/// pure round-polynomial computation from
/// <see cref="SumcheckRoundComputation"/> with Fiat-Shamir transcript
/// absorbs and squeezes. The round-polynomial computation is not
/// inlined here; keeping the two responsibilities separated lets each
/// be reasoned about and tested independently.
/// </summary>
/// <remarks>
/// The driver runs <c>log_2(rows)</c> rounds proving the <em>relaxed</em>
/// outer identity <c>eq(τ, x) · (Az·Bz − u·Cz − E)</c>. Per round:
/// compute <c>g_i</c> from the current folded <c>(Az, Bz, Cz, E, eq)</c>
/// via <see cref="SumcheckRoundComputation.ComputeOuterRoundPolynomialRelaxed"/>,
/// compress, absorb onto the transcript under
/// <see cref="WellKnownSpartanTranscriptLabels.SumcheckRoundPolynomial"/>,
/// squeeze the next challenge under
/// <see cref="WellKnownSpartanTranscriptLabels.SumcheckRoundChallenge"/>,
/// and fold all five MLEs against the squeeze. Standard R1CS is the
/// special case <c>u = 1</c>, <c>E ≡ 0</c>: the error MLE collapses to
/// the zero terminating value and the round polynomials match the
/// pre-relaxed computation byte-for-byte.
/// </remarks>
internal static class OuterSumcheckProver
{
    /// <summary>
    /// Runs the outer sumcheck and returns the round messages, the
    /// challenge vector <c>r_x</c>, the terminating evaluations
    /// <c>(Az(r_x), Bz(r_x), Cz(r_x))</c>, and the error-MLE evaluation
    /// <c>E(r_x)</c>. The terminating <c>Az/Bz/Cz</c> stay the pure
    /// matrix-product evaluations; <c>u</c> and <c>E</c> enter only the
    /// per-round polynomial (and the verifier's terminating check), not
    /// <c>Cz</c> itself, so the inner sumcheck still proves pure matrix
    /// products.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of per-round challenge scalars and the terminating Az/Bz/Cz/E scalars transfers to the returned OuterSumcheckProverResult, which owns their disposal. Exceptional paths are handled by the try/catch wrapping the loop.")]
    internal static OuterSumcheckProverResult Run(
        MultilinearExtension az,
        MultilinearExtension bz,
        MultilinearExtension cz,
        MultilinearExtension e,
        ReadOnlySpan<byte> uBytes,
        ReadOnlySpan<Scalar> tau,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        MleFoldDelegate mleFold,
        BaseMemoryPool pool,
        ScalarArithmeticBackend? batch = null)
    {
        ArgumentNullException.ThrowIfNull(az);
        ArgumentNullException.ThrowIfNull(bz);
        ArgumentNullException.ThrowIfNull(cz);
        ArgumentNullException.ThrowIfNull(e);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(mleFold);
        ArgumentNullException.ThrowIfNull(pool);

        if(az.VariableCount != bz.VariableCount || bz.VariableCount != cz.VariableCount || cz.VariableCount != e.VariableCount)
        {
            throw new ArgumentException(
                $"Outer sumcheck inputs must share variable count; received Az={az.VariableCount}, Bz={bz.VariableCount}, Cz={cz.VariableCount}, E={e.VariableCount}.");
        }

        if(tau.Length != az.VariableCount)
        {
            throw new ArgumentException(
                $"τ length {tau.Length} does not match Az variable count {az.VariableCount}.",
                nameof(tau));
        }

        int scalarSize = Scalar.SizeBytes;
        if(uBytes.Length != scalarSize)
        {
            throw new ArgumentException(
                $"u must be a single canonical scalar of {scalarSize} bytes; received {uBytes.Length}.",
                nameof(uBytes));
        }

        int numRounds = az.VariableCount;
        CurveParameterSet curve = az.Curve;

        //Working state: copy the input MLEs into pool-rented buffers we own,
        //so the per-round fold-and-dispose dance never touches the caller's
        //objects. Also build eq(τ, ·) once.
        MultilinearExtension azCurrent = MultilinearExtension.FromEvaluations(
            az.AsReadOnlySpan(), az.VariableCount, curve, pool);
        MultilinearExtension bzCurrent = MultilinearExtension.FromEvaluations(
            bz.AsReadOnlySpan(), bz.VariableCount, curve, pool);
        MultilinearExtension czCurrent = MultilinearExtension.FromEvaluations(
            cz.AsReadOnlySpan(), cz.VariableCount, curve, pool);
        MultilinearExtension eCurrent = MultilinearExtension.FromEvaluations(
            e.AsReadOnlySpan(), e.VariableCount, curve, pool);
        MultilinearExtension eqCurrent = SumcheckRoundComputation.BuildEqEvaluations(
            tau, subtract, multiply, curve, pool, batch);

        List<SumcheckRound> rounds = new(numRounds);
        List<Scalar> challenges = new(numRounds);

        try
        {
            for(int round = 0; round < numRounds; round++)
            {
                int remainingVariables = numRounds - round;

                Polynomial roundPoly = SumcheckRoundComputation.ComputeOuterRoundPolynomialRelaxed(
                    azCurrent.AsReadOnlySpan(),
                    bzCurrent.AsReadOnlySpan(),
                    czCurrent.AsReadOnlySpan(),
                    eCurrent.AsReadOnlySpan(),
                    eqCurrent.AsReadOnlySpan(),
                    uBytes,
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

                //Fold each working MLE by the round's challenge. The folded
                //result is a freshly-allocated MLE; the previous working MLE
                //is disposed and replaced.
                MultilinearExtension azNext = azCurrent.Fold(challenge, mleFold, pool);
                MultilinearExtension bzNext = bzCurrent.Fold(challenge, mleFold, pool);
                MultilinearExtension czNext = czCurrent.Fold(challenge, mleFold, pool);
                MultilinearExtension eNext = eCurrent.Fold(challenge, mleFold, pool);
                MultilinearExtension eqNext = eqCurrent.Fold(challenge, mleFold, pool);

                azCurrent.Dispose();
                bzCurrent.Dispose();
                czCurrent.Dispose();
                eCurrent.Dispose();
                eqCurrent.Dispose();

                azCurrent = azNext;
                bzCurrent = bzNext;
                czCurrent = czNext;
                eCurrent = eNext;
                eqCurrent = eqNext;
            }

            //After numRounds rounds each MLE collapses to a zero-variable MLE
            //holding the single terminating scalar. Materialise these as
            //Scalar leaf instances for the result and dispose
            //the carrier MLEs. E(r_x) is the error-MLE evaluation at the
            //outer challenge point; the prover proves it via a Hyrax opening
            //of the instance's error commitment at r_x.
            Scalar terminatingAz = Scalar.FromCanonical(azCurrent.AsReadOnlySpan(), curve, pool);
            Scalar terminatingBz = Scalar.FromCanonical(bzCurrent.AsReadOnlySpan(), curve, pool);
            Scalar terminatingCz = Scalar.FromCanonical(czCurrent.AsReadOnlySpan(), curve, pool);
            Scalar terminatingE = Scalar.FromCanonical(eCurrent.AsReadOnlySpan(), curve, pool);

            return new OuterSumcheckProverResult(rounds, challenges, terminatingAz, terminatingBz, terminatingCz, terminatingE);
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
            azCurrent.Dispose();
            bzCurrent.Dispose();
            czCurrent.Dispose();
            eCurrent.Dispose();
            eqCurrent.Dispose();
        }
    }
}


/// <summary>
/// The outer sumcheck phase's output: per-round messages (each
/// bundling the compressed round polynomial with the verifier's
/// challenge), the challenge vector <c>r_x</c> as a list, the three
/// terminating evaluations <c>(Az(r_x), Bz(r_x), Cz(r_x))</c>, and the
/// error-MLE evaluation <c>E(r_x)</c>.
/// </summary>
internal sealed class OuterSumcheckProverResult: IDisposable
{
    /// <summary>The per-round messages, in round order.</summary>
    public IReadOnlyList<SumcheckRound> Rounds { get; }

    /// <summary>The challenge vector <c>r_x</c>, length equal to <see cref="Rounds"/>.</summary>
    public IReadOnlyList<Scalar> Challenges { get; }

    /// <summary>The terminating evaluation <c>Az(r_x)</c>.</summary>
    public Scalar TerminatingAz { get; }

    /// <summary>The terminating evaluation <c>Bz(r_x)</c>.</summary>
    public Scalar TerminatingBz { get; }

    /// <summary>The terminating evaluation <c>Cz(r_x)</c>.</summary>
    public Scalar TerminatingCz { get; }

    /// <summary>The error-MLE terminating evaluation <c>E(r_x)</c>.</summary>
    public Scalar TerminatingE { get; }


    internal OuterSumcheckProverResult(
        IReadOnlyList<SumcheckRound> rounds,
        IReadOnlyList<Scalar> challenges,
        Scalar terminatingAz,
        Scalar terminatingBz,
        Scalar terminatingCz,
        Scalar terminatingE)
    {
        Rounds = rounds;
        Challenges = challenges;
        TerminatingAz = terminatingAz;
        TerminatingBz = terminatingBz;
        TerminatingCz = terminatingCz;
        TerminatingE = terminatingE;
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
        TerminatingAz.Dispose();
        TerminatingBz.Dispose();
        TerminatingCz.Dispose();
        TerminatingE.Dispose();
    }
}