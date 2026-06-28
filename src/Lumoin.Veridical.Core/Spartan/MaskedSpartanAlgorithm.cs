using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Internal algorithmic helpers for the statistical-mask ZK construction
/// implemented by <c>MaskedSpartanProver</c> (SM.7b): the masked outer and
/// inner sumcheck drivers with the sum-of-univariates kernel mask
/// (<see cref="MonomialBasisMask"/>) blended closed-form into each round's
/// coefficients.
/// </summary>
/// <remarks>
/// <para>
/// The construction is the Libra sum-of-univariates mask (Xie et al,
/// CRYPTO 2019, §4.1; lineage Chiesa, Forbes, Spooner 2017, IACR ePrint
/// 2017/305) with the v3 filler-laundered weighted-opening binding of
/// <c>ZK-STATMASK-DESIGN.md</c>. The mask's univariates match the
/// masked round degree (3 for the outer sumcheck, 2 for the inner), so every
/// revealed round coefficient — including the top one a multilinear mask
/// left bare — is uniform given the mask's degrees of freedom.
/// </para>
/// <para>
/// <b>Variable-order convention.</b> The kernel binds variables high-first
/// (round <c>k = d … 1</c>, the BaseFold fold order), while Spartan's MLE
/// folds bind the LOW eval-table bit first. The drivers therefore relabel:
/// kernel variable <c>X_j</c> is Spartan variable <c>x_{d+1−j}</c>, so
/// Spartan round <c>i</c> (zero-based) binds kernel variable <c>d − i</c>,
/// and the kernel's terminal evaluation point is the REVERSED challenge
/// vector. The sum-of-univariates basis is invariant under the relabeling
/// (it permutes monomials within each degree block), so this is purely an
/// internal convention — the prover's weight building and the verifier's
/// must both reverse, which <c>BuildReversedPoint</c> centralises.
/// </para>
/// </remarks>
internal static class MaskedSpartanAlgorithm
{
    /// <summary>
    /// Result of the masked outer sumcheck phase: per-round blended
    /// messages, the challenge vector <c>r_x</c>, and the four base
    /// terminating evaluations <c>(Az(r_x), Bz(r_x), Cz(r_x), E(r_x))</c>.
    /// The mask's terminal value is not carried — the verifier derives it
    /// from the masked chain and the weighted opening binds it.
    /// </summary>
    internal sealed class OuterResult: IDisposable
    {
        public IReadOnlyList<SumcheckRound> Rounds { get; }
        public IReadOnlyList<Scalar> Challenges { get; }
        public Scalar TerminatingAz { get; }
        public Scalar TerminatingBz { get; }
        public Scalar TerminatingCz { get; }
        public Scalar TerminatingE { get; }

        internal OuterResult(
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

        public void Dispose()
        {
            foreach(SumcheckRound r in Rounds)
            {
                r.Dispose();
            }

            foreach(Scalar c in Challenges)
            {
                c.Dispose();
            }

            TerminatingAz.Dispose();
            TerminatingBz.Dispose();
            TerminatingCz.Dispose();
            TerminatingE.Dispose();
        }
    }


    /// <summary>
    /// Result of the masked inner sumcheck phase: per-round blended
    /// messages, the challenge vector <c>r_y</c>, and the two base
    /// terminating evaluations <c>(ABC(r_y), z(r_y))</c>.
    /// </summary>
    internal sealed class InnerResult: IDisposable
    {
        public IReadOnlyList<SumcheckRound> Rounds { get; }
        public IReadOnlyList<Scalar> Challenges { get; }
        public Scalar TerminatingAbc { get; }
        public Scalar TerminatingZ { get; }

        internal InnerResult(
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

        public void Dispose()
        {
            foreach(SumcheckRound r in Rounds)
            {
                r.Dispose();
            }

            foreach(Scalar c in Challenges)
            {
                c.Dispose();
            }

            TerminatingAbc.Dispose();
            TerminatingZ.Dispose();
        }
    }


    /// <summary>
    /// Runs the masked outer (degree-3) sumcheck phase. Inputs are
    /// the base <c>(Az, Bz, Cz)</c> MLEs, the <c>τ</c> challenge
    /// vector (binding the <c>eq(τ, ·)</c> factor), the degree-3
    /// sum-of-univariates kernel mask <c>g_outer</c>, and the blending
    /// scalar <c>ρ_outer</c>. The driver mirrors <see cref="OuterSumcheckProver"/>'s
    /// per-round structure but blends the mask's closed-form round
    /// contribution into each round's coefficients before absorbing
    /// onto the transcript.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of per-round handles transfers to the returned OuterResult.")]
    internal static OuterResult RunMaskedOuterSumcheck(
        MultilinearExtension az,
        MultilinearExtension bz,
        MultilinearExtension cz,
        MultilinearExtension e,
        ReadOnlySpan<byte> uBytes,
        ReadOnlySpan<Scalar> tau,
        MonomialBasisMask gOuter,
        Scalar rhoOuter,
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
        int numRounds = az.VariableCount;
        CurveParameterSet curve = az.Curve;

        MultilinearExtension azCurrent = MultilinearExtension.FromEvaluations(az.AsReadOnlySpan(), numRounds, curve, pool);
        MultilinearExtension bzCurrent = MultilinearExtension.FromEvaluations(bz.AsReadOnlySpan(), numRounds, curve, pool);
        MultilinearExtension czCurrent = MultilinearExtension.FromEvaluations(cz.AsReadOnlySpan(), numRounds, curve, pool);
        MultilinearExtension eCurrent = MultilinearExtension.FromEvaluations(e.AsReadOnlySpan(), numRounds, curve, pool);
        MultilinearExtension eqCurrent = SumcheckRoundComputation.BuildEqEvaluations(tau, subtract, multiply, curve, pool, batch);

        //The kernel's one-based challenge registry: entry j holds the challenge
        //that bound kernel variable X_j = Spartan variable x_{d+1−j}. Spartan
        //round i fills entry d − i; the registry references the challenges the
        //result list owns, so it needs no disposal of its own.
        var challengesForVariable = new Scalar[numRounds + 1];

        List<SumcheckRound> rounds = new(numRounds);
        List<Scalar> challenges = new(numRounds);

        try
        {
            for(int round = 0; round < numRounds; round++)
            {
                int remainingVariables = numRounds - round;

                //The relaxed base round polynomial. The kernel blend adds the
                //mask's closed-form shares into c₀/c₂/c₃ (the linear share is
                //chain-elided), so it carries over to the relaxed identity
                //exactly as to the standard one (CFS-2017 carryover).
                Polynomial basePoly = SumcheckRoundComputation.ComputeOuterRoundPolynomialRelaxed(
                    azCurrent.AsReadOnlySpan(),
                    bzCurrent.AsReadOnlySpan(),
                    czCurrent.AsReadOnlySpan(),
                    eCurrent.AsReadOnlySpan(),
                    eqCurrent.AsReadOnlySpan(),
                    uBytes,
                    remainingVariables,
                    add, subtract, multiply, curve, pool, batch);

                Polynomial blended;
                CompressedRoundPolynomial compressed;
                using(basePoly)
                {
                    blended = BlendMaskedRound(
                        basePoly,
                        gOuter,
                        boundVariable: numRounds - round,
                        challengesForVariable,
                        rhoOuter,
                        add, multiply, pool);
                }

                using(blended)
                {
                    compressed = blended.Compress(pool);
                }

                Scalar challenge;
                using(compressed)
                {
                    transcript.AbsorbCompressedRoundPolynomial(compressed, hash);
                    challenge = transcript.SqueezeScalar(
                        new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.SumcheckRoundChallenge),
                        squeeze, hash, reduce, curve, pool);

                    rounds.Add(SumcheckRound.Create(round, compressed, challenge, pool));
                }

                challenges.Add(challenge);
                challengesForVariable[numRounds - round] = challenge;

                CryptographicOperationCounters.Increment(CryptographicOperationKind.SumcheckRound, curve);

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

            Scalar terminatingAz = Scalar.FromCanonical(azCurrent.AsReadOnlySpan(), curve, pool);
            Scalar terminatingBz = Scalar.FromCanonical(bzCurrent.AsReadOnlySpan(), curve, pool);
            Scalar terminatingCz = Scalar.FromCanonical(czCurrent.AsReadOnlySpan(), curve, pool);
            Scalar terminatingE = Scalar.FromCanonical(eCurrent.AsReadOnlySpan(), curve, pool);

            return new OuterResult(rounds, challenges, terminatingAz, terminatingBz, terminatingCz, terminatingE);
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


    /// <summary>
    /// Runs the masked inner (degree-2) sumcheck phase. Inputs are
    /// the <c>ABC</c> slice MLE (already batched at <c>r_x</c>), the
    /// <c>z</c> assignment MLE, the degree-2 sum-of-univariates kernel
    /// mask <c>g_inner</c>, and the blending scalar <c>ρ_inner</c>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of per-round handles transfers to the returned InnerResult.")]
    internal static InnerResult RunMaskedInnerSumcheck(
        MultilinearExtension polyAbc,
        MultilinearExtension polyZ,
        MonomialBasisMask gInner,
        Scalar rhoInner,
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
        int numRounds = polyAbc.VariableCount;
        CurveParameterSet curve = polyAbc.Curve;

        MultilinearExtension abcCurrent = MultilinearExtension.FromEvaluations(polyAbc.AsReadOnlySpan(), numRounds, curve, pool);
        MultilinearExtension zCurrent = MultilinearExtension.FromEvaluations(polyZ.AsReadOnlySpan(), numRounds, curve, pool);

        var challengesForVariable = new Scalar[numRounds + 1];

        List<SumcheckRound> rounds = new(numRounds);
        List<Scalar> challenges = new(numRounds);

        try
        {
            for(int round = 0; round < numRounds; round++)
            {
                int remainingVariables = numRounds - round;

                Polynomial basePoly = SumcheckRoundComputation.ComputeInnerRoundPolynomial(
                    abcCurrent.AsReadOnlySpan(),
                    zCurrent.AsReadOnlySpan(),
                    remainingVariables,
                    add, subtract, multiply, curve, pool, batch);

                Polynomial blended;
                CompressedRoundPolynomial compressed;
                using(basePoly)
                {
                    blended = BlendMaskedRound(
                        basePoly,
                        gInner,
                        boundVariable: numRounds - round,
                        challengesForVariable,
                        rhoInner,
                        add, multiply, pool);
                }

                using(blended)
                {
                    compressed = blended.Compress(pool);
                }

                Scalar challenge;
                using(compressed)
                {
                    transcript.AbsorbCompressedRoundPolynomial(compressed, hash);
                    challenge = transcript.SqueezeScalar(
                        new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.SumcheckRoundChallenge),
                        squeeze, hash, reduce, curve, pool);

                    rounds.Add(SumcheckRound.Create(round, compressed, challenge, pool));
                }

                challenges.Add(challenge);
                challengesForVariable[numRounds - round] = challenge;

                CryptographicOperationCounters.Increment(CryptographicOperationKind.SumcheckRound, curve);

                MultilinearExtension abcNext = abcCurrent.Fold(challenge, mleFold, pool);
                MultilinearExtension zNext = zCurrent.Fold(challenge, mleFold, pool);

                abcCurrent.Dispose();
                zCurrent.Dispose();

                abcCurrent = abcNext;
                zCurrent = zNext;
            }

            Scalar terminatingAbc = Scalar.FromCanonical(abcCurrent.AsReadOnlySpan(), curve, pool);
            Scalar terminatingZ = Scalar.FromCanonical(zCurrent.AsReadOnlySpan(), curve, pool);

            return new InnerResult(rounds, challenges, terminatingAbc, terminatingZ);
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


    /// <summary>
    /// The kernel's terminal evaluation point: the Spartan challenge vector
    /// reversed into the kernel's variable order (kernel variable <c>X_j</c> is
    /// Spartan variable <c>x_{d+1−j}</c>). The returned array references the
    /// supplied scalars — it carries no ownership and needs no disposal of its
    /// own.
    /// </summary>
    internal static Scalar[] BuildReversedPoint(ReadOnlySpan<Scalar> challenges)
    {
        var reversed = new Scalar[challenges.Length];
        for(int i = 0; i < challenges.Length; i++)
        {
            reversed[i] = challenges[challenges.Length - 1 - i];
        }

        return reversed;
    }


    /// <summary>
    /// Builds the weighted opening's public weight vector
    /// <c>w⁺ = (basis monomials at the kernel point ‖ 1…1 on the filler)</c>
    /// over the mask vector's <c>2^ℓ₂</c> coordinates (design v3): the basis
    /// weights bind the mask's terminal evaluation, the all-ones filler
    /// weights add the precommitted <c>σ_F</c> to the claim and launder the
    /// opening's reveals. Shared between the prover and the verifier so the
    /// two sides derive byte-identical weights.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The rented buffer transfers ownership to the returned MLE.")]
    internal static MultilinearExtension BuildMaskWeights(
        MonomialBasis basis,
        Commitments.BaseFold.StatisticalMaskParameters shape,
        ReadOnlySpan<Scalar> kernelPoint,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int scalarSize = Scalar.SizeBytes;
        int coordinateCount = shape.CoefficientCount;
        using IMemoryOwner<byte> weightsOwner = pool.Rent(coordinateCount * scalarSize);
        Span<byte> weights = weightsOwner.Memory.Span[..(coordinateCount * scalarSize)];
        MonomialBasisMask.BuildWeightVector(basis, kernelPoint, weights, multiply, curve);

        //Field one on every filler coordinate.
        for(int i = shape.MaskCoefficientCount; i < coordinateCount; i++)
        {
            Span<byte> weight = weights.Slice(i * scalarSize, scalarSize);
            weight.Clear();
            weight[scalarSize - 1] = 0x01;
        }

        return MultilinearExtension.FromEvaluations(weights, shape.CoefficientVariableCount, curve, pool);
    }


    /// <summary>
    /// Builds a fresh <see cref="Polynomial"/> with the kernel mask's round
    /// contribution blended in place over the base round polynomial's
    /// coefficients, scaled by the verifier-chosen blending scalar
    /// <paramref name="rho"/>: the constant share into <c>c₀</c>, the
    /// quadratic into <c>c₂</c>, and — when the round format is cubic — the
    /// cubic share into <c>c₃</c>. The linear share lands in the chain-elided
    /// <c>c₁</c> the verifier reconstructs from the running claim, which
    /// already absorbs the <c>ρ·σ</c> blend.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The returned polynomial transfers ownership to the caller.")]
    private static Polynomial BlendMaskedRound(
        Polynomial basePolynomial,
        MonomialBasisMask mask,
        int boundVariable,
        ReadOnlySpan<Scalar> challengesForVariable,
        Scalar rho,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        BaseMemoryPool pool)
    {
        int scalarSize = Scalar.SizeBytes;
        int degree = basePolynomial.Degree;
        int bufferSize = (degree + 1) * scalarSize;
        CurveParameterSet curve = basePolynomial.Curve;

        IMemoryOwner<byte> outputOwner = pool.Rent(bufferSize);
        Span<byte> output = outputOwner.Memory.Span[..bufferSize];
        basePolynomial.AsReadOnlySpan().CopyTo(output);

        Span<byte> c0 = output[..scalarSize];
        Span<byte> c2 = output.Slice(2 * scalarSize, scalarSize);
        if(degree >= 3)
        {
            Span<byte> c3 = output.Slice(3 * scalarSize, scalarSize);
            mask.AddRoundBlend(boundVariable, challengesForVariable, rho.AsReadOnlySpan(), c0, c2, c3, add, multiply);
        }
        else
        {
            mask.AddRoundBlend(boundVariable, challengesForVariable, rho.AsReadOnlySpan(), c0, c2, add, multiply);
        }

        Tag tag = Tag.Create(AlgebraicRole.PolynomialCoefficients)
            .With(curve)
            .With(new PolynomialDegree(degree));

        return new Polynomial(outputOwner, degree, scalarSize, curve, tag);
    }
}
