using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Analysis.Simulation;

/// <summary>
/// The witness-free simulator of the full zero-knowledge masked Spartan proof
/// (the <c>ProveZkBaseFold</c>/<c>VerifyZkBaseFold</c> path) — the
/// <see cref="ZkBaseFoldOpeningSimulator"/> recipe lifted from one opening to
/// the whole proof. Given only the public statement (the R1CS instance with
/// its public inputs), it produces a proof that verifies under a programmed
/// Fiat-Shamir oracle without ever holding a satisfying witness.
/// </summary>
/// <remarks>
/// <para>
/// The new element over the opening simulator is that a uniformly random
/// fake witness does not satisfy the constraint system: the outer sumcheck's
/// actual sum is <c>E_τ = Σ_x eq(τ,x)·(Az∘Bz − Cz)(x) = g̃(τ) ≠ 0</c>, where
/// the public target is zero. The patch is the same single pre-ρ reveal: the
/// honest fake run's chain starts at <c>E_τ + ρ_outer·σ</c>, the verifier
/// starts at <c>ρ_outer·σ′</c>, so <c>σ′ = σ + E_τ·ρ_outer⁻¹</c> makes them
/// equal and the entire numeric chain — outer rounds, the claimed
/// <c>Az/Bz/Cz</c> evaluations, the inner sumcheck (whose initial claim is
/// derived from absorbed proof values, needing no second patch), the
/// terminal mask derivations, and every PCS opening — is byte-identical to
/// the honest fake run. <c>E_τ</c> is the multilinear extension of the
/// per-row constraint error evaluated at the recorded <c>τ</c>, computed
/// here from the public matrices, the public inputs, and the simulator's
/// own fake witness through the library's own MLE machinery (so the
/// row-indexing and challenge-order conventions are the protocol's, not
/// re-derived).
/// </para>
/// <para>
/// As before, the only thing the patch breaks is challenge derivation — σ is
/// absorbed before <c>ρ_outer</c> is squeezed — and that is exactly what the
/// sequence-keyed replay of <see cref="ProgrammableFiatShamirOracle"/>
/// repairs. Providers capture their squeeze at construction, so the caller
/// supplies <see cref="SqueezeBoundProviderFactory"/> seams for the hiding
/// witness/mask provider and the deterministic error provider; verification
/// must build its providers from the same factories around
/// <see cref="ProgrammableFiatShamirOracle.CreateReplaySqueeze"/>.
/// </para>
/// </remarks>
public static class ZkBaseFoldMaskedSpartanSimulator
{
    private const int ScalarSize = Scalar.SizeBytes;

    //SqueezeScalar squeezes this many wide bytes before reducing; recorded
    //challenge responses are recovered the same way.
    private const int SqueezeWideBytes = 64;


    /// <summary>
    /// Simulates a full zero-knowledge masked Spartan proof for
    /// <paramref name="instance"/> without a satisfying witness.
    /// </summary>
    /// <param name="instance">The public statement: the R1CS matrices and public inputs.</param>
    /// <param name="transcript">A fresh transcript initialised exactly as the real prover's.</param>
    /// <param name="providerFactory">Builds the hiding witness/mask provider around a given squeeze (the real protocol's full-ZK BaseFold factory).</param>
    /// <param name="errorProviderFactory">Builds the deterministic zero-error provider around a given squeeze.</param>
    /// <param name="hash">The Fiat-Shamir fixed-output hash backend.</param>
    /// <param name="squeeze">The real XOF backend; the simulator wraps it in a recording oracle.</param>
    /// <param name="reduce">Scalar-reduce backend.</param>
    /// <param name="add">Scalar-addition backend.</param>
    /// <param name="subtract">Scalar-subtraction backend.</param>
    /// <param name="multiply">Scalar-multiplication backend.</param>
    /// <param name="invert">Scalar-inversion backend.</param>
    /// <param name="scalarRandom">The randomness source for the fake witness, salts, and masks.</param>
    /// <param name="g1Add">G1 addition backend (the prover signature requires the bundle even on the BaseFold path).</param>
    /// <param name="g1ScalarMultiply">G1 scalar-multiplication backend.</param>
    /// <param name="g1Msm">G1 multi-scalar-multiplication backend.</param>
    /// <param name="mleEvaluate">Multilinear-extension evaluation backend.</param>
    /// <param name="mleFold">Multilinear-extension fold backend.</param>
    /// <param name="queryCount">The IOPP query repetition count the providers were built with (the proof's wire shape).</param>
    /// <param name="digestSizeBytes">The Merkle digest size the providers were built with.</param>
    /// <param name="extraVariableCount">The hiding lift the full-ZK provider was built with.</param>
    /// <param name="pool">The pool for scratch and result buffers.</param>
    /// <returns>
    /// The simulated proof and the oracle whose replay squeeze the verifier
    /// must be given (both for its providers, via the same factories, and for
    /// the verify call). The caller owns the proof's disposal.
    /// </returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the instance's row count is not a power of two.</exception>
    /// <exception cref="InvalidOperationException">When the recorded run is structurally unexpected (missing challenges, or a zero outer blend — probability <c>1/|F|</c>; rerun).</exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000", Justification = "The Spartan proving key takes ownership of the factory-built provider and the prover disposes the key; the returned proof transfers to the caller.")]
    public static (ZkBaseFoldMaskedSpartanProof Proof, ProgrammableFiatShamirOracle Oracle) Simulate(
        RawR1csInstance instance,
        FiatShamirTranscript transcript,
        SqueezeBoundProviderFactory providerFactory,
        SqueezeBoundProviderFactory errorProviderFactory,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarRandomDelegate scalarRandom,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1MultiScalarMultiplyDelegate g1Msm,
        MleEvaluateDelegate mleEvaluate,
        MleFoldDelegate mleFold,
        int queryCount,
        int digestSizeBytes,
        int extraVariableCount,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(instance);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(providerFactory);
        ArgumentNullException.ThrowIfNull(errorProviderFactory);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(scalarRandom);
        ArgumentNullException.ThrowIfNull(mleEvaluate);
        ArgumentNullException.ThrowIfNull(pool);

        int rowCount = instance.A.RowCount;
        if(rowCount < 2 || (rowCount & (rowCount - 1)) != 0)
        {
            throw new ArgumentException($"The instance's row count must be a power of two; received {rowCount}.", nameof(instance));
        }

        CurveParameterSet curve = instance.Curve;
        var oracle = new ProgrammableFiatShamirOracle();
        FiatShamirSqueezeDelegate recording = oracle.CreateRecordingSqueeze(squeeze);

        //The fake witness f*: uniformly random, filling the witness slots of
        //z = (1, publicInputs, witness) exactly.
        int columnCount = instance.A.ColumnCount;
        int witnessLength = columnCount - 1 - instance.PublicInputCount;
        Tag scalarTag = WellKnownAlgebraicTags.ScalarFor(curve);
        using IMemoryOwner<byte> fakeBytesOwner = pool.Rent(witnessLength * ScalarSize);
        Span<byte> fakeBytes = fakeBytesOwner.Memory.Span[..(witnessLength * ScalarSize)];
        for(int i = 0; i < witnessLength; i++)
        {
            _ = scalarRandom(fakeBytes.Slice(i * ScalarSize, ScalarSize), curve, scalarTag);
        }

        using RawR1csWitness fakeWitness = RawR1csWitness.FromCanonical(fakeBytes, curve, pool);

        //The honest run over the fake witness, every oracle response recorded.
        var provingKey = new SpartanProvingKey(providerFactory(recording));
        using var prover = new MaskedSpartanProver(provingKey);
        using PolynomialCommitmentProvider errorProvider = errorProviderFactory(recording);

        using ZkBaseFoldMaskedSpartanProof fakeProof = prover.ProveZkBaseFoldWithoutSatisfactionGuard(
            instance, fakeWitness, transcript,
            hash, recording, reduce, add, subtract, multiply, invert, scalarRandom,
            g1Add, g1ScalarMultiply, g1Msm, mleEvaluate, mleFold, errorProvider, pool);

        //σ′ = σ + E_τ·ρ_outer⁻¹ against the public zero target.
        using Scalar rhoOuter = RecoverScalarChallenge(
            oracle, WellKnownMaskedSpartanTranscriptLabels.OuterBlendingChallenge, expectExactlyOne: true, reduce, curve, pool);
        if(IsZero(rhoOuter.AsReadOnlySpan()))
        {
            throw new InvalidOperationException("The recorded outer blend challenge is zero (probability 1/|F|); rerun the simulation.");
        }

        int rowVariableCount = BitOperations.Log2((uint)rowCount);
        Scalar[] tau = RecoverChallengeVector(
            oracle, WellKnownSpartanTranscriptLabels.OuterTau, rowVariableCount, reduce, curve, pool);
        try
        {
            using Scalar errorAtTau = EvaluateConstraintErrorMle(instance, fakeBytes, tau, add, subtract, multiply, mleEvaluate, curve, pool);

            Span<byte> delta = stackalloc byte[ScalarSize];
            Span<byte> rhoInverse = stackalloc byte[ScalarSize];
            invert(rhoOuter.AsReadOnlySpan(), rhoInverse, curve);
            multiply(errorAtTau.AsReadOnlySpan(), rhoInverse, delta, curve);

            ZkBaseFoldMaskedSpartanProof simulated = PatchOuterMaskSum(
                fakeProof, delta, rowVariableCount, BitOperations.Log2((uint)columnCount), queryCount, digestSizeBytes, extraVariableCount, add, curve, pool);

            return (simulated, oracle);
        }
        finally
        {
            foreach(Scalar coordinate in tau)
            {
                coordinate.Dispose();
            }
        }
    }


    //E_τ = g̃(τ) for g(row) = (Az)·(Bz) − (Cz) over z = (1, io, fakeWitness):
    //the outer sumcheck's actual sum over the boolean hypercube equals the
    //MLE of the per-row error at τ, so the library's own evaluation delegate
    //carries the indexing conventions.
    private static Scalar EvaluateConstraintErrorMle(
        RawR1csInstance instance,
        ReadOnlySpan<byte> fakeWitnessBytes,
        Scalar[] tau,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        MleEvaluateDelegate mleEvaluate,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool)
    {
        int rowCount = instance.A.RowCount;
        int columnCount = instance.A.ColumnCount;

        //z = (1, publicInputs, fakeWitness).
        using IMemoryOwner<byte> zOwner = pool.Rent(columnCount * ScalarSize);
        Span<byte> z = zOwner.Memory.Span[..(columnCount * ScalarSize)];
        z.Clear();
        z[ScalarSize - 1] = 0x01;
        instance.GetPublicInputsBytes().CopyTo(z[ScalarSize..]);
        fakeWitnessBytes.CopyTo(z[((1 + instance.PublicInputCount) * ScalarSize)..]);

        using IMemoryOwner<byte> azOwner = pool.Rent(rowCount * ScalarSize);
        using IMemoryOwner<byte> bzOwner = pool.Rent(rowCount * ScalarSize);
        using IMemoryOwner<byte> czOwner = pool.Rent(rowCount * ScalarSize);
        Span<byte> az = azOwner.Memory.Span[..(rowCount * ScalarSize)];
        Span<byte> bz = bzOwner.Memory.Span[..(rowCount * ScalarSize)];
        Span<byte> cz = czOwner.Memory.Span[..(rowCount * ScalarSize)];
        az.Clear();
        bz.Clear();
        cz.Clear();

        Span<byte> term = stackalloc byte[ScalarSize];
        AccumulateMatrixVectorProduct(instance.A, z, az, term, add, multiply, curve);
        AccumulateMatrixVectorProduct(instance.B, z, bz, term, add, multiply, curve);
        AccumulateMatrixVectorProduct(instance.C, z, cz, term, add, multiply, curve);

        //g(row) = az·bz − cz, then E_τ = g̃(τ).
        using IMemoryOwner<byte> gOwner = pool.Rent(rowCount * ScalarSize);
        Span<byte> g = gOwner.Memory.Span[..(rowCount * ScalarSize)];
        for(int row = 0; row < rowCount; row++)
        {
            Span<byte> slot = g.Slice(row * ScalarSize, ScalarSize);
            multiply(az.Slice(row * ScalarSize, ScalarSize), bz.Slice(row * ScalarSize, ScalarSize), term, curve);
            subtract(term, cz.Slice(row * ScalarSize, ScalarSize), slot, curve);
        }

        using MultilinearExtension gMle = MultilinearExtension.FromEvaluations(g, BitOperations.Log2((uint)rowCount), curve, pool);

        return gMle.Evaluate(tau, mleEvaluate, pool);
    }


    private static void AccumulateMatrixVectorProduct(
        R1csMatrix matrix,
        ReadOnlySpan<byte> z,
        Span<byte> destination,
        Span<byte> term,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        for(int i = 0; i < matrix.NonzeroCount; i++)
        {
            (int row, int column) = matrix.GetTriplePosition(i);
            multiply(matrix.GetValueBytes(i), z.Slice(column * ScalarSize, ScalarSize), term, curve);
            Span<byte> slot = destination.Slice(row * ScalarSize, ScalarSize);
            add(slot, term, slot, curve);
        }
    }


    //σ_outer sits immediately after the three commitment roots in the flat
    //wire layout (witness, outer mask, inner mask — the pinned serialization
    //order); the patched buffer rehydrates through the public FromBytes, so
    //a layout drift surfaces as a shape error or a verification failure, not
    //silent corruption.
    private static ZkBaseFoldMaskedSpartanProof PatchOuterMaskSum(
        ZkBaseFoldMaskedSpartanProof fakeProof,
        ReadOnlySpan<byte> delta,
        int outerRoundCount,
        int innerRoundCount,
        int queryCount,
        int digestSizeBytes,
        int extraVariableCount,
        ScalarAddDelegate add,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool)
    {
        ReadOnlySpan<byte> fakeBytes = fakeProof.AsReadOnlySpan();
        int sigmaOffset = 3 * digestSizeBytes;

        using IMemoryOwner<byte> patchedOwner = pool.Rent(fakeBytes.Length);
        Span<byte> patched = patchedOwner.Memory.Span[..fakeBytes.Length];
        fakeBytes.CopyTo(patched);
        Span<byte> sigma = patched.Slice(sigmaOffset, ScalarSize);
        add(sigma, delta, sigma, curve);

        return ZkBaseFoldMaskedSpartanProof.FromBytes(
            patched, outerRoundCount, innerRoundCount, queryCount, digestSizeBytes, extraVariableCount, curve, pool);
    }


    //Recovers a recorded scalar challenge by its operation label (the
    //transcript embeds labels verbatim in challenge inputs), reduced exactly
    //as SqueezeScalar reduces the wide squeeze.
    private static Scalar RecoverScalarChallenge(
        ProgrammableFiatShamirOracle oracle,
        string label,
        bool expectExactlyOne,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool)
    {
        byte[] labelBytes = new FiatShamirOperationLabel(label).Bytes;
        int found = -1;
        for(int i = 0; i < oracle.RecordedCount; i++)
        {
            if(oracle.GetRecordedInput(i).IndexOf(labelBytes) >= 0)
            {
                if(found >= 0 && expectExactlyOne)
                {
                    throw new InvalidOperationException($"The recorded run contains more than one '{label}' squeeze.");
                }

                found = i;
            }
        }

        if(found < 0)
        {
            throw new InvalidOperationException($"The recorded run contains no '{label}' squeeze.");
        }

        return ReduceRecorded(oracle, found, reduce, curve, pool);
    }


    private static Scalar[] RecoverChallengeVector(
        ProgrammableFiatShamirOracle oracle,
        string label,
        int count,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool)
    {
        byte[] labelBytes = new FiatShamirOperationLabel(label).Bytes;
        var challenges = new Scalar[count];
        int next = 0;
        try
        {
            for(int i = 0; i < oracle.RecordedCount && next < count; i++)
            {
                if(oracle.GetRecordedInput(i).IndexOf(labelBytes) >= 0)
                {
                    challenges[next++] = ReduceRecorded(oracle, i, reduce, curve, pool);
                }
            }

            if(next != count)
            {
                throw new InvalidOperationException($"The recorded run contains {next} '{label}' squeezes; expected {count}.");
            }

            return challenges;
        }
        catch
        {
            for(int i = 0; i < next; i++)
            {
                challenges[i].Dispose();
            }

            throw;
        }
    }


    private static Scalar ReduceRecorded(ProgrammableFiatShamirOracle oracle, int index, ScalarReduceDelegate reduce, CurveParameterSet curve, SensitiveMemoryPool<byte> pool)
    {
        ReadOnlySpan<byte> wide = oracle.GetRecordedOutput(index);
        if(wide.Length != SqueezeWideBytes)
        {
            throw new InvalidOperationException($"The recorded squeeze {index} carries {wide.Length} bytes; expected {SqueezeWideBytes}.");
        }

        return Scalar.FromBytesReduced(wide, reduce, curve, pool);
    }


    private static bool IsZero(ReadOnlySpan<byte> scalar)
    {
        for(int i = 0; i < scalar.Length; i++)
        {
            if(scalar[i] != 0)
            {
                return false;
            }
        }

        return true;
    }
}
