using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The byte-identity gate for the Fp256 batched <c>bind_quad</c> path: the
/// constraint builder's per-term four-way chained Montgomery product
/// <c>(v == 0 ? beta : v)·eqg[g]·eqh0[h0]·eqh1[h1]</c>, summed over a layer's terms, routed through the
/// lane-parallel AVX2 batch multiply (<see cref="P256BaseFieldMontgomeryBatchBackendAvx2.GetBatchMultiplyMontgomery"/>)
/// must produce a byte-for-byte identical <c>bind_quad</c> field element to the scalar three-multiply-per-term
/// chain (<c>ReduceRange</c>). <c>bind_quad</c> feeds <c>eqq = eqv·bind_quad</c>, which becomes a constraint
/// coefficient in the Ligero <c>A·w = b</c> system and thence the emitted proof bytes, so any divergence here
/// would break the wire-format conformance the end-to-end gates pin (crown / real-sig / prove-driver). This
/// gate isolates the change from those multi-minute [Slow] gates by driving <see cref="LongfellowZkConstraintBuilder.BindQuad"/>
/// directly both ways over a synthetic layer and asserting equality, the <see cref="LongfellowEqFillEqBatchTests"/>
/// pattern.
/// </summary>
/// <remarks>
/// <para>
/// The inputs are derived from a deterministic SHA-256 keystream keyed by the shape's seed (no
/// <see cref="System.Random"/>, which CA5394 forbids), so a failing shape reproduces; every scalar is a genuine
/// Montgomery residue (a reduced hash lifted through <see cref="P256BaseFieldMontgomeryBackend.ToMontgomery"/>),
/// matching the working-domain values the live sig path carries. The batch multiply is itself gated byte-identical
/// to the scalar single-CIOS <see cref="P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery"/> by
/// <see cref="P256BaseFieldMontgomeryBatchBackendAgreementTests"/>; this gate pins that <c>BindQuad</c> consumes
/// it (gather + three batched passes + field-add accumulate) without disturbing the result.
/// </para>
/// <para>
/// The shapes cover the sequential reduction regime (term count below the parallel threshold), the parallel
/// partition regime (where partials combine in partition-index order), single-chunk and multi-chunk-per-partition
/// spans (the gather chunk is 1024 terms), even/odd term counts, small vs larger eq tables, and the all-zero
/// (every term selects <c>beta</c>) and all-non-zero coefficient extremes. Gated on AVX2 (the live batch backend).
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowBindQuadFp256BatchTests
{
    /// <summary>The canonical scalar width in bytes.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>Mirrors <see cref="LongfellowZkConstraintBuilder.BindQuad"/>'s <c>MaxBindings</c>: <c>BindQuad</c> slices <c>handChallenges</c> into two hands at this offset and reads up to this many g/hand scalars, so the input buffers must be sized to it.</summary>
    private const int MaxBindings = 40;

    /// <summary>The keystream label for the layer's <c>g0</c> gate-index scalars.</summary>
    private const int GateZeroLabel = 0;

    /// <summary>The keystream label for the layer's <c>g1</c> gate-index scalars.</summary>
    private const int GateOneLabel = 1;

    /// <summary>The keystream label for the hand-challenge scalars.</summary>
    private const int HandLabel = 2;

    /// <summary>The keystream label for the alpha blending scalar.</summary>
    private const int AlphaLabel = 3;

    /// <summary>The keystream label for the beta blending scalar.</summary>
    private const int BetaLabel = 4;

    /// <summary>The keystream label for a term's coefficient scalar.</summary>
    private const int CoefficientLabel = 5;

    /// <summary>The keystream label for a term's gate index.</summary>
    private const int GateIndexLabel = 6;

    /// <summary>The keystream label for a term's left-hand index.</summary>
    private const int LeftIndexLabel = 7;

    /// <summary>The keystream label for a term's right-hand index.</summary>
    private const int RightIndexLabel = 8;

    /// <summary>The keystream label for a term's zero/non-zero coefficient decision.</summary>
    private const int ZeroDecisionLabel = 9;

    /// <summary>The zero-decision granularity: <c>zeroFraction</c> is taken in thousandths, so 0.10 selects about 10% of terms.</summary>
    private const int ZeroResolution = 1000;

    /// <summary>The curve parameter set passed to every delegate call in this test.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.None;

    /// <summary>The Fp256 Montgomery-domain addition delegate.</summary>
    private static ScalarAddDelegate Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();

    /// <summary>The Fp256 Montgomery-domain subtraction delegate.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();

    /// <summary>The Fp256 Montgomery-domain multiplication delegate.</summary>
    private static ScalarMultiplyDelegate MultiplyMontgomery { get; } = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();

    /// <summary>The P-256 base-field scalar reduction delegate.</summary>
    private static ScalarReduceDelegate Reduce { get; } = P256BaseFieldReference.GetReduce();


    /// <summary>Skips this test class's methods when the host CPU lacks AVX2, since the batch path under test requires it.</summary>
    [TestInitialize]
    public void RequireAvx2() => InstructionSetRequirements.RequireAvx2();


    /// <summary>Verifies that the AVX2 batched <c>bind_quad</c> path produces byte-identical results to the scalar three-multiply-per-term chain, across a range of shapes and zero-coefficient fractions.</summary>
    [TestMethod]
    public void Fp256BatchBindQuadIsByteIdenticalToTheScalarBindQuad()
    {
        ScalarBatchMultiplyDelegate batch = P256BaseFieldMontgomeryBatchBackendAvx2.GetBatchMultiplyMontgomery();

        //(logv, logw, termCount): nv = 2^logv and nw = 2^logw bound the keystreamed gate / hand indices. The
        //counts cross the parallel threshold (4096) and the gather chunk (1024) in both directions, with
        //even/odd tails.
        (int logv, int logw, int termCount)[] shapes =
        {
            (2, 2, 1), (2, 2, 2), (3, 2, 3), (4, 3, 5), (6, 4, 100), (8, 6, 1000),
            (8, 6, 4095), (8, 6, 4096), (6, 5, 5000), (10, 6, 16384), (4, 4, 8191),
        };

        int seed = 0x5EED5EED;
        foreach((int logv, int logw, int termCount) in shapes)
        {
            AssertByteIdentical(batch, logv, logw, termCount, zeroFraction: 0.10, seed++, $"mixed zeros, logv={logv} logw={logw} count={termCount}");
        }

        //The coefficient extremes at both the sequential and parallel regimes.
        AssertByteIdentical(batch, 6, 4, 1000, zeroFraction: 1.0, seed++, "all-zero coefficients, sequential");
        AssertByteIdentical(batch, 8, 6, 5000, zeroFraction: 1.0, seed++, "all-zero coefficients, parallel");
        AssertByteIdentical(batch, 6, 4, 1000, zeroFraction: 0.0, seed++, "all-non-zero coefficients, sequential");
        AssertByteIdentical(batch, 8, 6, 5000, zeroFraction: 0.0, seed++, "all-non-zero coefficients, parallel");
    }


    /// <summary>Builds a synthetic layer of deterministic terms and asserts that <see cref="LongfellowZkConstraintBuilder.BindQuad"/> produces the same result with and without the batched multiply delegate.</summary>
    /// <param name="batch">The batched Fp256 Montgomery multiply delegate under test.</param>
    /// <param name="logv">The layer's gate-index bit width.</param>
    /// <param name="logw">The layer's hand-index bit width.</param>
    /// <param name="termCount">The number of quad terms in the synthetic layer.</param>
    /// <param name="zeroFraction">The fraction of terms (in [0, 1]) whose coefficient is forced to zero.</param>
    /// <param name="seed">The deterministic keystream seed.</param>
    /// <param name="because">A human-readable label for the assertion failure message.</param>
    private static void AssertByteIdentical(ScalarBatchMultiplyDelegate batch, int logv, int logw, int termCount, double zeroFraction, int seed, string because)
    {
        int nv = 1 << logv;
        int nw = 1 << logw;

        //The g-points, hand challenges, alpha and beta, all genuine Montgomery residues; BindQuad fills the eq
        //tables from them with the scalar FillEq/RawEq2 (no GF broadcast on the Fp256 path) in both calls.
        byte[] g0 = MontgomeryScalars(seed, GateZeroLabel, MaxBindings);
        byte[] g1 = MontgomeryScalars(seed, GateOneLabel, MaxBindings);
        byte[] handChallenges = MontgomeryScalars(seed, HandLabel, 2 * MaxBindings);
        byte[] alpha = MontgomeryScalars(seed, AlphaLabel, 1);
        byte[] beta = MontgomeryScalars(seed, BetaLabel, 1);

        Span<byte> canonicalOne = stackalloc byte[ScalarSize];
        canonicalOne.Clear();
        canonicalOne[ScalarSize - 1] = 1;
        Span<byte> one = stackalloc byte[ScalarSize];
        P256BaseFieldMontgomeryBackend.ToMontgomery(canonicalOne, one);

        int zeroThreshold = (int)(zeroFraction * ZeroResolution);
        var terms = new LongfellowSumcheckQuadTerm[termCount];
        for(int k = 0; k < termCount; k++)
        {
            bool isZero = DeriveInt(seed, ZeroDecisionLabel, k, ZeroResolution) < zeroThreshold;
            byte[] coefficient = new byte[ScalarSize];
            if(!isZero)
            {
                DeriveMontgomery(seed, CoefficientLabel, k, coefficient);

                //A reduced hash could in principle be all-zero; force a non-zero coefficient so the term is
                //genuinely non-zero (the circuit's distinct constants are non-zero) and does NOT trip the
                //assert-zero beta path that the all-zero shape covers separately.
                if(coefficient.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                {
                    coefficient[ScalarSize - 1] = 1;
                }
            }

            int gate = DeriveInt(seed, GateIndexLabel, k, nv);
            int left = DeriveInt(seed, LeftIndexLabel, k, nw);
            int right = DeriveInt(seed, RightIndexLabel, k, nw);
            terms[k] = new LongfellowSumcheckQuadTerm(gate, left, right, coefficient);
        }

        var layer = new LongfellowSumcheckLayer(nw, logw, termCount, terms);

        Span<byte> scalarResult = stackalloc byte[ScalarSize];
        Span<byte> batchResult = stackalloc byte[ScalarSize];

        //Scalar path: fp256BatchMultiply null -> the ReduceRange three-multiply chain.
        LongfellowZkConstraintBuilder.BindQuad(
            layer, logv, g0, g1, alpha, beta, logw, handChallenges, Add, Subtract, MultiplyMontgomery, Curve, one,
            BaseMemoryPool.Shared, scalarResult, fp256BatchMultiply: null);

        //Batch path: fp256BatchMultiply supplied -> the gather + three batched passes + field-add accumulate.
        LongfellowZkConstraintBuilder.BindQuad(
            layer, logv, g0, g1, alpha, beta, logw, handChallenges, Add, Subtract, MultiplyMontgomery, Curve, one,
            BaseMemoryPool.Shared, batchResult, fp256BatchMultiply: batch);

        Assert.IsTrue(scalarResult.SequenceEqual(batchResult), $"The Fp256 batch bind_quad must equal the scalar bind_quad ({because}).");
    }


    /// <summary>Builds a row of <paramref name="count"/> canonical Montgomery residues derived from the <paramref name="seed"/>/<paramref name="label"/> keystream, one per index.</summary>
    /// <param name="seed">The deterministic keystream seed.</param>
    /// <param name="label">The keystream label distinguishing this row from other draws.</param>
    /// <param name="count">The number of scalars to derive.</param>
    /// <returns>The concatenated canonical Montgomery-domain scalars.</returns>
    private static byte[] MontgomeryScalars(int seed, int label, int count)
    {
        byte[] array = new byte[count * ScalarSize];
        for(int i = 0; i < count; i++)
        {
            DeriveMontgomery(seed, label, i, array.AsSpan(i * ScalarSize, ScalarSize));
        }

        return array;
    }


    /// <summary>Derives a genuine Montgomery residue for the <paramref name="seed"/>/<paramref name="label"/>/<paramref name="index"/> coordinate: SHA-256 of the three integers, reduced mod <c>p</c> and lifted into the Montgomery domain.</summary>
    /// <param name="seed">The deterministic keystream seed.</param>
    /// <param name="label">The keystream label.</param>
    /// <param name="index">The draw index within the label's stream.</param>
    /// <param name="destination">Receives the canonical Montgomery-domain scalar.</param>
    private static void DeriveMontgomery(int seed, int label, int index, Span<byte> destination)
    {
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        DeriveHash(seed, label, index, hash);

        Span<byte> canonical = stackalloc byte[ScalarSize];
        Reduce(hash, canonical, Curve);
        P256BaseFieldMontgomeryBackend.ToMontgomery(canonical, destination);
    }


    /// <summary>Derives a uniform-enough integer in <c>[0, exclusiveMax)</c> for the <paramref name="seed"/>/<paramref name="label"/>/<paramref name="index"/> coordinate; the modulo bias is immaterial to a byte-identity comparison, which holds for any in-range indices.</summary>
    /// <param name="seed">The deterministic keystream seed.</param>
    /// <param name="label">The keystream label.</param>
    /// <param name="index">The draw index within the label's stream.</param>
    /// <param name="exclusiveMax">The exclusive upper bound.</param>
    /// <returns>The derived integer.</returns>
    private static int DeriveInt(int seed, int label, int index, int exclusiveMax)
    {
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        DeriveHash(seed, label, index, hash);

        return (int)(BitConverter.ToUInt32(hash) % (uint)exclusiveMax);
    }


    /// <summary>Computes SHA-256 of the little-endian <paramref name="seed"/>/<paramref name="label"/>/<paramref name="index"/> triple: the deterministic keystream block every draw in this file derives from.</summary>
    /// <param name="seed">The deterministic keystream seed.</param>
    /// <param name="label">The keystream label.</param>
    /// <param name="index">The draw index within the label's stream.</param>
    /// <param name="destination">Receives the 32-byte digest.</param>
    private static void DeriveHash(int seed, int label, int index, Span<byte> destination)
    {
        Span<byte> input = stackalloc byte[sizeof(int) * 3];
        BitConverter.TryWriteBytes(input, seed);
        BitConverter.TryWriteBytes(input[sizeof(int)..], label);
        BitConverter.TryWriteBytes(input[(2 * sizeof(int))..], index);
        SHA256.HashData(input, destination);
    }
}
