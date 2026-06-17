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
/// The byte-identity gate for the Fp256 batched <c>bind_quad</c> path (Perf Increment, Stage 3): the
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
    private const int ScalarSize = Scalar.SizeBytes;

    //Mirrors LongfellowZkConstraintBuilder.MaxBindings: BindQuad slices handChallenges into two hands at this
    //offset and reads up to this many g/hand scalars, so the input buffers must be sized to it.
    private const int MaxBindings = 40;

    //Per-purpose keystream labels so the g-points, hand challenges, alpha, beta, coefficients, indices and the
    //zero decisions draw from independent SHA-256 streams within one shape's seed.
    private const int GateZeroLabel = 0;
    private const int GateOneLabel = 1;
    private const int HandLabel = 2;
    private const int AlphaLabel = 3;
    private const int BetaLabel = 4;
    private const int CoefficientLabel = 5;
    private const int GateIndexLabel = 6;
    private const int LeftIndexLabel = 7;
    private const int RightIndexLabel = 8;
    private const int ZeroDecisionLabel = 9;

    //The zero-decision granularity: zeroFraction is taken in thousandths so 0.10 selects ~10% of terms.
    private const int ZeroResolution = 1000;

    private static CurveParameterSet Curve { get; } = CurveParameterSet.None;

    private static ScalarAddDelegate Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();

    private static ScalarMultiplyDelegate MultiplyMontgomery { get; } = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();

    private static ScalarReduceDelegate Reduce { get; } = P256BaseFieldReference.GetReduce();


    [TestInitialize]
    public void RequireAvx2() => InstructionSetRequirements.RequireAvx2();


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


    //A row of count canonical Montgomery residues derived from the (seed, label) keystream, one per index.
    private static byte[] MontgomeryScalars(int seed, int label, int count)
    {
        byte[] array = new byte[count * ScalarSize];
        for(int i = 0; i < count; i++)
        {
            DeriveMontgomery(seed, label, i, array.AsSpan(i * ScalarSize, ScalarSize));
        }

        return array;
    }


    //A genuine Montgomery residue for the (seed, label, index) coordinate: SHA-256 of the three ints, reduced
    //mod p and lifted into the Montgomery domain.
    private static void DeriveMontgomery(int seed, int label, int index, Span<byte> destination)
    {
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        DeriveHash(seed, label, index, hash);

        Span<byte> canonical = stackalloc byte[ScalarSize];
        Reduce(hash, canonical, Curve);
        P256BaseFieldMontgomeryBackend.ToMontgomery(canonical, destination);
    }


    //A uniform-enough integer in [0, exclusiveMax) for the (seed, label, index) coordinate (the modulo bias is
    //immaterial to a byte-identity comparison, which holds for any in-range indices).
    private static int DeriveInt(int seed, int label, int index, int exclusiveMax)
    {
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        DeriveHash(seed, label, index, hash);

        return (int)(BitConverter.ToUInt32(hash) % (uint)exclusiveMax);
    }


    //SHA-256 of the little-endian (seed, label, index) triple — the deterministic keystream block.
    private static void DeriveHash(int seed, int label, int index, Span<byte> destination)
    {
        Span<byte> input = stackalloc byte[sizeof(int) * 3];
        BitConverter.TryWriteBytes(input, seed);
        BitConverter.TryWriteBytes(input[sizeof(int)..], label);
        BitConverter.TryWriteBytes(input[(2 * sizeof(int))..], index);
        SHA256.HashData(input, destination);
    }
}
