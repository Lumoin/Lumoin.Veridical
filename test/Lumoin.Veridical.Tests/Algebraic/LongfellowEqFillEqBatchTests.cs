using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The byte-identity gate for the GF(2^128) batched <see cref="LongfellowEq.FillEq"/> path (Perf Increment 2,
/// Commit 1): the per-level scalar-times-vector products <c>Q[level]·eq[i]</c> routed through
/// <see cref="Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate"/> must produce a byte-for-byte identical
/// <c>eq</c> array to the per-scalar multiply path. <c>filleq</c> feeds the constraint builder's
/// <c>eq0</c>/<c>eq1</c>/<c>eqh0</c>/<c>eqh1</c> tables, whose values flow into the Ligero <c>A·w = b</c>
/// system and thence the emitted proof bytes, so any divergence here would break the wire-format
/// conformance the end-to-end gates pin. This gate isolates the change from those multi-minute gates:
/// running the same <c>FillEq</c> both ways over a range of sizes (covering the even/odd split, the
/// first-iteration overflow special-case, and several binding levels) and asserting equality proves the
/// batched path is a pure dispatch change, not an arithmetic one.
/// </summary>
/// <remarks>
/// The randomness is a deterministic SHA-256 keystream (no <see cref="RandomNumberGenerator"/>), so a failure
/// reproduces. The broadcast primitive is itself gated byte-identical to the per-scalar multiply by
/// <see cref="Gf2k128BatchBackendAgreementTests"/>; this gate pins that <see cref="LongfellowEq.FillEq"/>
/// consumes it without disturbing the surrounding fill structure.
/// </remarks>
[TestClass]
internal sealed class LongfellowEqFillEqBatchTests
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int ElementBytes = 16;

    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    private static ScalarBroadcastMultiplyAccumulateDelegate BroadcastMultiplyAccumulate { get; } = Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate();


    [TestMethod]
    public void BatchedFillEqIsByteIdenticalToTheScalarFillEq()
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        WorkingOne(one);

        //The sizes cover: n == 1 (logn 0, no level), even/odd n (the trailing-element split), the
        //first-iteration overflow special-case (nl odd), and several binding levels (n up to 4096).
        ReadOnlySpan<int> sizes = [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31, 64, 100, 127, 128, 1000, 1024, 4096];

        int seed = 0;
        foreach(int n in sizes)
        {
            int logn = BitLength(n);

            byte[] qq = RandomScalars(logn, ref seed);

            byte[] scalar = new byte[n * ScalarSize];
            byte[] batched = new byte[n * ScalarSize];

            //The scalar reference path: no broadcast delegate supplied.
            LongfellowEq.FillEq(logn, n, qq, Subtract, Multiply, CurveParameterSet.None, one, scalar);

            //The batched path: the broadcast delegate plus a product scratch sized to the largest level's
            //prefix (ceil(n/2) scalars, the bound on every level's iStart).
            byte[] productScratch = new byte[Math.Max((n + 1) / 2, 1) * ScalarSize];
            LongfellowEq.FillEq(logn, n, qq, Subtract, Multiply, CurveParameterSet.None, one, batched, BroadcastMultiplyAccumulate, productScratch);

            Assert.IsTrue(scalar.AsSpan().SequenceEqual(batched), $"The batched FillEq must equal the scalar FillEq at n = {n}.");
        }
    }


    [TestMethod]
    public void AnUndersizedProductScratchFallsBackToTheScalarPathByteIdentically()
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        WorkingOne(one);

        const int n = 1024;
        int logn = BitLength(n);
        int seed = 7919;
        byte[] qq = RandomScalars(logn, ref seed);

        byte[] scalar = new byte[n * ScalarSize];
        byte[] fallback = new byte[n * ScalarSize];

        LongfellowEq.FillEq(logn, n, qq, Subtract, Multiply, CurveParameterSet.None, one, scalar);

        //A scratch one scalar short of ceil(n/2) must disengage the batch path and reproduce the scalar fill.
        byte[] shortScratch = new byte[(((n + 1) / 2) - 1) * ScalarSize];
        LongfellowEq.FillEq(logn, n, qq, Subtract, Multiply, CurveParameterSet.None, one, fallback, BroadcastMultiplyAccumulate, shortScratch);

        Assert.IsTrue(scalar.AsSpan().SequenceEqual(fallback), "An undersized product scratch must fall back to the byte-identical scalar fill.");
    }


    //The GF(2^128) multiplicative one in the canonical 32-byte big-endian slot (value 1 in the low limb).
    private static void WorkingOne(Span<byte> destination)
    {
        destination.Clear();
        destination[ScalarSize - 1] = 1;
    }


    //logn = the number of binding rounds for n entries = ceil(log2(n)); 0 for n == 1.
    private static int BitLength(int n)
    {
        int bits = 0;
        int value = n - 1;
        while(value > 0)
        {
            bits++;
            value >>= 1;
        }

        return bits;
    }


    //A deterministic SHA-256 keystream of count canonical GF(2^128) scalars: each scalar's low ElementBytes
    //carry keystream bytes, the high bytes stay zero (the canonical slot). The seed advances per draw so the
    //sizes do not share a q-point.
    private static byte[] RandomScalars(int count, ref int seed)
    {
        byte[] scalars = new byte[Math.Max(count, 1) * ScalarSize];
        Span<byte> block = stackalloc byte[SHA256.HashSizeInBytes];
        Span<byte> counter = stackalloc byte[sizeof(int) * 2];
        for(int i = 0; i < count; i++)
        {
            BitConverter.TryWriteBytes(counter, seed);
            BitConverter.TryWriteBytes(counter[sizeof(int)..], i);
            SHA256.HashData(counter, block);
            block[..ElementBytes].CopyTo(scalars.AsSpan((i * ScalarSize) + (ScalarSize - ElementBytes), ElementBytes));
        }

        seed++;

        return scalars;
    }
}
