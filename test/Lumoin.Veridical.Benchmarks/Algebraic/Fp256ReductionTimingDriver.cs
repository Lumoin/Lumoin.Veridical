using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Diagnostics;
using System.Globalization;

namespace Lumoin.Veridical.Benchmarks.Algebraic;

/// <summary>
/// Back-to-back wall-clock timing of the scalar Fp256 Montgomery multiply with its two reduction strategies:
/// the generic <c>m·Modulus</c> CIOS reduction (the live managed path) versus the P-256-specialized
/// signed-sparse reduction (the retained alternative; both ship side by side and emit the identical residue,
/// and the specialized form drops 20 of the 36 <see cref="ulong"/> multiplies yet runs slower in managed .NET
/// for lack of ADX). The dev box is noisy, so the absolute times are not trusted — the two are
/// timed INTERLEAVED across many rounds and only the generic/specialized RATIO is reported, in which the box's
/// common-mode noise cancels. Avoids BenchmarkDotNet (the soak project's auto-gen path is currently snagged);
/// this is a direct <see cref="Stopwatch"/> loop, the <c>--ligero-attribution</c> pattern.
/// </summary>
internal static class Fp256ReductionTimingDriver
{
    private const int ScalarSize = 32;
    private static readonly CurveParameterSet Curve = CurveParameterSet.None;
    private const int Operands = 1024;
    private const int InnerMultiplies = 256;
    private const int Rounds = 60;


    public static void Run()
    {
        ScalarReduceDelegate reduce = P256BaseFieldReference.GetReduce();
        ScalarMultiplyDelegate live = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();

        byte[] left = new byte[Operands * ScalarSize];
        byte[] right = new byte[Operands * ScalarSize];
        byte[] scratch = new byte[ScalarSize];

        var random = new Random(0x5EED5EED);
        Span<byte> raw = stackalloc byte[64];
        Span<byte> canonical = stackalloc byte[ScalarSize];
        for(int i = 0; i < Operands; i++)
        {
            random.NextBytes(raw);
            reduce(raw, canonical, Curve);
            P256BaseFieldMontgomeryBackend.ToMontgomery(canonical, left.AsSpan(i * ScalarSize, ScalarSize));
            random.NextBytes(raw);
            reduce(raw, canonical, Curve);
            P256BaseFieldMontgomeryBackend.ToMontgomery(canonical, right.AsSpan(i * ScalarSize, ScalarSize));
        }

        //Warm both paths so the JIT has settled before any timing.
        for(int w = 0; w < 4; w++)
        {
            TimeGeneric(live, left, right, scratch);
            TimeSpecial(left, right, scratch);
        }

        //Interleaved rounds: time generic then specialized each round so a noise burst hits both. Keep the best
        //(minimum) per-op of each — the minimum is the least noise-contaminated sample.
        double bestGeneric = double.MaxValue;
        double bestSpecial = double.MaxValue;
        double sumGeneric = 0;
        double sumSpecial = 0;
        for(int r = 0; r < Rounds; r++)
        {
            double g = TimeGeneric(live, left, right, scratch);
            double s = TimeSpecial(left, right, scratch);
            bestGeneric = Math.Min(bestGeneric, g);
            bestSpecial = Math.Min(bestSpecial, s);
            sumGeneric += g;
            sumSpecial += s;
        }

        double meanGeneric = sumGeneric / Rounds;
        double meanSpecial = sumSpecial / Rounds;

        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "=== SCALAR Fp256 Montgomery reduction: specialized vs generic (per-multiply, interleaved, RATIO trusted) ==="));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "generic     ns/mul: best {0:F2}  mean {1:F2}", bestGeneric, meanGeneric));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "specialized ns/mul: best {0:F2}  mean {1:F2}", bestSpecial, meanSpecial));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "scalar speedup (generic/specialized): best {0:F2}x  mean {1:F2}x", bestGeneric / bestSpecial, meanGeneric / meanSpecial));

        if(System.Runtime.Intrinsics.X86.Avx2.IsSupported)
        {
            ScalarBatchMultiplyDelegate genericBatch = P256BaseFieldMontgomeryBatchBackendAvx2.GetBatchMultiplyMontgomery();
            ScalarBatchMultiplyDelegate specialBatch = P256BaseFieldMontgomeryBatchBackendAvx2.GetBatchMultiplyMontgomerySpecializedReduce();
            byte[] batchResult = new byte[Operands * ScalarSize];

            for(int w = 0; w < 4; w++)
            {
                TimeBatch(genericBatch, left, right, batchResult);
                TimeBatch(specialBatch, left, right, batchResult);
            }

            double bestGenBatch = double.MaxValue, bestSpecBatch = double.MaxValue;
            for(int r = 0; r < Rounds; r++)
            {
                bestGenBatch = Math.Min(bestGenBatch, TimeBatch(genericBatch, left, right, batchResult));
                bestSpecBatch = Math.Min(bestSpecBatch, TimeBatch(specialBatch, left, right, batchResult));
            }

            Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "=== AVX2 BATCH Fp256: specialized vs generic (per-multiply) ==="));
            Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "batch generic     ns/mul best {0:F2}; batch specialized ns/mul best {1:F2}", bestGenBatch, bestSpecBatch));
            Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "batch speedup (generic/specialized): best {0:F2}x", bestGenBatch / bestSpecBatch));
            Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "AVX2 batch (generic) vs scalar (generic): best {0:F2}x faster per multiply", bestGeneric / bestGenBatch));
        }

        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "(op-count said specialized removes 20 of 36 ulong multiplies; wall-clock says the borrow/carry chains cost more than the multiplies in managed -- no ADX.)"));
    }


    private static double TimeBatch(ScalarBatchMultiplyDelegate batch, byte[] left, byte[] right, byte[] result)
    {
        Stopwatch watch = Stopwatch.StartNew();
        batch(left, right, result, Operands, Curve);
        watch.Stop();

        return watch.Elapsed.TotalMilliseconds * 1_000_000.0 / Operands;
    }


    private static double TimeGeneric(ScalarMultiplyDelegate live, byte[] left, byte[] right, byte[] scratch)
    {
        Stopwatch watch = Stopwatch.StartNew();
        for(int m = 0; m < InnerMultiplies; m++)
        {
            int offset = (m % Operands) * ScalarSize;
            live(left.AsSpan(offset, ScalarSize), right.AsSpan(offset, ScalarSize), scratch, Curve);
        }

        watch.Stop();

        return watch.Elapsed.TotalMilliseconds * 1_000_000.0 / InnerMultiplies;
    }


    private static double TimeSpecial(byte[] left, byte[] right, byte[] scratch)
    {
        Stopwatch watch = Stopwatch.StartNew();
        for(int m = 0; m < InnerMultiplies; m++)
        {
            int offset = (m % Operands) * ScalarSize;
            P256BaseFieldMontgomeryBackend.MultiplyMontgomerySpecializedReduce(left.AsSpan(offset, ScalarSize), right.AsSpan(offset, ScalarSize), scratch);
        }

        watch.Stop();

        return watch.Elapsed.TotalMilliseconds * 1_000_000.0 / InnerMultiplies;
    }
}
