using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Benchmarks.Algebraic;

/// <summary>
/// Stage-3 go/no-go measurement for wiring the AVX2 lane-parallel Fp256 batch multiply
/// (<see cref="P256BaseFieldMontgomeryBatchBackendAvx2.GetBatchMultiplyMontgomery"/>) into the Longfellow
/// <c>bind_quad</c> reduction (the dominant Fp256 cost, <see cref="LongfellowZkConstraintBuilder"/>'s
/// <c>ReduceRange</c>). The scalar path forms, per term, the four-way CHAINED Montgomery product
/// <c>(zero ? beta : coef) · eqg[g] · eqh0[h0] · eqh1[h1]</c> as three sequential single-CIOS multiplies
/// plus a field-add accumulate. The candidate path GATHERS each term's scattered operands into chunked
/// contiguous scratch, runs THREE batched multiply passes (<c>scaled·eqg</c>, <c>·eqh0</c>, <c>·eqh1</c>),
/// and field-add accumulates — reusing the validated batch multiply with NO new kernel.
/// </summary>
/// <remarks>
/// <para>
/// The batch multiply is 3.20×/multiply faster than the scalar on ALREADY-CONTIGUOUS operands
/// (<c>--fp256-reduction-timing</c>), but <c>bind_quad</c> operands are index-addressed (scattered), so the
/// per-term GATHER memory traffic may eat the gain. This driver measures the gather cost back-to-back: it is
/// the explicit gate for committing Stage 3 (the <c>115ec51</c> lesson — op-count proves a call-count change,
/// NOT a wall-clock win; measure before claiming perf). The dev box is noisy, so absolute times are not
/// trusted — the two paths are timed INTERLEAVED across many rounds and only the scalar/batch RATIO is
/// reported, in which the box's common-mode noise cancels. A per-shape byte-identity check confirms the
/// gather+batch path reproduces the scalar accumulator exactly before any timing is trusted.
/// </para>
/// <para>
/// The workload models the real <c>bind_quad</c> shape in the Montgomery working domain: small <c>eqg</c>
/// (<c>nv</c>) and <c>eqh0</c>/<c>eqh1</c> (<c>nw</c>) tables, a small deduped coefficient table reused across
/// terms (the circuit's constant table), random scattered gate/left/right indices (worst-case cache scatter —
/// real wiring has locality, so this is conservative for the gather), and a fraction of zero-coefficient terms
/// that select <c>beta</c>. AVX2 only (the validated live batch backend); the driver aborts on a non-AVX2 host.
/// </para>
/// </remarks>
internal static class Fp256BindQuadTimingDriver
{
    private const int ScalarSize = 32;
    private static readonly CurveParameterSet Curve = CurveParameterSet.None;

    //The deduped coefficient table size: the real circuit reuses a small constant table across many terms.
    private const int CoefficientDistinct = 256;

    //The fraction of terms whose coefficient is zero (so the term selects beta), mirroring the sparse circuit.
    private const double ZeroFraction = 0.10;

    //Chunked scratch keeps the gathered operands and the two intermediates resident in cache: 5 buffers of
    //ChunkSize * 32 bytes (left, right, qv, term, prod). 1024 -> 160 KB, comfortably L2-resident on Zen 3.
    private const int ChunkSize = 1024;

    private const int Rounds = 30;

    private static int sink;


    /// <summary>
    /// One synthetic <c>bind_quad</c> workload in the Montgomery working domain: the <c>eqg</c>/<c>eqh0</c>/<c>eqh1</c>
    /// tables, a deduped coefficient table, the assert-zero <c>beta</c>, and the per-term index/zero-flag arrays.
    /// </summary>
    private sealed class Workload
    {
        public int Nv { get; init; }
        public int Nw { get; init; }
        public int Count { get; init; }
        public byte[] Eqg { get; init; } = Array.Empty<byte>();
        public byte[] Eqh0 { get; init; } = Array.Empty<byte>();
        public byte[] Eqh1 { get; init; } = Array.Empty<byte>();
        public byte[] CoefficientTable { get; init; } = Array.Empty<byte>();
        public byte[] Beta { get; init; } = Array.Empty<byte>();
        public int[] GateIndex { get; init; } = Array.Empty<int>();
        public int[] LeftIndex { get; init; } = Array.Empty<int>();
        public int[] RightIndex { get; init; } = Array.Empty<int>();
        public int[] CoefficientIndex { get; init; } = Array.Empty<int>();
        public bool[] IsZero { get; init; } = Array.Empty<bool>();
    }


    public static void Run()
    {
        if(!Avx2.IsSupported)
        {
            Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "AVX2 not supported on this host; the Fp256 batch backend cannot run. Aborting --fp256-bindquad-timing."));
            return;
        }

        ScalarMultiplyDelegate mul = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();
        ScalarAddDelegate add = P256BaseFieldMontgomeryBackend.GetAdd();
        ScalarBatchMultiplyDelegate batch = P256BaseFieldMontgomeryBatchBackendAvx2.GetBatchMultiplyMontgomery();

        (int nv, int nw, int count)[] shapes =
        {
            //Small tables (cache-resident gather), increasing term count: the realistic Fp256 sig regime.
            (256, 256, 8192),
            (256, 256, 65536),
            (256, 256, 1 << 20),
            //Asymmetric and medium tables.
            (1024, 64, 262144),
            (4096, 256, 1 << 20),
            //Adversarial: large eqg (2 MB) so the gather reads miss cache — the gather's worst case.
            (65536, 256, 1 << 20),
        };

        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "=== Fp256 bind_quad: scalar 3-multiply chain vs gather + AVX2 batch (per-term, interleaved, RATIO trusted) ==="));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "chunk={0}, coefDistinct={1}, zeroFrac={2:F2}, rounds={3}", ChunkSize, CoefficientDistinct, ZeroFraction, Rounds));

        foreach((int nv, int nw, int count) in shapes)
        {
            Workload workload = BuildWorkload(nv, nw, count);

            byte[] left = new byte[ChunkSize * ScalarSize];
            byte[] right = new byte[ChunkSize * ScalarSize];
            byte[] qv = new byte[ChunkSize * ScalarSize];
            byte[] termBuffer = new byte[ChunkSize * ScalarSize];
            byte[] prod = new byte[ChunkSize * ScalarSize];

            //Byte-identity: the gather+batch accumulator must equal the scalar accumulator exactly.
            byte[] scalarOut = new byte[ScalarSize];
            byte[] batchOut = new byte[ScalarSize];
            ScalarBindQuad(workload, mul, add, scalarOut);
            GatherBatchBindQuad(workload, batch, add, batchOut, left, right, qv, termBuffer, prod);
            bool identical = scalarOut.AsSpan().SequenceEqual(batchOut);

            int iterations = count <= 8192 ? 64 : count <= 131072 ? 8 : 2;

            //Warm both paths so the JIT has settled before any timing.
            for(int w = 0; w < 3; w++)
            {
                TimeScalar(workload, mul, add, scalarOut, iterations);
                TimeBatch(workload, batch, add, batchOut, left, right, qv, termBuffer, prod, iterations);
            }

            double bestScalar = double.MaxValue;
            double bestBatch = double.MaxValue;
            for(int r = 0; r < Rounds; r++)
            {
                bestScalar = Math.Min(bestScalar, TimeScalar(workload, mul, add, scalarOut, iterations));
                bestBatch = Math.Min(bestBatch, TimeBatch(workload, batch, add, batchOut, left, right, qv, termBuffer, prod, iterations));
            }

            Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
                "nv={0,6} nw={1,5} count={2,8} | scalar {3,7:F2} ns/term | batch {4,7:F2} ns/term | speedup {5,5:F2}x | byte-identical {6}",
                nv, nw, count, bestScalar, bestBatch, bestScalar / bestBatch, identical ? "YES" : "NO!!"));
        }

        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "(speedup > 1 => gather+batch wins; the 3.20x/mul ceiling is only reachable if the gather were free. DO NOT commit on op-count. sink={0})", sink));
    }


    //The scalar reduction: the byte-for-byte mirror of LongfellowZkConstraintBuilder.ReduceRange, three
    //sequential single-CIOS Montgomery multiplies plus a field-add accumulate per term.
    private static void ScalarBindQuad(Workload workload, ScalarMultiplyDelegate mul, ScalarAddDelegate add, Span<byte> result)
    {
        Span<byte> accumulator = stackalloc byte[ScalarSize];
        accumulator.Clear();
        Span<byte> qv = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> sum = stackalloc byte[ScalarSize];

        int count = workload.Count;
        for(int k = 0; k < count; k++)
        {
            ReadOnlySpan<byte> scaledV = workload.IsZero[k]
                ? workload.Beta.AsSpan()
                : workload.CoefficientTable.AsSpan(workload.CoefficientIndex[k] * ScalarSize, ScalarSize);

            mul(scaledV, workload.Eqg.AsSpan(workload.GateIndex[k] * ScalarSize, ScalarSize), qv, Curve);
            mul(qv, workload.Eqh0.AsSpan(workload.LeftIndex[k] * ScalarSize, ScalarSize), term, Curve);
            mul(term, workload.Eqh1.AsSpan(workload.RightIndex[k] * ScalarSize, ScalarSize), term, Curve);

            add(accumulator, term, sum, Curve);
            sum.CopyTo(accumulator);
        }

        accumulator.CopyTo(result);
    }


    //The candidate: gather each chunk's scattered operands into contiguous scratch, three batched multiply
    //passes (scaled.eqg -> .eqh0 -> .eqh1), then a field-add accumulate. Reuses the validated batch multiply.
    private static void GatherBatchBindQuad(
        Workload workload,
        ScalarBatchMultiplyDelegate batch,
        ScalarAddDelegate add,
        Span<byte> result,
        byte[] left,
        byte[] right,
        byte[] qv,
        byte[] termBuffer,
        byte[] prod)
    {
        Span<byte> accumulator = stackalloc byte[ScalarSize];
        accumulator.Clear();
        Span<byte> sum = stackalloc byte[ScalarSize];

        int count = workload.Count;
        for(int start = 0; start < count; start += ChunkSize)
        {
            int n = Math.Min(ChunkSize, count - start);
            int nBytes = n * ScalarSize;

            //Pass 1 operands: left = (zero ? beta : coef), right = eqg[g].
            for(int j = 0; j < n; j++)
            {
                int k = start + j;
                ReadOnlySpan<byte> scaledV = workload.IsZero[k]
                    ? workload.Beta.AsSpan()
                    : workload.CoefficientTable.AsSpan(workload.CoefficientIndex[k] * ScalarSize, ScalarSize);
                scaledV.CopyTo(left.AsSpan(j * ScalarSize, ScalarSize));
                workload.Eqg.AsSpan(workload.GateIndex[k] * ScalarSize, ScalarSize).CopyTo(right.AsSpan(j * ScalarSize, ScalarSize));
            }

            batch(left.AsSpan(0, nBytes), right.AsSpan(0, nBytes), qv.AsSpan(0, nBytes), n, Curve);

            //Pass 2: right = eqh0[h0], left = qv.
            for(int j = 0; j < n; j++)
            {
                int k = start + j;
                workload.Eqh0.AsSpan(workload.LeftIndex[k] * ScalarSize, ScalarSize).CopyTo(right.AsSpan(j * ScalarSize, ScalarSize));
            }

            batch(qv.AsSpan(0, nBytes), right.AsSpan(0, nBytes), termBuffer.AsSpan(0, nBytes), n, Curve);

            //Pass 3: right = eqh1[h1], left = term.
            for(int j = 0; j < n; j++)
            {
                int k = start + j;
                workload.Eqh1.AsSpan(workload.RightIndex[k] * ScalarSize, ScalarSize).CopyTo(right.AsSpan(j * ScalarSize, ScalarSize));
            }

            batch(termBuffer.AsSpan(0, nBytes), right.AsSpan(0, nBytes), prod.AsSpan(0, nBytes), n, Curve);

            //Field-add accumulate (same count of adds as the scalar path, so the add cost cancels in the ratio).
            for(int j = 0; j < n; j++)
            {
                add(accumulator, prod.AsSpan(j * ScalarSize, ScalarSize), sum, Curve);
                sum.CopyTo(accumulator);
            }
        }

        accumulator.CopyTo(result);
    }


    private static double TimeScalar(Workload workload, ScalarMultiplyDelegate mul, ScalarAddDelegate add, byte[] outBuffer, int iterations)
    {
        Stopwatch watch = Stopwatch.StartNew();
        for(int it = 0; it < iterations; it++)
        {
            ScalarBindQuad(workload, mul, add, outBuffer);
        }

        watch.Stop();
        sink ^= outBuffer[0];

        return watch.Elapsed.TotalMilliseconds * 1_000_000.0 / ((double)workload.Count * iterations);
    }


    private static double TimeBatch(
        Workload workload,
        ScalarBatchMultiplyDelegate batch,
        ScalarAddDelegate add,
        byte[] outBuffer,
        byte[] left,
        byte[] right,
        byte[] qv,
        byte[] termBuffer,
        byte[] prod,
        int iterations)
    {
        Stopwatch watch = Stopwatch.StartNew();
        for(int it = 0; it < iterations; it++)
        {
            GatherBatchBindQuad(workload, batch, add, outBuffer, left, right, qv, termBuffer, prod);
        }

        watch.Stop();
        sink ^= outBuffer[0];

        return watch.Elapsed.TotalMilliseconds * 1_000_000.0 / ((double)workload.Count * iterations);
    }


    private static Workload BuildWorkload(int nv, int nw, int count)
    {
        var random = new Random(0x5EED5EED);
        ScalarReduceDelegate reduce = P256BaseFieldReference.GetReduce();

        var workload = new Workload
        {
            Nv = nv,
            Nw = nw,
            Count = count,
            Eqg = MakeMontgomeryArray(nv, random, reduce),
            Eqh0 = MakeMontgomeryArray(nw, random, reduce),
            Eqh1 = MakeMontgomeryArray(nw, random, reduce),
            CoefficientTable = MakeMontgomeryArray(CoefficientDistinct, random, reduce),
            Beta = MakeMontgomeryArray(1, random, reduce),
            GateIndex = new int[count],
            LeftIndex = new int[count],
            RightIndex = new int[count],
            CoefficientIndex = new int[count],
            IsZero = new bool[count],
        };

        for(int k = 0; k < count; k++)
        {
            workload.GateIndex[k] = random.Next(nv);
            workload.LeftIndex[k] = random.Next(nw);
            workload.RightIndex[k] = random.Next(nw);
            workload.CoefficientIndex[k] = random.Next(CoefficientDistinct);
            workload.IsZero[k] = random.NextDouble() < ZeroFraction;
        }

        return workload;
    }


    private static byte[] MakeMontgomeryArray(int count, Random random, ScalarReduceDelegate reduce)
    {
        byte[] array = new byte[count * ScalarSize];
        Span<byte> raw = stackalloc byte[64];
        Span<byte> canonical = stackalloc byte[ScalarSize];
        for(int i = 0; i < count; i++)
        {
            random.NextBytes(raw);
            reduce(raw, canonical, Curve);
            P256BaseFieldMontgomeryBackend.ToMontgomery(canonical, array.AsSpan(i * ScalarSize, ScalarSize));
        }

        return array;
    }
}
