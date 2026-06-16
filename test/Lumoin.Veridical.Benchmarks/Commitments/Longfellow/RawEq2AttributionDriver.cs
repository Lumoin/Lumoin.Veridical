using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Benchmarks.Commitments.Longfellow;

/// <summary>
/// Deterministic, noise-immune op-count attribution of the de-recursed <see cref="LongfellowEq.RawEq2"/>
/// (Perf Increment 2c). The dev box is noisy, so wall-clock deltas are unreliable; the win of removing the
/// <c>fill_recursive</c> recursion is a CALL-COUNT and frame-elimination story, which is identical every run.
/// For a range of sizes this counts the field-delegate calls the OLD recursion made (a local copy) versus the
/// NEW GF(2^128) batched path: the per-term scalar multiplies collapse from ~2n individual delegate calls
/// into <c>2·logn + 1</c> wide batch calls, the ~n leaf adds fold into the combine, and the ~2n recursion
/// frames (each with a 128-byte <c>stackalloc</c>) vanish entirely. The output is the input to the perf
/// decision, not a benchmark; it carries no timing.
/// </summary>
internal static class RawEq2AttributionDriver
{
    private const int ScalarSize = 32;
    private const int ElementBytes = 16;
    private static readonly CurveParameterSet Curve = CurveParameterSet.None;

    private static readonly ScalarAddDelegate Add = Gf2k128Backend.GetAdd();
    private static readonly ScalarSubtractDelegate Subtract = Gf2k128Backend.GetSubtract();
    private static readonly ScalarMultiplyDelegate Multiply = Gf2k128Backend.GetMultiply();
    private static readonly ScalarBroadcastMultiplyAccumulateDelegate BroadcastMultiplyAccumulate = Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate();


    public static void Run()
    {
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "=== raw_eq2 de-recursion op-count attribution (GF(2^128), deterministic) ==="));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
            "{0,8}  {1,5}  | {2,30} | {3,30}", "n", "logn", "OLD recursion (scalar calls)", "NEW batched (scalar + batch)"));

        int[] sizes = [1024, 4096, 16384, 65536];
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[ScalarSize - 1] = 1;

        foreach(int n in sizes)
        {
            int logn = BitLength(n);
            byte[] g0 = RandomScalars(logn, n);
            byte[] g1 = RandomScalars(logn, n + 1);
            byte[] alpha = RandomScalars(1, n + 2);

            //OLD: the recursion (local copy), counting its scalar field calls.
            var oldCounter = new CountingField(Add, Subtract, Multiply);
            byte[] oldEq = new byte[n * ScalarSize];
            FillRecursive(oldEq, logn, n, g0, g1, one.ToArray(), alpha, oldCounter);

            //NEW: the batched GF path, counting scalar field calls AND broadcast-MAC calls.
            var newCounter = new CountingField(Add, Subtract, Multiply);
            long macCalls = 0;
            ScalarBroadcastMultiplyAccumulateDelegate countingMac = (scalar, ops, acc, accumulate, count, curve) =>
            {
                macCalls++;
                BroadcastMultiplyAccumulate(scalar, ops, acc, accumulate, count, curve);
            };
            byte[] newEq = new byte[n * ScalarSize];
            byte[] scratch = new byte[(n + ((n + 1) / 2)) * ScalarSize];
            LongfellowEq.RawEq2(logn, n, g0, g1, alpha, newCounter.Add, newCounter.Subtract, newCounter.Multiply, Curve, one, newEq, countingMac, scratch);

            if(!oldEq.AsSpan().SequenceEqual(newEq))
            {
                throw new InvalidOperationException($"Byte mismatch at n = {n}: the attribution oracle diverged.");
            }

            Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
                "{0,8}  {1,5}  | mul={2,8} sub={3,8} add={4,6} | mul={5} sub={6,6} add={7} mac={8} (= 2*logn+1)",
                n, logn, oldCounter.Mul, oldCounter.Sub, oldCounter.Add_, newCounter.Mul, newCounter.Sub, newCounter.Add_, macCalls));
        }

        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "Note: scalar MULTIPLIES collapse to 0 (folded into the batch MAC calls); the ~n leaf"));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "ADDS fold into the combine MAC; the ~2n recursion frames + per-frame stackalloc vanish."));
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "Subtracts persist (FillEq's v - q*v), the same already-shipped iterative filleq cost."));
    }


    //fill_recursive(eq, l, n, G0, G1, w0, w1): the OLD raw_eq2 recursion, retained here to count its calls.
    private static void FillRecursive(byte[] eq, int level, int n, byte[] g0, byte[] g1, byte[] w0, byte[] w1, CountingField field)
    {
        FillRecursive(eq.AsSpan(), level, n, g0, g1, w0, w1, field);
    }


    private static void FillRecursive(Span<byte> eq, int level, int n, ReadOnlySpan<byte> g0, ReadOnlySpan<byte> g1, ReadOnlySpan<byte> w0, ReadOnlySpan<byte> w1, CountingField field)
    {
        if(level > 0)
        {
            int nl = level - 1;
            int s = 1 << nl;

            Span<byte> w0hi = stackalloc byte[ScalarSize];
            Span<byte> w1hi = stackalloc byte[ScalarSize];
            Span<byte> w0lo = stackalloc byte[ScalarSize];
            Span<byte> w1lo = stackalloc byte[ScalarSize];

            field.Multiply(w0, g0.Slice(nl * ScalarSize, ScalarSize), w0hi, Curve);
            field.Multiply(w1, g1.Slice(nl * ScalarSize, ScalarSize), w1hi, Curve);
            field.Subtract(w0, w0hi, w0lo, Curve);
            field.Subtract(w1, w1hi, w1lo, Curve);

            if(n <= s)
            {
                FillRecursive(eq, nl, n, g0, g1, w0lo, w1lo, field);
            }
            else
            {
                FillRecursive(eq, nl, s, g0, g1, w0lo, w1lo, field);
                FillRecursive(eq[(s * ScalarSize)..], nl, n - s, g0, g1, w0hi, w1hi, field);
            }
        }
        else
        {
            field.Add(w0, w1, eq[..ScalarSize], Curve);
        }
    }


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


    private static byte[] RandomScalars(int count, int seed)
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

        return scalars;
    }


    //Field delegates that count their calls by kind, forwarding to the raw backend.
    private sealed class CountingField
    {
        private readonly ScalarAddDelegate rawAdd;
        private readonly ScalarSubtractDelegate rawSubtract;
        private readonly ScalarMultiplyDelegate rawMultiply;

        public long Mul;
        public long Add_;
        public long Sub;

        public CountingField(ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply)
        {
            rawAdd = add;
            rawSubtract = subtract;
            rawMultiply = multiply;
        }

        public void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
        {
            Add_++;
            rawAdd(a, b, result, curve);
        }

        public void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
        {
            Sub++;
            rawSubtract(a, b, result, curve);
        }

        public void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
        {
            Mul++;
            rawMultiply(a, b, result, curve);
        }
    }
}
