using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The Pippenger (bucket-method) BN254 G1 multi-scalar multiplication —
/// an algorithmic implementation of the existing
/// <see cref="G1MultiScalarMultiplyDelegate"/> seam, built over the
/// Jacobian core of <see cref="Bn254BigIntegerG1Reference"/>. The
/// naive reference computes one full double-and-add ladder per point plus an
/// affine accumulate (each with its own field inversion); the bucket method
/// shares the doubling ladder across every point and pays one inversion
/// total, asymptotically <c>n / log n</c> group operations instead of
/// <c>n · bits</c>.
/// </summary>
/// <remarks>
/// <para>
/// Per <c>c</c>-bit window from most significant to least: every point whose
/// window digit is non-zero lands in bucket <c>digit</c> via a mixed
/// (Jacobian + affine) addition; the buckets aggregate with the standard
/// running-suffix trick (<c>Σ b·B_b</c> as two passes of plain Jacobian
/// additions); the running total shifts by <c>c</c> doublings between
/// windows. One Jacobian-to-affine conversion at the end.
/// </para>
/// <para>
/// The result is the same group element the naive method computes, so the
/// canonical encoding is byte-identical — the agreement gates pin this. The
/// implementation is correctness-first BigInteger like its reference
/// substrate and is not constant-time; the MSM inputs on every current call
/// path are commitment generators and blinding/witness scalars whose
/// protection model matches the rest of the reference arithmetic.
/// </para>
/// </remarks>
internal static class Bn254PippengerG1Backend
{
    //Canonical BN254 scalars are below 2^254; 256 covers the full byte width.
    private const int ScalarBits = 256;

    //Decoded-point cache bound for the caching delegate: generator sets are
    //few and stable (commitment keys reuse the same generators every call),
    //so a small cap suffices; when it is reached, new sets simply decode
    //per call instead of evicting — no staleness, no eviction policy.
    private const int MaximumCachedPointSets = 32;


    /// <summary>Returns the Pippenger G1 multi-scalar-multiplication delegate.</summary>
    public static G1MultiScalarMultiplyDelegate GetMultiScalarMultiply() => MultiScalarMultiply;


    /// <summary>
    /// Returns a Pippenger delegate that caches decoded point sets,
    /// content-addressed by a BLAKE3 digest of the compressed points buffer.
    /// Decoding a compressed G1 point costs one base-field square root
    /// (a 254-bit modular exponentiation in this substrate); commitment keys
    /// pass the same generator set on every call, so the second and later
    /// MSMs over a set pay one ~microsecond hash instead of <c>n</c> square
    /// roots. A mutated buffer hashes to a different digest, so the cache can
    /// never serve stale points. The cache lives in the returned delegate's
    /// closure and is safe under concurrent callers.
    /// </summary>
    public static G1MultiScalarMultiplyDelegate CreateCachingMultiScalarMultiply()
    {
        var cache = new System.Collections.Concurrent.ConcurrentDictionary<PointSetDigest, Bn254BigIntegerG1Reference.AffinePoint[]>();

        return (pointsConcatenated, scalarsConcatenated, count, result, curve) =>
        {
            CryptographicOperationCounters.Increment(CryptographicOperationKind.G1MultiScalarMultiply, curve, count);
            ValidateInputs(pointsConcatenated, scalarsConcatenated, count);

            if(count == 0)
            {
                Bn254BigIntegerG1Reference.Encode(Bn254BigIntegerG1Reference.AffinePoint.Identity, result);

                return;
            }

            Span<byte> digestBytes = stackalloc byte[32];
            Lumoin.Veridical.Hashing.Blake3.Hash(pointsConcatenated, digestBytes);
            var digest = new PointSetDigest(
                System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(digestBytes[..8]),
                System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(digestBytes.Slice(8, 8)),
                System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(digestBytes.Slice(16, 8)),
                System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(digestBytes.Slice(24, 8)));

            if(!cache.TryGetValue(digest, out Bn254BigIntegerG1Reference.AffinePoint[]? points))
            {
                points = DecodePoints(pointsConcatenated, count);
                if(cache.Count < MaximumCachedPointSets)
                {
                    _ = cache.TryAdd(digest, points);
                }
            }

            MultiScalarMultiplyOverDecoded(points, scalarsConcatenated, count, result);
        };
    }


    private readonly record struct PointSetDigest(ulong A, ulong B, ulong C, ulong D);


    private static void MultiScalarMultiply(
        ReadOnlySpan<byte> pointsConcatenated,
        ReadOnlySpan<byte> scalarsConcatenated,
        int count,
        Span<byte> result,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1MultiScalarMultiply, curve, count);
        ValidateInputs(pointsConcatenated, scalarsConcatenated, count);

        if(count == 0)
        {
            Bn254BigIntegerG1Reference.Encode(Bn254BigIntegerG1Reference.AffinePoint.Identity, result);

            return;
        }

        MultiScalarMultiplyOverDecoded(DecodePoints(pointsConcatenated, count), scalarsConcatenated, count, result);
    }


    private static void ValidateInputs(ReadOnlySpan<byte> pointsConcatenated, ReadOnlySpan<byte> scalarsConcatenated, int count)
    {
        int pointStride = WellKnownCurves.Bn254G1CompressedSizeBytes;
        int scalarStride = Scalar.SizeBytes;

        if(pointsConcatenated.Length != count * pointStride)
        {
            throw new ArgumentException(
                $"pointsConcatenated must hold {count} compressed G1 points of {pointStride} bytes each; received {pointsConcatenated.Length} bytes.",
                nameof(pointsConcatenated));
        }

        if(scalarsConcatenated.Length != count * scalarStride)
        {
            throw new ArgumentException(
                $"scalarsConcatenated must hold {count} canonical scalars of {scalarStride} bytes each; received {scalarsConcatenated.Length} bytes.",
                nameof(scalarsConcatenated));
        }
    }


    //Decode every point once; the buckets then run on mixed additions.
    private static Bn254BigIntegerG1Reference.AffinePoint[] DecodePoints(ReadOnlySpan<byte> pointsConcatenated, int count)
    {
        int pointStride = WellKnownCurves.Bn254G1CompressedSizeBytes;
        var points = new Bn254BigIntegerG1Reference.AffinePoint[count];
        for(int i = 0; i < count; i++)
        {
            points[i] = Bn254BigIntegerG1Reference.Decode(pointsConcatenated.Slice(i * pointStride, pointStride));
        }

        return points;
    }


    private static void MultiScalarMultiplyOverDecoded(
        Bn254BigIntegerG1Reference.AffinePoint[] points,
        ReadOnlySpan<byte> scalarsConcatenated,
        int count,
        Span<byte> result)
    {
        int scalarStride = Scalar.SizeBytes;
        int windowBits = WindowBitsFor(count);
        int windowCount = (ScalarBits + windowBits - 1) / windowBits;
        var buckets = new Bn254BigIntegerG1Reference.JacobianPoint[1 << windowBits];

        Bn254BigIntegerG1Reference.JacobianPoint total = Bn254BigIntegerG1Reference.JacobianPoint.Identity;
        for(int window = windowCount - 1; window >= 0; window--)
        {
            if(window != windowCount - 1)
            {
                for(int d = 0; d < windowBits; d++)
                {
                    total = Bn254BigIntegerG1Reference.JacobianDouble(total);
                }
            }

            Array.Fill(buckets, Bn254BigIntegerG1Reference.JacobianPoint.Identity);
            for(int i = 0; i < count; i++)
            {
                int digit = ExtractWindowDigit(scalarsConcatenated.Slice(i * scalarStride, scalarStride), window, windowBits);
                if(digit != 0 && !points[i].IsInfinity)
                {
                    buckets[digit] = Bn254BigIntegerG1Reference.JacobianAddMixed(buckets[digit], points[i]);
                }
            }

            //Σ b·B_b by the running-suffix trick: running accumulates the
            //suffix of buckets from the top down, and each step adds the
            //running suffix into the window sum, so bucket b is counted b
            //times.
            Bn254BigIntegerG1Reference.JacobianPoint running = Bn254BigIntegerG1Reference.JacobianPoint.Identity;
            Bn254BigIntegerG1Reference.JacobianPoint windowSum = Bn254BigIntegerG1Reference.JacobianPoint.Identity;
            for(int b = buckets.Length - 1; b >= 1; b--)
            {
                running = JacobianAdd(running, buckets[b]);
                windowSum = JacobianAdd(windowSum, running);
            }

            total = JacobianAdd(total, windowSum);
        }

        Bn254BigIntegerG1Reference.Encode(Bn254BigIntegerG1Reference.JacobianToAffine(total), result);
    }


    //The window width that balances the per-window digit additions (n) against
    //the bucket aggregation (2 · 2^c): minimise the standard cost model
    //(ScalarBits / c) · (n + 2^(c+1)) directly — sixteen candidates, a few
    //integer operations each, negligible next to one group addition. A plain
    //log2(n) overshoots: the aggregation grows exponentially in c while the
    //digit side only shrinks linearly in the window count.
    private static int WindowBitsFor(int count)
    {
        int bestBits = 2;
        long bestCost = long.MaxValue;
        for(int c = 2; c <= 16; c++)
        {
            int windows = (ScalarBits + c - 1) / c;
            long cost = (long)windows * (count + (2L << c));
            if(cost < bestCost)
            {
                bestCost = cost;
                bestBits = c;
            }
        }

        return bestBits;
    }


    //Digit of the c-bit window at index `window` (windows counted from the
    //least significant bit) of a canonical big-endian scalar.
    private static int ExtractWindowDigit(ReadOnlySpan<byte> scalar, int window, int windowBits)
    {
        int digit = 0;
        int firstBit = window * windowBits;
        for(int bit = 0; bit < windowBits; bit++)
        {
            int position = firstBit + bit;
            if(position >= ScalarBits)
            {
                break;
            }

            int byteIndex = scalar.Length - 1 - (position / 8);
            if(((scalar[byteIndex] >> (position % 8)) & 1) == 1)
            {
                digit |= 1 << bit;
            }
        }

        return digit;
    }


    //General Jacobian + Jacobian addition (the buckets aggregate
    //Jacobian-to-Jacobian; the reference only carries the mixed form). The
    //textbook formula with the identity, doubling, and inverse cases handled
    //explicitly.
    private static Bn254BigIntegerG1Reference.JacobianPoint JacobianAdd(
        Bn254BigIntegerG1Reference.JacobianPoint p,
        Bn254BigIntegerG1Reference.JacobianPoint q)
    {
        if(p.IsIdentity)
        {
            return q;
        }

        if(q.IsIdentity)
        {
            return p;
        }

        BigInteger prime = Bn254BigIntegerG1Reference.BaseFieldPrime;
        BigInteger z1Squared = Bn254BigIntegerG1Reference.Mod(p.Z * p.Z, prime);
        BigInteger z2Squared = Bn254BigIntegerG1Reference.Mod(q.Z * q.Z, prime);
        BigInteger u1 = Bn254BigIntegerG1Reference.Mod(p.X * z2Squared, prime);
        BigInteger u2 = Bn254BigIntegerG1Reference.Mod(q.X * z1Squared, prime);
        BigInteger s1 = Bn254BigIntegerG1Reference.Mod(p.Y * q.Z * z2Squared, prime);
        BigInteger s2 = Bn254BigIntegerG1Reference.Mod(q.Y * p.Z * z1Squared, prime);

        if(u1 == u2)
        {
            if(s1 == s2)
            {
                return Bn254BigIntegerG1Reference.JacobianDouble(p);
            }

            return Bn254BigIntegerG1Reference.JacobianPoint.Identity;
        }

        BigInteger h = Bn254BigIntegerG1Reference.Mod(u2 - u1, prime);
        BigInteger hSquared = Bn254BigIntegerG1Reference.Mod(h * h, prime);
        BigInteger hCubed = Bn254BigIntegerG1Reference.Mod(h * hSquared, prime);
        BigInteger r = Bn254BigIntegerG1Reference.Mod(s2 - s1, prime);
        BigInteger v = Bn254BigIntegerG1Reference.Mod(u1 * hSquared, prime);
        BigInteger xResult = Bn254BigIntegerG1Reference.Mod((r * r) - hCubed - (2 * v), prime);
        BigInteger yResult = Bn254BigIntegerG1Reference.Mod((r * (v - xResult)) - (s1 * hCubed), prime);
        BigInteger zResult = Bn254BigIntegerG1Reference.Mod(p.Z * q.Z * h, prime);

        return new Bn254BigIntegerG1Reference.JacobianPoint(xResult, yResult, zResult);
    }
}
