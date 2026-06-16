using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The P-256 affine-curve math an ECDSA verifier reconstructs the nonce point from: given the
/// public signature alone (Q, e, r, s) it recovers R = u1·G + u2·Q with u1 = e/s, u2 = r/s
/// (mod n), which equals the prover's k·G for a valid signature without knowledge of the nonce.
/// Shared by the in-circuit ECDSA gadget tests and the cross-field mdoc-ECDSA end-to-end so the
/// curve oracle is defined in one place.
/// </summary>
internal static class EcdsaNonceRecovery
{
    private const int ScalarSize = Scalar.SizeBytes;

    public static BigInteger P { get; } = P256BigIntegerG1Reference.BaseFieldPrime;

    public static BigInteger A { get; } = P256BigIntegerG1Reference.CurveA;

    public static BigInteger N { get; } = WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.P256);

    public static BigInteger Gx { get; } = Hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");

    public static BigInteger Gy { get; } = Hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

    public static (BigInteger X, BigInteger Y) G { get; } = (Gx, Gy);


    //The nonce point a verifier reconstructs from the public signature alone:
    //R = u1·G + u2·Q with u1 = e/s, u2 = r/s (mod n). For a valid signature this is
    //exactly k·G, recovered without knowledge of the nonce k.
    public static (BigInteger X, BigInteger Y) RecoverNoncePoint(BigInteger qx, BigInteger qy, BigInteger e, BigInteger r, BigInteger s)
    {
        BigInteger sInverse = ModInvN(s);
        (BigInteger X, BigInteger Y)? point = OracleAdd(
            OracleScalarMultiply(ModN(e * sInverse), G),
            OracleScalarMultiply(ModN(r * sInverse), (qx, qy)));

        return point!.Value;
    }


    public static BigInteger ToInteger(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


    public static byte[] Bytes(BigInteger value)
    {
        byte[] result = new byte[ScalarSize];
        value.TryWriteBytes(result, out int written, isUnsigned: true, isBigEndian: true);
        if(written < ScalarSize)
        {
            int shift = ScalarSize - written;
            result.AsSpan(0, written).CopyTo(result.AsSpan(shift));
            result.AsSpan(0, shift).Clear();
        }

        return result;
    }


    public static BigInteger Hex(string value) => BigInteger.Parse("0" + value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);


    private static BigInteger Mod(BigInteger v) => ((v % P) + P) % P;

    private static BigInteger ModInverse(BigInteger v) => BigInteger.ModPow(Mod(v), P - 2, P);

    public static BigInteger ModN(BigInteger v) => ((v % N) + N) % N;

    public static BigInteger ModInvN(BigInteger v) => BigInteger.ModPow(ModN(v), N - 2, N);


    public static (BigInteger X, BigInteger Y) AffineAdd((BigInteger X, BigInteger Y) a, (BigInteger X, BigInteger Y) b)
    {
        if(a.X == b.X && a.Y == b.Y)
        {
            return AffineDouble(a);
        }

        BigInteger slope = Mod((b.Y - a.Y) * ModInverse(b.X - a.X));
        BigInteger x3 = Mod((slope * slope) - a.X - b.X);

        return (x3, Mod((slope * (a.X - x3)) - a.Y));
    }


    public static (BigInteger X, BigInteger Y) AffineDouble((BigInteger X, BigInteger Y) a)
    {
        BigInteger slope = Mod(((3 * a.X * a.X) + A) * ModInverse(2 * a.Y));
        BigInteger x3 = Mod((slope * slope) - (2 * a.X));

        return (x3, Mod((slope * (a.X - x3)) - a.Y));
    }


    public static (BigInteger X, BigInteger Y) ScalarMultiply(BigInteger scalar, (BigInteger X, BigInteger Y) point)
    {
        (BigInteger X, BigInteger Y)? accumulator = null;
        (BigInteger X, BigInteger Y) addend = point;
        for(BigInteger m = ModN(scalar); m > 0; m >>= 1)
        {
            if(!(m & BigInteger.One).IsZero)
            {
                accumulator = accumulator is null ? addend : AffineAdd(accumulator.Value, addend);
            }

            addend = AffineDouble(addend);
        }

        return accumulator!.Value;
    }


    //Identity-aware oracle (null = the point at infinity O), for gating the Alg.4 sum.
    public static (BigInteger X, BigInteger Y)? OracleAdd((BigInteger X, BigInteger Y)? a, (BigInteger X, BigInteger Y)? b)
    {
        if(a is null)
        {
            return b;
        }

        if(b is null)
        {
            return a;
        }

        if(a.Value.X == b.Value.X && Mod(a.Value.Y + b.Value.Y).IsZero)
        {
            return null;
        }

        return AffineAdd(a.Value, b.Value);
    }


    public static (BigInteger X, BigInteger Y)? OracleScalarMultiply(BigInteger scalar, (BigInteger X, BigInteger Y) point)
    {
        (BigInteger X, BigInteger Y)? accumulator = null;
        (BigInteger X, BigInteger Y) addend = point;
        for(BigInteger k = ModN(scalar); k > 0; k >>= 1)
        {
            if(!(k & BigInteger.One).IsZero)
            {
                accumulator = OracleAdd(accumulator, addend);
            }

            addend = AffineDouble(addend);
        }

        return accumulator;
    }
}
