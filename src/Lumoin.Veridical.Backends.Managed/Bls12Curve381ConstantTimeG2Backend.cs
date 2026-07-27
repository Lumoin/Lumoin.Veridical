using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Constant-time BLS12-381 G2 secret-scalar point multiplication, exposed as a drop-in
/// <see cref="G2ScalarMultiplyDelegate"/> that is byte-for-byte identical to the variable-time
/// <see cref="Bls12Curve381BigIntegerG2Reference"/> it replaces at the BBS key-generation seam
/// (<c>PK = SK·BP2</c> — the long-term secret key against the G2 base point).
/// </summary>
/// <remarks>
/// <para>
/// The reference G2 multiplication is affine double-and-add: it branches on every secret bit
/// <em>and</em> pays a data-dependent Fp2 inversion per iteration, making it the leakiest ladder in
/// the backend set. This backend replaces it with the shared
/// <see cref="ConstantTimeWeierstrassLadder"/> — the identical complete-formula
/// double-and-add-always that serves the G1 backends — instantiated over the constant-time
/// quadratic extension field <see cref="Bls12Curve381ConstantTimeFp2Backend"/>: 96-byte
/// <c>[c0|c1]</c> elements whose component arithmetic is the CIOS Montgomery base field. The twist
/// curve <c>y² = x³ + 4(1+u)</c> carries an odd-order group (odd cofactor times the prime subgroup
/// order), so the complete formulas are exception-free on it, exactly as on G1.
/// </para>
/// <para>
/// At the secret-scalar call site the multiplied point is the public G2 base point and only the
/// scalar is secret, so decoding the input point and encoding the output point (the published
/// public key) reuse the reference's paths — including its <c>[x.c1 : x.c0]</c> wire order and
/// larger-y flag rule — and are not secret-bearing. The final projective-to-affine normalize is one
/// constant-time Fp2 inversion (a norm plus a Fermat inversion over the public exponent).
/// </para>
/// <para>
/// This is best-effort <em>managed</em> constant time with the same limits as the other
/// constant-time ladders; see <c>SECURITY.md</c>.
/// </para>
/// </remarks>
internal static class Bls12Curve381ConstantTimeG2Backend
{
    private const int ComponentSize = Bls12Curve381BaseFieldMontgomeryBackend.ElementSize;
    private const int ElementSize = Bls12Curve381ConstantTimeFp2Backend.ElementSize;

    /// <summary>
    /// The cached constant-time Fp2 addition the complete formulas run on; extension-field
    /// arithmetic ignores the curve argument.
    /// </summary>
    private static ScalarAddDelegate FieldAdd { get; } = Bls12Curve381ConstantTimeFp2Backend.GetAdd();

    /// <summary>The cached constant-time Fp2 subtraction.</summary>
    private static ScalarSubtractDelegate FieldSubtract { get; } = Bls12Curve381ConstantTimeFp2Backend.GetSubtract();

    /// <summary>The cached constant-time Fp2 multiplication.</summary>
    private static ScalarMultiplyDelegate FieldMultiply { get; } = Bls12Curve381ConstantTimeFp2Backend.GetMultiply();

    /// <summary>The cached constant-time Fp2 inversion for the final normalize.</summary>
    private static ScalarInvertDelegate FieldInvert { get; } = Bls12Curve381ConstantTimeFp2Backend.GetInvert();

    /// <summary>
    /// The twist coefficient a = 0, as a canonical 96-byte [c0|c1] Fp2 element. Public curve data,
    /// derived once from the reference constants.
    /// </summary>
    private static byte[] CurveACanonical { get; } = new byte[ElementSize];
    /// <summary>
    /// The Renes–Costello–Batina constant 3·b' = 12 + 12u, as a canonical 96-byte [c0|c1] Fp2
    /// element. Public curve data, derived once from the reference constants.
    /// </summary>
    private static byte[] CurveBTimes3Canonical { get; } = ToCanonicalFp2(new Bls12Curve381BigIntegerG2Reference.Fp2Value(
        Bls12Curve381BigIntegerG1Reference.Mod(3 * Bls12Curve381BigIntegerG2Reference.CurveB.C0, Bls12Curve381BigIntegerG1Reference.BaseFieldPrime),
        Bls12Curve381BigIntegerG1Reference.Mod(3 * Bls12Curve381BigIntegerG2Reference.CurveB.C1, Bls12Curve381BigIntegerG1Reference.BaseFieldPrime)));
    private static byte[] OneCanonical { get; } = ToCanonicalFp2(new Bls12Curve381BigIntegerG2Reference.Fp2Value(BigInteger.One, BigInteger.Zero));


    /// <summary>Returns the constant-time BLS12-381 G2 scalar-multiply delegate.</summary>
    public static G2ScalarMultiplyDelegate GetScalarMultiply() => ScalarMultiply;


    /// <summary>
    /// The ladder field the trace gate re-wraps with recording delegates: the cached constant-time
    /// Fp2 operations plus the public twist constants.
    /// </summary>
    internal static ConstantTimeLadderField CreateLadderField() =>
        new(FieldAdd, FieldSubtract, FieldMultiply, CurveACanonical, CurveBTimes3Canonical, OneCanonical);


    private static void ScalarMultiply(ReadOnlySpan<byte> point, ReadOnlySpan<byte> scalar, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G2ScalarMultiply, curve);

        //The base point is public at the secret-scalar site, so decoding it here is not a secret path.
        Bls12Curve381BigIntegerG2Reference.AffinePoint basePoint = Bls12Curve381BigIntegerG2Reference.Decode(point);
        if(basePoint.IsInfinity)
        {
            Bls12Curve381BigIntegerG2Reference.Encode(Bls12Curve381BigIntegerG2Reference.AffinePoint.Identity, result);

            return;
        }

        Span<byte> baseX = stackalloc byte[ElementSize];
        Span<byte> baseY = stackalloc byte[ElementSize];
        WriteCanonicalFp2(basePoint.X, baseX);
        WriteCanonicalFp2(basePoint.Y, baseY);

        Span<byte> accumulatorX = stackalloc byte[ElementSize];
        Span<byte> accumulatorY = stackalloc byte[ElementSize];
        Span<byte> accumulatorZ = stackalloc byte[ElementSize];
        ConstantTimeLadderField field = CreateLadderField();
        ConstantTimeWeierstrassLadder.ScalarMultiply(field, baseX, baseY, scalar, accumulatorX, accumulatorY, accumulatorZ);

        //This branch fires exactly when the encoded output is the identity point — a fact the returned
        //bytes publish anyway — so its direction reveals nothing beyond the output; every wired secret
        //scalar is nonzero modulo the subgroup order, so in practice it never fires on a secret path.
        if(IsZeroElement(accumulatorZ))
        {
            Bls12Curve381BigIntegerG2Reference.Encode(Bls12Curve381BigIntegerG2Reference.AffinePoint.Identity, result);

            return;
        }

        //Normalize (X/Z, Y/Z) via the constant-time Fp2 inversion.
        Span<byte> zInverse = stackalloc byte[ElementSize];
        FieldInvert(accumulatorZ, zInverse, CurveParameterSet.None);

        Span<byte> affineX = stackalloc byte[ElementSize];
        Span<byte> affineY = stackalloc byte[ElementSize];
        FieldMultiply(accumulatorX, zInverse, affineX, CurveParameterSet.None);
        FieldMultiply(accumulatorY, zInverse, affineY, CurveParameterSet.None);

        //Re-encoding the public output point through the reference guarantees the exact compressed byte
        //layout (the [x.c1 : x.c0] order and the larger-y flag rule included).
        Bls12Curve381BigIntegerG2Reference.AffinePoint affine = new(ReadCanonicalFp2(affineX), ReadCanonicalFp2(affineY), IsInfinity: false);
        Bls12Curve381BigIntegerG2Reference.Encode(affine, result);
    }


    private static bool IsZeroElement(ReadOnlySpan<byte> value)
    {
        int accumulated = 0;
        for(int i = 0; i < ElementSize; i++)
        {
            accumulated |= value[i];
        }

        return accumulated == 0;
    }


    private static byte[] ToCanonicalFp2(Bls12Curve381BigIntegerG2Reference.Fp2Value value)
    {
        byte[] canonical = new byte[ElementSize];
        WriteCanonicalFp2(value, canonical);

        return canonical;
    }


    /// <summary>
    /// The ladder-internal Fp2 layout is [c0 : 48 BE][c1 : 48 BE], matching the constant-time Fp2
    /// backend (the point wire encoding's [x.c1 : x.c0] order is the reference Encode's concern).
    /// </summary>
    private static void WriteCanonicalFp2(Bls12Curve381BigIntegerG2Reference.Fp2Value value, Span<byte> destination)
    {
        WriteCanonicalComponent(value.C0, destination[..ComponentSize]);
        WriteCanonicalComponent(value.C1, destination[ComponentSize..ElementSize]);
    }


    private static Bls12Curve381BigIntegerG2Reference.Fp2Value ReadCanonicalFp2(ReadOnlySpan<byte> source)
    {
        return new Bls12Curve381BigIntegerG2Reference.Fp2Value(
            new BigInteger(source[..ComponentSize], isUnsigned: true, isBigEndian: true),
            new BigInteger(source[ComponentSize..ElementSize], isUnsigned: true, isBigEndian: true));
    }


    private static void WriteCanonicalComponent(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("A BLS12-381 base-field component did not fit in 48 bytes.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
