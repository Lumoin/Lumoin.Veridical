using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Constant-time BN254 G1 secret-scalar point multiplication, exposed as a drop-in
/// <see cref="G1ScalarMultiplyDelegate"/> that is byte-for-byte identical to the variable-time
/// <see cref="Bn254BigIntegerG1Reference"/> ladder it replaces at the prover-side seams that
/// carry secret scalars (Hyrax opening blinds and the inner-product-argument prover scalars flow
/// through the single-scalar-multiply delegate; the multi-scalar Pippenger seam is a separately
/// documented boundary).
/// </summary>
/// <remarks>
/// <para>
/// The reference ladder leaks the secret scalar two ways: the per-bit add executes only for set bits
/// (a square-and-multiply Hamming-weight/bit-pattern channel) and its loop walks the minimal big-endian
/// byte length of <c>k</c> (a magnitude channel). This backend closes both with the shared
/// <see cref="ConstantTimeWeierstrassLadder"/> — a fixed-iteration double-and-add-always over the
/// complete Renes–Costello–Batina formulas — running on the constant-time base field
/// <see cref="Bn254BaseFieldMontgomeryBackend"/> (CIOS Montgomery multiply; Fermat inversion over the
/// <em>public</em> exponent <c>p−2</c>), never <c>BigInteger.ModPow</c> or <c>%</c> on a secret
/// coordinate. BN254 has cofactor one, so the curve order is the odd prime subgroup order and the
/// complete formulas are exception-free on the whole curve.
/// </para>
/// <para>
/// At every call site the multiplied <em>point</em> is public (a commitment-key generator or a
/// public commitment) and only the <em>scalar</em> may be secret, so decoding the input point and
/// encoding the output point reuse the reference's <see cref="Bn254BigIntegerG1Reference"/> paths
/// (the gnark-style two-bit-tag layout included) and are not secret-bearing.
/// </para>
/// <para>
/// This is best-effort <em>managed</em> constant time with the same limits as the other
/// constant-time ladders; see <c>SECURITY.md</c>. Correctness-first: the field ops run in the
/// canonical domain (two CIOS per multiply); a Montgomery-domain ladder is a deferred perf item.
/// </para>
/// </remarks>
internal static class Bn254ConstantTimeG1Backend
{
    private const int CoordinateSize = Bn254BaseFieldMontgomeryBackend.ElementSize;

    /// <summary>
    /// The cached constant-time base-field addition the complete formulas run on, in the canonical
    /// domain; base-field arithmetic ignores the curve argument.
    /// </summary>
    private static ScalarAddDelegate FieldAdd { get; } = Bn254BaseFieldMontgomeryBackend.GetAdd();

    /// <summary>The cached constant-time base-field subtraction.</summary>
    private static ScalarSubtractDelegate FieldSubtract { get; } = Bn254BaseFieldMontgomeryBackend.GetSubtract();

    /// <summary>The cached constant-time base-field multiplication.</summary>
    private static ScalarMultiplyDelegate FieldMultiply { get; } = Bn254BaseFieldMontgomeryBackend.GetMultiply();

    /// <summary>The cached constant-time base-field Fermat inversion for the final normalize.</summary>
    private static ScalarInvertDelegate FieldInvert { get; } = Bn254BaseFieldMontgomeryBackend.GetInvert();

    /// <summary>
    /// The curve coefficient a = 0, as a canonical 32-byte big-endian field element. Public curve
    /// data, derived once from the reference constants.
    /// </summary>
    private static byte[] CurveACanonical { get; } = new byte[CoordinateSize];
    /// <summary>
    /// The Renes–Costello–Batina constant 3·b = 9 mod p, as a canonical 32-byte big-endian field
    /// element. Public curve data, derived once from the reference constants.
    /// </summary>
    private static byte[] CurveBTimes3Canonical { get; } = ToCanonical(
        Bn254BigIntegerG1Reference.Mod(3 * Bn254BigIntegerG1Reference.CurveB, Bn254BigIntegerG1Reference.BaseFieldPrime));
    private static byte[] OneCanonical { get; } = ToCanonical(BigInteger.One);


    /// <summary>Returns the constant-time BN254 G1 scalar-multiply delegate.</summary>
    public static G1ScalarMultiplyDelegate GetScalarMultiply() => ScalarMultiply;


    /// <summary>
    /// The ladder field the trace gate re-wraps with recording delegates: the cached constant-time
    /// base-field operations plus the public curve constants.
    /// </summary>
    internal static ConstantTimeLadderField CreateLadderField() =>
        new(FieldAdd, FieldSubtract, FieldMultiply, CurveACanonical, CurveBTimes3Canonical, OneCanonical);


    private static void ScalarMultiply(ReadOnlySpan<byte> point, ReadOnlySpan<byte> scalar, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1ScalarMultiply, curve);

        //The base point is public at every secret-scalar site, so decoding it here is not a secret path.
        Bn254BigIntegerG1Reference.AffinePoint basePoint = Bn254BigIntegerG1Reference.Decode(point);
        if(basePoint.IsInfinity)
        {
            Bn254BigIntegerG1Reference.Encode(Bn254BigIntegerG1Reference.AffinePoint.Identity, result);

            return;
        }

        Span<byte> baseX = stackalloc byte[CoordinateSize];
        Span<byte> baseY = stackalloc byte[CoordinateSize];
        WriteCanonical(basePoint.X, baseX);
        WriteCanonical(basePoint.Y, baseY);

        Span<byte> accumulatorX = stackalloc byte[CoordinateSize];
        Span<byte> accumulatorY = stackalloc byte[CoordinateSize];
        Span<byte> accumulatorZ = stackalloc byte[CoordinateSize];
        ConstantTimeLadderField field = CreateLadderField();
        ConstantTimeWeierstrassLadder.ScalarMultiply(field, baseX, baseY, scalar, accumulatorX, accumulatorY, accumulatorZ);

        //This branch fires exactly when the encoded output is the identity point — a fact the returned
        //bytes publish anyway — so its direction reveals nothing beyond the output; every wired secret
        //scalar is nonzero modulo the group order, so in practice it never fires on a secret path.
        if(IsZeroField(accumulatorZ))
        {
            Bn254BigIntegerG1Reference.Encode(Bn254BigIntegerG1Reference.AffinePoint.Identity, result);

            return;
        }

        //Normalize (X/Z, Y/Z) via the constant-time Fermat inverse over the public exponent p − 2.
        Span<byte> zInverse = stackalloc byte[CoordinateSize];
        FieldInvert(accumulatorZ, zInverse, CurveParameterSet.None);

        Span<byte> affineX = stackalloc byte[CoordinateSize];
        Span<byte> affineY = stackalloc byte[CoordinateSize];
        FieldMultiply(accumulatorX, zInverse, affineX, CurveParameterSet.None);
        FieldMultiply(accumulatorY, zInverse, affineY, CurveParameterSet.None);

        //Re-encoding the public output point through the reference guarantees the exact compressed byte
        //layout (the gnark two-bit tag rule included).
        Bn254BigIntegerG1Reference.AffinePoint affine = new(
            new BigInteger(affineX, isUnsigned: true, isBigEndian: true),
            new BigInteger(affineY, isUnsigned: true, isBigEndian: true),
            IsInfinity: false);
        Bn254BigIntegerG1Reference.Encode(affine, result);
    }


    private static bool IsZeroField(ReadOnlySpan<byte> value)
    {
        int accumulated = 0;
        for(int i = 0; i < CoordinateSize; i++)
        {
            accumulated |= value[i];
        }

        return accumulated == 0;
    }


    private static byte[] ToCanonical(BigInteger value)
    {
        byte[] canonical = new byte[CoordinateSize];
        WriteCanonical(value, canonical);

        return canonical;
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("A BN254 base-field element did not fit in 32 bytes.");
        }

        if(written < CoordinateSize)
        {
            int shift = CoordinateSize - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
