using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Constant-time NIST P-256 (secp256r1) secret-scalar point multiplication, exposed as a drop-in
/// <see cref="G1ScalarMultiplyDelegate"/> that is byte-for-byte identical to the variable-time
/// <see cref="P256BigIntegerG1Reference"/> ladder it replaces at the signing seams (ECDSA/SECDSA
/// <c>k·G</c>, the SECDSA split-key derivation, and the DL-equality NIZK commitments).
/// </summary>
/// <remarks>
/// <para>
/// The reference ladder leaks the secret scalar two ways: the per-bit add executes only for set bits
/// (a square-and-multiply Hamming-weight/bit-pattern channel) and its loop walks the minimal big-endian
/// byte length of <c>k</c> (a magnitude channel). This backend closes both with a fixed 256-iteration
/// double-and-add-<em>always</em> over the <em>complete</em> Renes–Costello–Batina 2016 addition/doubling
/// formulas (<see href="https://eprint.iacr.org/2015/1060.pdf">eprint 2015/1060</see>, the same
/// operation sequence the in-tree oracle <c>ProjectivePointFp256</c> carries): every bit does one
/// doubling and one addition unconditionally, and a branch-free <see cref="ConstantTimeSelect"/> on the
/// secret bit keeps the doubled-plus-base point or the doubled point. Complete formulas mean the
/// reference's data-dependent exceptional-case branches (P=Q, P=−P, identity, y=0) simply do not exist,
/// so there is no secret-dependent branch and no secret-indexed memory access; there is no precompute
/// table, so no constant-time gather is needed.
/// </para>
/// <para>
/// All field arithmetic runs over the shipped constant-time base field
/// <see cref="P256BaseFieldMontgomeryBackend"/> (CIOS Montgomery multiply; Fermat inversion over the
/// <em>public</em> exponent <c>p−2</c>) — never <c>BigInteger.ModPow</c> or <c>%</c> on a secret
/// coordinate. At every secret-scalar call site the multiplied <em>point</em> is public (the generator
/// or a public generator <c>G_i</c>) and only the <em>scalar</em> is secret, so decoding the input point
/// and encoding the output point (both a deterministic function of public values — the output <c>R</c>
/// has its x-coordinate published as <c>r</c>) reuse the reference's <see cref="P256BigIntegerG1Reference"/>
/// paths and are not secret-bearing.
/// </para>
/// <para>
/// This is best-effort <em>managed</em> constant time: the source carries no secret-dependent branch,
/// no secret-indexed access, and a branch-free select, but the JIT may still lower a masked blend to a
/// conditional move, the GC may pause mid-ladder, and cache/branch-predictor state is uncontrolled. A
/// hardened native backend behind the same delegate stays the long-term answer; see <c>SECURITY.md</c>.
/// Correctness-first: the field ops run in the canonical domain (two CIOS per multiply); a single-CIOS
/// Montgomery-domain ladder is a deferred perf item.
/// </para>
/// </remarks>
internal static class P256ConstantTimeG1Backend
{
    private const int CoordinateSize = 32;
    private const int ScalarSizeBytes = 32;

    //The complete-formula field operations run in the canonical domain over the shipped constant-time
    //P-256 base field; the delegates are cached once (base-field arithmetic ignores the curve argument).
    private static readonly ScalarAddDelegate FieldAdd = P256BaseFieldMontgomeryBackend.GetAdd();
    private static readonly ScalarSubtractDelegate FieldSubtract = P256BaseFieldMontgomeryBackend.GetSubtract();
    private static readonly ScalarMultiplyDelegate FieldMultiply = P256BaseFieldMontgomeryBackend.GetMultiply();
    private static readonly ScalarInvertDelegate FieldInvert = P256BaseFieldMontgomeryBackend.GetInvert();

    //The curve coefficient a = p − 3 and the Renes–Costello–Batina constant k3b = 3·b mod p, as canonical
    //32-byte big-endian field elements. Public curve data, derived once from the reference constants.
    private static readonly byte[] CurveACanonical = ToCanonical(P256BigIntegerG1Reference.CurveA);
    private static readonly byte[] CurveK3bCanonical = ToCanonical(
        P256BigIntegerG1Reference.Mod(3 * P256BigIntegerG1Reference.CurveB, P256BigIntegerG1Reference.BaseFieldPrime));


    /// <summary>Returns the constant-time P-256 scalar-multiply delegate.</summary>
    public static G1ScalarMultiplyDelegate GetScalarMultiply() => ScalarMultiply;


    private static void ScalarMultiply(ReadOnlySpan<byte> point, ReadOnlySpan<byte> scalar, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1ScalarMultiply, curve);

        //The base point is public at every secret-scalar site, so decoding it here is not a secret path.
        P256BigIntegerG1Reference.AffinePoint basePoint = P256BigIntegerG1Reference.Decode(point);
        if(basePoint.IsInfinity)
        {
            P256BigIntegerG1Reference.Encode(P256BigIntegerG1Reference.AffinePoint.Identity, result);

            return;
        }

        //Lift the base to homogeneous projective (x : y : 1) in canonical field bytes.
        Span<byte> baseX = stackalloc byte[CoordinateSize];
        Span<byte> baseY = stackalloc byte[CoordinateSize];
        Span<byte> baseZ = stackalloc byte[CoordinateSize];
        WriteCanonical(basePoint.X, baseX);
        WriteCanonical(basePoint.Y, baseY);
        SetOne(baseZ);

        //accumulator = identity (0 : 1 : 0).
        Span<byte> accX = stackalloc byte[CoordinateSize];
        Span<byte> accY = stackalloc byte[CoordinateSize];
        Span<byte> accZ = stackalloc byte[CoordinateSize];
        accX.Clear();
        SetOne(accY);
        accZ.Clear();

        //Scratch for the always-computed doubled point and doubled-plus-base point.
        Span<byte> doubledX = stackalloc byte[CoordinateSize];
        Span<byte> doubledY = stackalloc byte[CoordinateSize];
        Span<byte> doubledZ = stackalloc byte[CoordinateSize];
        Span<byte> sumX = stackalloc byte[CoordinateSize];
        Span<byte> sumY = stackalloc byte[CoordinateSize];
        Span<byte> sumZ = stackalloc byte[CoordinateSize];

        //Fixed 256-iteration double-and-add-always, most-significant bit first over the full 32-byte
        //scalar. The loop count is constant (no minimal-byte-length magnitude leak); the addition is
        //always computed and kept or discarded by a branch-free select on the secret bit.
        for(int byteIndex = 0; byteIndex < ScalarSizeBytes; byteIndex++)
        {
            int octet = scalar[byteIndex];
            for(int bitIndex = 7; bitIndex >= 0; bitIndex--)
            {
                PointDouble(accX, accY, accZ, doubledX, doubledY, doubledZ);
                PointAdd(doubledX, doubledY, doubledZ, baseX, baseY, baseZ, sumX, sumY, sumZ);

                int bit = (octet >> bitIndex) & 1;
                ConstantTimeSelect(sumX, doubledX, bit, accX);
                ConstantTimeSelect(sumY, doubledY, bit, accY);
                ConstantTimeSelect(sumZ, doubledZ, bit, accZ);
            }
        }

        //Whether the result is the identity is a property of the public inputs (for a valid nonce over the
        //public generator it never is), so this branch reveals nothing secret.
        if(IsZeroField(accZ))
        {
            P256BigIntegerG1Reference.Encode(P256BigIntegerG1Reference.AffinePoint.Identity, result);

            return;
        }

        //Normalize (X/Z, Y/Z) via the constant-time Fermat inverse over the public exponent p − 2.
        Span<byte> zInverse = stackalloc byte[CoordinateSize];
        FieldInvert(accZ, zInverse, CurveParameterSet.None);

        Span<byte> affineX = stackalloc byte[CoordinateSize];
        Span<byte> affineY = stackalloc byte[CoordinateSize];
        FieldMultiply(accX, zInverse, affineX, CurveParameterSet.None);
        FieldMultiply(accY, zInverse, affineY, CurveParameterSet.None);

        //Re-encoding the public output point through the reference guarantees the exact SEC1 byte layout.
        P256BigIntegerG1Reference.AffinePoint affine = new(
            new BigInteger(affineX, isUnsigned: true, isBigEndian: true),
            new BigInteger(affineY, isUnsigned: true, isBigEndian: true),
            IsInfinity: false);
        P256BigIntegerG1Reference.Encode(affine, result);
    }


    //Complete projective addition — Algorithm 1 of eprint 2015/1060, the same operation-for-operation
    //sequence as ProjectivePointFp256.Add, with the BigInteger field ops replaced by the constant-time
    //canonical base-field delegates. Valid for all inputs (equal points, identity, inverses); the output
    //buffers (x3, y3, z3) must not alias any input. Every field op reads both operands before writing its
    //result, so the in-place variable reuse below is alias-safe.
    private static void PointAdd(
        ReadOnlySpan<byte> x1, ReadOnlySpan<byte> y1, ReadOnlySpan<byte> z1,
        ReadOnlySpan<byte> x2, ReadOnlySpan<byte> y2, ReadOnlySpan<byte> z2,
        Span<byte> x3, Span<byte> y3, Span<byte> z3)
    {
        Span<byte> t0 = stackalloc byte[CoordinateSize];
        Span<byte> t1 = stackalloc byte[CoordinateSize];
        Span<byte> t2 = stackalloc byte[CoordinateSize];
        Span<byte> t3 = stackalloc byte[CoordinateSize];
        Span<byte> t4 = stackalloc byte[CoordinateSize];
        Span<byte> t5 = stackalloc byte[CoordinateSize];

        Multiply(x1, x2, t0);
        Multiply(y1, y2, t1);
        Multiply(z1, z2, t2);
        Add(x1, y1, t3);
        Add(x2, y2, t4);
        Multiply(t3, t4, t3);
        Add(t0, t1, t4);
        Subtract(t3, t4, t3);
        Add(x1, z1, t4);
        Add(x2, z2, t5);
        Multiply(t4, t5, t4);
        Add(t0, t2, t5);
        Subtract(t4, t5, t4);
        Add(y1, z1, t5);
        Add(y2, z2, x3);
        Multiply(t5, x3, t5);
        Add(t1, t2, x3);
        Subtract(t5, x3, t5);
        Multiply(CurveACanonical, t4, z3);
        Multiply(CurveK3bCanonical, t2, x3);
        Add(x3, z3, z3);
        Subtract(t1, z3, x3);
        Add(t1, z3, z3);
        Multiply(x3, z3, y3);
        Add(t0, t0, t1);
        Add(t1, t0, t1);
        Multiply(CurveACanonical, t2, t2);
        Multiply(CurveK3bCanonical, t4, t4);
        Add(t1, t2, t1);
        Subtract(t0, t2, t2);
        Multiply(CurveACanonical, t2, t2);
        Add(t4, t2, t4);
        Multiply(t1, t4, t0);
        Add(y3, t0, y3);
        Multiply(t5, t4, t0);
        Multiply(t3, x3, x3);
        Subtract(x3, t0, x3);
        Multiply(t3, t1, t0);
        Multiply(t5, z3, z3);
        Add(z3, t0, z3);
    }


    //Complete projective doubling — Algorithm 3 of eprint 2015/1060, matching ProjectivePointFp256.Double.
    //The output buffers (x3, y3, z3) must not alias any input.
    private static void PointDouble(
        ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, ReadOnlySpan<byte> z,
        Span<byte> x3, Span<byte> y3, Span<byte> z3)
    {
        Span<byte> t0 = stackalloc byte[CoordinateSize];
        Span<byte> t1 = stackalloc byte[CoordinateSize];
        Span<byte> t2 = stackalloc byte[CoordinateSize];
        Span<byte> t3 = stackalloc byte[CoordinateSize];

        Multiply(x, x, t0);
        Multiply(y, y, t1);
        Multiply(z, z, t2);
        Multiply(x, y, t3);
        Add(t3, t3, t3);
        Multiply(x, z, z3);
        Add(z3, z3, z3);
        Multiply(CurveACanonical, z3, x3);
        Multiply(CurveK3bCanonical, t2, y3);
        Add(x3, y3, y3);
        Subtract(t1, y3, x3);
        Add(t1, y3, y3);
        Multiply(x3, y3, y3);
        Multiply(t3, x3, x3);
        Multiply(CurveK3bCanonical, z3, z3);
        Multiply(CurveACanonical, t2, t2);
        Subtract(t0, t2, t3);
        Multiply(CurveACanonical, t3, t3);
        Add(t3, z3, t3);
        Add(t0, t0, z3);
        Add(z3, t0, t0);
        Add(t0, t2, t0);
        Multiply(t0, t3, t0);
        Add(y3, t0, y3);
        Multiply(y, z, t2);
        Add(t2, t2, t2);
        Multiply(t2, t3, t0);
        Subtract(x3, t0, x3);
        Multiply(t2, t1, z3);
        Add(z3, z3, z3);
        Add(z3, z3, z3);
    }


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result) =>
        FieldAdd(a, b, result, CurveParameterSet.None);


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result) =>
        FieldSubtract(a, b, result, CurveParameterSet.None);


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result) =>
        FieldMultiply(a, b, result, CurveParameterSet.None);


    //Branch-free blend: onTrue when the secret bit is 1, else onFalse. The full-width mask is derived
    //arithmetically from the 0/1 bit (no `? :`), mirroring PrimeField256.Select, so the JIT is not invited
    //to lower a value-selecting ternary to a conditional move.
    private static void ConstantTimeSelect(ReadOnlySpan<byte> onTrue, ReadOnlySpan<byte> onFalse, int bit, Span<byte> destination)
    {
        byte mask = (byte)(0 - bit);
        for(int i = 0; i < CoordinateSize; i++)
        {
            destination[i] = (byte)((onTrue[i] & mask) | (onFalse[i] & (byte)~mask));
        }
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


    private static void SetOne(Span<byte> canonical)
    {
        canonical.Clear();
        canonical[CoordinateSize - 1] = 1;
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
            throw new InvalidOperationException("A P-256 field element did not fit in 32 bytes.");
        }

        if(written < CoordinateSize)
        {
            int shift = CoordinateSize - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
