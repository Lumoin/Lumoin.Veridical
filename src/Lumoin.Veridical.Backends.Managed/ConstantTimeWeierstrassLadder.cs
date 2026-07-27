using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The field operations and public curve constants a <see cref="ConstantTimeWeierstrassLadder"/>
/// run rides on: constant-time canonical-bytes add/subtract/multiply delegates over a fixed
/// element size, plus the curve coefficient <c>a</c>, the Renes–Costello–Batina constant
/// <c>3·b</c>, and the field's one — all as canonical big-endian elements. The element size is
/// implied by <see cref="One"/>; every span the ladder touches has that length, which is what
/// lets the same ladder serve a 48-byte prime field, a 32-byte prime field, or a concatenated
/// extension-field element behind extension-field delegates.
/// </summary>
internal readonly ref struct ConstantTimeLadderField
{
    public ConstantTimeLadderField(
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ReadOnlySpan<byte> curveA,
        ReadOnlySpan<byte> curveBTimes3,
        ReadOnlySpan<byte> one)
    {
        Add = add;
        Subtract = subtract;
        Multiply = multiply;
        CurveA = curveA;
        CurveBTimes3 = curveBTimes3;
        One = one;
    }


    /// <summary>Field addition over canonical elements; the curve argument is passed as <see cref="CurveParameterSet.None"/>.</summary>
    public ScalarAddDelegate Add { get; }

    /// <summary>Field subtraction over canonical elements.</summary>
    public ScalarSubtractDelegate Subtract { get; }

    /// <summary>Field multiplication over canonical elements.</summary>
    public ScalarMultiplyDelegate Multiply { get; }

    /// <summary>The curve coefficient <c>a</c> as a canonical element (all zero for the pairing curves' <c>a = 0</c>).</summary>
    public ReadOnlySpan<byte> CurveA { get; }

    /// <summary>The Renes–Costello–Batina constant <c>3·b mod p</c> as a canonical element.</summary>
    public ReadOnlySpan<byte> CurveBTimes3 { get; }

    /// <summary>The field's multiplicative identity as a canonical element; its length fixes the element size.</summary>
    public ReadOnlySpan<byte> One { get; }

    /// <summary>The canonical byte length of one field element.</summary>
    public int ElementSize => One.Length;
}


/// <summary>
/// Field-generic constant-time scalar multiplication on a short Weierstrass curve: a fixed-iteration
/// double-and-add-<em>always</em> ladder over the <em>complete</em> Renes–Costello–Batina addition and
/// doubling formulas (<see href="https://eprint.iacr.org/2015/1060.pdf">eprint 2015/1060</see>,
/// Algorithms 1 and 3), the same operation-for-operation sequence the shipped
/// <see cref="P256ConstantTimeG1Backend"/> carries, lifted one level: the field arithmetic and the
/// curve constants arrive through a <see cref="ConstantTimeLadderField"/> instead of being baked in,
/// so the identical ladder serves BLS12-381 G1 (48-byte base field, <c>a = 0</c>), BN254 G1
/// (32-byte base field, <c>a = 0</c>), and an extension-field group behind extension-field delegates.
/// </summary>
/// <remarks>
/// <para>
/// Every scalar bit performs one complete doubling and one complete addition unconditionally, and a
/// branch-free <see cref="Select"/> on the secret bit keeps the doubled-plus-base point or the doubled
/// point. The loop count is fixed by the scalar span length (no minimal-byte-length magnitude leak),
/// complete formulas remove the data-dependent exceptional-case branches (P=Q, P=−P, identity, y=0 —
/// the general Algorithms 1/3 are exception-free for any curve coefficient, including <c>a = 0</c>,
/// on odd-order curves), and there is no precompute table, so no secret-indexed access exists. The
/// multiplications by <see cref="ConstantTimeLadderField.CurveA"/> are retained even when <c>a</c> is
/// zero: they keep the operation sequence identical across curves and secret values, at a cost the
/// house correctness-first rule accepts.
/// </para>
/// <para>
/// The injected delegates are the constant-time discipline boundary: at delegate granularity the
/// ladder issues a scalar-independent operation sequence (the witness-independence trace gate pins
/// this), and inside one field operation the backend's own discipline applies. This is best-effort
/// <em>managed</em> constant time with the same limits as the P-256 ladder; see <c>SECURITY.md</c>.
/// </para>
/// </remarks>
internal static class ConstantTimeWeierstrassLadder
{
    /// <summary>
    /// Complete projective addition — Algorithm 1 of eprint 2015/1060, the operation-for-operation
    /// transcription carried by <see cref="P256ConstantTimeG1Backend"/> with the field ops routed
    /// through the injected delegates. Valid for all inputs on an odd-order curve (equal points,
    /// identity, inverses); the output buffers must not alias any input. Every field op reads both
    /// operands before writing its result, so the in-place variable reuse below is alias-safe.
    /// </summary>
    internal static void PointAdd(
        in ConstantTimeLadderField field,
        ReadOnlySpan<byte> x1, ReadOnlySpan<byte> y1, ReadOnlySpan<byte> z1,
        ReadOnlySpan<byte> x2, ReadOnlySpan<byte> y2, ReadOnlySpan<byte> z2,
        Span<byte> x3, Span<byte> y3, Span<byte> z3)
    {
        int size = field.ElementSize;
        Span<byte> t0 = stackalloc byte[size];
        Span<byte> t1 = stackalloc byte[size];
        Span<byte> t2 = stackalloc byte[size];
        Span<byte> t3 = stackalloc byte[size];
        Span<byte> t4 = stackalloc byte[size];
        Span<byte> t5 = stackalloc byte[size];

        field.Multiply(x1, x2, t0, CurveParameterSet.None);
        field.Multiply(y1, y2, t1, CurveParameterSet.None);
        field.Multiply(z1, z2, t2, CurveParameterSet.None);
        field.Add(x1, y1, t3, CurveParameterSet.None);
        field.Add(x2, y2, t4, CurveParameterSet.None);
        field.Multiply(t3, t4, t3, CurveParameterSet.None);
        field.Add(t0, t1, t4, CurveParameterSet.None);
        field.Subtract(t3, t4, t3, CurveParameterSet.None);
        field.Add(x1, z1, t4, CurveParameterSet.None);
        field.Add(x2, z2, t5, CurveParameterSet.None);
        field.Multiply(t4, t5, t4, CurveParameterSet.None);
        field.Add(t0, t2, t5, CurveParameterSet.None);
        field.Subtract(t4, t5, t4, CurveParameterSet.None);
        field.Add(y1, z1, t5, CurveParameterSet.None);
        field.Add(y2, z2, x3, CurveParameterSet.None);
        field.Multiply(t5, x3, t5, CurveParameterSet.None);
        field.Add(t1, t2, x3, CurveParameterSet.None);
        field.Subtract(t5, x3, t5, CurveParameterSet.None);
        field.Multiply(field.CurveA, t4, z3, CurveParameterSet.None);
        field.Multiply(field.CurveBTimes3, t2, x3, CurveParameterSet.None);
        field.Add(x3, z3, z3, CurveParameterSet.None);
        field.Subtract(t1, z3, x3, CurveParameterSet.None);
        field.Add(t1, z3, z3, CurveParameterSet.None);
        field.Multiply(x3, z3, y3, CurveParameterSet.None);
        field.Add(t0, t0, t1, CurveParameterSet.None);
        field.Add(t1, t0, t1, CurveParameterSet.None);
        field.Multiply(field.CurveA, t2, t2, CurveParameterSet.None);
        field.Multiply(field.CurveBTimes3, t4, t4, CurveParameterSet.None);
        field.Add(t1, t2, t1, CurveParameterSet.None);
        field.Subtract(t0, t2, t2, CurveParameterSet.None);
        field.Multiply(field.CurveA, t2, t2, CurveParameterSet.None);
        field.Add(t4, t2, t4, CurveParameterSet.None);
        field.Multiply(t1, t4, t0, CurveParameterSet.None);
        field.Add(y3, t0, y3, CurveParameterSet.None);
        field.Multiply(t5, t4, t0, CurveParameterSet.None);
        field.Multiply(t3, x3, x3, CurveParameterSet.None);
        field.Subtract(x3, t0, x3, CurveParameterSet.None);
        field.Multiply(t3, t1, t0, CurveParameterSet.None);
        field.Multiply(t5, z3, z3, CurveParameterSet.None);
        field.Add(z3, t0, z3, CurveParameterSet.None);
    }


    /// <summary>
    /// Complete projective doubling — Algorithm 3 of eprint 2015/1060, matching the
    /// <see cref="P256ConstantTimeG1Backend"/> transcription. The output buffers must not alias any input.
    /// </summary>
    internal static void PointDouble(
        in ConstantTimeLadderField field,
        ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, ReadOnlySpan<byte> z,
        Span<byte> x3, Span<byte> y3, Span<byte> z3)
    {
        int size = field.ElementSize;
        Span<byte> t0 = stackalloc byte[size];
        Span<byte> t1 = stackalloc byte[size];
        Span<byte> t2 = stackalloc byte[size];
        Span<byte> t3 = stackalloc byte[size];

        field.Multiply(x, x, t0, CurveParameterSet.None);
        field.Multiply(y, y, t1, CurveParameterSet.None);
        field.Multiply(z, z, t2, CurveParameterSet.None);
        field.Multiply(x, y, t3, CurveParameterSet.None);
        field.Add(t3, t3, t3, CurveParameterSet.None);
        field.Multiply(x, z, z3, CurveParameterSet.None);
        field.Add(z3, z3, z3, CurveParameterSet.None);
        field.Multiply(field.CurveA, z3, x3, CurveParameterSet.None);
        field.Multiply(field.CurveBTimes3, t2, y3, CurveParameterSet.None);
        field.Add(x3, y3, y3, CurveParameterSet.None);
        field.Subtract(t1, y3, x3, CurveParameterSet.None);
        field.Add(t1, y3, y3, CurveParameterSet.None);
        field.Multiply(x3, y3, y3, CurveParameterSet.None);
        field.Multiply(t3, x3, x3, CurveParameterSet.None);
        field.Multiply(field.CurveBTimes3, z3, z3, CurveParameterSet.None);
        field.Multiply(field.CurveA, t2, t2, CurveParameterSet.None);
        field.Subtract(t0, t2, t3, CurveParameterSet.None);
        field.Multiply(field.CurveA, t3, t3, CurveParameterSet.None);
        field.Add(t3, z3, t3, CurveParameterSet.None);
        field.Add(t0, t0, z3, CurveParameterSet.None);
        field.Add(z3, t0, t0, CurveParameterSet.None);
        field.Add(t0, t2, t0, CurveParameterSet.None);
        field.Multiply(t0, t3, t0, CurveParameterSet.None);
        field.Add(y3, t0, y3, CurveParameterSet.None);
        field.Multiply(y, z, t2, CurveParameterSet.None);
        field.Add(t2, t2, t2, CurveParameterSet.None);
        field.Multiply(t2, t3, t0, CurveParameterSet.None);
        field.Subtract(x3, t0, x3, CurveParameterSet.None);
        field.Multiply(t2, t1, z3, CurveParameterSet.None);
        field.Add(z3, z3, z3, CurveParameterSet.None);
        field.Add(z3, z3, z3, CurveParameterSet.None);
    }


    /// <summary>
    /// The fixed-iteration double-and-add-always ladder: multiplies the affine base point
    /// (<paramref name="baseX"/>, <paramref name="baseY"/>) — canonical field elements, not the
    /// identity — by the full <paramref name="scalar"/> span, walking every bit most-significant
    /// first. The accumulator is returned in homogeneous projective coordinates
    /// (<paramref name="accumulatorX"/> : <paramref name="accumulatorY"/> : <paramref name="accumulatorZ"/>);
    /// the caller normalizes with its field's constant-time inversion and encodes. The iteration
    /// count is <c>scalar.Length × 8</c> regardless of the scalar's value, the addition result is
    /// kept or discarded by a branch-free select on the secret bit, and a zero scalar leaves the
    /// accumulator at the projective identity (0 : 1 : 0) without an early return.
    /// </summary>
    /// <remarks>
    /// The fixed-iteration guarantee is only as strong as the span the caller passes: the ladder
    /// walks whatever length it receives, so callers must supply the scalar in its full fixed-width
    /// canonical encoding (32 bytes at every wired site), never a minimal-length trimming such as
    /// <c>BigInteger.ToByteArray</c> produces — a trimmed span would reintroduce the magnitude
    /// channel this ladder exists to close while remaining value-correct on every agreement gate.
    /// </remarks>
    internal static void ScalarMultiply(
        in ConstantTimeLadderField field,
        ReadOnlySpan<byte> baseX,
        ReadOnlySpan<byte> baseY,
        ReadOnlySpan<byte> scalar,
        Span<byte> accumulatorX,
        Span<byte> accumulatorY,
        Span<byte> accumulatorZ)
    {
        int size = field.ElementSize;

        //Lift the base to homogeneous projective (x : y : 1).
        Span<byte> baseZ = stackalloc byte[size];
        field.One.CopyTo(baseZ);

        //accumulator = identity (0 : 1 : 0).
        accumulatorX.Clear();
        accumulatorY.Clear();
        field.One.CopyTo(accumulatorY);
        accumulatorZ.Clear();

        //Scratch for the always-computed doubled point and doubled-plus-base point.
        Span<byte> doubledX = stackalloc byte[size];
        Span<byte> doubledY = stackalloc byte[size];
        Span<byte> doubledZ = stackalloc byte[size];
        Span<byte> sumX = stackalloc byte[size];
        Span<byte> sumY = stackalloc byte[size];
        Span<byte> sumZ = stackalloc byte[size];

        for(int byteIndex = 0; byteIndex < scalar.Length; byteIndex++)
        {
            int octet = scalar[byteIndex];
            for(int bitIndex = 7; bitIndex >= 0; bitIndex--)
            {
                PointDouble(field, accumulatorX, accumulatorY, accumulatorZ, doubledX, doubledY, doubledZ);
                PointAdd(field, doubledX, doubledY, doubledZ, baseX, baseY, baseZ, sumX, sumY, sumZ);

                int bit = (octet >> bitIndex) & 1;
                Select(sumX, doubledX, bit, accumulatorX);
                Select(sumY, doubledY, bit, accumulatorY);
                Select(sumZ, doubledZ, bit, accumulatorZ);
            }
        }
    }


    /// <summary>
    /// Branch-free blend: onTrue when the secret bit is 1, else onFalse. The full-width mask is derived
    /// arithmetically from the 0/1 bit (no `? :`), mirroring PrimeField256.Select, so the JIT is not invited
    /// to lower a value-selecting ternary to a conditional move.
    /// </summary>
    internal static void Select(ReadOnlySpan<byte> onTrue, ReadOnlySpan<byte> onFalse, int bit, Span<byte> destination)
    {
        byte mask = (byte)(0 - bit);
        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)((onTrue[i] & mask) | (onFalse[i] & (byte)~mask));
        }
    }
}
