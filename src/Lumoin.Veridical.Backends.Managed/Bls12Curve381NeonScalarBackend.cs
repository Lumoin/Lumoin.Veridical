using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// NEON (ARM AArch64 Advanced SIMD) implementation of BLS12-381 scalar
/// arithmetic. Mirror of <see cref="Bls12Curve381Avx2ScalarBackend"/> with
/// the lane width halved — NEON registers are 128 bits to AVX2's 256, so
/// batching packs two scalars per pair instead of four per quartet.
/// </summary>
/// <remarks>
/// <para>
/// Same algorithm as the AVX2 backend, same delegate signatures, same
/// per-op counter wiring. Each limb-position holds two scalars in lane 0
/// and lane 1 of a <see cref="Vector128{T}"/>; the carry/borrow chain
/// across the four 64-bit limbs advances both scalars in parallel.
/// </para>
/// <para>
/// Requires AArch64 NEON because the lane-wise unsigned 64-bit compare
/// (<see cref="AdvSimd.Arm64.CompareGreaterThan(Vector128{ulong}, Vector128{ulong})"/>)
/// only exists on the 64-bit instruction set. 32-bit ARM hosts fall
/// through to <see cref="Bls12Curve381BigIntegerScalarReference"/> via
/// <see cref="Bls12Curve381SimdScalarBackend"/>. In practice every
/// modern mobile and ARM-server target is AArch64.
/// </para>
/// <para>
/// Modular reduction uses
/// <see cref="AdvSimd.BitwiseSelect(Vector128{ulong}, Vector128{ulong}, Vector128{ulong})"/>
/// for the constant-time conditional swap. NEON's <c>BSL</c> uses every
/// bit of the selector mask — when our masks are all-ones or all-zeros
/// per lane (which they always are here, produced by unsigned compares),
/// this matches the AVX2 <c>BlendVariable</c> semantics lane-for-lane.
/// </para>
/// </remarks>
internal static class Bls12Curve381NeonScalarBackend
{
    /// <summary>True when the host CPU supports AArch64 NEON. Required for unsigned 64-bit compare.</summary>
    public static bool IsSupported => AdvSimd.Arm64.IsSupported;


    /// <summary>The number of 64-bit limbs that compose a BLS12-381 scalar (256 bits / 64 bits per limb).</summary>
    private const int LimbCount = 4;

    /// <summary>The number of canonical bytes per 64-bit limb.</summary>
    private const int BytesPerLimb = sizeof(ulong);

    /// <summary>
    /// The number of independent scalars packed into one SIMD pair.
    /// Matches the number of 64-bit lanes in <see cref="Vector128{T}"/>:
    /// two scalars share each limb-position register, one per lane.
    /// </summary>
    private const int ScalarsPerPair = 2;

    /// <summary>The number of canonical bytes per scalar pair (two scalars, each <see cref="Scalar.SizeBytes"/> bytes).</summary>
    private const int PairBytes = ScalarsPerPair * Scalar.SizeBytes;


    /// <summary>BLS12-381 scalar-field modulus <c>r</c> as four little-endian 64-bit limbs.</summary>
    private static readonly ulong[] FieldOrderLimbs =
    [
        0xffffffff00000001UL,
        0x53bda402fffe5bfeUL,
        0x3339d80809a1d805UL,
        0x73eda753299d7d48UL
    ];


    /// <summary>Per-lane broadcasts of the four limbs of <c>r</c>. Each <see cref="Vector128{T}"/> has the same limb value in both 64-bit lanes.</summary>
    private static readonly Vector128<ulong> FieldOrderLane0 = Vector128.Create(0xffffffff00000001UL);
    private static readonly Vector128<ulong> FieldOrderLane1 = Vector128.Create(0x53bda402fffe5bfeUL);
    private static readonly Vector128<ulong> FieldOrderLane2 = Vector128.Create(0x3339d80809a1d805UL);
    private static readonly Vector128<ulong> FieldOrderLane3 = Vector128.Create(0x73eda753299d7d48UL);


    /// <summary>Returns the NEON-backed scalar-add delegate.</summary>
    public static ScalarAddDelegate GetAdd() => Add;

    /// <summary>Returns the NEON-backed scalar-subtract delegate.</summary>
    public static ScalarSubtractDelegate GetSubtract() => Subtract;

    /// <summary>Returns the NEON-backed batched scalar-add delegate. Two scalars per SIMD pair, single-element fallback for the trailing odd element.</summary>
    public static ScalarBatchAddDelegate GetBatchAdd() => BatchAdd;

    /// <summary>Returns the NEON-backed batched scalar-subtract delegate.</summary>
    public static ScalarBatchSubtractDelegate GetBatchSubtract() => BatchSubtract;

    /// <summary>Returns the scalar-multiply delegate (serial CIOS Montgomery multiply; the body is ISA-independent and shared across the backends).</summary>
    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    /// <summary>Returns the scalar-negate delegate: modular negation <c>r − a</c>, with zero mapping to zero.</summary>
    public static ScalarNegateDelegate GetNegate() => Negate;

    /// <summary>Returns the scalar-invert delegate: Fermat inversion <c>a^(r−2) mod r</c> over the Montgomery multiply; throws for zero, matching the reference.</summary>
    public static ScalarInvertDelegate GetInvert() => Invert;

    /// <summary>
    /// Returns the lane-interleaved batched scalar-multiply delegate: a 32-bit-limb
    /// CIOS Montgomery multiply running two independent scalars per NEON pair (one
    /// per 64-bit lane), each 32×32→64 partial product a single widening multiply
    /// (<c>UMULL</c>). The trailing odd element falls back to the shared serial
    /// Montgomery multiply.
    /// </summary>
    public static ScalarBatchMultiplyDelegate GetBatchMultiply() => BatchMultiply;


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarAdd, curve);
        AddCore(a, b, result);
    }


    private static void AddCore(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        Span<ulong> sum = stackalloc ulong[LimbCount];
        Span<ulong> sumMinusR = stackalloc ulong[LimbCount];

        LoadCanonicalToLimbs(a, aLimbs);
        LoadCanonicalToLimbs(b, bLimbs);

        bool carry = AddWithCarry256(aLimbs, bLimbs, sum);
        sum.CopyTo(sumMinusR);
        bool borrow = SubtractWithBorrow256(sumMinusR, FieldOrderLimbs);

        bool useReduced = carry || !borrow;
        ConditionalSelect(sumMinusR, sum, useReduced, result);
    }


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarSubtract, curve);
        SubtractCore(a, b, result);
    }


    private static void SubtractCore(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        Span<ulong> diff = stackalloc ulong[LimbCount];
        Span<ulong> diffPlusR = stackalloc ulong[LimbCount];

        LoadCanonicalToLimbs(a, aLimbs);
        LoadCanonicalToLimbs(b, bLimbs);

        aLimbs.CopyTo(diff);
        bool borrow = SubtractWithBorrow256(diff, bLimbs);

        diff.CopyTo(diffPlusR);
        _ = AddWithCarry256(diffPlusR, FieldOrderLimbs, diffPlusR);

        ConditionalSelect(diffPlusR, diff, borrow, result);
    }


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarMultiply, curve);

        //A single Montgomery multiply is a serial limb carry chain that SIMD does not
        //accelerate; the ISA-independent body is shared across the backends.
        Bls12Curve381MontgomeryArithmetic.Multiply(a, b, result);
    }


    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarInvert, curve);
        Bls12Curve381MontgomeryArithmetic.Invert(a, result);
    }


    private static void Negate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarNegate, curve);
        NegateCore(a, result);
    }


    /// <summary>Counter-free arithmetic body of <see cref="Negate"/>.</summary>
    private static void NegateCore(ReadOnlySpan<byte> a, Span<byte> result)
    {
        //Modular negation is subtraction from zero: (0 − a) mod r = r − a for a ≠ 0,
        //and 0 for a = 0 — exactly what the constant-time subtract core computes.
        Span<byte> zero = stackalloc byte[Scalar.SizeBytes];
        zero.Clear();
        SubtractCore(zero, a, result);
    }


    private static void BatchAdd(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchAdd, curve, count);

        int stride = Scalar.SizeBytes;
        ValidateBatchedLengths(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count, stride);

        //Walk full pairs through the SIMD path: each iteration adds two
        //scalars in lane-parallel form.
        int pairs = count / ScalarsPerPair;
        for(int pairIndex = 0; pairIndex < pairs; pairIndex++)
        {
            int offset = pairIndex * PairBytes;
            AddPair(
                leftOperandsConcatenated.Slice(offset, PairBytes),
                rightOperandsConcatenated.Slice(offset, PairBytes),
                resultsConcatenated.Slice(offset, PairBytes));
        }

        //Tail is at most one element on a 2-wide backend.
        int tailStart = pairs * PairBytes;
        int tailCount = count % ScalarsPerPair;
        for(int i = 0; i < tailCount; i++)
        {
            int offset = tailStart + i * stride;
            AddCore(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    private static void BatchSubtract(
        ReadOnlySpan<byte> minuendsConcatenated,
        ReadOnlySpan<byte> subtrahendsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchSubtract, curve, count);

        int stride = Scalar.SizeBytes;
        ValidateBatchedLengths(minuendsConcatenated, subtrahendsConcatenated, resultsConcatenated, count, stride);

        int pairs = count / ScalarsPerPair;
        for(int pairIndex = 0; pairIndex < pairs; pairIndex++)
        {
            int offset = pairIndex * PairBytes;
            SubtractPair(
                minuendsConcatenated.Slice(offset, PairBytes),
                subtrahendsConcatenated.Slice(offset, PairBytes),
                resultsConcatenated.Slice(offset, PairBytes));
        }

        int tailStart = pairs * PairBytes;
        int tailCount = count % ScalarsPerPair;
        for(int i = 0; i < tailCount; i++)
        {
            int offset = tailStart + i * stride;
            SubtractCore(
                minuendsConcatenated.Slice(offset, stride),
                subtrahendsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    /// <summary>
    /// SIMD inner loop: adds two scalars in parallel, two 64-bit lanes per
    /// <see cref="Vector128{T}"/>, one limb position per register. Same
    /// carry-chain structure as the AVX2 variant — only the lane width
    /// differs.
    /// </summary>
    private static void AddPair(
        ReadOnlySpan<byte> aPair,
        ReadOnlySpan<byte> bPair,
        Span<byte> resultPair)
    {
        LoadPairToLimbVectors(aPair, out Vector128<ulong> a0, out Vector128<ulong> a1, out Vector128<ulong> a2, out Vector128<ulong> a3);
        LoadPairToLimbVectors(bPair, out Vector128<ulong> b0, out Vector128<ulong> b1, out Vector128<ulong> b2, out Vector128<ulong> b3);

        //Add with carry chain. Carry mask is all-ones per overflowed lane; converted
        //to a {0, 1}-per-lane value via 0 - mask for the next limb's add.
        Vector128<ulong> sum0 = AdvSimd.Add(a0, b0);
        Vector128<ulong> carryMask0 = UnsignedLessThan(sum0, a0);
        Vector128<ulong> carry0Value = AdvSimd.Subtract(Vector128<ulong>.Zero, carryMask0);

        AddLimbWithCarry(a1, b1, carry0Value, out Vector128<ulong> sum1, out Vector128<ulong> carryMask1);
        Vector128<ulong> carry1Value = AdvSimd.Subtract(Vector128<ulong>.Zero, carryMask1);

        AddLimbWithCarry(a2, b2, carry1Value, out Vector128<ulong> sum2, out Vector128<ulong> carryMask2);
        Vector128<ulong> carry2Value = AdvSimd.Subtract(Vector128<ulong>.Zero, carryMask2);

        AddLimbWithCarry(a3, b3, carry2Value, out Vector128<ulong> sum3, out Vector128<ulong> finalCarryMask);

        //Speculatively compute sum - r with a borrow chain.
        Vector128<ulong> diff0 = AdvSimd.Subtract(sum0, FieldOrderLane0);
        Vector128<ulong> borrowMask0 = UnsignedLessThan(sum0, FieldOrderLane0);
        Vector128<ulong> borrow0Value = AdvSimd.Subtract(Vector128<ulong>.Zero, borrowMask0);

        SubtractLimbWithBorrow(sum1, FieldOrderLane1, borrow0Value, out Vector128<ulong> diff1, out Vector128<ulong> borrowMask1);
        Vector128<ulong> borrow1Value = AdvSimd.Subtract(Vector128<ulong>.Zero, borrowMask1);

        SubtractLimbWithBorrow(sum2, FieldOrderLane2, borrow1Value, out Vector128<ulong> diff2, out Vector128<ulong> borrowMask2);
        Vector128<ulong> borrow2Value = AdvSimd.Subtract(Vector128<ulong>.Zero, borrowMask2);

        SubtractLimbWithBorrow(sum3, FieldOrderLane3, borrow2Value, out Vector128<ulong> diff3, out Vector128<ulong> finalBorrowMask);

        //Reduce iff finalCarry OR not finalBorrow. notFinalBorrow is the bitwise NOT.
        Vector128<ulong> notFinalBorrow = AdvSimd.Not(finalBorrowMask.AsByte()).AsUInt64();
        Vector128<ulong> useDiffMask = AdvSimd.Or(finalCarryMask, notFinalBorrow);

        Vector128<ulong> result0 = AdvSimd.BitwiseSelect(useDiffMask, diff0, sum0);
        Vector128<ulong> result1 = AdvSimd.BitwiseSelect(useDiffMask, diff1, sum1);
        Vector128<ulong> result2 = AdvSimd.BitwiseSelect(useDiffMask, diff2, sum2);
        Vector128<ulong> result3 = AdvSimd.BitwiseSelect(useDiffMask, diff3, sum3);

        StoreLimbVectorsToPair(result0, result1, result2, result3, resultPair);
    }


    private static void SubtractPair(
        ReadOnlySpan<byte> aPair,
        ReadOnlySpan<byte> bPair,
        Span<byte> resultPair)
    {
        LoadPairToLimbVectors(aPair, out Vector128<ulong> a0, out Vector128<ulong> a1, out Vector128<ulong> a2, out Vector128<ulong> a3);
        LoadPairToLimbVectors(bPair, out Vector128<ulong> b0, out Vector128<ulong> b1, out Vector128<ulong> b2, out Vector128<ulong> b3);

        //Subtract a - b with borrow chain.
        Vector128<ulong> diff0 = AdvSimd.Subtract(a0, b0);
        Vector128<ulong> borrowMask0 = UnsignedLessThan(a0, b0);
        Vector128<ulong> borrow0Value = AdvSimd.Subtract(Vector128<ulong>.Zero, borrowMask0);

        SubtractLimbWithBorrow(a1, b1, borrow0Value, out Vector128<ulong> diff1, out Vector128<ulong> borrowMask1);
        Vector128<ulong> borrow1Value = AdvSimd.Subtract(Vector128<ulong>.Zero, borrowMask1);

        SubtractLimbWithBorrow(a2, b2, borrow1Value, out Vector128<ulong> diff2, out Vector128<ulong> borrowMask2);
        Vector128<ulong> borrow2Value = AdvSimd.Subtract(Vector128<ulong>.Zero, borrowMask2);

        SubtractLimbWithBorrow(a3, b3, borrow2Value, out Vector128<ulong> diff3, out Vector128<ulong> finalBorrowMask);

        //Speculatively compute diff + r (ignoring final carry).
        AddLimbWithCarry(diff0, FieldOrderLane0, Vector128<ulong>.Zero, out Vector128<ulong> diffPlusR0, out Vector128<ulong> carryMask0);
        Vector128<ulong> carry0Value = AdvSimd.Subtract(Vector128<ulong>.Zero, carryMask0);

        AddLimbWithCarry(diff1, FieldOrderLane1, carry0Value, out Vector128<ulong> diffPlusR1, out Vector128<ulong> carryMask1);
        Vector128<ulong> carry1Value = AdvSimd.Subtract(Vector128<ulong>.Zero, carryMask1);

        AddLimbWithCarry(diff2, FieldOrderLane2, carry1Value, out Vector128<ulong> diffPlusR2, out Vector128<ulong> carryMask2);
        Vector128<ulong> carry2Value = AdvSimd.Subtract(Vector128<ulong>.Zero, carryMask2);

        AddLimbWithCarry(diff3, FieldOrderLane3, carry2Value, out Vector128<ulong> diffPlusR3, out _);

        //Use diff + r where a < b (borrow=all-ones), else diff.
        Vector128<ulong> result0 = AdvSimd.BitwiseSelect(finalBorrowMask, diffPlusR0, diff0);
        Vector128<ulong> result1 = AdvSimd.BitwiseSelect(finalBorrowMask, diffPlusR1, diff1);
        Vector128<ulong> result2 = AdvSimd.BitwiseSelect(finalBorrowMask, diffPlusR2, diff2);
        Vector128<ulong> result3 = AdvSimd.BitwiseSelect(finalBorrowMask, diffPlusR3, diff3);

        StoreLimbVectorsToPair(result0, result1, result2, result3, resultPair);
    }


    /// <summary>One limb of carry-chain addition. Same shape as the AVX2 variant, halved width.</summary>
    private static void AddLimbWithCarry(
        Vector128<ulong> a,
        Vector128<ulong> b,
        Vector128<ulong> carryIn,
        out Vector128<ulong> sum,
        out Vector128<ulong> carryOutMask)
    {
        Vector128<ulong> innerSum = AdvSimd.Add(a, b);
        Vector128<ulong> innerCarryMask = UnsignedLessThan(innerSum, a);
        sum = AdvSimd.Add(innerSum, carryIn);
        Vector128<ulong> outerCarryMask = UnsignedLessThan(sum, innerSum);
        carryOutMask = AdvSimd.Or(innerCarryMask, outerCarryMask);
    }


    /// <summary>One limb of borrow-chain subtraction.</summary>
    private static void SubtractLimbWithBorrow(
        Vector128<ulong> a,
        Vector128<ulong> b,
        Vector128<ulong> borrowIn,
        out Vector128<ulong> diff,
        out Vector128<ulong> borrowOutMask)
    {
        Vector128<ulong> innerDiff = AdvSimd.Subtract(a, b);
        Vector128<ulong> innerBorrowMask = UnsignedLessThan(a, b);
        diff = AdvSimd.Subtract(innerDiff, borrowIn);
        Vector128<ulong> outerBorrowMask = UnsignedLessThan(innerDiff, borrowIn);
        borrowOutMask = AdvSimd.Or(innerBorrowMask, outerBorrowMask);
    }


    /// <summary>
    /// Lane-wise unsigned less-than. AArch64 has a native unsigned 64-bit
    /// compare (<see cref="AdvSimd.Arm64.CompareGreaterThan(Vector128{ulong}, Vector128{ulong})"/>),
    /// which is cleaner than the XOR-with-sign trick the AVX2 path needs.
    /// </summary>
    private static Vector128<ulong> UnsignedLessThan(Vector128<ulong> a, Vector128<ulong> b)
    {
        //a < b unsigned is equivalent to b > a unsigned.
        return AdvSimd.Arm64.CompareGreaterThan(b, a);
    }


    private static void LoadCanonicalToLimbs(ReadOnlySpan<byte> canonical, Span<ulong> limbs)
    {
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int offset = (LimbCount - 1 - limbIndex) * BytesPerLimb;
            limbs[limbIndex] = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(offset, BytesPerLimb));
        }
    }


    private static void StoreLimbsToCanonical(ReadOnlySpan<ulong> limbs, Span<byte> canonical)
    {
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int offset = (LimbCount - 1 - limbIndex) * BytesPerLimb;
            BinaryPrimitives.WriteUInt64BigEndian(canonical.Slice(offset, BytesPerLimb), limbs[limbIndex]);
        }
    }


    private static bool AddWithCarry256(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result)
    {
        UInt128 carry = UInt128.Zero;
        for(int i = 0; i < LimbCount; i++)
        {
            UInt128 lanesSum = (UInt128)a[i] + b[i] + carry;
            result[i] = (ulong)lanesSum;
            carry = lanesSum >> 64;
        }


        return carry != UInt128.Zero;
    }


    private static bool SubtractWithBorrow256(Span<ulong> a, ReadOnlySpan<ulong> b)
    {
        ulong borrow = 0UL;
        for(int i = 0; i < LimbCount; i++)
        {
            ulong x = a[i];
            ulong y = b[i];
            ulong diffOut = unchecked(x - y - borrow);
            ulong newBorrow = (x < y) || (x == y && borrow != 0UL) ? 1UL : 0UL;
            a[i] = diffOut;
            borrow = newBorrow;
        }


        return borrow != 0UL;
    }


    /// <summary>
    /// Constant-time selection of one of two limb tuples based on a
    /// scalar boolean, using <see cref="AdvSimd.BitwiseSelect(Vector128{ulong}, Vector128{ulong}, Vector128{ulong})"/>
    /// so neither branch's bits enter the destination based on the
    /// condition value.
    /// </summary>
    private static void ConditionalSelect(
        ReadOnlySpan<ulong> onTrue,
        ReadOnlySpan<ulong> onFalse,
        bool condition,
        Span<byte> destination)
    {
        Vector128<ulong> mask = condition ? Vector128<ulong>.AllBitsSet : Vector128<ulong>.Zero;

        Span<ulong> selectedLimbs = stackalloc ulong[LimbCount];
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            //BitwiseSelect: selector=1-bit → take from second; selector=0-bit → take from third.
            //Argument order: (selector, trueValue, falseValue).
            Vector128<ulong> trueLane = Vector128.Create(onTrue[limbIndex]);
            Vector128<ulong> falseLane = Vector128.Create(onFalse[limbIndex]);
            Vector128<ulong> picked = AdvSimd.BitwiseSelect(mask, trueLane, falseLane);
            selectedLimbs[limbIndex] = picked.GetElement(0);
        }

        StoreLimbsToCanonical(selectedLimbs, destination);
    }


    private static void LoadPairToLimbVectors(
        ReadOnlySpan<byte> pairBytes,
        out Vector128<ulong> limb0,
        out Vector128<ulong> limb1,
        out Vector128<ulong> limb2,
        out Vector128<ulong> limb3)
    {
        Span<ulong> scalar0 = stackalloc ulong[LimbCount];
        Span<ulong> scalar1 = stackalloc ulong[LimbCount];

        int stride = Scalar.SizeBytes;
        LoadCanonicalToLimbs(pairBytes.Slice(0 * stride, stride), scalar0);
        LoadCanonicalToLimbs(pairBytes.Slice(1 * stride, stride), scalar1);

        limb0 = Vector128.Create(scalar0[0], scalar1[0]);
        limb1 = Vector128.Create(scalar0[1], scalar1[1]);
        limb2 = Vector128.Create(scalar0[2], scalar1[2]);
        limb3 = Vector128.Create(scalar0[3], scalar1[3]);
    }


    private static void StoreLimbVectorsToPair(
        Vector128<ulong> limb0,
        Vector128<ulong> limb1,
        Vector128<ulong> limb2,
        Vector128<ulong> limb3,
        Span<byte> pairBytes)
    {
        Span<ulong> scalarLimbs = stackalloc ulong[LimbCount];
        int stride = Scalar.SizeBytes;
        for(int scalarIndex = 0; scalarIndex < ScalarsPerPair; scalarIndex++)
        {
            scalarLimbs[0] = limb0.GetElement(scalarIndex);
            scalarLimbs[1] = limb1.GetElement(scalarIndex);
            scalarLimbs[2] = limb2.GetElement(scalarIndex);
            scalarLimbs[3] = limb3.GetElement(scalarIndex);
            StoreLimbsToCanonical(scalarLimbs, pairBytes.Slice(scalarIndex * stride, stride));
        }
    }


    private static void ValidateBatchedLengths(
        ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second,
        ReadOnlySpan<byte> third,
        int count,
        int stride)
    {
        int expected = count * stride;
        if(first.Length != expected || second.Length != expected || third.Length != expected)
        {
            throw new ArgumentException(
                $"Batched scalar buffers must each be exactly {count} * {stride} bytes for count = {count}.");
        }
    }


    private static void EnsureSupported()
    {
        if(!AdvSimd.Arm64.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "Bls12Curve381NeonScalarBackend requires AArch64 NEON; check IsSupported before wiring it as a delegate.");
        }
    }


    //--- Lane-interleaved batch Montgomery multiply (32-bit-limb CIOS, 2-wide) ---

    private const int Limb32Count = 8;

    private static readonly Vector128<ulong> Low32Mask = Vector128.Create(0xFFFFFFFFUL);
    private static readonly Vector128<ulong> NPrime32Broadcast = Vector128.Create((ulong)Bls12Curve381MontgomeryParameters.NPrime32);
    private static readonly Vector128<ulong>[] Modulus32Broadcast = BuildBroadcast(Bls12Curve381MontgomeryParameters.Modulus32Limbs);
    private static readonly Vector128<ulong>[] RSquared32Broadcast = BuildBroadcast(Bls12Curve381MontgomeryParameters.RSquared32Limbs);


    private static Vector128<ulong>[] BuildBroadcast(ReadOnlySpan<uint> limbs32)
    {
        var vectors = new Vector128<ulong>[Limb32Count];
        for(int i = 0; i < Limb32Count; i++)
        {
            vectors[i] = Vector128.Create((ulong)limbs32[i]);
        }

        return vectors;
    }


    //32×32→64 per lane: narrow both operands to their low 32 bits (XTN) then
    //widening-multiply (UMULL). Each limb register holds its 32-bit value in the
    //low 32 bits of both 64-bit lanes.
    private static Vector128<ulong> Multiply32(Vector128<ulong> a, Vector128<ulong> b)
    {
        return AdvSimd.MultiplyWideningLower(AdvSimd.ExtractNarrowingLower(a), AdvSimd.ExtractNarrowingLower(b));
    }


    private static void BatchMultiply(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchMultiply, curve, count);

        int stride = Scalar.SizeBytes;
        ValidateBatchedLengths(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count, stride);

        int pairs = count / ScalarsPerPair;
        for(int pairIndex = 0; pairIndex < pairs; pairIndex++)
        {
            int offset = pairIndex * PairBytes;
            MultiplyPair(
                leftOperandsConcatenated.Slice(offset, PairBytes),
                rightOperandsConcatenated.Slice(offset, PairBytes),
                resultsConcatenated.Slice(offset, PairBytes));
        }

        int tailStart = pairs * PairBytes;
        int tailCount = count % ScalarsPerPair;
        for(int i = 0; i < tailCount; i++)
        {
            int offset = tailStart + i * stride;
            Bls12Curve381MontgomeryArithmetic.Multiply(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    private static void MultiplyPair(
        ReadOnlySpan<byte> aPair,
        ReadOnlySpan<byte> bPair,
        Span<byte> resultPair)
    {
        Span<Vector128<ulong>> a = stackalloc Vector128<ulong>[Limb32Count];
        Span<Vector128<ulong>> b = stackalloc Vector128<ulong>[Limb32Count];
        Span<Vector128<ulong>> aMontgomery = stackalloc Vector128<ulong>[Limb32Count];
        Span<Vector128<ulong>> product = stackalloc Vector128<ulong>[Limb32Count];

        LoadPairTo32LimbVectors(aPair, a);
        LoadPairTo32LimbVectors(bPair, b);

        MontgomeryMultiplyPair(a, RSquared32Broadcast, aMontgomery);
        MontgomeryMultiplyPair(aMontgomery, b, product);

        Store32LimbVectorsToPair(product, resultPair);
    }


    private static void MontgomeryMultiplyPair(
        ReadOnlySpan<Vector128<ulong>> x,
        ReadOnlySpan<Vector128<ulong>> y,
        Span<Vector128<ulong>> result)
    {
        Span<Vector128<ulong>> t = stackalloc Vector128<ulong>[Limb32Count + 2];
        for(int k = 0; k < Limb32Count + 2; k++)
        {
            t[k] = Vector128<ulong>.Zero;
        }

        Vector128<ulong> mask = Low32Mask;

        for(int i = 0; i < Limb32Count; i++)
        {
            Vector128<ulong> carry = Vector128<ulong>.Zero;
            for(int j = 0; j < Limb32Count; j++)
            {
                Vector128<ulong> partial = Multiply32(x[j], y[i]);
                Vector128<ulong> sum = AdvSimd.Add(AdvSimd.Add(t[j], partial), carry);
                t[j] = AdvSimd.And(sum, mask);
                carry = AdvSimd.ShiftRightLogical(sum, 32);
            }

            Vector128<ulong> highSum = AdvSimd.Add(t[Limb32Count], carry);
            t[Limb32Count] = AdvSimd.And(highSum, mask);
            t[Limb32Count + 1] = AdvSimd.ShiftRightLogical(highSum, 32);

            Vector128<ulong> m = AdvSimd.And(Multiply32(t[0], NPrime32Broadcast), mask);
            Vector128<ulong> reduceLow = AdvSimd.Add(t[0], Multiply32(m, Modulus32Broadcast[0]));
            carry = AdvSimd.ShiftRightLogical(reduceLow, 32);
            for(int j = 1; j < Limb32Count; j++)
            {
                Vector128<ulong> reduceTerm = AdvSimd.Add(AdvSimd.Add(t[j], Multiply32(m, Modulus32Broadcast[j])), carry);
                t[j - 1] = AdvSimd.And(reduceTerm, mask);
                carry = AdvSimd.ShiftRightLogical(reduceTerm, 32);
            }

            Vector128<ulong> reduceHigh = AdvSimd.Add(t[Limb32Count], carry);
            t[Limb32Count - 1] = AdvSimd.And(reduceHigh, mask);
            t[Limb32Count] = AdvSimd.Add(t[Limb32Count + 1], AdvSimd.ShiftRightLogical(reduceHigh, 32));
        }

        ConditionalSubtractModulusPair(t, result);
    }


    private static void ConditionalSubtractModulusPair(ReadOnlySpan<Vector128<ulong>> t, Span<Vector128<ulong>> result)
    {
        Vector128<ulong> mask = Low32Mask;
        Span<Vector128<ulong>> reduced = stackalloc Vector128<ulong>[Limb32Count];

        Vector128<ulong> borrow = Vector128<ulong>.Zero;
        for(int j = 0; j < Limb32Count; j++)
        {
            Vector128<ulong> difference = AdvSimd.Subtract(AdvSimd.Subtract(t[j], Modulus32Broadcast[j]), borrow);
            reduced[j] = AdvSimd.And(difference, mask);
            borrow = AdvSimd.ShiftRightLogical(difference, 63);
        }

        Vector128<ulong> overflowMask = AdvSimd.Subtract(Vector128<ulong>.Zero, t[Limb32Count]);
        Vector128<ulong> borrowMask = AdvSimd.Subtract(Vector128<ulong>.Zero, borrow);
        Vector128<ulong> notBorrowMask = AdvSimd.Not(borrowMask.AsByte()).AsUInt64();
        Vector128<ulong> useReducedMask = AdvSimd.Or(overflowMask, notBorrowMask);

        for(int j = 0; j < Limb32Count; j++)
        {
            result[j] = AdvSimd.BitwiseSelect(useReducedMask, reduced[j], t[j]);
        }
    }


    private static void LoadPairTo32LimbVectors(ReadOnlySpan<byte> pairBytes, Span<Vector128<ulong>> limbVectors)
    {
        Span<uint> scalar0 = stackalloc uint[Limb32Count];
        Span<uint> scalar1 = stackalloc uint[Limb32Count];

        int stride = Scalar.SizeBytes;
        LoadCanonicalTo32Limbs(pairBytes.Slice(0 * stride, stride), scalar0);
        LoadCanonicalTo32Limbs(pairBytes.Slice(1 * stride, stride), scalar1);

        for(int k = 0; k < Limb32Count; k++)
        {
            limbVectors[k] = Vector128.Create((ulong)scalar0[k], scalar1[k]);
        }
    }


    private static void Store32LimbVectorsToPair(ReadOnlySpan<Vector128<ulong>> limbVectors, Span<byte> pairBytes)
    {
        int stride = Scalar.SizeBytes;
        Span<uint> scalarLimbs = stackalloc uint[Limb32Count];
        for(int scalarIndex = 0; scalarIndex < ScalarsPerPair; scalarIndex++)
        {
            for(int k = 0; k < Limb32Count; k++)
            {
                scalarLimbs[k] = (uint)limbVectors[k].GetElement(scalarIndex);
            }

            StoreCanonicalFrom32Limbs(scalarLimbs, pairBytes.Slice(scalarIndex * stride, stride));
        }
    }


    private static void LoadCanonicalTo32Limbs(ReadOnlySpan<byte> canonical, Span<uint> limbs)
    {
        for(int i = 0; i < Limb32Count; i++)
        {
            limbs[i] = BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice((Limb32Count - 1 - i) * sizeof(uint), sizeof(uint)));
        }
    }


    private static void StoreCanonicalFrom32Limbs(ReadOnlySpan<uint> limbs, Span<byte> canonical)
    {
        for(int i = 0; i < Limb32Count; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(canonical.Slice((Limb32Count - 1 - i) * sizeof(uint), sizeof(uint)), limbs[i]);
        }
    }
}