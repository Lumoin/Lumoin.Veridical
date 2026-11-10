using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// AVX-512 implementation of BN254 scalar add/subtract (and their batch forms), the
/// BN254 mirror of <see cref="Bls12Curve381Avx512ScalarBackend"/>. Same algorithm as
/// the BN254 AVX2 backend with the lane width doubled: eight scalars per octet
/// instead of four per quartet, and AVX-512's native unsigned 64-bit compare in
/// place of the AVX2 sign-flip trick.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Vector512{T}"/> holds eight 64-bit lanes, so the limb-major carry
/// chain advances eight independent scalars in parallel per limb step. The
/// conditional modular reduction uses
/// <see cref="Vector512.ConditionalSelect{T}(Vector512{T}, Vector512{T}, Vector512{T})"/>,
/// which the JIT lowers to a single-cycle data-independent bitwise selection, so the
/// reduction stays constant-time per lane.
/// </para>
/// <para>
/// Add, subtract, and the batch forms are implemented here; multiplication and
/// inversion are the shared Montgomery path. Only the modulus
/// constants differ from the BLS12-381 AVX-512 backend.
/// </para>
/// </remarks>
internal static class Bn254Avx512ScalarBackend
{
    /// <summary>True when the host CPU supports the AVX-512 foundation instructions this backend uses.</summary>
    public static bool IsSupported => Avx512F.IsSupported;


    /// <summary>The number of 64-bit limbs that compose a BN254 scalar (256 bits / 64 bits per limb).</summary>
    private const int LimbCount = 4;

    /// <summary>The number of canonical bytes per 64-bit limb.</summary>
    private const int BytesPerLimb = sizeof(ulong);

    /// <summary>The number of independent scalars packed into one SIMD octet (one per 64-bit lane of <see cref="Vector512{T}"/>).</summary>
    private const int ScalarsPerOctet = 8;

    /// <summary>The number of canonical bytes per scalar octet (eight scalars, each <see cref="Scalar.SizeBytes"/> bytes).</summary>
    private const int OctetBytes = ScalarsPerOctet * Scalar.SizeBytes;


    /// <summary>
    /// BN254 scalar-field modulus <c>r</c> as four little-endian 64-bit limbs.
    /// <c>r = 0x30644e72e131a029 b85045b68181585d 2833e84879b97091 43e1f593f0000001</c>.
    /// </summary>
    private static ulong[] FieldOrderLimbs { get; } =
    [
        0x43e1f593f0000001UL,
        0x2833e84879b97091UL,
        0xb85045b68181585dUL,
        0x30644e72e131a029UL
    ];


    /// <summary>The broadcast of r's least-significant 64-bit limb into all eight lanes of a <see cref="Vector512{T}"/>.</summary>
    private static Vector512<ulong> FieldOrderLane0 { get; } = Vector512.Create(0x43e1f593f0000001UL);

    /// <summary>The broadcast of r's second 64-bit limb into all eight lanes of a <see cref="Vector512{T}"/>.</summary>
    private static Vector512<ulong> FieldOrderLane1 { get; } = Vector512.Create(0x2833e84879b97091UL);

    /// <summary>The broadcast of r's third 64-bit limb into all eight lanes of a <see cref="Vector512{T}"/>.</summary>
    private static Vector512<ulong> FieldOrderLane2 { get; } = Vector512.Create(0xb85045b68181585dUL);

    /// <summary>The broadcast of r's most-significant 64-bit limb into all eight lanes of a <see cref="Vector512{T}"/>.</summary>
    private static Vector512<ulong> FieldOrderLane3 { get; } = Vector512.Create(0x30644e72e131a029UL);


    /// <summary>Returns the AVX-512-backed scalar-add delegate.</summary>
    public static ScalarAddDelegate GetAdd() => Add;

    /// <summary>Returns the AVX-512-backed scalar-subtract delegate.</summary>
    public static ScalarSubtractDelegate GetSubtract() => Subtract;

    /// <summary>Returns the AVX-512-backed batched scalar-add delegate. Eight scalars per SIMD octet, single-element fallback for the trailing 1-7 elements.</summary>
    public static ScalarBatchAddDelegate GetBatchAdd() => BatchAdd;

    /// <summary>Returns the AVX-512-backed batched scalar-subtract delegate.</summary>
    public static ScalarBatchSubtractDelegate GetBatchSubtract() => BatchSubtract;

    /// <summary>Returns the scalar-multiply delegate (serial CIOS Montgomery multiply; the body is ISA-independent and shared across the backends).</summary>
    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    /// <summary>Returns the scalar-negate delegate: modular negation <c>r − a</c>, with zero mapping to zero.</summary>
    public static ScalarNegateDelegate GetNegate() => Negate;

    /// <summary>Returns the scalar-invert delegate: Fermat inversion <c>a^(r−2) mod r</c> over the Montgomery multiply; throws for zero, matching the reference.</summary>
    public static ScalarInvertDelegate GetInvert() => Invert;

    /// <summary>
    /// Returns the lane-interleaved batched scalar-multiply delegate: a 32-bit-limb
    /// CIOS Montgomery multiply running eight independent scalars per AVX-512 octet
    /// (one per 64-bit lane), each 32×32→64 partial product a single <c>vpmuludq</c>.
    /// The trailing 1–7 elements fall back to the shared serial Montgomery multiply.
    /// </summary>
    public static ScalarBatchMultiplyDelegate GetBatchMultiply() => BatchMultiply;


    /// <summary>Scalar addition: increments the operation counter, then delegates to <see cref="AddCore"/>.</summary>
    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarAdd, curve);
        AddCore(a, b, result);
    }


    /// <summary>Adds two canonical scalars modulo r via a carry chain and a speculative reduction, selected without a data-dependent branch.</summary>
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

        //Branch-free combination of the secret-derived carry and borrow flags.
        bool useReduced = carry | !borrow;
        ConditionalSelect(sumMinusR, sum, useReduced, result);
    }


    /// <summary>Scalar subtraction: increments the operation counter, then delegates to <see cref="SubtractCore"/>.</summary>
    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarSubtract, curve);
        SubtractCore(a, b, result);
    }


    /// <summary>Subtracts two canonical scalars modulo r via a borrow chain and a speculative correction, selected without a data-dependent branch.</summary>
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


    /// <summary>Scalar multiplication: increments the operation counter, then delegates to the shared serial Montgomery multiply.</summary>
    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarMultiply, curve);

        //A single Montgomery multiply is a serial limb carry chain that SIMD does not
        //accelerate; the ISA-independent body is shared across the backends.
        Bn254MontgomeryArithmetic.Multiply(a, b, result);
    }


    /// <summary>Scalar inversion: increments the operation counter, then delegates to the shared Fermat inversion.</summary>
    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarInvert, curve);
        Bn254MontgomeryArithmetic.Invert(a, result);
    }


    /// <summary>Scalar negation: increments the operation counter, then delegates to <see cref="NegateCore"/>.</summary>
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


    /// <summary>Adds scalar pairs in SIMD octets, falling back to <see cref="AddCore"/> for the trailing 1–7 elements.</summary>
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

        int octets = count / ScalarsPerOctet;
        for(int octetIndex = 0; octetIndex < octets; octetIndex++)
        {
            int offset = octetIndex * OctetBytes;
            AddOctet(
                leftOperandsConcatenated.Slice(offset, OctetBytes),
                rightOperandsConcatenated.Slice(offset, OctetBytes),
                resultsConcatenated.Slice(offset, OctetBytes));
        }

        int tailStart = octets * OctetBytes;
        int tailCount = count % ScalarsPerOctet;
        for(int i = 0; i < tailCount; i++)
        {
            int offset = tailStart + i * stride;
            AddCore(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    /// <summary>Subtracts scalar pairs in SIMD octets, falling back to <see cref="SubtractCore"/> for the trailing 1–7 elements.</summary>
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

        int octets = count / ScalarsPerOctet;
        for(int octetIndex = 0; octetIndex < octets; octetIndex++)
        {
            int offset = octetIndex * OctetBytes;
            SubtractOctet(
                minuendsConcatenated.Slice(offset, OctetBytes),
                subtrahendsConcatenated.Slice(offset, OctetBytes),
                resultsConcatenated.Slice(offset, OctetBytes));
        }

        int tailStart = octets * OctetBytes;
        int tailCount = count % ScalarsPerOctet;
        for(int i = 0; i < tailCount; i++)
        {
            int offset = tailStart + i * stride;
            SubtractCore(
                minuendsConcatenated.Slice(offset, stride),
                subtrahendsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    /// <summary>SIMD inner loop: adds eight scalars in parallel using AVX-512 lane-interleaved arithmetic.</summary>
    private static void AddOctet(
        ReadOnlySpan<byte> aOctet,
        ReadOnlySpan<byte> bOctet,
        Span<byte> resultOctet)
    {
        LoadOctetToLimbVectors(aOctet, out Vector512<ulong> a0, out Vector512<ulong> a1, out Vector512<ulong> a2, out Vector512<ulong> a3);
        LoadOctetToLimbVectors(bOctet, out Vector512<ulong> b0, out Vector512<ulong> b1, out Vector512<ulong> b2, out Vector512<ulong> b3);

        //Add with carry chain across the four limbs. Native u64 compare on AVX-512
        //means the per-limb carry detection is one instruction.
        Vector512<ulong> sum0 = Avx512F.Add(a0, b0);
        Vector512<ulong> carryMask0 = UnsignedLessThan(sum0, a0);
        Vector512<ulong> carry0Value = Avx512F.Subtract(Vector512<ulong>.Zero, carryMask0);

        AddLimbWithCarry(a1, b1, carry0Value, out Vector512<ulong> sum1, out Vector512<ulong> carryMask1);
        Vector512<ulong> carry1Value = Avx512F.Subtract(Vector512<ulong>.Zero, carryMask1);

        AddLimbWithCarry(a2, b2, carry1Value, out Vector512<ulong> sum2, out Vector512<ulong> carryMask2);
        Vector512<ulong> carry2Value = Avx512F.Subtract(Vector512<ulong>.Zero, carryMask2);

        AddLimbWithCarry(a3, b3, carry2Value, out Vector512<ulong> sum3, out Vector512<ulong> finalCarryMask);

        //Speculatively compute sum - r with a borrow chain.
        Vector512<ulong> diff0 = Avx512F.Subtract(sum0, FieldOrderLane0);
        Vector512<ulong> borrowMask0 = UnsignedLessThan(sum0, FieldOrderLane0);
        Vector512<ulong> borrow0Value = Avx512F.Subtract(Vector512<ulong>.Zero, borrowMask0);

        SubtractLimbWithBorrow(sum1, FieldOrderLane1, borrow0Value, out Vector512<ulong> diff1, out Vector512<ulong> borrowMask1);
        Vector512<ulong> borrow1Value = Avx512F.Subtract(Vector512<ulong>.Zero, borrowMask1);

        SubtractLimbWithBorrow(sum2, FieldOrderLane2, borrow1Value, out Vector512<ulong> diff2, out Vector512<ulong> borrowMask2);
        Vector512<ulong> borrow2Value = Avx512F.Subtract(Vector512<ulong>.Zero, borrowMask2);

        SubtractLimbWithBorrow(sum3, FieldOrderLane3, borrow2Value, out Vector512<ulong> diff3, out Vector512<ulong> finalBorrowMask);

        //Reduce iff finalCarry OR not finalBorrow. notFinalBorrow is the bitwise NOT.
        Vector512<ulong> notFinalBorrow = Avx512F.Xor(finalBorrowMask, Vector512<ulong>.AllBitsSet);
        Vector512<ulong> useDiffMask = Avx512F.Or(finalCarryMask, notFinalBorrow);

        //ConditionalSelect lowers to vpternlogq or vpblendmq — constant-time bitwise
        //selection independent of the condition's data path.
        Vector512<ulong> result0 = Vector512.ConditionalSelect(useDiffMask, diff0, sum0);
        Vector512<ulong> result1 = Vector512.ConditionalSelect(useDiffMask, diff1, sum1);
        Vector512<ulong> result2 = Vector512.ConditionalSelect(useDiffMask, diff2, sum2);
        Vector512<ulong> result3 = Vector512.ConditionalSelect(useDiffMask, diff3, sum3);

        StoreLimbVectorsToOctet(result0, result1, result2, result3, resultOctet);
    }


    /// <summary>SIMD inner loop: subtracts eight scalars in parallel using AVX-512 lane-interleaved arithmetic.</summary>
    private static void SubtractOctet(
        ReadOnlySpan<byte> aOctet,
        ReadOnlySpan<byte> bOctet,
        Span<byte> resultOctet)
    {
        LoadOctetToLimbVectors(aOctet, out Vector512<ulong> a0, out Vector512<ulong> a1, out Vector512<ulong> a2, out Vector512<ulong> a3);
        LoadOctetToLimbVectors(bOctet, out Vector512<ulong> b0, out Vector512<ulong> b1, out Vector512<ulong> b2, out Vector512<ulong> b3);

        //Subtract a - b with borrow chain.
        Vector512<ulong> diff0 = Avx512F.Subtract(a0, b0);
        Vector512<ulong> borrowMask0 = UnsignedLessThan(a0, b0);
        Vector512<ulong> borrow0Value = Avx512F.Subtract(Vector512<ulong>.Zero, borrowMask0);

        SubtractLimbWithBorrow(a1, b1, borrow0Value, out Vector512<ulong> diff1, out Vector512<ulong> borrowMask1);
        Vector512<ulong> borrow1Value = Avx512F.Subtract(Vector512<ulong>.Zero, borrowMask1);

        SubtractLimbWithBorrow(a2, b2, borrow1Value, out Vector512<ulong> diff2, out Vector512<ulong> borrowMask2);
        Vector512<ulong> borrow2Value = Avx512F.Subtract(Vector512<ulong>.Zero, borrowMask2);

        SubtractLimbWithBorrow(a3, b3, borrow2Value, out Vector512<ulong> diff3, out Vector512<ulong> finalBorrowMask);

        //Speculatively compute diff + r (ignoring final carry).
        AddLimbWithCarry(diff0, FieldOrderLane0, Vector512<ulong>.Zero, out Vector512<ulong> diffPlusR0, out Vector512<ulong> carryMask0);
        Vector512<ulong> carry0Value = Avx512F.Subtract(Vector512<ulong>.Zero, carryMask0);

        AddLimbWithCarry(diff1, FieldOrderLane1, carry0Value, out Vector512<ulong> diffPlusR1, out Vector512<ulong> carryMask1);
        Vector512<ulong> carry1Value = Avx512F.Subtract(Vector512<ulong>.Zero, carryMask1);

        AddLimbWithCarry(diff2, FieldOrderLane2, carry1Value, out Vector512<ulong> diffPlusR2, out Vector512<ulong> carryMask2);
        Vector512<ulong> carry2Value = Avx512F.Subtract(Vector512<ulong>.Zero, carryMask2);

        AddLimbWithCarry(diff3, FieldOrderLane3, carry2Value, out Vector512<ulong> diffPlusR3, out _);

        Vector512<ulong> result0 = Vector512.ConditionalSelect(finalBorrowMask, diffPlusR0, diff0);
        Vector512<ulong> result1 = Vector512.ConditionalSelect(finalBorrowMask, diffPlusR1, diff1);
        Vector512<ulong> result2 = Vector512.ConditionalSelect(finalBorrowMask, diffPlusR2, diff2);
        Vector512<ulong> result3 = Vector512.ConditionalSelect(finalBorrowMask, diffPlusR3, diff3);

        StoreLimbVectorsToOctet(result0, result1, result2, result3, resultOctet);
    }


    /// <summary>Adds one 64-bit limb across all eight lanes with an incoming carry, returning the sum and the outgoing carry mask.</summary>
    private static void AddLimbWithCarry(
        Vector512<ulong> a,
        Vector512<ulong> b,
        Vector512<ulong> carryIn,
        out Vector512<ulong> sum,
        out Vector512<ulong> carryOutMask)
    {
        Vector512<ulong> innerSum = Avx512F.Add(a, b);
        Vector512<ulong> innerCarryMask = UnsignedLessThan(innerSum, a);
        sum = Avx512F.Add(innerSum, carryIn);
        Vector512<ulong> outerCarryMask = UnsignedLessThan(sum, innerSum);
        carryOutMask = Avx512F.Or(innerCarryMask, outerCarryMask);
    }


    /// <summary>Subtracts one 64-bit limb across all eight lanes with an incoming borrow, returning the difference and the outgoing borrow mask.</summary>
    private static void SubtractLimbWithBorrow(
        Vector512<ulong> a,
        Vector512<ulong> b,
        Vector512<ulong> borrowIn,
        out Vector512<ulong> diff,
        out Vector512<ulong> borrowOutMask)
    {
        Vector512<ulong> innerDiff = Avx512F.Subtract(a, b);
        Vector512<ulong> innerBorrowMask = UnsignedLessThan(a, b);
        diff = Avx512F.Subtract(innerDiff, borrowIn);
        Vector512<ulong> outerBorrowMask = UnsignedLessThan(innerDiff, borrowIn);
        borrowOutMask = Avx512F.Or(innerBorrowMask, outerBorrowMask);
    }


    /// <summary>Lane-wise unsigned less-than via AVX-512's native <c>vpcmpuq</c>: all-ones per lane where <paramref name="a"/> &lt; <paramref name="b"/> unsigned.</summary>
    private static Vector512<ulong> UnsignedLessThan(Vector512<ulong> a, Vector512<ulong> b)
    {
        //a < b unsigned is equivalent to b > a unsigned.
        return Avx512F.CompareGreaterThan(b, a);
    }


    /// <summary>Reads a canonical big-endian scalar into little-endian 64-bit limbs.</summary>
    private static void LoadCanonicalToLimbs(ReadOnlySpan<byte> canonical, Span<ulong> limbs)
    {
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int offset = (LimbCount - 1 - limbIndex) * BytesPerLimb;
            limbs[limbIndex] = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(offset, BytesPerLimb));
        }
    }


    /// <summary>Writes little-endian 64-bit limbs back out as a canonical big-endian scalar.</summary>
    private static void StoreLimbsToCanonical(ReadOnlySpan<ulong> limbs, Span<byte> canonical)
    {
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int offset = (LimbCount - 1 - limbIndex) * BytesPerLimb;
            BinaryPrimitives.WriteUInt64BigEndian(canonical.Slice(offset, BytesPerLimb), limbs[limbIndex]);
        }
    }


    /// <summary>Adds two 256-bit limb tuples with carry propagation, returning whether the sum overflowed.</summary>
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


    /// <summary>Subtracts one 256-bit limb tuple from another in place with borrow propagation, returning whether the result underflowed.</summary>
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


    /// <summary>Constant-time selection of one of two limb tuples based on a scalar boolean.</summary>
    private static void ConditionalSelect(
        ReadOnlySpan<ulong> onTrue,
        ReadOnlySpan<ulong> onFalse,
        bool condition,
        Span<byte> destination)
    {
        Vector512<ulong> mask = condition ? Vector512<ulong>.AllBitsSet : Vector512<ulong>.Zero;

        Span<ulong> selectedLimbs = stackalloc ulong[LimbCount];
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            Vector512<ulong> trueLane = Vector512.Create(onTrue[limbIndex]);
            Vector512<ulong> falseLane = Vector512.Create(onFalse[limbIndex]);
            Vector512<ulong> picked = Vector512.ConditionalSelect(mask, trueLane, falseLane);
            selectedLimbs[limbIndex] = picked.GetElement(0);
        }

        StoreLimbsToCanonical(selectedLimbs, destination);
    }


    /// <summary>Loads eight canonical scalars into four limb-major <see cref="Vector512{T}"/> registers, one lane per scalar.</summary>
    /// <remarks>
    /// Scalars 0-3 and scalars 4-7 are each loaded as byte-reversed limb vectors by
    /// <see cref="LoadScalarLimbs"/> and transposed to limb-major form by
    /// <see cref="TransposeQuartetLanes"/>; each limb position's two half-width results are then
    /// joined with <c>Vector512.Create(lower, upper)</c>, which places the first operand in
    /// lanes 0-3 and the second in lanes 4-7.
    /// </remarks>
    /// <param name="octetBytes">Eight consecutive canonical scalars.</param>
    /// <param name="limb0">Receives the least-significant limb of each scalar, one per lane.</param>
    /// <param name="limb1">Receives the second limb of each scalar, one per lane.</param>
    /// <param name="limb2">Receives the third limb of each scalar, one per lane.</param>
    /// <param name="limb3">Receives the most-significant limb of each scalar, one per lane.</param>
    private static void LoadOctetToLimbVectors(
        ReadOnlySpan<byte> octetBytes,
        out Vector512<ulong> limb0,
        out Vector512<ulong> limb1,
        out Vector512<ulong> limb2,
        out Vector512<ulong> limb3)
    {
        int stride = Scalar.SizeBytes;
        Vector256<ulong> scalar0 = LoadScalarLimbs(octetBytes.Slice(0 * stride, stride));
        Vector256<ulong> scalar1 = LoadScalarLimbs(octetBytes.Slice(1 * stride, stride));
        Vector256<ulong> scalar2 = LoadScalarLimbs(octetBytes.Slice(2 * stride, stride));
        Vector256<ulong> scalar3 = LoadScalarLimbs(octetBytes.Slice(3 * stride, stride));
        Vector256<ulong> scalar4 = LoadScalarLimbs(octetBytes.Slice(4 * stride, stride));
        Vector256<ulong> scalar5 = LoadScalarLimbs(octetBytes.Slice(5 * stride, stride));
        Vector256<ulong> scalar6 = LoadScalarLimbs(octetBytes.Slice(6 * stride, stride));
        Vector256<ulong> scalar7 = LoadScalarLimbs(octetBytes.Slice(7 * stride, stride));

        TransposeQuartetLanes(scalar0, scalar1, scalar2, scalar3, out Vector256<ulong> lowerLimb0, out Vector256<ulong> lowerLimb1, out Vector256<ulong> lowerLimb2, out Vector256<ulong> lowerLimb3);
        TransposeQuartetLanes(scalar4, scalar5, scalar6, scalar7, out Vector256<ulong> upperLimb0, out Vector256<ulong> upperLimb1, out Vector256<ulong> upperLimb2, out Vector256<ulong> upperLimb3);

        limb0 = Vector512.Create(lowerLimb0, upperLimb0);
        limb1 = Vector512.Create(lowerLimb1, upperLimb1);
        limb2 = Vector512.Create(lowerLimb2, upperLimb2);
        limb3 = Vector512.Create(lowerLimb3, upperLimb3);
    }


    /// <summary>Writes four limb-major <see cref="Vector512{T}"/> registers back into eight canonical scalars, one lane per scalar.</summary>
    /// <remarks>
    /// A 4x4 transpose is its own inverse, so <see cref="TransposeQuartetLanes"/> applied to the
    /// lower halves (<c>GetLower</c>) and the upper halves (<c>GetUpper</c>) of the four limb
    /// registers recovers scalars 0-3 and scalars 4-7, which <see cref="StoreScalarLimbs"/> writes
    /// back as canonical bytes.
    /// </remarks>
    /// <param name="limb0">The least-significant limb of each scalar, one per lane.</param>
    /// <param name="limb1">The second limb of each scalar, one per lane.</param>
    /// <param name="limb2">The third limb of each scalar, one per lane.</param>
    /// <param name="limb3">The most-significant limb of each scalar, one per lane.</param>
    /// <param name="octetBytes">Receives the eight consecutive canonical scalars.</param>
    private static void StoreLimbVectorsToOctet(
        Vector512<ulong> limb0,
        Vector512<ulong> limb1,
        Vector512<ulong> limb2,
        Vector512<ulong> limb3,
        Span<byte> octetBytes)
    {
        TransposeQuartetLanes(limb0.GetLower(), limb1.GetLower(), limb2.GetLower(), limb3.GetLower(), out Vector256<ulong> scalar0, out Vector256<ulong> scalar1, out Vector256<ulong> scalar2, out Vector256<ulong> scalar3);
        TransposeQuartetLanes(limb0.GetUpper(), limb1.GetUpper(), limb2.GetUpper(), limb3.GetUpper(), out Vector256<ulong> scalar4, out Vector256<ulong> scalar5, out Vector256<ulong> scalar6, out Vector256<ulong> scalar7);

        int stride = Scalar.SizeBytes;
        StoreScalarLimbs(scalar0, octetBytes.Slice(0 * stride, stride));
        StoreScalarLimbs(scalar1, octetBytes.Slice(1 * stride, stride));
        StoreScalarLimbs(scalar2, octetBytes.Slice(2 * stride, stride));
        StoreScalarLimbs(scalar3, octetBytes.Slice(3 * stride, stride));
        StoreScalarLimbs(scalar4, octetBytes.Slice(4 * stride, stride));
        StoreScalarLimbs(scalar5, octetBytes.Slice(5 * stride, stride));
        StoreScalarLimbs(scalar6, octetBytes.Slice(6 * stride, stride));
        StoreScalarLimbs(scalar7, octetBytes.Slice(7 * stride, stride));
    }


    /// <summary>Reads one scalar's 32 canonical big-endian bytes as its four 64-bit limbs, least-significant first.</summary>
    /// <remarks>
    /// Reversing the 32 bytes end to end and reading little-endian 64-bit words in increasing offset
    /// order yields the big-endian words of the original in decreasing offset order, which is
    /// exactly limb 0 through limb 3. The reinterpretation relies on the little-endian lane layout
    /// of the x86-64 hosts this backend runs on.
    /// </remarks>
    /// <param name="canonical">The 32 canonical big-endian scalar bytes.</param>
    private static Vector256<ulong> LoadScalarLimbs(ReadOnlySpan<byte> canonical)
    {
        Vector256<byte> canonicalBytes = Vector256.Create(canonical);
        Vector256<byte> littleEndianBytes = Vector256.Reverse(canonicalBytes);

        return littleEndianBytes.AsUInt64();
    }


    /// <summary>Writes one scalar's four 64-bit limbs, least-significant first, as its 32 canonical big-endian bytes; the inverse of <see cref="LoadScalarLimbs"/>.</summary>
    /// <param name="limbs">The four 64-bit limbs.</param>
    /// <param name="canonical">Receives the 32 canonical big-endian scalar bytes.</param>
    private static void StoreScalarLimbs(Vector256<ulong> limbs, Span<byte> canonical)
    {
        Vector256<byte> littleEndianBytes = limbs.AsByte();
        Vector256<byte> canonicalBytes = Vector256.Reverse(littleEndianBytes);

        canonicalBytes.CopyTo(canonical);
    }


    /// <summary>
    /// Transposes four <see cref="Vector256{T}"/> of <see cref="ulong"/>, each holding one source's
    /// four values, into four vectors each holding one position with lane <c>i</c> carrying source
    /// <c>i</c>'s value at that position.
    /// </summary>
    /// <remarks>
    /// A matrix transpose is its own inverse, so running this method on its own output recovers its
    /// inputs and one implementation serves both load and store. The pairing stage zips sources
    /// <c>(0, 1)</c> and <c>(2, 3)</c> with <c>ZipLower</c> and <c>ZipUpper</c>; the assembly stage
    /// selects the matching half of each pair with <c>ConcatLowerLower</c> and <c>ConcatUpperUpper</c>.
    /// </remarks>
    private static void TransposeQuartetLanes(
        Vector256<ulong> v0,
        Vector256<ulong> v1,
        Vector256<ulong> v2,
        Vector256<ulong> v3,
        out Vector256<ulong> w0,
        out Vector256<ulong> w1,
        out Vector256<ulong> w2,
        out Vector256<ulong> w3)
    {
        Vector256<ulong> lo01 = Vector256.ZipLower(v0, v1);
        Vector256<ulong> hi01 = Vector256.ZipUpper(v0, v1);
        Vector256<ulong> lo23 = Vector256.ZipLower(v2, v3);
        Vector256<ulong> hi23 = Vector256.ZipUpper(v2, v3);

        w0 = Vector256.ConcatLowerLower(lo01, lo23);
        w1 = Vector256.ConcatUpperUpper(lo01, lo23);
        w2 = Vector256.ConcatLowerLower(hi01, hi23);
        w3 = Vector256.ConcatUpperUpper(hi01, hi23);
    }

    /// <summary>Throws when a batched operand or result buffer is not exactly <paramref name="count"/> times <paramref name="stride"/> bytes.</summary>
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


    /// <summary>Throws when the host CPU does not support AVX-512F.</summary>
    private static void EnsureSupported()
    {
        if(!Avx512F.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "Bn254Avx512ScalarBackend requires AVX-512F; check IsSupported before wiring it as a delegate.");
        }
    }


    /// <summary>The number of 32-bit limbs that compose a BN254 scalar for the lane-interleaved batch Montgomery multiply (256 bits / 32 bits per limb).</summary>
    private const int Limb32Count = 8;

    /// <summary>The per-lane mask that keeps the low 32 bits of a 64-bit lane, discarding the carry bits a 32×32→64 product or a limb sum accumulates above bit 31.</summary>
    private static Vector512<ulong> Low32Mask { get; } = Vector512.Create(0xFFFFFFFFUL);

    /// <summary>The Montgomery reduction constant <c>n'</c> for the 32-bit-limb CIOS scheme, broadcast into all eight lanes.</summary>
    private static Vector512<ulong> NPrime32Broadcast { get; } = Vector512.Create((ulong)Bn254MontgomeryParameters.NPrime32);

    /// <summary>The BN254 modulus's 32-bit limbs, each broadcast into its own per-lane <see cref="Vector512{T}"/>.</summary>
    private static Vector512<ulong>[] Modulus32Broadcast { get; } = BuildBroadcast(Bn254MontgomeryParameters.Modulus32Limbs);

    /// <summary>The Montgomery constant <c>R² mod r</c>'s 32-bit limbs, each broadcast into its own per-lane <see cref="Vector512{T}"/>, used to lift an operand into the Montgomery domain.</summary>
    private static Vector512<ulong>[] RSquared32Broadcast { get; } = BuildBroadcast(Bn254MontgomeryParameters.RSquared32Limbs);


    /// <summary>Broadcasts each 32-bit limb of a limb array into its own per-lane <see cref="Vector512{T}"/>.</summary>
    private static Vector512<ulong>[] BuildBroadcast(ReadOnlySpan<uint> limbs32)
    {
        var vectors = new Vector512<ulong>[Limb32Count];
        for(int i = 0; i < Limb32Count; i++)
        {
            vectors[i] = Vector512.Create((ulong)limbs32[i]);
        }

        return vectors;
    }


    /// <summary>Multiplies scalar pairs in SIMD octets via the lane-interleaved 32-bit-limb CIOS Montgomery multiply, falling back to the shared serial Montgomery multiply for the trailing 1–7 elements.</summary>
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

        int octets = count / ScalarsPerOctet;
        for(int octetIndex = 0; octetIndex < octets; octetIndex++)
        {
            int offset = octetIndex * OctetBytes;
            MultiplyOctet(
                leftOperandsConcatenated.Slice(offset, OctetBytes),
                rightOperandsConcatenated.Slice(offset, OctetBytes),
                resultsConcatenated.Slice(offset, OctetBytes));
        }

        int tailStart = octets * OctetBytes;
        int tailCount = count % ScalarsPerOctet;
        for(int i = 0; i < tailCount; i++)
        {
            int offset = tailStart + i * stride;
            Bn254MontgomeryArithmetic.Multiply(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    /// <summary>SIMD inner loop: multiplies eight scalar pairs in parallel by lifting the left operand into the Montgomery domain and then performing one Montgomery multiply against the right operand.</summary>
    private static void MultiplyOctet(
        ReadOnlySpan<byte> aOctet,
        ReadOnlySpan<byte> bOctet,
        Span<byte> resultOctet)
    {
        Span<Vector512<ulong>> a = stackalloc Vector512<ulong>[Limb32Count];
        Span<Vector512<ulong>> b = stackalloc Vector512<ulong>[Limb32Count];
        Span<Vector512<ulong>> aMontgomery = stackalloc Vector512<ulong>[Limb32Count];
        Span<Vector512<ulong>> product = stackalloc Vector512<ulong>[Limb32Count];

        LoadOctetTo32LimbVectors(aOctet, a);
        LoadOctetTo32LimbVectors(bOctet, b);

        MontgomeryMultiplyOctet(a, RSquared32Broadcast, aMontgomery);
        MontgomeryMultiplyOctet(aMontgomery, b, product);

        Store32LimbVectorsToOctet(product, resultOctet);
    }


    /// <summary>The lane-interleaved 32-bit-limb CIOS Montgomery multiply: computes <c>x·y·R⁻¹ mod r</c> across all eight lanes at once, each 32×32→64 partial product a single <c>vpmuludq</c>.</summary>
    private static void MontgomeryMultiplyOctet(
        ReadOnlySpan<Vector512<ulong>> x,
        ReadOnlySpan<Vector512<ulong>> y,
        Span<Vector512<ulong>> result)
    {
        Span<Vector512<ulong>> t = stackalloc Vector512<ulong>[Limb32Count + 2];
        for(int k = 0; k < Limb32Count + 2; k++)
        {
            t[k] = Vector512<ulong>.Zero;
        }

        Vector512<ulong> mask = Low32Mask;

        for(int i = 0; i < Limb32Count; i++)
        {
            Vector512<ulong> carry = Vector512<ulong>.Zero;
            for(int j = 0; j < Limb32Count; j++)
            {
                Vector512<ulong> partial = Avx512F.Multiply(x[j].AsUInt32(), y[i].AsUInt32());
                Vector512<ulong> sum = Avx512F.Add(Avx512F.Add(t[j], partial), carry);
                t[j] = Avx512F.And(sum, mask);
                carry = Avx512F.ShiftRightLogical(sum, 32);
            }

            Vector512<ulong> highSum = Avx512F.Add(t[Limb32Count], carry);
            t[Limb32Count] = Avx512F.And(highSum, mask);
            t[Limb32Count + 1] = Avx512F.ShiftRightLogical(highSum, 32);

            Vector512<ulong> m = Avx512F.And(Avx512F.Multiply(t[0].AsUInt32(), NPrime32Broadcast.AsUInt32()), mask);
            Vector512<ulong> reduceLow = Avx512F.Add(t[0], Avx512F.Multiply(m.AsUInt32(), Modulus32Broadcast[0].AsUInt32()));
            carry = Avx512F.ShiftRightLogical(reduceLow, 32);
            for(int j = 1; j < Limb32Count; j++)
            {
                Vector512<ulong> reduceTerm = Avx512F.Add(Avx512F.Add(t[j], Avx512F.Multiply(m.AsUInt32(), Modulus32Broadcast[j].AsUInt32())), carry);
                t[j - 1] = Avx512F.And(reduceTerm, mask);
                carry = Avx512F.ShiftRightLogical(reduceTerm, 32);
            }

            Vector512<ulong> reduceHigh = Avx512F.Add(t[Limb32Count], carry);
            t[Limb32Count - 1] = Avx512F.And(reduceHigh, mask);
            t[Limb32Count] = Avx512F.Add(t[Limb32Count + 1], Avx512F.ShiftRightLogical(reduceHigh, 32));
        }

        ConditionalSubtractModulusOctet(t, result);
    }


    /// <summary>Speculatively subtracts the modulus from the CIOS accumulator across all eight lanes and selects the reduced or unreduced result per lane without a data-dependent branch.</summary>
    private static void ConditionalSubtractModulusOctet(ReadOnlySpan<Vector512<ulong>> t, Span<Vector512<ulong>> result)
    {
        Vector512<ulong> mask = Low32Mask;
        Span<Vector512<ulong>> reduced = stackalloc Vector512<ulong>[Limb32Count];

        Vector512<ulong> borrow = Vector512<ulong>.Zero;
        for(int j = 0; j < Limb32Count; j++)
        {
            Vector512<ulong> difference = Avx512F.Subtract(Avx512F.Subtract(t[j], Modulus32Broadcast[j]), borrow);
            reduced[j] = Avx512F.And(difference, mask);
            borrow = Avx512F.ShiftRightLogical(difference, 63);
        }

        Vector512<ulong> overflowMask = Avx512F.Subtract(Vector512<ulong>.Zero, t[Limb32Count]);
        Vector512<ulong> borrowMask = Avx512F.Subtract(Vector512<ulong>.Zero, borrow);
        Vector512<ulong> notBorrowMask = Avx512F.Xor(borrowMask, Vector512<ulong>.AllBitsSet);
        Vector512<ulong> useReducedMask = Avx512F.Or(overflowMask, notBorrowMask);

        for(int j = 0; j < Limb32Count; j++)
        {
            result[j] = Vector512.ConditionalSelect(useReducedMask, reduced[j], t[j]);
        }
    }


    /// <summary>Loads eight canonical scalars into eight limb-major <see cref="Vector512{T}"/> registers of 32-bit limbs, one lane per scalar.</summary>
    /// <remarks>
    /// <see cref="LoadScalarLowHighLimbs"/> yields each scalar's limbs 0-3 and 4-7 zero-extended to
    /// 64-bit lanes. Scalars 0-3 and scalars 4-7 are transposed separately by
    /// <see cref="TransposeQuartetLanes"/>, once for each limb half, and every limb position's two
    /// half-width results are joined with <c>Vector512.Create(lower, upper)</c>.
    /// </remarks>
    /// <param name="octetBytes">Eight consecutive canonical scalars.</param>
    /// <param name="limbVectors">Receives the eight 32-bit-limb vectors, least-significant limb first.</param>
    private static void LoadOctetTo32LimbVectors(ReadOnlySpan<byte> octetBytes, Span<Vector512<ulong>> limbVectors)
    {
        int stride = Scalar.SizeBytes;
        LoadScalarLowHighLimbs(octetBytes.Slice(0 * stride, stride), out Vector256<ulong> scalar0Low, out Vector256<ulong> scalar0High);
        LoadScalarLowHighLimbs(octetBytes.Slice(1 * stride, stride), out Vector256<ulong> scalar1Low, out Vector256<ulong> scalar1High);
        LoadScalarLowHighLimbs(octetBytes.Slice(2 * stride, stride), out Vector256<ulong> scalar2Low, out Vector256<ulong> scalar2High);
        LoadScalarLowHighLimbs(octetBytes.Slice(3 * stride, stride), out Vector256<ulong> scalar3Low, out Vector256<ulong> scalar3High);
        LoadScalarLowHighLimbs(octetBytes.Slice(4 * stride, stride), out Vector256<ulong> scalar4Low, out Vector256<ulong> scalar4High);
        LoadScalarLowHighLimbs(octetBytes.Slice(5 * stride, stride), out Vector256<ulong> scalar5Low, out Vector256<ulong> scalar5High);
        LoadScalarLowHighLimbs(octetBytes.Slice(6 * stride, stride), out Vector256<ulong> scalar6Low, out Vector256<ulong> scalar6High);
        LoadScalarLowHighLimbs(octetBytes.Slice(7 * stride, stride), out Vector256<ulong> scalar7Low, out Vector256<ulong> scalar7High);

        TransposeQuartetLanes(scalar0Low, scalar1Low, scalar2Low, scalar3Low, out Vector256<ulong> lowerLimb0, out Vector256<ulong> lowerLimb1, out Vector256<ulong> lowerLimb2, out Vector256<ulong> lowerLimb3);
        TransposeQuartetLanes(scalar4Low, scalar5Low, scalar6Low, scalar7Low, out Vector256<ulong> upperLimb0, out Vector256<ulong> upperLimb1, out Vector256<ulong> upperLimb2, out Vector256<ulong> upperLimb3);
        limbVectors[0] = Vector512.Create(lowerLimb0, upperLimb0);
        limbVectors[1] = Vector512.Create(lowerLimb1, upperLimb1);
        limbVectors[2] = Vector512.Create(lowerLimb2, upperLimb2);
        limbVectors[3] = Vector512.Create(lowerLimb3, upperLimb3);

        TransposeQuartetLanes(scalar0High, scalar1High, scalar2High, scalar3High, out Vector256<ulong> lowerLimb4, out Vector256<ulong> lowerLimb5, out Vector256<ulong> lowerLimb6, out Vector256<ulong> lowerLimb7);
        TransposeQuartetLanes(scalar4High, scalar5High, scalar6High, scalar7High, out Vector256<ulong> upperLimb4, out Vector256<ulong> upperLimb5, out Vector256<ulong> upperLimb6, out Vector256<ulong> upperLimb7);
        limbVectors[4] = Vector512.Create(lowerLimb4, upperLimb4);
        limbVectors[5] = Vector512.Create(lowerLimb5, upperLimb5);
        limbVectors[6] = Vector512.Create(lowerLimb6, upperLimb6);
        limbVectors[7] = Vector512.Create(lowerLimb7, upperLimb7);
    }


    /// <summary>Writes eight limb-major 32-bit-limb <see cref="Vector512{T}"/> registers back into eight canonical scalars, one lane per scalar.</summary>
    /// <remarks>
    /// <see cref="TransposeQuartetLanes"/> inverts limb-major back to scalar-major, applied to the
    /// lower and upper halves of limbs 0-3 and of limbs 4-7. <see cref="StoreScalarLowHighLimbs"/>
    /// narrows and writes each scalar's pair of halves as canonical bytes.
    /// </remarks>
    /// <param name="limbVectors">The eight 32-bit-limb vectors, least-significant limb first.</param>
    /// <param name="octetBytes">Receives the eight consecutive canonical scalars.</param>
    private static void Store32LimbVectorsToOctet(ReadOnlySpan<Vector512<ulong>> limbVectors, Span<byte> octetBytes)
    {
        TransposeQuartetLanes(limbVectors[0].GetLower(), limbVectors[1].GetLower(), limbVectors[2].GetLower(), limbVectors[3].GetLower(), out Vector256<ulong> scalar0Low, out Vector256<ulong> scalar1Low, out Vector256<ulong> scalar2Low, out Vector256<ulong> scalar3Low);
        TransposeQuartetLanes(limbVectors[0].GetUpper(), limbVectors[1].GetUpper(), limbVectors[2].GetUpper(), limbVectors[3].GetUpper(), out Vector256<ulong> scalar4Low, out Vector256<ulong> scalar5Low, out Vector256<ulong> scalar6Low, out Vector256<ulong> scalar7Low);
        TransposeQuartetLanes(limbVectors[4].GetLower(), limbVectors[5].GetLower(), limbVectors[6].GetLower(), limbVectors[7].GetLower(), out Vector256<ulong> scalar0High, out Vector256<ulong> scalar1High, out Vector256<ulong> scalar2High, out Vector256<ulong> scalar3High);
        TransposeQuartetLanes(limbVectors[4].GetUpper(), limbVectors[5].GetUpper(), limbVectors[6].GetUpper(), limbVectors[7].GetUpper(), out Vector256<ulong> scalar4High, out Vector256<ulong> scalar5High, out Vector256<ulong> scalar6High, out Vector256<ulong> scalar7High);

        int stride = Scalar.SizeBytes;
        StoreScalarLowHighLimbs(scalar0Low, scalar0High, octetBytes.Slice(0 * stride, stride));
        StoreScalarLowHighLimbs(scalar1Low, scalar1High, octetBytes.Slice(1 * stride, stride));
        StoreScalarLowHighLimbs(scalar2Low, scalar2High, octetBytes.Slice(2 * stride, stride));
        StoreScalarLowHighLimbs(scalar3Low, scalar3High, octetBytes.Slice(3 * stride, stride));
        StoreScalarLowHighLimbs(scalar4Low, scalar4High, octetBytes.Slice(4 * stride, stride));
        StoreScalarLowHighLimbs(scalar5Low, scalar5High, octetBytes.Slice(5 * stride, stride));
        StoreScalarLowHighLimbs(scalar6Low, scalar6High, octetBytes.Slice(6 * stride, stride));
        StoreScalarLowHighLimbs(scalar7Low, scalar7High, octetBytes.Slice(7 * stride, stride));
    }


    /// <summary>Reads one scalar's 32 canonical big-endian bytes as its eight 32-bit limbs, zero-extended into two <see cref="Vector256{T}"/> of <see cref="ulong"/>.</summary>
    /// <remarks>
    /// The reversed-byte-string identity described on <see cref="LoadScalarLimbs"/> holds at 32-bit
    /// granularity: reversing the buffer and reading little-endian 32-bit words in increasing offset
    /// order yields limbs 0-7 least-significant first.
    /// </remarks>
    /// <param name="canonical">The 32 canonical big-endian scalar bytes.</param>
    /// <param name="low">Receives limbs 0-3, one per 64-bit lane.</param>
    /// <param name="high">Receives limbs 4-7, one per 64-bit lane.</param>
    private static void LoadScalarLowHighLimbs(ReadOnlySpan<byte> canonical, out Vector256<ulong> low, out Vector256<ulong> high)
    {
        Vector256<byte> canonicalBytes = Vector256.Create(canonical);
        Vector256<byte> littleEndianBytes = Vector256.Reverse(canonicalBytes);
        Vector256<uint> limbs32 = littleEndianBytes.AsUInt32();

        low = Vector256.WidenLower(limbs32);
        high = Vector256.WidenUpper(limbs32);
    }


    /// <summary>Writes one scalar's eight 32-bit limbs, held zero-extended across <paramref name="low"/> and <paramref name="high"/>, as its 32 canonical big-endian bytes; the inverse of <see cref="LoadScalarLowHighLimbs"/>.</summary>
    /// <param name="low">Limbs 0-3, one per 64-bit lane.</param>
    /// <param name="high">Limbs 4-7, one per 64-bit lane.</param>
    /// <param name="canonical">Receives the 32 canonical big-endian scalar bytes.</param>
    private static void StoreScalarLowHighLimbs(Vector256<ulong> low, Vector256<ulong> high, Span<byte> canonical)
    {
        Vector256<uint> limbs32 = Vector256.Narrow(low, high);
        Vector256<byte> littleEndianBytes = limbs32.AsByte();
        Vector256<byte> canonicalBytes = Vector256.Reverse(littleEndianBytes);

        canonicalBytes.CopyTo(canonical);
    }
}
