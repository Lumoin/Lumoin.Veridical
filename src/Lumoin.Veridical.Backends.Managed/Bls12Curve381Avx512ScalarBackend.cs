using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// AVX-512 (Intel/AMD x86_64) implementation of BLS12-381 scalar
/// arithmetic. Same algorithm as the AVX2 backend with the lane width
/// doubled: eight scalars per octet instead of four per quartet.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Vector512{T}"/> holds eight 64-bit lanes, so the
/// limb-major layout used by the carry chain now advances eight
/// independent scalars in parallel per limb step. The serial carry chain
/// across the four limbs is unchanged from the AVX2 path; only the lane
/// count differs.
/// </para>
/// <para>
/// AVX-512's <c>vpcmpuq</c> instruction provides a native unsigned 64-bit
/// compare, exposed by .NET as
/// <see cref="Avx512F.CompareGreaterThan(Vector512{ulong}, Vector512{ulong})"/>.
/// The AVX2 path needs the XOR-with-sign-bit trick to emulate this;
/// AVX-512 does not. The conditional modular reduction uses
/// <see cref="Vector512.ConditionalSelect{T}(Vector512{T}, Vector512{T}, Vector512{T})"/>,
/// which the JIT lowers to <c>vpternlogq</c> or a masked <c>vpblendmq</c>
/// — single-cycle bitwise selection independent of input data, so the
/// conditional reduction stays constant-time per lane.
/// </para>
/// <para>
/// Hardware availability: Intel Sapphire Rapids (Xeon, 2023+), AMD Zen 4+
/// (Ryzen 7000+ / EPYC 9004+). NOT available on most Intel consumer chips
/// post-Rocket Lake (Intel disabled AVX-512 in Alder Lake and later
/// consumer CPUs). On unsupported hosts the dispatch facade
/// (<see cref="Bls12Curve381SimdScalarBackend"/>) falls through to AVX2
/// or NEON.
/// </para>
/// <para>
/// Multiply, negate, and invert are implemented (the serial CIOS
/// Montgomery multiply / Fermat ladder shared via
/// <see cref="Bls12Curve381MontgomeryArithmetic"/>); the AVX-512 lane width
/// accelerates the batched add/subtract, not a single serial multiply. The
/// larger AVX-512 multiply win for ZKP workloads lies in the IFMA52
/// instructions (<c>vpmadd52luq</c>/<c>vpmadd52huq</c>, 52-bit limb
/// products with a fused accumulate), which .NET exposes no intrinsic for;
/// the multiply therefore stays on the shared serial path.
/// </para>
/// </remarks>
internal static class Bls12Curve381Avx512ScalarBackend
{
    /// <summary>True when the host CPU supports the AVX-512 foundation instructions this backend uses.</summary>
    public static bool IsSupported => Avx512F.IsSupported;


    /// <summary>The number of 64-bit limbs that compose a BLS12-381 scalar (256 bits / 64 bits per limb).</summary>
    private const int LimbCount = 4;

    /// <summary>The number of canonical bytes per 64-bit limb.</summary>
    private const int BytesPerLimb = sizeof(ulong);

    /// <summary>
    /// The number of independent scalars packed into one SIMD octet.
    /// Matches the number of 64-bit lanes in <see cref="Vector512{T}"/>:
    /// eight scalars share each limb-position register, one per lane.
    /// </summary>
    private const int ScalarsPerOctet = 8;

    /// <summary>The number of canonical bytes per scalar octet (eight scalars, each <see cref="Scalar.SizeBytes"/> bytes).</summary>
    private const int OctetBytes = ScalarsPerOctet * Scalar.SizeBytes;


    /// <summary>
    /// BLS12-381 scalar-field modulus <c>r</c> as four little-endian
    /// 64-bit limbs.
    /// </summary>
    private static ulong[] FieldOrderLimbs { get; } =
    [
        0xffffffff00000001UL,
        0x53bda402fffe5bfeUL,
        0x3339d80809a1d805UL,
        0x73eda753299d7d48UL
    ];


    /// <summary>Broadcast of <c>r</c>'s least-significant limb (<see cref="FieldOrderLimbs"/> index 0) across all eight 64-bit lanes.</summary>
    private static Vector512<ulong> FieldOrderLane0 { get; } = Vector512.Create(0xffffffff00000001UL);

    /// <summary>Broadcast of <c>r</c>'s second limb (<see cref="FieldOrderLimbs"/> index 1) across all eight 64-bit lanes.</summary>
    private static Vector512<ulong> FieldOrderLane1 { get; } = Vector512.Create(0x53bda402fffe5bfeUL);

    /// <summary>Broadcast of <c>r</c>'s third limb (<see cref="FieldOrderLimbs"/> index 2) across all eight 64-bit lanes.</summary>
    private static Vector512<ulong> FieldOrderLane2 { get; } = Vector512.Create(0x3339d80809a1d805UL);

    /// <summary>Broadcast of <c>r</c>'s most-significant limb (<see cref="FieldOrderLimbs"/> index 3) across all eight 64-bit lanes.</summary>
    private static Vector512<ulong> FieldOrderLane3 { get; } = Vector512.Create(0x73eda753299d7d48UL);


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


    /// <summary>The <see cref="ScalarAddDelegate"/> implementation: verifies AVX-512 support, records the operation, and computes the canonical sum via <see cref="AddCore"/>.</summary>
    /// <param name="a">The first canonical scalar.</param>
    /// <param name="b">The second canonical scalar.</param>
    /// <param name="result">Receives the canonical sum.</param>
    /// <param name="curve">The curve parameter set, used only for operation-counter attribution.</param>
    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarAdd, curve);
        AddCore(a, b, result);
    }


    /// <summary>Computes the canonical sum of two scalars modulo the field order, without the AVX-512 support check or operation counting.</summary>
    /// <param name="a">The first canonical scalar.</param>
    /// <param name="b">The second canonical scalar.</param>
    /// <param name="result">Receives the canonical sum.</param>
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


    /// <summary>The <see cref="ScalarSubtractDelegate"/> implementation: verifies AVX-512 support, records the operation, and computes the canonical difference via <see cref="SubtractCore"/>.</summary>
    /// <param name="a">The minuend canonical scalar.</param>
    /// <param name="b">The subtrahend canonical scalar.</param>
    /// <param name="result">Receives the canonical difference.</param>
    /// <param name="curve">The curve parameter set, used only for operation-counter attribution.</param>
    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarSubtract, curve);
        SubtractCore(a, b, result);
    }


    /// <summary>Computes the canonical difference of two scalars modulo the field order, without the AVX-512 support check or operation counting.</summary>
    /// <param name="a">The minuend canonical scalar.</param>
    /// <param name="b">The subtrahend canonical scalar.</param>
    /// <param name="result">Receives the canonical difference.</param>
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


    /// <summary>The <see cref="ScalarMultiplyDelegate"/> implementation: verifies AVX-512 support, records the operation, and multiplies via the ISA-independent serial CIOS Montgomery multiply.</summary>
    /// <param name="a">The first canonical scalar.</param>
    /// <param name="b">The second canonical scalar.</param>
    /// <param name="result">Receives the canonical product.</param>
    /// <param name="curve">The curve parameter set, used only for operation-counter attribution.</param>
    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarMultiply, curve);

        //A single Montgomery multiply is a serial limb carry chain that SIMD does not
        //accelerate; the ISA-independent body is shared across the backends.
        Bls12Curve381MontgomeryArithmetic.Multiply(a, b, result);
    }


    /// <summary>The <see cref="ScalarInvertDelegate"/> implementation: verifies AVX-512 support, records the operation, and inverts via the shared Fermat-ladder Montgomery arithmetic.</summary>
    /// <param name="a">The canonical scalar to invert.</param>
    /// <param name="result">Receives the canonical inverse.</param>
    /// <param name="curve">The curve parameter set, used only for operation-counter attribution.</param>
    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        EnsureSupported();

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarInvert, curve);
        Bls12Curve381MontgomeryArithmetic.Invert(a, result);
    }


    /// <summary>The <see cref="ScalarNegateDelegate"/> implementation: verifies AVX-512 support, records the operation, and negates via <see cref="NegateCore"/>.</summary>
    /// <param name="a">The canonical scalar to negate.</param>
    /// <param name="result">Receives the canonical negation.</param>
    /// <param name="curve">The curve parameter set, used only for operation-counter attribution.</param>
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


    /// <summary>The <see cref="ScalarBatchAddDelegate"/> implementation: adds <paramref name="count"/> scalar pairs, eight at a time via <see cref="AddOctet"/>, with a scalar fallback via <see cref="AddCore"/> for the trailing 1-7 elements.</summary>
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


    /// <summary>The <see cref="ScalarBatchSubtractDelegate"/> implementation: subtracts <paramref name="count"/> scalar pairs, eight at a time via <see cref="SubtractOctet"/>, with a scalar fallback via <see cref="SubtractCore"/> for the trailing 1-7 elements.</summary>
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

        //Add with carry chain across the four limbs. Native u64 compare on
        //AVX-512 means the per-limb carry detection is one instruction.
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

        //ConditionalSelect lowers to vpternlogq or vpblendmq — constant-time
        //bitwise selection independent of the condition's data path.
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


    /// <summary>Adds one limb position across all eight lanes with an incoming carry, returning the sum and the outgoing carry mask.</summary>
    /// <param name="a">The first operand's limb, one value per lane.</param>
    /// <param name="b">The second operand's limb, one value per lane.</param>
    /// <param name="carryIn">The incoming carry: all-ones per lane where a carry is pending, zero otherwise.</param>
    /// <param name="sum">Receives the limb sum, per lane.</param>
    /// <param name="carryOutMask">Receives the outgoing carry: all-ones per lane where the addition carried.</param>
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


    /// <summary>Subtracts one limb position across all eight lanes with an incoming borrow, returning the difference and the outgoing borrow mask.</summary>
    /// <param name="a">The minuend's limb, one value per lane.</param>
    /// <param name="b">The subtrahend's limb, one value per lane.</param>
    /// <param name="borrowIn">The incoming borrow: all-ones per lane where a borrow is pending, zero otherwise.</param>
    /// <param name="diff">Receives the limb difference, per lane.</param>
    /// <param name="borrowOutMask">Receives the outgoing borrow: all-ones per lane where the subtraction borrowed.</param>
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


    /// <summary>
    /// Lane-wise unsigned less-than via AVX-512's native <c>vpcmpuq</c>.
    /// Returns all-ones per lane where <paramref name="a"/> is unsigned
    /// less than <paramref name="b"/>.
    /// </summary>
    private static Vector512<ulong> UnsignedLessThan(Vector512<ulong> a, Vector512<ulong> b)
    {
        //a < b unsigned is equivalent to b > a unsigned.
        return Avx512F.CompareGreaterThan(b, a);
    }


    /// <summary>Reads a canonical big-endian scalar into little-endian-ordered 64-bit limbs.</summary>
    /// <param name="canonical">The canonical big-endian scalar bytes.</param>
    /// <param name="limbs">Receives the four 64-bit limbs, least-significant first.</param>
    private static void LoadCanonicalToLimbs(ReadOnlySpan<byte> canonical, Span<ulong> limbs)
    {
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int offset = (LimbCount - 1 - limbIndex) * BytesPerLimb;
            limbs[limbIndex] = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(offset, BytesPerLimb));
        }
    }


    /// <summary>Writes little-endian-ordered 64-bit limbs back into a canonical big-endian scalar.</summary>
    /// <param name="limbs">The four 64-bit limbs, least-significant first.</param>
    /// <param name="canonical">Receives the canonical big-endian scalar bytes.</param>
    private static void StoreLimbsToCanonical(ReadOnlySpan<ulong> limbs, Span<byte> canonical)
    {
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int offset = (LimbCount - 1 - limbIndex) * BytesPerLimb;
            BinaryPrimitives.WriteUInt64BigEndian(canonical.Slice(offset, BytesPerLimb), limbs[limbIndex]);
        }
    }


    /// <summary>Adds two 256-bit limb arrays with carry propagation across all four limbs.</summary>
    /// <param name="a">The first operand's limbs, least-significant first.</param>
    /// <param name="b">The second operand's limbs, least-significant first.</param>
    /// <param name="result">Receives the sum's limbs, least-significant first.</param>
    /// <returns><see langword="true"/> when the addition carried out of the top limb.</returns>
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


    /// <summary>Subtracts <paramref name="b"/> from <paramref name="a"/> in place, with borrow propagation across all four limbs.</summary>
    /// <param name="a">The minuend's limbs on entry, least-significant first; receives the difference's limbs.</param>
    /// <param name="b">The subtrahend's limbs, least-significant first.</param>
    /// <returns><see langword="true"/> when the subtraction borrowed past the top limb.</returns>
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
        //Build all-ones-per-lane mask for the chosen path. The Vector512.ConditionalSelect
        //below picks bits from onTrue where mask is 1, onFalse where 0.
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
        Span<ulong> scalar0 = stackalloc ulong[LimbCount];
        Span<ulong> scalar1 = stackalloc ulong[LimbCount];
        Span<ulong> scalar2 = stackalloc ulong[LimbCount];
        Span<ulong> scalar3 = stackalloc ulong[LimbCount];
        Span<ulong> scalar4 = stackalloc ulong[LimbCount];
        Span<ulong> scalar5 = stackalloc ulong[LimbCount];
        Span<ulong> scalar6 = stackalloc ulong[LimbCount];
        Span<ulong> scalar7 = stackalloc ulong[LimbCount];

        int stride = Scalar.SizeBytes;
        LoadCanonicalToLimbs(octetBytes.Slice(0 * stride, stride), scalar0);
        LoadCanonicalToLimbs(octetBytes.Slice(1 * stride, stride), scalar1);
        LoadCanonicalToLimbs(octetBytes.Slice(2 * stride, stride), scalar2);
        LoadCanonicalToLimbs(octetBytes.Slice(3 * stride, stride), scalar3);
        LoadCanonicalToLimbs(octetBytes.Slice(4 * stride, stride), scalar4);
        LoadCanonicalToLimbs(octetBytes.Slice(5 * stride, stride), scalar5);
        LoadCanonicalToLimbs(octetBytes.Slice(6 * stride, stride), scalar6);
        LoadCanonicalToLimbs(octetBytes.Slice(7 * stride, stride), scalar7);

        limb0 = Vector512.Create(scalar0[0], scalar1[0], scalar2[0], scalar3[0], scalar4[0], scalar5[0], scalar6[0], scalar7[0]);
        limb1 = Vector512.Create(scalar0[1], scalar1[1], scalar2[1], scalar3[1], scalar4[1], scalar5[1], scalar6[1], scalar7[1]);
        limb2 = Vector512.Create(scalar0[2], scalar1[2], scalar2[2], scalar3[2], scalar4[2], scalar5[2], scalar6[2], scalar7[2]);
        limb3 = Vector512.Create(scalar0[3], scalar1[3], scalar2[3], scalar3[3], scalar4[3], scalar5[3], scalar6[3], scalar7[3]);
    }


    /// <summary>Writes four limb-major <see cref="Vector512{T}"/> registers back into eight canonical scalars, one lane per scalar.</summary>
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
        Span<ulong> scalarLimbs = stackalloc ulong[LimbCount];
        int stride = Scalar.SizeBytes;
        for(int scalarIndex = 0; scalarIndex < ScalarsPerOctet; scalarIndex++)
        {
            scalarLimbs[0] = limb0.GetElement(scalarIndex);
            scalarLimbs[1] = limb1.GetElement(scalarIndex);
            scalarLimbs[2] = limb2.GetElement(scalarIndex);
            scalarLimbs[3] = limb3.GetElement(scalarIndex);
            StoreLimbsToCanonical(scalarLimbs, octetBytes.Slice(scalarIndex * stride, stride));
        }
    }


    /// <summary>Validates that three batched-operand buffers each hold exactly <paramref name="count"/> elements of <paramref name="stride"/> bytes.</summary>
    /// <exception cref="ArgumentException">When any buffer's length does not equal <paramref name="count"/> · <paramref name="stride"/>.</exception>
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


    /// <summary>Throws when the host CPU lacks the AVX-512 foundation instructions this backend requires.</summary>
    /// <exception cref="PlatformNotSupportedException">When <see cref="Avx512F.IsSupported"/> is <see langword="false"/>.</exception>
    private static void EnsureSupported()
    {
        if(!Avx512F.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "Bls12Curve381Avx512ScalarBackend requires AVX-512F; check IsSupported before wiring it as a delegate.");
        }
    }


    /// <summary>The number of 32-bit limbs that compose a BLS12-381 scalar (256 bits / 32 bits per limb) for the lane-interleaved batch Montgomery multiply.</summary>
    private const int Limb32Count = 8;

    /// <summary>Per-lane mask selecting the low 32 bits of a 64-bit lane, keeping each 32-bit limb isolated between multiply-accumulate steps.</summary>
    private static Vector512<ulong> Low32Mask { get; } = Vector512.Create(0xFFFFFFFFUL);

    /// <summary>Per-lane broadcast of the 32-bit Montgomery reduction constant <c>n' mod 2^32</c>.</summary>
    private static Vector512<ulong> NPrime32Broadcast { get; } = Vector512.Create((ulong)Bls12Curve381MontgomeryParameters.NPrime32);

    /// <summary>Per-lane broadcasts of the eight 32-bit limbs of the BLS12-381 scalar-field modulus.</summary>
    private static Vector512<ulong>[] Modulus32Broadcast { get; } = BuildBroadcast(Bls12Curve381MontgomeryParameters.Modulus32Limbs);

    /// <summary>Per-lane broadcasts of the eight 32-bit limbs of <c>R^2 mod r</c>, the Montgomery-domain conversion constant.</summary>
    private static Vector512<ulong>[] RSquared32Broadcast { get; } = BuildBroadcast(Bls12Curve381MontgomeryParameters.RSquared32Limbs);


    /// <summary>Broadcasts each 32-bit limb of a limb array across all eight lanes of its own <see cref="Vector512{T}"/>.</summary>
    /// <param name="limbs32">The eight 32-bit limbs, least-significant first.</param>
    /// <returns>One broadcast vector per limb.</returns>
    private static Vector512<ulong>[] BuildBroadcast(ReadOnlySpan<uint> limbs32)
    {
        var vectors = new Vector512<ulong>[Limb32Count];
        for(int i = 0; i < Limb32Count; i++)
        {
            vectors[i] = Vector512.Create((ulong)limbs32[i]);
        }

        return vectors;
    }


    /// <summary>The <see cref="ScalarBatchMultiplyDelegate"/> implementation: multiplies <paramref name="count"/> scalar pairs, eight at a time via <see cref="MultiplyOctet"/>, with a scalar fallback via the shared serial Montgomery multiply for the trailing 1-7 elements.</summary>
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
            Bls12Curve381MontgomeryArithmetic.Multiply(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    /// <summary>Multiplies eight scalar pairs in parallel: lifts the left operand into the Montgomery domain, then performs the lane-interleaved Montgomery multiply against the right operand.</summary>
    /// <param name="aOctet">Eight consecutive canonical left-operand scalars.</param>
    /// <param name="bOctet">Eight consecutive canonical right-operand scalars.</param>
    /// <param name="resultOctet">Receives the eight consecutive canonical products.</param>
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


    /// <summary>Computes the lane-interleaved 32-bit-limb CIOS Montgomery product of two octets: eight independent scalar multiplications sharing one instruction stream, one per lane.</summary>
    /// <param name="x">The eight left-operand scalars' 32-bit limbs, lane-major.</param>
    /// <param name="y">The eight right-operand scalars' 32-bit limbs, lane-major.</param>
    /// <param name="result">Receives the eight products' 32-bit limbs, lane-major, reduced into canonical range.</param>
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


    /// <summary>Conditionally subtracts the modulus from each lane's Montgomery-multiply accumulator, reducing it into canonical range.</summary>
    /// <param name="t">The eight lanes' unreduced accumulator limbs, plus one overflow limb.</param>
    /// <param name="result">Receives the eight lanes' reduced product limbs.</param>
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
    /// <param name="octetBytes">Eight consecutive canonical scalars.</param>
    /// <param name="limbVectors">Receives the eight 32-bit-limb vectors, least-significant limb first.</param>
    private static void LoadOctetTo32LimbVectors(ReadOnlySpan<byte> octetBytes, Span<Vector512<ulong>> limbVectors)
    {
        Span<uint> s = stackalloc uint[ScalarsPerOctet * Limb32Count];
        int stride = Scalar.SizeBytes;
        for(int scalarIndex = 0; scalarIndex < ScalarsPerOctet; scalarIndex++)
        {
            LoadCanonicalTo32Limbs(octetBytes.Slice(scalarIndex * stride, stride), s.Slice(scalarIndex * Limb32Count, Limb32Count));
        }

        for(int k = 0; k < Limb32Count; k++)
        {
            limbVectors[k] = Vector512.Create(
                (ulong)s[(0 * Limb32Count) + k], s[(1 * Limb32Count) + k], s[(2 * Limb32Count) + k], s[(3 * Limb32Count) + k],
                s[(4 * Limb32Count) + k], s[(5 * Limb32Count) + k], s[(6 * Limb32Count) + k], s[(7 * Limb32Count) + k]);
        }
    }


    /// <summary>Writes eight limb-major 32-bit-limb <see cref="Vector512{T}"/> registers back into eight canonical scalars, one lane per scalar.</summary>
    /// <param name="limbVectors">The eight 32-bit-limb vectors, least-significant limb first.</param>
    /// <param name="octetBytes">Receives the eight consecutive canonical scalars.</param>
    private static void Store32LimbVectorsToOctet(ReadOnlySpan<Vector512<ulong>> limbVectors, Span<byte> octetBytes)
    {
        int stride = Scalar.SizeBytes;
        Span<uint> scalarLimbs = stackalloc uint[Limb32Count];
        for(int scalarIndex = 0; scalarIndex < ScalarsPerOctet; scalarIndex++)
        {
            for(int k = 0; k < Limb32Count; k++)
            {
                scalarLimbs[k] = (uint)limbVectors[k].GetElement(scalarIndex);
            }

            StoreCanonicalFrom32Limbs(scalarLimbs, octetBytes.Slice(scalarIndex * stride, stride));
        }
    }


    /// <summary>Reads a canonical big-endian scalar into little-endian-ordered 32-bit limbs.</summary>
    /// <param name="canonical">The canonical big-endian scalar bytes.</param>
    /// <param name="limbs">Receives the eight 32-bit limbs, least-significant first.</param>
    private static void LoadCanonicalTo32Limbs(ReadOnlySpan<byte> canonical, Span<uint> limbs)
    {
        for(int i = 0; i < Limb32Count; i++)
        {
            limbs[i] = BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice((Limb32Count - 1 - i) * sizeof(uint), sizeof(uint)));
        }
    }


    /// <summary>Writes little-endian-ordered 32-bit limbs back into a canonical big-endian scalar.</summary>
    /// <param name="limbs">The eight 32-bit limbs, least-significant first.</param>
    /// <param name="canonical">Receives the canonical big-endian scalar bytes.</param>
    private static void StoreCanonicalFrom32Limbs(ReadOnlySpan<uint> limbs, Span<byte> canonical)
    {
        for(int i = 0; i < Limb32Count; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(canonical.Slice((Limb32Count - 1 - i) * sizeof(uint), sizeof(uint)), limbs[i]);
        }
    }
}