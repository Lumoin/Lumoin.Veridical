using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// AVX2 limb-arithmetic backend for BN254 scalar-field <see cref="ScalarAddDelegate"/>
/// and <see cref="ScalarSubtractDelegate"/> (and their batch forms), the BN254
/// mirror of <see cref="Bls12Curve381Avx2ScalarBackend"/>. It agrees byte-for-byte
/// with <see cref="Bn254BigIntegerScalarReference"/>, demonstrating the same
/// backend-agnostic delegate boundary across a second curve: the arithmetic body is
/// identical and only the modulus constants change.
/// </summary>
/// <remarks>
/// <para>
/// Internal representation is 4 × <see cref="ulong"/> limbs in little-endian order:
/// <c>limb[0]</c> is the least-significant 64 bits, <c>limb[3]</c> the most. The
/// constant-time conditional reduction uses AVX2
/// <see cref="Avx2.BlendVariable(Vector256{byte}, Vector256{byte}, Vector256{byte})"/>
/// so the wrong branch's bits never enter the destination on secret-dependent input.
/// </para>
/// <para>
/// Add, subtract, and the batch forms are implemented here; multiplication and
/// inversion are the shared Montgomery path. The carry/borrow
/// chains across limbs are serial, but the batch quartet advances four scalars
/// through that chain at once, one per 64-bit lane.
/// </para>
/// </remarks>
internal static class Bn254Avx2ScalarBackend
{
    /// <summary>Indicates whether the host CPU supports the instructions this backend uses.</summary>
    public static bool IsSupported => Avx2.IsSupported;


    /// <summary>The number of 64-bit limbs that compose a BN254 scalar (256 bits / 64 bits per limb).</summary>
    private const int LimbCount = 4;

    /// <summary>The number of canonical bytes per 64-bit limb.</summary>
    private const int BytesPerLimb = sizeof(ulong);

    /// <summary>The number of independent scalars packed into one SIMD quartet (one per 64-bit lane of <see cref="Vector256{T}"/>).</summary>
    private const int ScalarsPerQuartet = 4;

    /// <summary>The number of canonical bytes per scalar quartet (four scalars, each <see cref="Scalar.SizeBytes"/> bytes).</summary>
    private const int QuartetBytes = ScalarsPerQuartet * Scalar.SizeBytes;


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


    /// <summary>Returns the SIMD-backed scalar-add delegate.</summary>
    public static ScalarAddDelegate GetAdd() => Add;

    /// <summary>Returns the SIMD-backed scalar-subtract delegate.</summary>
    public static ScalarSubtractDelegate GetSubtract() => Subtract;

    /// <summary>Returns the SIMD-backed batched scalar-add delegate (four scalars per quartet, single-element fallback for the trailing 1–3).</summary>
    public static ScalarBatchAddDelegate GetBatchAdd() => BatchAdd;

    /// <summary>Returns the SIMD-backed batched scalar-subtract delegate.</summary>
    public static ScalarBatchSubtractDelegate GetBatchSubtract() => BatchSubtract;

    /// <summary>Returns the scalar-multiply delegate (serial CIOS Montgomery multiply; the body is ISA-independent and shared across the backends).</summary>
    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    /// <summary>
    /// Returns the lane-interleaved batched scalar-multiply delegate: a 32-bit-limb
    /// CIOS Montgomery multiply running four independent scalars per AVX2 quartet
    /// (one per 64-bit lane), each 32×32→64 partial product a single <c>vpmuludq</c>.
    /// The trailing 1–3 elements fall back to the shared serial Montgomery multiply.
    /// </summary>
    public static ScalarBatchMultiplyDelegate GetBatchMultiply() => BatchMultiply;

    /// <summary>Returns the scalar-negate delegate: modular negation <c>r − a</c>, with zero mapping to zero.</summary>
    public static ScalarNegateDelegate GetNegate() => Negate;

    /// <summary>Returns the scalar-invert delegate: Fermat inversion <c>a^(r−2) mod r</c> over the Montgomery multiply; throws for zero, matching the reference.</summary>
    public static ScalarInvertDelegate GetInvert() => Invert;


    /// <summary>The <see cref="ScalarAddDelegate"/> this backend exposes: constant-time BN254 scalar addition.</summary>
    /// <param name="a">The first canonical big-endian operand.</param>
    /// <param name="b">The second canonical big-endian operand.</param>
    /// <param name="result">The buffer receiving the canonical big-endian sum.</param>
    /// <param name="curve">The curve the operation is counted against.</param>
    /// <exception cref="PlatformNotSupportedException">When the host CPU lacks AVX2.</exception>
    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bn254Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
        }

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarAdd, curve);
        AddCore(a, b, result);
    }


    /// <summary>Counter-free arithmetic body of <see cref="Add"/>, used by the batched tail to avoid double-counting.</summary>
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

        //If addition overflowed past 2^256 the true sum is conceptually 2^256 plus
        //what we stored; subtracting r mod 2^256 (ignoring the borrow out) yields the
        //correct reduced result. Otherwise, if sumMinusR did not borrow then sum >= r
        //and the subtracted value is correct. In both cases we want sumMinusR; only
        //when neither holds do we want sum.
        bool useReduced = carry | !borrow;
        ConditionalSelect(sumMinusR, sum, useReduced, result);
    }


    /// <summary>The <see cref="ScalarSubtractDelegate"/> this backend exposes: constant-time BN254 scalar subtraction.</summary>
    /// <param name="a">The minuend, canonical big-endian.</param>
    /// <param name="b">The subtrahend, canonical big-endian.</param>
    /// <param name="result">The buffer receiving the canonical big-endian difference.</param>
    /// <param name="curve">The curve the operation is counted against.</param>
    /// <exception cref="PlatformNotSupportedException">When the host CPU lacks AVX2.</exception>
    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bn254Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
        }

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarSubtract, curve);
        SubtractCore(a, b, result);
    }


    /// <summary>Counter-free arithmetic body of <see cref="Subtract"/>.</summary>
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
        //Discard the carry out: the modular result we want is (diff + r) mod 2^256,
        //which is exactly what AddWithCarry256 leaves in diffPlusR after the carry
        //flag is ignored.
        _ = AddWithCarry256(diffPlusR, FieldOrderLimbs, diffPlusR);

        //If the unsigned subtraction borrowed, a < b — the modular result is
        //a - b + r, which is diffPlusR. Otherwise the canonical result is diff.
        ConditionalSelect(diffPlusR, diff, borrow, result);
    }


    /// <summary>The <see cref="ScalarMultiplyDelegate"/> this backend exposes: the shared, ISA-independent serial Montgomery multiply.</summary>
    /// <param name="a">The first canonical big-endian operand.</param>
    /// <param name="b">The second canonical big-endian operand.</param>
    /// <param name="result">The buffer receiving the canonical big-endian product.</param>
    /// <param name="curve">The curve the operation is counted against.</param>
    /// <exception cref="PlatformNotSupportedException">When the host CPU lacks AVX2.</exception>
    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bn254Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
        }

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarMultiply, curve);

        //A single Montgomery multiply is a serial limb carry chain that SIMD does not
        //accelerate; the ISA-independent body is shared across the backends.
        Bn254MontgomeryArithmetic.Multiply(a, b, result);
    }


    /// <summary>The <see cref="ScalarInvertDelegate"/> this backend exposes: Fermat inversion over the shared Montgomery multiply.</summary>
    /// <param name="a">The canonical big-endian operand to invert; must be nonzero.</param>
    /// <param name="result">The buffer receiving the canonical big-endian inverse.</param>
    /// <param name="curve">The curve the operation is counted against.</param>
    /// <exception cref="PlatformNotSupportedException">When the host CPU lacks AVX2.</exception>
    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bn254Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
        }

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarInvert, curve);
        Bn254MontgomeryArithmetic.Invert(a, result);
    }


    /// <summary>The <see cref="ScalarNegateDelegate"/> this backend exposes: modular negation <c>r - a</c>, with zero mapping to zero.</summary>
    /// <param name="a">The canonical big-endian operand to negate.</param>
    /// <param name="result">The buffer receiving the canonical big-endian negation.</param>
    /// <param name="curve">The curve the operation is counted against.</param>
    /// <exception cref="PlatformNotSupportedException">When the host CPU lacks AVX2.</exception>
    private static void Negate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bn254Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
        }

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


    /// <summary>Reads a canonical big-endian scalar into its four little-endian 64-bit limbs.</summary>
    /// <param name="canonical"><see cref="Scalar.SizeBytes"/> big-endian bytes, most significant first.</param>
    /// <param name="limbs">The buffer receiving the limbs; <c>limbs[0]</c> is the least significant 64 bits, <c>limbs[LimbCount - 1]</c> the most.</param>
    private static void LoadCanonicalToLimbs(ReadOnlySpan<byte> canonical, Span<ulong> limbs)
    {
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int offset = (LimbCount - 1 - limbIndex) * BytesPerLimb;
            limbs[limbIndex] = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(offset, BytesPerLimb));
        }
    }


    /// <summary>Writes four little-endian 64-bit limbs as a canonical big-endian scalar, the inverse of <see cref="LoadCanonicalToLimbs"/>.</summary>
    /// <param name="limbs">The limbs to write; <c>limbs[0]</c> is the least significant 64 bits, <c>limbs[LimbCount - 1]</c> the most.</param>
    /// <param name="canonical">The buffer receiving <see cref="Scalar.SizeBytes"/> big-endian bytes.</param>
    private static void StoreLimbsToCanonical(ReadOnlySpan<ulong> limbs, Span<byte> canonical)
    {
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int offset = (LimbCount - 1 - limbIndex) * BytesPerLimb;
            BinaryPrimitives.WriteUInt64BigEndian(canonical.Slice(offset, BytesPerLimb), limbs[limbIndex]);
        }
    }


    /// <summary>Adds two 256-bit values held as four 64-bit limbs each, with carry propagation across all four limbs.</summary>
    /// <param name="a">The first operand's limbs, least significant first.</param>
    /// <param name="b">The second operand's limbs, least significant first.</param>
    /// <param name="result">The buffer receiving the sum's limbs, least significant first.</param>
    /// <returns><see langword="true"/> when the addition carried out of the most significant limb.</returns>
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


    /// <summary>Subtracts two 256-bit values held as four 64-bit limbs each, in place on <paramref name="a"/>, with borrow propagation across all four limbs.</summary>
    /// <param name="a">The minuend's limbs on entry, least significant first; overwritten with the difference's limbs.</param>
    /// <param name="b">The subtrahend's limbs, least significant first.</param>
    /// <returns><see langword="true"/> when the subtraction borrowed out of the most significant limb (the true difference is negative).</returns>
    private static bool SubtractWithBorrow256(Span<ulong> a, ReadOnlySpan<ulong> b)
    {
        ulong borrow = 0UL;
        for(int i = 0; i < LimbCount; i++)
        {
            ulong x = a[i];
            ulong y = b[i];
            ulong diffOut = unchecked(x - y - borrow);

            //New borrow is 1 iff x < y + borrow. Two cases: x < y (regardless of
            //borrow), or x == y and borrow == 1.
            ulong newBorrow = (x < y) || (x == y && borrow != 0UL) ? 1UL : 0UL;
            a[i] = diffOut;
            borrow = newBorrow;
        }

        return borrow != 0UL;
    }


    /// <summary>
    /// Writes either <paramref name="onTrue"/> or <paramref name="onFalse"/> to
    /// <paramref name="destination"/> based on <paramref name="condition"/>, using
    /// <see cref="Avx2.BlendVariable(Vector256{byte}, Vector256{byte}, Vector256{byte})"/>
    /// so the unused branch's bits never enter the destination.
    /// </summary>
    private static void ConditionalSelect(
        ReadOnlySpan<ulong> onTrue,
        ReadOnlySpan<ulong> onFalse,
        bool condition,
        Span<byte> destination)
    {
        Vector256<ulong> trueValue = Vector256.Create(onTrue[0], onTrue[1], onTrue[2], onTrue[3]);
        Vector256<ulong> falseValue = Vector256.Create(onFalse[0], onFalse[1], onFalse[2], onFalse[3]);

        //All-ones mask selects from onTrue; all-zeros mask selects from onFalse.
        //BlendVariable inspects the high bit of each byte lane of the mask, and a
        //homogeneous mask satisfies that uniformly.
        Vector256<byte> mask = condition ? Vector256<byte>.AllBitsSet : Vector256<byte>.Zero;
        Vector256<ulong> selected = Avx2.BlendVariable(falseValue.AsByte(), trueValue.AsByte(), mask).AsUInt64();

        Span<ulong> selectedLimbs = stackalloc ulong[LimbCount];
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            selectedLimbs[limbIndex] = selected.GetElement(limbIndex);
        }

        StoreLimbsToCanonical(selectedLimbs, destination);
    }


    /// <summary>The <see cref="ScalarBatchAddDelegate"/> this backend exposes: adds <paramref name="count"/> scalar pairs, four per SIMD quartet with a serial fallback for the trailing 1-3.</summary>
    /// <param name="leftOperandsConcatenated">The first operands, <paramref name="count"/> canonical scalars concatenated.</param>
    /// <param name="rightOperandsConcatenated">The second operands, <paramref name="count"/> canonical scalars concatenated.</param>
    /// <param name="resultsConcatenated">The buffer receiving <paramref name="count"/> concatenated canonical sums.</param>
    /// <param name="count">The number of scalar pairs to add.</param>
    /// <param name="curve">The curve the operation is counted against.</param>
    /// <exception cref="PlatformNotSupportedException">When the host CPU lacks AVX2.</exception>
    /// <exception cref="ArgumentException">When a buffer's length does not match <paramref name="count"/>.</exception>
    private static void BatchAdd(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bn254Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
        }

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchAdd, curve, count);

        int stride = Scalar.SizeBytes;
        ValidateBatchedLengths(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count, stride);

        int quartets = count / ScalarsPerQuartet;
        for(int quartetIndex = 0; quartetIndex < quartets; quartetIndex++)
        {
            int offset = quartetIndex * QuartetBytes;
            AddQuartet(
                leftOperandsConcatenated.Slice(offset, QuartetBytes),
                rightOperandsConcatenated.Slice(offset, QuartetBytes),
                resultsConcatenated.Slice(offset, QuartetBytes));
        }

        int tailStart = quartets * QuartetBytes;
        int tailCount = count % ScalarsPerQuartet;
        for(int i = 0; i < tailCount; i++)
        {
            int offset = tailStart + i * stride;
            //Use AddCore not Add so the ScalarAdd counter is not bumped on top of the
            //ScalarBatchAdd increment recorded above.
            AddCore(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    /// <summary>The <see cref="ScalarBatchSubtractDelegate"/> this backend exposes: subtracts <paramref name="count"/> scalar pairs, four per SIMD quartet with a serial fallback for the trailing 1-3.</summary>
    /// <param name="minuendsConcatenated">The minuends, <paramref name="count"/> canonical scalars concatenated.</param>
    /// <param name="subtrahendsConcatenated">The subtrahends, <paramref name="count"/> canonical scalars concatenated.</param>
    /// <param name="resultsConcatenated">The buffer receiving <paramref name="count"/> concatenated canonical differences.</param>
    /// <param name="count">The number of scalar pairs to subtract.</param>
    /// <param name="curve">The curve the operation is counted against.</param>
    /// <exception cref="PlatformNotSupportedException">When the host CPU lacks AVX2.</exception>
    /// <exception cref="ArgumentException">When a buffer's length does not match <paramref name="count"/>.</exception>
    private static void BatchSubtract(
        ReadOnlySpan<byte> minuendsConcatenated,
        ReadOnlySpan<byte> subtrahendsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bn254Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
        }

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchSubtract, curve, count);

        int stride = Scalar.SizeBytes;
        ValidateBatchedLengths(minuendsConcatenated, subtrahendsConcatenated, resultsConcatenated, count, stride);

        int quartets = count / ScalarsPerQuartet;
        for(int quartetIndex = 0; quartetIndex < quartets; quartetIndex++)
        {
            int offset = quartetIndex * QuartetBytes;
            SubtractQuartet(
                minuendsConcatenated.Slice(offset, QuartetBytes),
                subtrahendsConcatenated.Slice(offset, QuartetBytes),
                resultsConcatenated.Slice(offset, QuartetBytes));
        }

        int tailStart = quartets * QuartetBytes;
        int tailCount = count % ScalarsPerQuartet;
        for(int i = 0; i < tailCount; i++)
        {
            int offset = tailStart + i * stride;
            SubtractCore(
                minuendsConcatenated.Slice(offset, stride),
                subtrahendsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    /// <summary>Throws unless each of the three buffers is exactly <c>count * stride</c> bytes.</summary>
    /// <param name="first">The first buffer to check.</param>
    /// <param name="second">The second buffer to check.</param>
    /// <param name="third">The third buffer to check.</param>
    /// <param name="count">The number of elements each buffer must hold.</param>
    /// <param name="stride">The byte width of one element.</param>
    /// <exception cref="ArgumentException">When any buffer's length does not equal <c>count * stride</c>.</exception>
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


    /// <summary>SIMD inner loop: adds four scalars in parallel, four 64-bit lanes per <see cref="Vector256{T}"/>, one limb position per register.</summary>
    /// <summary>Adds four independent scalars in parallel, one 64-bit limb per lane, reducing per lane against the field modulus.</summary>
    /// <param name="aQuartet">The four first operands, concatenated canonical scalars.</param>
    /// <param name="bQuartet">The four second operands, concatenated canonical scalars.</param>
    /// <param name="resultQuartet">The buffer receiving the four concatenated canonical sums.</param>
    private static void AddQuartet(
        ReadOnlySpan<byte> aQuartet,
        ReadOnlySpan<byte> bQuartet,
        Span<byte> resultQuartet)
    {
        LoadQuartetToLimbVectors(aQuartet, out Vector256<ulong> a0, out Vector256<ulong> a1, out Vector256<ulong> a2, out Vector256<ulong> a3);
        LoadQuartetToLimbVectors(bQuartet, out Vector256<ulong> b0, out Vector256<ulong> b1, out Vector256<ulong> b2, out Vector256<ulong> b3);

        //Add with carry chain: each limb position adds a, b, and the carry value from
        //the previous limb. Carry mask is "all-ones per lane that overflowed" and is
        //turned into a {0, 1}-per-lane value via 0 - mask.
        Vector256<ulong> sum0 = Avx2.Add(a0, b0);
        Vector256<ulong> carryMask0 = UnsignedLessThan(sum0, a0);
        Vector256<ulong> carry0Value = Avx2.Subtract(Vector256<ulong>.Zero, carryMask0);

        AddLimbWithCarry(a1, b1, carry0Value, out Vector256<ulong> sum1, out Vector256<ulong> carryMask1);
        Vector256<ulong> carry1Value = Avx2.Subtract(Vector256<ulong>.Zero, carryMask1);

        AddLimbWithCarry(a2, b2, carry1Value, out Vector256<ulong> sum2, out Vector256<ulong> carryMask2);
        Vector256<ulong> carry2Value = Avx2.Subtract(Vector256<ulong>.Zero, carryMask2);

        AddLimbWithCarry(a3, b3, carry2Value, out Vector256<ulong> sum3, out Vector256<ulong> finalCarryMask);

        //Speculatively compute sum - r with a borrow chain. The final-borrow mask
        //tells us per lane whether sum < r (borrow = all-ones) or sum >= r (borrow = 0).
        Vector256<ulong> diff0 = Avx2.Subtract(sum0, FieldOrderLane0);
        Vector256<ulong> borrowMask0 = UnsignedLessThan(sum0, FieldOrderLane0);
        Vector256<ulong> borrow0Value = Avx2.Subtract(Vector256<ulong>.Zero, borrowMask0);

        SubtractLimbWithBorrow(sum1, FieldOrderLane1, borrow0Value, out Vector256<ulong> diff1, out Vector256<ulong> borrowMask1);
        Vector256<ulong> borrow1Value = Avx2.Subtract(Vector256<ulong>.Zero, borrowMask1);

        SubtractLimbWithBorrow(sum2, FieldOrderLane2, borrow1Value, out Vector256<ulong> diff2, out Vector256<ulong> borrowMask2);
        Vector256<ulong> borrow2Value = Avx2.Subtract(Vector256<ulong>.Zero, borrowMask2);

        SubtractLimbWithBorrow(sum3, FieldOrderLane3, borrow2Value, out Vector256<ulong> diff3, out Vector256<ulong> finalBorrowMask);

        //Reduce iff finalCarry OR not finalBorrow. notFinalBorrow is the bitwise NOT.
        Vector256<ulong> notFinalBorrow = Avx2.Xor(finalBorrowMask, Vector256<ulong>.AllBitsSet);
        Vector256<ulong> useDiffMask = Avx2.Or(finalCarryMask, notFinalBorrow);
        Vector256<byte> blendMask = useDiffMask.AsByte();

        Vector256<ulong> result0 = Avx2.BlendVariable(sum0.AsByte(), diff0.AsByte(), blendMask).AsUInt64();
        Vector256<ulong> result1 = Avx2.BlendVariable(sum1.AsByte(), diff1.AsByte(), blendMask).AsUInt64();
        Vector256<ulong> result2 = Avx2.BlendVariable(sum2.AsByte(), diff2.AsByte(), blendMask).AsUInt64();
        Vector256<ulong> result3 = Avx2.BlendVariable(sum3.AsByte(), diff3.AsByte(), blendMask).AsUInt64();

        StoreLimbVectorsToQuartet(result0, result1, result2, result3, resultQuartet);
    }


    /// <summary>Subtracts four independent scalar pairs in parallel, one 64-bit limb per lane, reducing per lane against the field modulus.</summary>
    /// <param name="aQuartet">The four minuends, concatenated canonical scalars.</param>
    /// <param name="bQuartet">The four subtrahends, concatenated canonical scalars.</param>
    /// <param name="resultQuartet">The buffer receiving the four concatenated canonical differences.</param>
    private static void SubtractQuartet(
        ReadOnlySpan<byte> aQuartet,
        ReadOnlySpan<byte> bQuartet,
        Span<byte> resultQuartet)
    {
        LoadQuartetToLimbVectors(aQuartet, out Vector256<ulong> a0, out Vector256<ulong> a1, out Vector256<ulong> a2, out Vector256<ulong> a3);
        LoadQuartetToLimbVectors(bQuartet, out Vector256<ulong> b0, out Vector256<ulong> b1, out Vector256<ulong> b2, out Vector256<ulong> b3);

        //Subtract a - b with borrow chain.
        Vector256<ulong> diff0 = Avx2.Subtract(a0, b0);
        Vector256<ulong> borrowMask0 = UnsignedLessThan(a0, b0);
        Vector256<ulong> borrow0Value = Avx2.Subtract(Vector256<ulong>.Zero, borrowMask0);

        SubtractLimbWithBorrow(a1, b1, borrow0Value, out Vector256<ulong> diff1, out Vector256<ulong> borrowMask1);
        Vector256<ulong> borrow1Value = Avx2.Subtract(Vector256<ulong>.Zero, borrowMask1);

        SubtractLimbWithBorrow(a2, b2, borrow1Value, out Vector256<ulong> diff2, out Vector256<ulong> borrowMask2);
        Vector256<ulong> borrow2Value = Avx2.Subtract(Vector256<ulong>.Zero, borrowMask2);

        SubtractLimbWithBorrow(a3, b3, borrow2Value, out Vector256<ulong> diff3, out Vector256<ulong> finalBorrowMask);

        //Speculatively compute diff + r (ignoring final carry).
        AddLimbWithCarry(diff0, FieldOrderLane0, Vector256<ulong>.Zero, out Vector256<ulong> diffPlusR0, out Vector256<ulong> carryMask0);
        Vector256<ulong> carry0Value = Avx2.Subtract(Vector256<ulong>.Zero, carryMask0);

        AddLimbWithCarry(diff1, FieldOrderLane1, carry0Value, out Vector256<ulong> diffPlusR1, out Vector256<ulong> carryMask1);
        Vector256<ulong> carry1Value = Avx2.Subtract(Vector256<ulong>.Zero, carryMask1);

        AddLimbWithCarry(diff2, FieldOrderLane2, carry1Value, out Vector256<ulong> diffPlusR2, out Vector256<ulong> carryMask2);
        Vector256<ulong> carry2Value = Avx2.Subtract(Vector256<ulong>.Zero, carryMask2);

        AddLimbWithCarry(diff3, FieldOrderLane3, carry2Value, out Vector256<ulong> diffPlusR3, out _);

        //Use diff + r iff a < b (i.e., borrow=all-ones), else use diff.
        Vector256<byte> blendMask = finalBorrowMask.AsByte();

        Vector256<ulong> result0 = Avx2.BlendVariable(diff0.AsByte(), diffPlusR0.AsByte(), blendMask).AsUInt64();
        Vector256<ulong> result1 = Avx2.BlendVariable(diff1.AsByte(), diffPlusR1.AsByte(), blendMask).AsUInt64();
        Vector256<ulong> result2 = Avx2.BlendVariable(diff2.AsByte(), diffPlusR2.AsByte(), blendMask).AsUInt64();
        Vector256<ulong> result3 = Avx2.BlendVariable(diff3.AsByte(), diffPlusR3.AsByte(), blendMask).AsUInt64();

        StoreLimbVectorsToQuartet(result0, result1, result2, result3, resultQuartet);
    }


    /// <summary>One limb of carry-chain addition: <c>sum = a + b + carryIn</c>, with <paramref name="carryIn"/> a per-lane {0, 1} value. Outputs the lane-wise all-ones carry-out mask.</summary>
    private static void AddLimbWithCarry(
        Vector256<ulong> a,
        Vector256<ulong> b,
        Vector256<ulong> carryIn,
        out Vector256<ulong> sum,
        out Vector256<ulong> carryOutMask)
    {
        Vector256<ulong> innerSum = Avx2.Add(a, b);
        Vector256<ulong> innerCarryMask = UnsignedLessThan(innerSum, a);
        sum = Avx2.Add(innerSum, carryIn);
        Vector256<ulong> outerCarryMask = UnsignedLessThan(sum, innerSum);
        carryOutMask = Avx2.Or(innerCarryMask, outerCarryMask);
    }


    /// <summary>One limb of borrow-chain subtraction: <c>diff = a - b - borrowIn</c>, with <paramref name="borrowIn"/> a per-lane {0, 1} value. Outputs the lane-wise all-ones borrow-out mask.</summary>
    private static void SubtractLimbWithBorrow(
        Vector256<ulong> a,
        Vector256<ulong> b,
        Vector256<ulong> borrowIn,
        out Vector256<ulong> diff,
        out Vector256<ulong> borrowOutMask)
    {
        Vector256<ulong> innerDiff = Avx2.Subtract(a, b);
        Vector256<ulong> innerBorrowMask = UnsignedLessThan(a, b);
        diff = Avx2.Subtract(innerDiff, borrowIn);
        Vector256<ulong> outerBorrowMask = UnsignedLessThan(innerDiff, borrowIn);
        borrowOutMask = Avx2.Or(innerBorrowMask, outerBorrowMask);
    }


    /// <summary>Lane-wise unsigned less-than. AVX2's signed compare flips into unsigned by XORing both operands with the sign bit first.</summary>
    private static Vector256<ulong> UnsignedLessThan(Vector256<ulong> a, Vector256<ulong> b)
    {
        Vector256<long> signFlip = Vector256.Create(long.MinValue);
        Vector256<long> aFlipped = Avx2.Xor(a.AsInt64(), signFlip);
        Vector256<long> bFlipped = Avx2.Xor(b.AsInt64(), signFlip);

        return Avx2.CompareGreaterThan(bFlipped, aFlipped).AsUInt64();
    }


    /// <summary>The BN254 scalar modulus's least-significant 64-bit limb, broadcast to every lane so the quartet shares the modulus.</summary>
    private static Vector256<ulong> FieldOrderLane0 { get; } = Vector256.Create(0x43e1f593f0000001UL);

    /// <summary>The BN254 scalar modulus's second 64-bit limb, broadcast to every lane so the quartet shares the modulus.</summary>
    private static Vector256<ulong> FieldOrderLane1 { get; } = Vector256.Create(0x2833e84879b97091UL);

    /// <summary>The BN254 scalar modulus's third 64-bit limb, broadcast to every lane so the quartet shares the modulus.</summary>
    private static Vector256<ulong> FieldOrderLane2 { get; } = Vector256.Create(0xb85045b68181585dUL);

    /// <summary>The BN254 scalar modulus's most-significant 64-bit limb, broadcast to every lane so the quartet shares the modulus.</summary>
    private static Vector256<ulong> FieldOrderLane3 { get; } = Vector256.Create(0x30644e72e131a029UL);


    /// <summary>Transposes <see cref="ScalarsPerQuartet"/> scalar-major canonical encodings into limb-major SIMD registers (lane <c>i</c> holds scalar <c>i</c>'s contribution at that limb).</summary>
    private static void LoadQuartetToLimbVectors(
        ReadOnlySpan<byte> quartetBytes,
        out Vector256<ulong> limb0,
        out Vector256<ulong> limb1,
        out Vector256<ulong> limb2,
        out Vector256<ulong> limb3)
    {
        int stride = Scalar.SizeBytes;
        Vector256<ulong> scalar0 = LoadScalarLimbs(quartetBytes.Slice(0 * stride, stride));
        Vector256<ulong> scalar1 = LoadScalarLimbs(quartetBytes.Slice(1 * stride, stride));
        Vector256<ulong> scalar2 = LoadScalarLimbs(quartetBytes.Slice(2 * stride, stride));
        Vector256<ulong> scalar3 = LoadScalarLimbs(quartetBytes.Slice(3 * stride, stride));

        TransposeQuartetLanes(scalar0, scalar1, scalar2, scalar3, out limb0, out limb1, out limb2, out limb3);
    }


    /// <summary>Reads one scalar's <see cref="Scalar.SizeBytes"/> canonical big-endian bytes as its four 64-bit limbs, in the same <c>limb0..limb3</c> order <see cref="LoadCanonicalToLimbs"/> produces.</summary>
    private static Vector256<ulong> LoadScalarLimbs(ReadOnlySpan<byte> canonical)
    {
        Vector256<byte> canonicalBytes = Vector256.Create(canonical);
        Vector256<byte> littleEndianBytes = Vector256.Reverse(canonicalBytes);

        return littleEndianBytes.AsUInt64();
    }


    /// <summary>Inverse of <see cref="LoadQuartetToLimbVectors"/>: writes four limb-major SIMD registers as <see cref="ScalarsPerQuartet"/> scalar-major canonical encodings.</summary>
    private static void StoreLimbVectorsToQuartet(
        Vector256<ulong> limb0,
        Vector256<ulong> limb1,
        Vector256<ulong> limb2,
        Vector256<ulong> limb3,
        Span<byte> quartetBytes)
    {
        TransposeQuartetLanes(limb0, limb1, limb2, limb3, out Vector256<ulong> scalar0, out Vector256<ulong> scalar1, out Vector256<ulong> scalar2, out Vector256<ulong> scalar3);

        int stride = Scalar.SizeBytes;
        StoreScalarLimbs(scalar0, quartetBytes.Slice(0 * stride, stride));
        StoreScalarLimbs(scalar1, quartetBytes.Slice(1 * stride, stride));
        StoreScalarLimbs(scalar2, quartetBytes.Slice(2 * stride, stride));
        StoreScalarLimbs(scalar3, quartetBytes.Slice(3 * stride, stride));
    }


    /// <summary>Writes one scalar's four 64-bit limbs, in <c>limb0..limb3</c> order, as its <see cref="Scalar.SizeBytes"/> canonical big-endian bytes — the inverse of <see cref="LoadScalarLimbs"/>.</summary>
    private static void StoreScalarLimbs(Vector256<ulong> limbs, Span<byte> canonical)
    {
        Vector256<byte> littleEndianBytes = limbs.AsByte();
        Vector256<byte> canonicalBytes = Vector256.Reverse(littleEndianBytes);

        canonicalBytes.CopyTo(canonical);
    }


    /// <summary>Transposes four <see cref="Vector256{T}"/> of <see cref="ulong"/>, each holding one source's four values, into four vectors each holding one position with lane <c>i</c> carrying source <c>i</c>'s contribution at that position — a 4x4 transpose over (source index, position index), its own inverse, so every quartet load and store in this file shares this one implementation for both directions.</summary>
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


    /// <summary>The number of 32-bit limbs that compose a BN254 scalar in the lane-interleaved batch Montgomery multiply (256 bits / 32 bits per limb).</summary>
    private const int Limb32Count = 8;

    /// <summary>A per-lane mask selecting the low 32 bits of each 64-bit lane, used to keep each 32-bit-limb accumulator from bleeding into its neighbour.</summary>
    private static Vector256<ulong> Low32Mask { get; } = Vector256.Create(0xFFFFFFFFUL);

    /// <summary>The Montgomery reduction constant <c>n' mod 2^32</c>, broadcast to every lane of every 64-bit slot.</summary>
    private static Vector256<ulong> NPrime32Broadcast { get; } = Vector256.Create((ulong)Bn254MontgomeryParameters.NPrime32);

    /// <summary>The BN254 scalar modulus's eight 32-bit limbs, each broadcast to every lane, indexed the same way as <see cref="Bn254MontgomeryParameters.Modulus32Limbs"/>.</summary>
    private static Vector256<ulong>[] Modulus32Broadcast { get; } = BuildBroadcast(Bn254MontgomeryParameters.Modulus32Limbs);

    /// <summary>The Montgomery constant <c>R² mod r</c>'s eight 32-bit limbs, each broadcast to every lane, indexed the same way as <see cref="Bn254MontgomeryParameters.RSquared32Limbs"/>.</summary>
    private static Vector256<ulong>[] RSquared32Broadcast { get; } = BuildBroadcast(Bn254MontgomeryParameters.RSquared32Limbs);


    /// <summary>Broadcasts each of eight 32-bit limbs to every lane of its own <see cref="Vector256{T}"/>.</summary>
    /// <param name="limbs32">The eight 32-bit limbs to broadcast, least significant first.</param>
    /// <returns>Eight vectors, one per limb, each lane holding that limb's value.</returns>
    private static Vector256<ulong>[] BuildBroadcast(ReadOnlySpan<uint> limbs32)
    {
        var vectors = new Vector256<ulong>[Limb32Count];
        for(int i = 0; i < Limb32Count; i++)
        {
            vectors[i] = Vector256.Create((ulong)limbs32[i]);
        }

        return vectors;
    }


    /// <summary>The <see cref="ScalarBatchMultiplyDelegate"/> this backend exposes: multiplies <paramref name="count"/> scalar pairs, four per SIMD quartet through the lane-interleaved 32-bit-limb Montgomery multiply, with a serial fallback for the trailing 1-3.</summary>
    /// <param name="leftOperandsConcatenated">The first operands, <paramref name="count"/> canonical scalars concatenated.</param>
    /// <param name="rightOperandsConcatenated">The second operands, <paramref name="count"/> canonical scalars concatenated.</param>
    /// <param name="resultsConcatenated">The buffer receiving <paramref name="count"/> concatenated canonical products.</param>
    /// <param name="count">The number of scalar pairs to multiply.</param>
    /// <param name="curve">The curve the operation is counted against.</param>
    /// <exception cref="PlatformNotSupportedException">When the host CPU lacks AVX2.</exception>
    /// <exception cref="ArgumentException">When a buffer's length does not match <paramref name="count"/>.</exception>
    private static void BatchMultiply(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bn254Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
        }

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchMultiply, curve, count);

        int stride = Scalar.SizeBytes;
        ValidateBatchedLengths(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count, stride);

        int quartets = count / ScalarsPerQuartet;
        for(int quartetIndex = 0; quartetIndex < quartets; quartetIndex++)
        {
            int offset = quartetIndex * QuartetBytes;
            MultiplyQuartet(
                leftOperandsConcatenated.Slice(offset, QuartetBytes),
                rightOperandsConcatenated.Slice(offset, QuartetBytes),
                resultsConcatenated.Slice(offset, QuartetBytes));
        }

        int tailStart = quartets * QuartetBytes;
        int tailCount = count % ScalarsPerQuartet;
        for(int i = 0; i < tailCount; i++)
        {
            int offset = tailStart + i * stride;
            Bn254MontgomeryArithmetic.Multiply(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    /// <summary>Multiplies four independent scalars in parallel: <c>result = a · b mod r</c> per lane, via two Montgomery multiplies (lift by <c>R²</c>, then by canonical <c>b</c>).</summary>
    private static void MultiplyQuartet(
        ReadOnlySpan<byte> aQuartet,
        ReadOnlySpan<byte> bQuartet,
        Span<byte> resultQuartet)
    {
        Span<Vector256<ulong>> a = stackalloc Vector256<ulong>[Limb32Count];
        Span<Vector256<ulong>> b = stackalloc Vector256<ulong>[Limb32Count];
        Span<Vector256<ulong>> aMontgomery = stackalloc Vector256<ulong>[Limb32Count];
        Span<Vector256<ulong>> product = stackalloc Vector256<ulong>[Limb32Count];

        LoadQuartetTo32LimbVectors(aQuartet, a);
        LoadQuartetTo32LimbVectors(bQuartet, b);

        MontgomeryMultiplyQuartet(a, RSquared32Broadcast, aMontgomery);
        MontgomeryMultiplyQuartet(aMontgomery, b, product);

        Store32LimbVectorsToQuartet(product, resultQuartet);
    }


    /// <summary>Lane-parallel CIOS Montgomery multiply over 32-bit limbs: <c>result = x · y · R⁻¹ mod r</c> per lane, reduced once.</summary>
    private static void MontgomeryMultiplyQuartet(
        ReadOnlySpan<Vector256<ulong>> x,
        ReadOnlySpan<Vector256<ulong>> y,
        Span<Vector256<ulong>> result)
    {
        Span<Vector256<ulong>> t = stackalloc Vector256<ulong>[Limb32Count + 2];
        for(int k = 0; k < Limb32Count + 2; k++)
        {
            t[k] = Vector256<ulong>.Zero;
        }

        Vector256<ulong> mask = Low32Mask;

        for(int i = 0; i < Limb32Count; i++)
        {
            Vector256<ulong> carry = Vector256<ulong>.Zero;
            for(int j = 0; j < Limb32Count; j++)
            {
                Vector256<ulong> partial = Avx2.Multiply(x[j].AsUInt32(), y[i].AsUInt32());
                Vector256<ulong> sum = Avx2.Add(Avx2.Add(t[j], partial), carry);
                t[j] = Avx2.And(sum, mask);
                carry = Avx2.ShiftRightLogical(sum, 32);
            }

            Vector256<ulong> highSum = Avx2.Add(t[Limb32Count], carry);
            t[Limb32Count] = Avx2.And(highSum, mask);
            t[Limb32Count + 1] = Avx2.ShiftRightLogical(highSum, 32);

            Vector256<ulong> m = Avx2.And(Avx2.Multiply(t[0].AsUInt32(), NPrime32Broadcast.AsUInt32()), mask);
            Vector256<ulong> reduceLow = Avx2.Add(t[0], Avx2.Multiply(m.AsUInt32(), Modulus32Broadcast[0].AsUInt32()));
            carry = Avx2.ShiftRightLogical(reduceLow, 32);
            for(int j = 1; j < Limb32Count; j++)
            {
                Vector256<ulong> reduceTerm = Avx2.Add(Avx2.Add(t[j], Avx2.Multiply(m.AsUInt32(), Modulus32Broadcast[j].AsUInt32())), carry);
                t[j - 1] = Avx2.And(reduceTerm, mask);
                carry = Avx2.ShiftRightLogical(reduceTerm, 32);
            }

            Vector256<ulong> reduceHigh = Avx2.Add(t[Limb32Count], carry);
            t[Limb32Count - 1] = Avx2.And(reduceHigh, mask);
            t[Limb32Count] = Avx2.Add(t[Limb32Count + 1], Avx2.ShiftRightLogical(reduceHigh, 32));
        }

        ConditionalSubtractModulusQuartet(t, result);
    }


    /// <summary>Conditionally subtracts the modulus from each lane's 33-limb (8×32-bit plus overflow) accumulator, per lane selecting the subtracted value when it did not borrow or the accumulator overflowed its 256-bit range.</summary>
    /// <param name="t">The nine-limb accumulator per lane (eight 32-bit limbs plus one overflow limb), from the Montgomery reduction.</param>
    /// <param name="result">The buffer receiving the reduced eight-limb result per lane.</param>
    private static void ConditionalSubtractModulusQuartet(ReadOnlySpan<Vector256<ulong>> t, Span<Vector256<ulong>> result)
    {
        Vector256<ulong> mask = Low32Mask;
        Span<Vector256<ulong>> reduced = stackalloc Vector256<ulong>[Limb32Count];

        Vector256<ulong> borrow = Vector256<ulong>.Zero;
        for(int j = 0; j < Limb32Count; j++)
        {
            Vector256<ulong> difference = Avx2.Subtract(Avx2.Subtract(t[j], Modulus32Broadcast[j]), borrow);
            reduced[j] = Avx2.And(difference, mask);
            borrow = Avx2.ShiftRightLogical(difference, 63);
        }

        Vector256<ulong> overflowMask = Avx2.Subtract(Vector256<ulong>.Zero, t[Limb32Count]);
        Vector256<ulong> borrowMask = Avx2.Subtract(Vector256<ulong>.Zero, borrow);
        Vector256<ulong> notBorrowMask = Avx2.Xor(borrowMask, Vector256<ulong>.AllBitsSet);
        Vector256<byte> useReducedMask = Avx2.Or(overflowMask, notBorrowMask).AsByte();

        for(int j = 0; j < Limb32Count; j++)
        {
            result[j] = Avx2.BlendVariable(t[j].AsByte(), reduced[j].AsByte(), useReducedMask).AsUInt64();
        }
    }


    /// <summary>Transposes the four scalar-major canonical encodings of a quartet into eight limb-major registers, each holding one 32-bit limb position with lane <c>i</c> carrying scalar <c>i</c>'s limb (zero-extended into the lane's low 32 bits).</summary>
    private static void LoadQuartetTo32LimbVectors(ReadOnlySpan<byte> quartetBytes, Span<Vector256<ulong>> limbVectors)
    {
        int stride = Scalar.SizeBytes;
        LoadScalarLowHighLimbs(quartetBytes.Slice(0 * stride, stride), out Vector256<ulong> scalar0Low, out Vector256<ulong> scalar0High);
        LoadScalarLowHighLimbs(quartetBytes.Slice(1 * stride, stride), out Vector256<ulong> scalar1Low, out Vector256<ulong> scalar1High);
        LoadScalarLowHighLimbs(quartetBytes.Slice(2 * stride, stride), out Vector256<ulong> scalar2Low, out Vector256<ulong> scalar2High);
        LoadScalarLowHighLimbs(quartetBytes.Slice(3 * stride, stride), out Vector256<ulong> scalar3Low, out Vector256<ulong> scalar3High);

        TransposeQuartetLanes(scalar0Low, scalar1Low, scalar2Low, scalar3Low, out Vector256<ulong> limb0, out Vector256<ulong> limb1, out Vector256<ulong> limb2, out Vector256<ulong> limb3);
        limbVectors[0] = limb0;
        limbVectors[1] = limb1;
        limbVectors[2] = limb2;
        limbVectors[3] = limb3;

        TransposeQuartetLanes(scalar0High, scalar1High, scalar2High, scalar3High, out Vector256<ulong> limb4, out Vector256<ulong> limb5, out Vector256<ulong> limb6, out Vector256<ulong> limb7);
        limbVectors[4] = limb4;
        limbVectors[5] = limb5;
        limbVectors[6] = limb6;
        limbVectors[7] = limb7;
    }


    /// <summary>Reads one scalar's <see cref="Scalar.SizeBytes"/> canonical big-endian bytes as its eight 32-bit limbs, zero-extended into two <see cref="Vector256{T}"/> of <see cref="ulong"/>: <paramref name="low"/> holds limbs 0-3, <paramref name="high"/> holds limbs 4-7, in the same increasing-significance order <see cref="LoadScalarLimbs"/> uses at 64-bit granularity.</summary>
    private static void LoadScalarLowHighLimbs(ReadOnlySpan<byte> canonical, out Vector256<ulong> low, out Vector256<ulong> high)
    {
        Vector256<byte> canonicalBytes = Vector256.Create(canonical);
        Vector256<byte> littleEndianBytes = Vector256.Reverse(canonicalBytes);
        Vector256<uint> limbs32 = littleEndianBytes.AsUInt32();

        low = Vector256.WidenLower(limbs32);
        high = Vector256.WidenUpper(limbs32);
    }


    /// <summary>Inverse of <see cref="LoadQuartetTo32LimbVectors"/>: writes eight limb-major 32-bit-limb registers as <see cref="ScalarsPerQuartet"/> scalar-major canonical encodings.</summary>
    private static void Store32LimbVectorsToQuartet(ReadOnlySpan<Vector256<ulong>> limbVectors, Span<byte> quartetBytes)
    {
        TransposeQuartetLanes(limbVectors[0], limbVectors[1], limbVectors[2], limbVectors[3], out Vector256<ulong> scalar0Low, out Vector256<ulong> scalar1Low, out Vector256<ulong> scalar2Low, out Vector256<ulong> scalar3Low);
        TransposeQuartetLanes(limbVectors[4], limbVectors[5], limbVectors[6], limbVectors[7], out Vector256<ulong> scalar0High, out Vector256<ulong> scalar1High, out Vector256<ulong> scalar2High, out Vector256<ulong> scalar3High);

        int stride = Scalar.SizeBytes;
        StoreScalarLowHighLimbs(scalar0Low, scalar0High, quartetBytes.Slice(0 * stride, stride));
        StoreScalarLowHighLimbs(scalar1Low, scalar1High, quartetBytes.Slice(1 * stride, stride));
        StoreScalarLowHighLimbs(scalar2Low, scalar2High, quartetBytes.Slice(2 * stride, stride));
        StoreScalarLowHighLimbs(scalar3Low, scalar3High, quartetBytes.Slice(3 * stride, stride));
    }


    /// <summary>Writes one scalar's eight 32-bit limbs, held zero-extended across <paramref name="low"/> (limbs 0-3) and <paramref name="high"/> (limbs 4-7), as its <see cref="Scalar.SizeBytes"/> canonical big-endian bytes — the inverse of <see cref="LoadScalarLowHighLimbs"/>.</summary>
    private static void StoreScalarLowHighLimbs(Vector256<ulong> low, Vector256<ulong> high, Span<byte> canonical)
    {
        Vector256<uint> limbs32 = Vector256.Narrow(low, high);
        Vector256<byte> littleEndianBytes = limbs32.AsByte();
        Vector256<byte> canonicalBytes = Vector256.Reverse(littleEndianBytes);

        canonicalBytes.CopyTo(canonical);
    }
}
