using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// A second-implementation reference for BLS12-381 scalar-field
/// <see cref="ScalarAddDelegate"/> and <see cref="ScalarSubtractDelegate"/>,
/// sitting alongside <see cref="Bls12Curve381BigIntegerScalarReference"/>.
/// Uses 64-bit limb arithmetic with explicit carry/borrow chains and AVX2
/// instructions for the constant-time conditional swap at the modular
/// reduction step.
/// </summary>
/// <remarks>
/// <para>
/// The reason this exists has nothing to do with being faster than the
/// BigInteger reference (it is, but that is incidental). It exists to
/// demonstrate that the delegate-based backend boundary is genuinely
/// backend-agnostic — two implementations with totally different internal
/// representations (heap-allocated arbitrary-precision integers vs.
/// 4-limb fixed-width unsigned arithmetic in 256-bit SIMD registers)
/// produce bit-identical canonical bytes when wired through the same
/// delegate signature. The agreement is verified by
/// <c>Bls12Curve381ScalarBackendAgreementTests</c> which sweeps random
/// inputs through both implementations and asserts byte equality of the
/// output — the property-based testing pattern used to gate every
/// independently-implemented backend against its reference.
/// </para>
/// <para>
/// Internal representation is 4 × <see cref="ulong"/> limbs in
/// little-endian order: <c>limb[0]</c> is the least-significant 64 bits,
/// <c>limb[3]</c> the most-significant. Canonical big-endian 32-byte
/// boundary input is read via <see cref="BinaryPrimitives"/>; the
/// constant-time conditional reduction at the end uses AVX2
/// <see cref="Avx2.BlendVariable(Vector256{byte}, Vector256{byte}, Vector256{byte})"/>
/// so the wrong branch is not taken on secret-dependent input. AVX2 is
/// required; <see cref="IsSupported"/> reports whether the host CPU
/// satisfies that.
/// </para>
/// <para>
/// Add, subtract, multiply, negate, and invert are implemented (plus the
/// batched add/subtract). Add/subtract are the lane-interleaved SIMD path;
/// multiply and invert are the serial CIOS Montgomery multiply / Fermat
/// ladder shared via <see cref="Bls12Curve381MontgomeryArithmetic"/> (SIMD
/// accelerates batches of multiplications, not a single serial one).
/// Wide-input <c>Reduce</c> stays on the BigInteger reference (a general
/// 512-bit reduction is Barrett-class, not the bounded conditional
/// subtraction the SIMD operations use).
/// </para>
/// </remarks>
internal static class Bls12Curve381Avx2ScalarBackend
{
    /// <summary>Indicates whether the host CPU supports the instructions this backend uses.</summary>
    public static bool IsSupported => Avx2.IsSupported;


    /// <summary>The number of 64-bit limbs that compose a BLS12-381 scalar (256 bits / 64 bits per limb).</summary>
    private const int LimbCount = 4;

    /// <summary>The number of canonical bytes per 64-bit limb.</summary>
    private const int BytesPerLimb = sizeof(ulong);

    /// <summary>
    /// The number of independent scalars packed into one SIMD quartet.
    /// Matches the number of 64-bit lanes in <see cref="Vector256{T}"/>:
    /// four scalars share each limb-position register, one per lane.
    /// </summary>
    private const int ScalarsPerQuartet = 4;

    /// <summary>The number of canonical bytes per scalar quartet (four scalars, each <see cref="Scalar.SizeBytes"/> bytes).</summary>
    private const int QuartetBytes = ScalarsPerQuartet * Scalar.SizeBytes;


    /// <summary>
    /// BLS12-381 scalar-field modulus <c>r</c> as four little-endian
    /// 64-bit limbs. <c>r = 0x73eda753299d7d48 3339d80809a1d805
    /// 53bda402fffe5bfe ffffffff00000001</c>.
    /// </summary>
    /// <remarks>
    /// Held as a <c>readonly</c> array rather than four <see cref="UInt64"/>
    /// constants so the limb slice can be passed to span-accepting helpers
    /// without per-call array allocation.
    /// </remarks>
    private static ulong[] FieldOrderLimbs { get; } =
    [
        0xffffffff00000001UL,
        0x53bda402fffe5bfeUL,
        0x3339d80809a1d805UL,
        0x73eda753299d7d48UL
    ];


    /// <summary>Returns the SIMD-backed reference scalar-add delegate.</summary>
    public static ScalarAddDelegate GetAdd() => Add;

    /// <summary>Returns the SIMD-backed reference scalar-subtract delegate.</summary>
    public static ScalarSubtractDelegate GetSubtract() => Subtract;

    /// <summary>
    /// Returns the SIMD-backed batched scalar-add delegate. Processes full
    /// quartets of scalars in parallel using AVX2 lane-interleaved arithmetic
    /// (4 scalars, one per 64-bit lane of <see cref="Vector256{T}"/>, with
    /// every limb-position holding one register), and falls back to the
    /// single-element <see cref="Add"/> for the trailing 1–3 elements that
    /// do not fill a complete quartet.
    /// </summary>
    public static ScalarBatchAddDelegate GetBatchAdd() => BatchAdd;

    /// <summary>Returns the SIMD-backed batched scalar-subtract delegate. See <see cref="GetBatchAdd"/> for the layout.</summary>
    public static ScalarBatchSubtractDelegate GetBatchSubtract() => BatchSubtract;

    /// <summary>
    /// Returns the scalar-multiply delegate. A single multiplication is a serial
    /// CIOS Montgomery multiply over the four 64-bit limbs (lane-parallel batching
    /// is a separate concern); inputs and outputs are canonical big-endian — the
    /// Montgomery form is internal and never observed at the delegate boundary.
    /// </summary>
    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    /// <summary>
    /// Returns the lane-interleaved batched scalar-multiply delegate. Processes
    /// full quartets of scalars in parallel: a 32-bit-limb CIOS Montgomery multiply
    /// where each 32×32→64 partial product is one <c>vpmuludq</c> and the four
    /// scalars advance through the (per-lane independent) reduction simultaneously,
    /// one per 64-bit lane. The trailing 1–3 elements that do not fill a quartet
    /// fall back to the shared serial Montgomery multiply.
    /// </summary>
    public static ScalarBatchMultiplyDelegate GetBatchMultiply() => BatchMultiply;

    /// <summary>Returns the scalar-negate delegate: modular negation <c>r − a</c>, with zero mapping to zero.</summary>
    public static ScalarNegateDelegate GetNegate() => Negate;

    /// <summary>
    /// Returns the scalar-invert delegate: Fermat inversion <c>a^(r−2) mod r</c> over
    /// the Montgomery multiply. Throws for a zero input, matching the reference.
    /// </summary>
    public static ScalarInvertDelegate GetInvert() => Invert;


    /// <summary>Adds two canonical scalars via the constant-time carry/reduce core, requiring AVX2.</summary>
    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bls12Curve381Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
        }

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarAdd, curve);
        AddCore(a, b, result);
    }


    /// <summary>Counter-free arithmetic body of <see cref="Add"/>, used by the batched tail to avoid double-counting <see cref="CryptographicOperationKind.ScalarBatchAdd"/> against <see cref="CryptographicOperationKind.ScalarAdd"/>.</summary>
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

        //If addition overflowed past 2^256 the true sum is conceptually 2^256
        //plus what we stored; subtracting r mod 2^256 (ignoring the borrow out)
        //yields the correct reduced result. Otherwise, if sumMinusR did not
        //borrow then sum >= r and the subtracted value is the correct one. In
        //both cases we want sumMinusR; only when neither holds do we want sum.
        bool useReduced = carry | !borrow;
        ConditionalSelect(sumMinusR, sum, useReduced, result);
    }


    /// <summary>Subtracts two canonical scalars via the constant-time borrow/reduce core, requiring AVX2.</summary>
    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bls12Curve381Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
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


    /// <summary>Multiplies two canonical scalars via the shared serial CIOS Montgomery multiply, requiring AVX2 (checked for consistency with this backend's other operations, though the multiply body itself is not SIMD).</summary>
    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bls12Curve381Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
        }

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarMultiply, curve);

        //A single Montgomery multiply is a serial limb carry chain that SIMD does not
        //accelerate; the ISA-independent body is shared across the backends.
        Bls12Curve381MontgomeryArithmetic.Multiply(a, b, result);
    }


    /// <summary>Inverts a canonical scalar via the shared Fermat-ladder Montgomery inversion, requiring AVX2 for consistency with this backend's other operations.</summary>
    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bls12Curve381Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
        }

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarInvert, curve);
        Bls12Curve381MontgomeryArithmetic.Invert(a, result);
    }


    /// <summary>Negates a canonical scalar modulo r via the constant-time subtract-from-zero core, requiring AVX2.</summary>
    private static void Negate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bls12Curve381Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
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


    /// <summary>Reads a scalar's canonical big-endian bytes into its four little-endian 64-bit limbs (limb 0 least significant).</summary>
    private static void LoadCanonicalToLimbs(ReadOnlySpan<byte> canonical, Span<ulong> limbs)
    {
        //canonical: Scalar.SizeBytes big-endian bytes, MSB first.
        //limbs: limbs[0] is the least significant 64 bits, limbs[LimbCount - 1] the most.
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int offset = (LimbCount - 1 - limbIndex) * BytesPerLimb;
            limbs[limbIndex] = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(offset, BytesPerLimb));
        }
    }


    /// <summary>Writes four little-endian 64-bit limbs (limb 0 least significant) as a scalar's canonical big-endian bytes — the inverse of <see cref="LoadCanonicalToLimbs"/>.</summary>
    private static void StoreLimbsToCanonical(ReadOnlySpan<ulong> limbs, Span<byte> canonical)
    {
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int offset = (LimbCount - 1 - limbIndex) * BytesPerLimb;
            BinaryPrimitives.WriteUInt64BigEndian(canonical.Slice(offset, BytesPerLimb), limbs[limbIndex]);
        }
    }


    /// <summary>Adds two 4-limb values with a carry chain, writing the 256-bit (wrapped) sum into <paramref name="result"/> and returning whether the addition carried out past the fourth limb.</summary>
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


    /// <summary>Subtracts a 4-limb value from another in place with a borrow chain, overwriting <paramref name="a"/> with the (wrapped) difference and returning whether the subtraction borrowed past the fourth limb.</summary>
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
    /// Writes either <paramref name="onTrue"/> or <paramref name="onFalse"/>
    /// to <paramref name="destination"/> based on <paramref name="condition"/>,
    /// using <see cref="Avx2.BlendVariable(Vector256{byte}, Vector256{byte}, Vector256{byte})"/>
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
        //BlendVariable inspects the high bit of each byte lane of the mask, and
        //a homogeneous mask satisfies that uniformly.
        Vector256<byte> mask = condition ? Vector256<byte>.AllBitsSet : Vector256<byte>.Zero;
        Vector256<ulong> selected = Avx2.BlendVariable(falseValue.AsByte(), trueValue.AsByte(), mask).AsUInt64();

        Span<ulong> selectedLimbs = stackalloc ulong[LimbCount];
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            selectedLimbs[limbIndex] = selected.GetElement(limbIndex);
        }

        StoreLimbsToCanonical(selectedLimbs, destination);
    }


    /// <summary>Adds a batch of scalars pairwise, processing full quartets through the SIMD lane-parallel path and the trailing 1-3 elements through the serial <see cref="AddCore"/>.</summary>
    private static void BatchAdd(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bls12Curve381Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
        }

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchAdd, curve, count);

        int stride = Scalar.SizeBytes;
        ValidateBatchedLengths(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count, stride);

        //Walk full quartets through the SIMD path: each iteration adds four
        //independent scalars in lane-parallel form. The serial part is the
        //carry chain across limbs; the SIMD part is that all four scalars
        //advance through that chain simultaneously, one lane per scalar.
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
            //Use AddCore not Add so the operation-counter for ScalarAdd is not
            //bumped on top of the ScalarBatchAdd increment recorded above.
            AddCore(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    /// <summary>Subtracts a batch of scalars pairwise, processing full quartets through the SIMD lane-parallel path and the trailing 1-3 elements through the serial <see cref="SubtractCore"/>.</summary>
    private static void BatchSubtract(
        ReadOnlySpan<byte> minuendsConcatenated,
        ReadOnlySpan<byte> subtrahendsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bls12Curve381Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
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


    /// <summary>Throws an <see cref="ArgumentException"/> unless each of the three buffers holds exactly <paramref name="count"/> elements of <paramref name="stride"/> bytes.</summary>
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


    /// <summary>
    /// SIMD inner loop: adds four scalars in parallel, four 64-bit lanes
    /// per <see cref="Vector256{T}"/>, one limb position per register.
    /// </summary>
    /// <remarks>
    /// The carry chain across limbs is still serial — that is intrinsic to
    /// multi-precision addition — but the chain operates on four scalars
    /// simultaneously. After the chain finishes, conditional modular
    /// reduction uses <see cref="Avx2.BlendVariable(Vector256{byte}, Vector256{byte}, Vector256{byte})"/>
    /// with a per-lane mask, so the wrong branch's bits never enter the
    /// destination of any lane.
    /// </remarks>
    private static void AddQuartet(
        ReadOnlySpan<byte> aQuartet,
        ReadOnlySpan<byte> bQuartet,
        Span<byte> resultQuartet)
    {
        LoadQuartetToLimbVectors(aQuartet, out Vector256<ulong> a0, out Vector256<ulong> a1, out Vector256<ulong> a2, out Vector256<ulong> a3);
        LoadQuartetToLimbVectors(bQuartet, out Vector256<ulong> b0, out Vector256<ulong> b1, out Vector256<ulong> b2, out Vector256<ulong> b3);

        //Add with carry chain: each limb position adds a, b, and the carry value
        //from the previous limb. Carry mask is "all-ones per lane that overflowed"
        //and is turned into a {0, 1}-per-lane value via 0 - mask.
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


    /// <summary>SIMD inner loop: subtracts four scalars in parallel, mirroring <see cref="AddQuartet"/>'s lane layout and constant-time conditional reduction.</summary>
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


    /// <summary>
    /// One limb of carry-chain addition: <c>sum = a + b + carryIn</c>, with
    /// <paramref name="carryIn"/> a per-lane {0, 1} value. Outputs the lane-wise
    /// all-ones mask describing the carry out of this limb.
    /// </summary>
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


    /// <summary>
    /// One limb of borrow-chain subtraction: <c>diff = a - b - borrowIn</c>, with
    /// <paramref name="borrowIn"/> a per-lane {0, 1} value. Outputs the lane-wise
    /// all-ones mask describing the borrow out of this limb.
    /// </summary>
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


    /// <summary>
    /// Lane-wise unsigned less-than. AVX2's signed compare flips into
    /// unsigned by XORing both operands with the sign bit first.
    /// </summary>
    private static Vector256<ulong> UnsignedLessThan(Vector256<ulong> a, Vector256<ulong> b)
    {
        Vector256<long> signFlip = Vector256.Create(long.MinValue);
        Vector256<long> aFlipped = Avx2.Xor(a.AsInt64(), signFlip);
        Vector256<long> bFlipped = Avx2.Xor(b.AsInt64(), signFlip);
        return Avx2.CompareGreaterThan(bFlipped, aFlipped).AsUInt64();
    }


    /// <summary>The BLS12-381 scalar-field modulus's limb 0 (least significant), broadcast to every lane of a <see cref="Vector256{T}"/> so the four scalars in a quartet share the modulus.</summary>
    private static Vector256<ulong> FieldOrderLane0 { get; } = Vector256.Create(0xffffffff00000001UL);

    /// <summary>The BLS12-381 scalar-field modulus's limb 1, broadcast to every lane.</summary>
    private static Vector256<ulong> FieldOrderLane1 { get; } = Vector256.Create(0x53bda402fffe5bfeUL);

    /// <summary>The BLS12-381 scalar-field modulus's limb 2, broadcast to every lane.</summary>
    private static Vector256<ulong> FieldOrderLane2 { get; } = Vector256.Create(0x3339d80809a1d805UL);

    /// <summary>The BLS12-381 scalar-field modulus's limb 3 (most significant), broadcast to every lane.</summary>
    private static Vector256<ulong> FieldOrderLane3 { get; } = Vector256.Create(0x73eda753299d7d48UL);


    /// <summary>
    /// Transposes <see cref="ScalarsPerQuartet"/> scalar-major canonical
    /// encodings into limb-major SIMD registers. Each output register
    /// holds one limb position with lane <c>i</c> containing scalar
    /// <c>i</c>'s contribution at that limb.
    /// </summary>
    /// <remarks>
    /// Each scalar's 32 canonical bytes are loaded whole, byte-reversed,
    /// and reinterpreted as four little-endian 64-bit lanes by
    /// <see cref="LoadScalarLimbs"/>; reversing a big-endian byte string
    /// and reading little-endian words off it in increasing offset order
    /// reproduces the same <c>limb0..limb3</c> values, in the same order,
    /// that <see cref="LoadCanonicalToLimbs"/> computes one limb at a
    /// time. The four scalars' limb vectors are then transposed into
    /// limb-major form by <see cref="TransposeQuartetLanes"/>.
    /// </remarks>
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


    /// <summary>
    /// Reads one scalar's 32 canonical big-endian bytes as its four
    /// 64-bit limbs, in the same <c>limb0..limb3</c> order
    /// <see cref="LoadCanonicalToLimbs"/> produces.
    /// </summary>
    /// <remarks>
    /// The canonical bytes are loaded as one <see cref="Vector256{T}"/> of
    /// <see cref="byte"/> and reversed end to end; the byte at position
    /// <c>31 - k</c> of a big-endian buffer is the byte at position
    /// <c>k</c> of its little-endian reverse, so the reversed buffer's
    /// four 8-byte little-endian words, read in increasing offset order,
    /// equal the original buffer's four 8-byte big-endian words read in
    /// decreasing offset order — exactly <c>limb0..limb3</c>. Reinterpreting
    /// those reversed bytes directly as <see cref="ulong"/> lanes relies on
    /// the little-endian lane layout of the x86-64 hosts this AVX2 backend
    /// runs on.
    /// </remarks>
    private static Vector256<ulong> LoadScalarLimbs(ReadOnlySpan<byte> canonical)
    {
        Vector256<byte> canonicalBytes = Vector256.Create(canonical);
        Vector256<byte> littleEndianBytes = Vector256.Reverse(canonicalBytes);

        return littleEndianBytes.AsUInt64();
    }


    /// <summary>
    /// Inverse of <see cref="LoadQuartetToLimbVectors"/>: writes four
    /// limb-major SIMD registers as <see cref="ScalarsPerQuartet"/>
    /// scalar-major canonical encodings.
    /// </summary>
    /// <remarks>
    /// A matrix transpose is its own inverse, so
    /// <see cref="TransposeQuartetLanes"/> — the same method
    /// <see cref="LoadQuartetToLimbVectors"/> uses to go scalar-major to
    /// limb-major — also goes limb-major back to scalar-major here. Each
    /// resulting scalar vector is written back to canonical bytes by
    /// <see cref="StoreScalarLimbs"/>.
    /// </remarks>
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


    /// <summary>
    /// Writes one scalar's four 64-bit limbs, in <c>limb0..limb3</c>
    /// order, as its 32 canonical big-endian bytes — the inverse of
    /// <see cref="LoadScalarLimbs"/>.
    /// </summary>
    private static void StoreScalarLimbs(Vector256<ulong> limbs, Span<byte> canonical)
    {
        Vector256<byte> littleEndianBytes = limbs.AsByte();
        Vector256<byte> canonicalBytes = Vector256.Reverse(littleEndianBytes);

        canonicalBytes.CopyTo(canonical);
    }


    /// <summary>
    /// Transposes four <see cref="Vector256{T}"/> of <see cref="ulong"/>,
    /// each holding one source's four values, into four vectors each
    /// holding one position with lane <c>i</c> carrying source <c>i</c>'s
    /// contribution at that position — a 4x4 transpose over (source
    /// index, position index).
    /// </summary>
    /// <remarks>
    /// A matrix transpose is its own inverse, so this method run again on
    /// its own output recovers the original four inputs; every quartet
    /// load and store in this file shares this one implementation for
    /// both directions on that strength. The pairing stage zips sources
    /// <c>(0, 1)</c> and <c>(2, 3)</c>: <c>ZipLower</c> interleaves the
    /// lower half of each pair element-wise and <c>ZipUpper</c> does the
    /// same for the upper half. The assembly stage then selects the
    /// matching half from each pair: <c>ConcatLowerLower</c> takes the
    /// lower half of each zipped pair, <c>ConcatUpperUpper</c> the upper
    /// half.
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


    /// <summary>The number of 32-bit limbs that compose a scalar (256 bits / 32 bits).</summary>
    private const int Limb32Count = 8;

    /// <summary>Per-lane broadcast: every 64-bit lane holds <c>0x00000000FFFFFFFF</c>, the low-32 mask.</summary>
    private static Vector256<ulong> Low32Mask { get; } = Vector256.Create(0xFFFFFFFFUL);

    /// <summary><c>N'32 = −r⁻¹ mod 2³²</c> broadcast to every lane (value in the low 32 bits).</summary>
    private static Vector256<ulong> NPrime32Broadcast { get; } = Vector256.Create((ulong)Bls12Curve381MontgomeryParameters.NPrime32);

    /// <summary>The eight 32-bit modulus limbs, each broadcast to every lane.</summary>
    private static Vector256<ulong>[] Modulus32Broadcast { get; } = BuildBroadcast(Bls12Curve381MontgomeryParameters.Modulus32Limbs);

    /// <summary>The eight 32-bit <c>R² mod r</c> limbs, each broadcast to every lane.</summary>
    private static Vector256<ulong>[] RSquared32Broadcast { get; } = BuildBroadcast(Bls12Curve381MontgomeryParameters.RSquared32Limbs);


    /// <summary>Broadcasts each of the given 32-bit limbs to every lane of its own <see cref="Vector256{T}"/>, one vector per limb.</summary>
    private static Vector256<ulong>[] BuildBroadcast(ReadOnlySpan<uint> limbs32)
    {
        var vectors = new Vector256<ulong>[Limb32Count];
        for(int i = 0; i < Limb32Count; i++)
        {
            vectors[i] = Vector256.Create((ulong)limbs32[i]);
        }

        return vectors;
    }


    /// <summary>Multiplies a batch of scalars pairwise, processing full quartets through the lane-interleaved 32-bit-limb CIOS Montgomery multiply and the trailing 1-3 elements through the shared serial Montgomery multiply.</summary>
    private static void BatchMultiply(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("Bls12Curve381Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.");
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
            //Serial Montgomery multiply for the sub-quartet remainder; no extra
            //counter bump (the ScalarBatchMultiply count was recorded above).
            Bls12Curve381MontgomeryArithmetic.Multiply(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    /// <summary>
    /// Multiplies four independent scalars in parallel: <c>result = a · b mod r</c>
    /// per lane, via two Montgomery multiplies (lift to Montgomery form by <c>R²</c>,
    /// then multiply by the canonical <c>b</c>). Inputs and outputs are canonical
    /// big-endian; the Montgomery domain is internal.
    /// </summary>
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

        //aR = MontMul(a, R²); ab = MontMul(aR, b) = aR·b·R⁻¹ = a·b mod r.
        MontgomeryMultiplyQuartet(a, RSquared32Broadcast, aMontgomery);
        MontgomeryMultiplyQuartet(aMontgomery, b, product);

        Store32LimbVectorsToQuartet(product, resultQuartet);
    }


    /// <summary>
    /// Lane-parallel CIOS Montgomery multiply over 32-bit limbs:
    /// <c>result = x · y · R⁻¹ mod r</c> per lane, <c>R = 2²⁵⁶</c>. Inputs assumed
    /// reduced (&lt; r); the output is reduced by one constant-time conditional
    /// subtraction. Each limb register holds one 32-bit limb per lane in its low 32
    /// bits, so a single <see cref="Avx2.Multiply(Vector256{uint}, Vector256{uint})"/>
    /// yields the four lanes' 32×32→64 partial products at once.
    /// </summary>
    private static void MontgomeryMultiplyQuartet(
        ReadOnlySpan<Vector256<ulong>> x,
        ReadOnlySpan<Vector256<ulong>> y,
        Span<Vector256<ulong>> result)
    {
        //Two guard limbs above the eight result limbs hold the running carry-out of
        //each pass; the accumulator stays below 2r throughout (CIOS invariant).
        Span<Vector256<ulong>> t = stackalloc Vector256<ulong>[Limb32Count + 2];
        for(int k = 0; k < Limb32Count + 2; k++)
        {
            t[k] = Vector256<ulong>.Zero;
        }

        Vector256<ulong> mask = Low32Mask;

        for(int i = 0; i < Limb32Count; i++)
        {
            //Multiply pass: t += x · y[i].
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

            //Reduction pass: m = (t[0]·N'32) mod 2³² clears the low limb; add m·n and
            //shift down by one 32-bit limb (the division by 2³² that builds R⁻¹).
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


    /// <summary>
    /// Constant-time final reduction: the candidate <c>t[0..7]</c> (with overflow
    /// limb <c>t[8]</c>) is &lt; 2r, so subtract r once per lane iff the lane
    /// overflowed or the candidate is &gt;= r (the speculative subtraction did not
    /// borrow). Per-lane select via <see cref="Avx2.BlendVariable(Vector256{byte}, Vector256{byte}, Vector256{byte})"/>.
    /// </summary>
    private static void ConditionalSubtractModulusQuartet(ReadOnlySpan<Vector256<ulong>> t, Span<Vector256<ulong>> result)
    {
        Vector256<ulong> mask = Low32Mask;
        Span<Vector256<ulong>> reduced = stackalloc Vector256<ulong>[Limb32Count];

        Vector256<ulong> borrow = Vector256<ulong>.Zero;
        for(int j = 0; j < Limb32Count; j++)
        {
            //t[j], n[j] and borrow are all <= 2³²-1, so the wrapping 64-bit
            //subtraction's bit 63 is the borrow-out (set iff the true 32-bit
            //difference went negative), and its low 32 bits are the reduced limb.
            Vector256<ulong> difference = Avx2.Subtract(Avx2.Subtract(t[j], Modulus32Broadcast[j]), borrow);
            reduced[j] = Avx2.And(difference, mask);
            borrow = Avx2.ShiftRightLogical(difference, 63);
        }

        //Subtract iff the overflow limb is non-zero OR the candidate did not borrow
        //(candidate >= r). 0 − x yields an all-ones lane mask when x is 1, zero when 0.
        Vector256<ulong> overflowMask = Avx2.Subtract(Vector256<ulong>.Zero, t[Limb32Count]);
        Vector256<ulong> borrowMask = Avx2.Subtract(Vector256<ulong>.Zero, borrow);
        Vector256<ulong> notBorrowMask = Avx2.Xor(borrowMask, Vector256<ulong>.AllBitsSet);
        Vector256<byte> useReducedMask = Avx2.Or(overflowMask, notBorrowMask).AsByte();

        for(int j = 0; j < Limb32Count; j++)
        {
            result[j] = Avx2.BlendVariable(t[j].AsByte(), reduced[j].AsByte(), useReducedMask).AsUInt64();
        }
    }


    /// <summary>
    /// Transposes the four scalar-major canonical encodings of a quartet into eight
    /// limb-major registers, each holding one 32-bit limb position with lane <c>i</c>
    /// carrying scalar <c>i</c>'s limb (zero-extended into the lane's low 32 bits).
    /// </summary>
    /// <remarks>
    /// <see cref="LoadScalarLowHighLimbs"/> loads and byte-reverses each scalar the
    /// same way <see cref="LoadScalarLimbs"/> does for the 64-bit path, but
    /// reinterprets the reversed bytes as eight little-endian 32-bit lanes instead
    /// of four 64-bit ones, then zero-extends the low and high four of those eight
    /// lanes into two <see cref="Vector256{T}"/> of <see cref="ulong"/> with
    /// <c>WidenLower</c> and <c>WidenUpper</c>. Each of those two per-scalar
    /// vectors is transposed across the four scalars by
    /// <see cref="TransposeQuartetLanes"/>, once for limbs 0-3 and once for limbs
    /// 4-7.
    /// </remarks>
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


    /// <summary>
    /// Reads one scalar's 32 canonical big-endian bytes as its eight 32-bit
    /// limbs, zero-extended into two <see cref="Vector256{T}"/> of
    /// <see cref="ulong"/>: <paramref name="low"/> holds limbs 0-3,
    /// <paramref name="high"/> holds limbs 4-7, in the same increasing-
    /// significance order <see cref="LoadScalarLimbs"/> uses at 64-bit
    /// granularity.
    /// </summary>
    /// <remarks>
    /// The reversed-byte-string identity <see cref="LoadScalarLimbs"/>
    /// relies on at 64-bit granularity holds identically at 32-bit
    /// granularity: reversing the canonical buffer and reading
    /// little-endian 32-bit words off it in increasing offset order
    /// reproduces the same eight big-endian 32-bit words a scalar loop
    /// would read in decreasing offset order.
    /// </remarks>
    private static void LoadScalarLowHighLimbs(ReadOnlySpan<byte> canonical, out Vector256<ulong> low, out Vector256<ulong> high)
    {
        Vector256<byte> canonicalBytes = Vector256.Create(canonical);
        Vector256<byte> littleEndianBytes = Vector256.Reverse(canonicalBytes);
        Vector256<uint> limbs32 = littleEndianBytes.AsUInt32();

        low = Vector256.WidenLower(limbs32);
        high = Vector256.WidenUpper(limbs32);
    }


    /// <summary>
    /// Inverse of <see cref="LoadQuartetTo32LimbVectors"/>: writes eight
    /// limb-major 32-bit-limb registers as <see cref="ScalarsPerQuartet"/>
    /// scalar-major canonical encodings.
    /// </summary>
    /// <remarks>
    /// <see cref="TransposeQuartetLanes"/> inverts limb-major back to
    /// scalar-major the same way described on
    /// <see cref="StoreLimbVectorsToQuartet"/>, applied once to limbs 0-3
    /// and once to limbs 4-7 to recover each scalar's low and high
    /// four-limb halves. <see cref="StoreScalarLowHighLimbs"/> narrows and
    /// writes each scalar's pair of halves back to canonical bytes.
    /// </remarks>
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


    /// <summary>
    /// Writes one scalar's eight 32-bit limbs, held zero-extended across
    /// <paramref name="low"/> (limbs 0-3) and <paramref name="high"/>
    /// (limbs 4-7), as its 32 canonical big-endian bytes — the inverse of
    /// <see cref="LoadScalarLowHighLimbs"/>.
    /// </summary>
    private static void StoreScalarLowHighLimbs(Vector256<ulong> low, Vector256<ulong> high, Span<byte> canonical)
    {
        Vector256<uint> limbs32 = Vector256.Narrow(low, high);
        Vector256<byte> littleEndianBytes = limbs32.AsByte();
        Vector256<byte> canonicalBytes = Vector256.Reverse(littleEndianBytes);

        canonicalBytes.CopyTo(canonical);
    }
}