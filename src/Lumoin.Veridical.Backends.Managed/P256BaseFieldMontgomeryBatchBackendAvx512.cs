using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// AVX-512 lane-parallel batch backend for the P-256 base field Fp256
/// <see cref="ScalarBatchMultiplyDelegate"/>, the AVX-512 mirror of
/// <see cref="P256BaseFieldMontgomeryBatchBackendAvx2"/>. Same single-CIOS
/// Montgomery-domain algorithm with the lane width doubled: eight Montgomery residues
/// per octet (one per 64-bit lane of <see cref="Vector512{T}"/>) instead of four per
/// quartet, the conditional reduction a single
/// <see cref="Vector512.ConditionalSelect{T}(Vector512{T}, Vector512{T}, Vector512{T})"/>.
/// </summary>
/// <remarks>
/// <para>
/// As in the AVX2 backend the public op is a <em>single-CIOS Montgomery-domain</em>
/// multiply — residues <c>aR, bR</c> in, <c>abR = mont(ab)</c> out, no <c>R²</c> lift —
/// so it agrees byte-for-byte with the scalar
/// <see cref="P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery"/>. Eight 32-bit
/// limbs per lane, transposed lane-major; <c>R = 2²⁵⁶</c> in both radices, so the
/// residue is identical to the scalar backend's.
/// </para>
/// <para>
/// On a host without AVX-512 the agreement gate reports Inconclusive rather than failing;
/// correctness is pinned on AVX-512 hardware (or an AVX-512-capable runner) against the scalar
/// single-CIOS <see cref="P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery"/>.
/// </para>
/// <para>
/// Two CIOS reduction sub-steps live here and produce the identical final Montgomery residue.
/// The live path, <see cref="MontgomeryMultiplyOctetGenericReduce"/> reached through
/// <see cref="GetBatchMultiplyMontgomery"/>, forms the per-step term <c>r·p</c> through the full
/// <c>m·Modulus32[j]</c> product (the textbook generic Montgomery reduction). The alternative path,
/// <see cref="MontgomeryMultiplyOctet"/> reached through
/// <see cref="GetBatchMultiplyMontgomerySpecializedReduce"/>, uses the P-256-specialized reduction:
/// because <c>p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1</c> is signed-sparse, the same <c>r·p</c> (with quotient
/// digit <c>r = t[0]</c>, since <c>N'32 = 1</c>) is added by subtracting <c>r</c> at limbs {0, 7} and
/// adding <c>r</c> at limbs {3, 6, 8} with borrow/carry propagation — no multiply by the modulus. It is
/// retained for comparison (see <see cref="MontgomeryMultiplyOctet"/> for why the generic form is live).
/// Both mirror <c>Fp256Reduce</c> in <c>lib/algebra/fp_p256.h</c> / <c>fp_generic.h</c> respectively.
/// </para>
/// </remarks>
internal static class P256BaseFieldMontgomeryBatchBackendAvx512
{
    /// <summary>True when the host CPU supports the AVX-512 foundation instructions this backend uses.</summary>
    public static bool IsSupported => Avx512F.IsSupported;


    /// <summary>The number of canonical bytes per Fp256 element.</summary>
    private const int ElementBytes = Scalar.SizeBytes;

    /// <summary>The number of independent elements packed into one SIMD octet (one per 64-bit lane of <see cref="Vector512{T}"/>).</summary>
    private const int ElementsPerOctet = 8;

    /// <summary>The number of canonical bytes per octet (eight elements, each <see cref="Scalar.SizeBytes"/> bytes).</summary>
    private const int OctetBytes = ElementsPerOctet * ElementBytes;

    /// <summary>The number of 32-bit limbs that compose one Fp256 element (256 bits / 32 bits per limb).</summary>
    private const int Limb32Count = 8;

    /// <summary>The number of accumulator limbs in the CIOS window: <see cref="Limb32Count"/> plus two headroom limbs.</summary>
    private const int AccumulatorLimbCount = Limb32Count + 2;

    /// <summary>The limb where the specialized reduction subtracts <c>r</c> for the <c>−2⁰</c> term.</summary>
    /// <remarks>
    /// The five sparse-limb constants are the signed-sparse limb offsets of p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1 in
    /// 32-bit limbs: subtract <c>r</c> at limbs {0, 7} and add it at limbs {3, 6, 8}. They express
    /// r·p = r·2²⁵⁶ − r·2²²⁴ + r·2¹⁹² + r·2⁹⁶ − r in 2³²-radix limb positions (2²⁵⁶ at limb 8, 2²²⁴ at limb 7,
    /// 2¹⁹² at limb 6, 2⁹⁶ at limb 3, 2⁰ at limb 0).
    /// </remarks>
    private const int SparseSubtractLimbLow = 0;

    /// <summary>The limb where the specialized reduction subtracts <c>r</c> for the <c>−2²²⁴</c> term.</summary>
    private const int SparseSubtractLimbHigh = 7;

    /// <summary>The limb where the specialized reduction adds <c>r</c> for the <c>+2⁹⁶</c> term (also the accum window start).</summary>
    private const int SparseAddLimbLow = 3;

    /// <summary>The limb where the specialized reduction adds <c>r</c> for the <c>+2¹⁹²</c> term.</summary>
    private const int SparseAddLimbMid = 6;

    /// <summary>The limb where the specialized reduction adds <c>r</c> for the <c>+2²⁵⁶</c> term.</summary>
    private const int SparseAddLimbHigh = 8;


    /// <summary>The mask that keeps the low 32 bits of every 64-bit lane, isolating one limb from its carry.</summary>
    private static Vector512<ulong> Low32Mask { get; } = Vector512.Create(0xFFFFFFFFUL);
    /// <summary>The 32-bit Montgomery constant <c>n'</c> (−p⁻¹ mod 2³²) broadcast to every lane.</summary>
    private static Vector512<ulong> NPrime32Broadcast { get; } = Vector512.Create((ulong)Fp256MontgomeryParameters.NPrime32);
    /// <summary>The eight 32-bit limbs of the P-256 base-field modulus, each broadcast to every lane.</summary>
    private static Vector512<ulong>[] Modulus32Broadcast { get; } = BuildBroadcast(Fp256MontgomeryParameters.Modulus32Limbs);


    /// <summary>
    /// Returns the lane-interleaved batched Montgomery-domain multiply delegate: a 32-bit-limb single-CIOS
    /// Montgomery multiply running eight Montgomery residues per AVX-512 octet (one per 64-bit lane), with the
    /// generic <c>m·Modulus32</c> reduction (the live managed path). The trailing 1–7 elements fall back to the
    /// counter-free scalar single-CIOS core.
    /// </summary>
    public static ScalarBatchMultiplyDelegate GetBatchMultiplyMontgomery() => BatchMultiplyMontgomery;


    /// <summary>
    /// Returns the batched Montgomery-domain multiply delegate that reduces with the P-256-specialized
    /// signed-sparse CIOS step instead of the generic <c>m·Modulus32</c> step. It produces the identical final
    /// Montgomery residue as <see cref="GetBatchMultiplyMontgomery"/>; the agreement gate drives both against the
    /// same scalar oracle to pin that equivalence. Retained as the reference-faithful alternative (see
    /// <see cref="MontgomeryMultiplyOctet"/>); the generic reduction is the live path.
    /// </summary>
    internal static ScalarBatchMultiplyDelegate GetBatchMultiplyMontgomerySpecializedReduce() => BatchMultiplyMontgomerySpecializedReduce;


    /// <summary>Broadcasts each of the eight 32-bit limbs to a full vector of 64-bit lanes.</summary>
    /// <param name="limbs32">The eight 32-bit limbs, least significant first.</param>
    /// <returns>One vector per limb with the limb replicated in every lane.</returns>
    private static Vector512<ulong>[] BuildBroadcast(ReadOnlySpan<uint> limbs32)
    {
        var vectors = new Vector512<ulong>[Limb32Count];
        for(int i = 0; i < Limb32Count; i++)
        {
            vectors[i] = Vector512.Create((ulong)limbs32[i]);
        }

        return vectors;
    }


    /// <summary>The batched Montgomery multiply that reduces with the generic <c>m·Modulus32</c> step.</summary>
    /// <param name="leftOperandsConcatenated">The left operands, concatenated.</param>
    /// <param name="rightOperandsConcatenated">The right operands, concatenated.</param>
    /// <param name="resultsConcatenated">The destination for the products, concatenated.</param>
    /// <param name="count">The number of elements in each concatenation.</param>
    /// <param name="curve">The curve the operation is attributed to.</param>
    private static void BatchMultiplyMontgomery(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        BatchMultiply(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count, curve, useSpecializedReduce: false);
    }


    /// <summary>The batched Montgomery multiply that reduces with the P-256 signed-sparse step.</summary>
    /// <param name="leftOperandsConcatenated">The left operands, concatenated.</param>
    /// <param name="rightOperandsConcatenated">The right operands, concatenated.</param>
    /// <param name="resultsConcatenated">The destination for the products, concatenated.</param>
    /// <param name="count">The number of elements in each concatenation.</param>
    /// <param name="curve">The curve the operation is attributed to.</param>
    private static void BatchMultiplyMontgomerySpecializedReduce(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        BatchMultiply(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count, curve, useSpecializedReduce: true);
    }


    /// <summary>
    /// Multiplies the concatenated operands octet by octet, then finishes the trailing elements with the scalar core.
    /// </summary>
    /// <param name="leftOperandsConcatenated">The left operands, concatenated.</param>
    /// <param name="rightOperandsConcatenated">The right operands, concatenated.</param>
    /// <param name="resultsConcatenated">The destination for the products, concatenated.</param>
    /// <param name="count">The number of elements in each concatenation.</param>
    /// <param name="curve">The curve the operation is attributed to.</param>
    /// <param name="useSpecializedReduce">Whether the reduction step is the P-256 signed-sparse one rather than the generic one.</param>
    private static void BatchMultiply(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve,
        bool useSpecializedReduce)
    {
        if(!Avx512F.IsSupported)
        {
            throw new PlatformNotSupportedException("P256BaseFieldMontgomeryBatchBackendAvx512 requires AVX-512F; check IsSupported before wiring it as a delegate.");
        }

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchMultiply, curve, count);

        int stride = ElementBytes;
        ValidateBatchedLengths(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count, stride);

        int octets = count / ElementsPerOctet;
        for(int octetIndex = 0; octetIndex < octets; octetIndex++)
        {
            int offset = octetIndex * OctetBytes;
            MultiplyOctet(
                leftOperandsConcatenated.Slice(offset, OctetBytes),
                rightOperandsConcatenated.Slice(offset, OctetBytes),
                resultsConcatenated.Slice(offset, OctetBytes),
                useSpecializedReduce);
        }

        int tailStart = octets * OctetBytes;
        int tailCount = count % ElementsPerOctet;
        for(int i = 0; i < tailCount; i++)
        {
            int offset = tailStart + i * stride;
            //Counter-free single-CIOS core so the per-call ScalarBatchMultiply increment is not double-bumped.
            P256BaseFieldMontgomeryBackend.MultiplyMontgomeryCore(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    /// <summary>
    /// Multiplies eight independent Montgomery residues in parallel: <c>result = a · b · R⁻¹ mod p</c>
    /// per lane via a single CIOS (no <c>R²</c> lift), which on residue inputs <c>aR, bR</c> yields
    /// <c>abR = mont(ab)</c>. The <paramref name="useSpecializedReduce"/> flag selects the
    /// P-256-specialized signed-sparse reduction or the generic <c>m·Modulus32</c> reduction; both yield
    /// the identical final residue.
    /// </summary>
    private static void MultiplyOctet(
        ReadOnlySpan<byte> aOctet,
        ReadOnlySpan<byte> bOctet,
        Span<byte> resultOctet,
        bool useSpecializedReduce)
    {
        Span<Vector512<ulong>> a = stackalloc Vector512<ulong>[Limb32Count];
        Span<Vector512<ulong>> b = stackalloc Vector512<ulong>[Limb32Count];
        Span<Vector512<ulong>> product = stackalloc Vector512<ulong>[Limb32Count];

        LoadOctetTo32LimbVectors(aOctet, a);
        LoadOctetTo32LimbVectors(bOctet, b);

        //SINGLE CIOS, residue-in/residue-out (aR·bR·R⁻¹ = abR = mont(ab)). Do NOT add an R²-lift here — that
        //emits the canonical a·b mod p, off by R⁻¹ from the scalar MultiplyMontgomery this must match
        //byte-for-byte.
        if(useSpecializedReduce)
        {
            MontgomeryMultiplyOctet(a, b, product);
        }
        else
        {
            MontgomeryMultiplyOctetGenericReduce(a, b, product);
        }

        Store32LimbVectorsToOctet(product, resultOctet);
    }


    /// <summary>
    /// Lane-parallel CIOS Montgomery multiply over 32-bit limbs with the P-256-specialized reduction, retained
    /// as the comparison alternative to the live generic <see cref="MontgomeryMultiplyOctetGenericReduce"/>:
    /// <c>result = x · y · R⁻¹ mod p</c> per lane, reduced once. Each outer step accumulates the column
    /// product, then adds <c>r·p</c> for quotient digit <c>r = t[0]</c> (because <c>N'32 = 1</c>) using the
    /// signed-sparse form of <c>p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1</c> — subtract <c>r</c> at limbs {0, 7}, add
    /// <c>r</c> at limbs {3, 6, 8}, propagate borrow/carry — with no multiply by the modulus, then shifts the
    /// window down one limb. It mirrors the 32-bit <c>Fp256Reduce</c> reduction step in
    /// google/longfellow-zk <c>fp_p256.h</c>; it removes the per-limb modulus multiplies, but in managed .NET it
    /// is SLOWER than the generic <c>m·Modulus32</c> reduction (no ADX/ADCX/ADOX, so the dependent borrow/carry
    /// chains cost more than the generic's pipelined multiplies). It is kept as the reference-faithful form and
    /// the right reduction for a future hand-asm / ADX-intrinsic backend; the generic reduction is the live
    /// managed path. The output is byte-identical to the generic kernel.
    /// </summary>
    private static void MontgomeryMultiplyOctet(
        ReadOnlySpan<Vector512<ulong>> x,
        ReadOnlySpan<Vector512<ulong>> y,
        Span<Vector512<ulong>> result)
    {
        Span<Vector512<ulong>> t = stackalloc Vector512<ulong>[AccumulatorLimbCount];
        for(int k = 0; k < AccumulatorLimbCount; k++)
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

            SpecializedReduceStepOctet(t, mask);
        }

        ConditionalSubtractModulusOctet(t, result);
    }


    /// <summary>
    /// Adds <c>r·p</c> for <c>r = t[0]</c> via the signed-sparse form of <c>p</c> and shifts the accumulator
    /// window down one limb (the CIOS divide by <c>2³²</c>). Subtracts <c>r</c> at limbs {0, 7} with
    /// borrow propagation, then adds <c>r</c> at limbs {3, 6, 8} with carry propagation, both across the full
    /// <see cref="AccumulatorLimbCount"/>-limb window; limb 0 cancels to zero and the shift discards it.
    /// </summary>
    private static void SpecializedReduceStepOctet(Span<Vector512<ulong>> t, Vector512<ulong> mask)
    {
        Vector512<ulong> r = t[0];

        //negaccum: subtract r at limbs {0, 7}, borrow up through the window. Borrow is the lane's sign bit of
        //the 64-bit difference (the >>63 pattern the conditional subtraction also uses).
        Vector512<ulong> borrow = Vector512<ulong>.Zero;
        for(int j = 0; j < AccumulatorLimbCount; j++)
        {
            Vector512<ulong> subtrahend = (j == SparseSubtractLimbLow || j == SparseSubtractLimbHigh) ? r : Vector512<ulong>.Zero;
            Vector512<ulong> difference = Avx512F.Subtract(Avx512F.Subtract(t[j], subtrahend), borrow);
            t[j] = Avx512F.And(difference, mask);
            borrow = Avx512F.ShiftRightLogical(difference, 63);
        }

        //accum: add r at limbs {3, 6, 8}, carry up through the window.
        Vector512<ulong> carry = Vector512<ulong>.Zero;
        for(int j = SparseAddLimbLow; j < AccumulatorLimbCount; j++)
        {
            Vector512<ulong> addend = (j == SparseAddLimbLow || j == SparseAddLimbMid || j == SparseAddLimbHigh) ? r : Vector512<ulong>.Zero;
            Vector512<ulong> sum = Avx512F.Add(Avx512F.Add(t[j], addend), carry);
            t[j] = Avx512F.And(sum, mask);
            carry = Avx512F.ShiftRightLogical(sum, 32);
        }

        //Shift the window down one limb (limb 0 is zero after the r@0 cancellation); top limb clears.
        for(int j = 1; j < AccumulatorLimbCount; j++)
        {
            t[j - 1] = t[j];
        }

        t[AccumulatorLimbCount - 1] = Vector512<ulong>.Zero;
    }


    /// <summary>
    /// Lane-parallel CIOS Montgomery multiply over 32-bit limbs with the generic <c>m·Modulus32</c>
    /// reduction: <c>result = x · y · R⁻¹ mod p</c> per lane, reduced once. Each outer step forms the quotient
    /// digit <c>m = t[0]·N'32 mod 2³²</c> and adds <c>m·p</c> through the full per-limb modulus product before
    /// shifting the window down. This is the textbook generic Montgomery reduction (the lane-parallel mirror
    /// of <c>FpGeneric</c>'s reduction), kept alongside <see cref="MontgomeryMultiplyOctet"/> as the
    /// non-specialized reference; both produce the identical final residue.
    /// </summary>
    private static void MontgomeryMultiplyOctetGenericReduce(
        ReadOnlySpan<Vector512<ulong>> x,
        ReadOnlySpan<Vector512<ulong>> y,
        Span<Vector512<ulong>> result)
    {
        Span<Vector512<ulong>> t = stackalloc Vector512<ulong>[AccumulatorLimbCount];
        for(int k = 0; k < AccumulatorLimbCount; k++)
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


    /// <summary>
    /// Subtracts the modulus from an octet's accumulator when it is at least the modulus, without branching on
    /// lane values, so every lane ends in the canonical range.
    /// </summary>
    /// <param name="t">The nine-limb accumulator of the octet.</param>
    /// <param name="result">The eight reduced result limbs.</param>
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
        int stride = ElementBytes;
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

        int stride = ElementBytes;
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
    /// Reversing the 32 bytes end to end and reading little-endian 32-bit words in increasing offset
    /// order yields the big-endian words of the original in decreasing offset order, which is limbs 0-7
    /// least-significant first. The reinterpretation relies on the little-endian lane layout of the
    /// x86-64 hosts this backend runs on.
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

    /// <summary>Throws unless all three buffers hold exactly <paramref name="count"/> elements of <paramref name="stride"/> bytes.</summary>
    /// <param name="first">The first buffer.</param>
    /// <param name="second">The second buffer.</param>
    /// <param name="third">The third buffer.</param>
    /// <param name="count">The element count.</param>
    /// <param name="stride">The bytes per element.</param>
    /// <exception cref="ArgumentException">When any buffer has a different length.</exception>
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
                $"Batched Fp256 buffers must each be exactly {count} * {stride} bytes for count = {count}.");
        }
    }
}
