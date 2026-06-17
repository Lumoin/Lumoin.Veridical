using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers.Binary;
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

    //Signed-sparse limb offsets of p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1 in 32-bit limbs: subtract r at {0, 7},
    //add r at {3, 6, 8}. These are r·p = r·2²⁵⁶ − r·2²²⁴ + r·2¹⁹² + r·2⁹⁶ − r expressed in 2³²-radix limb
    //positions (2²⁵⁶ → limb 8, 2²²⁴ → limb 7, 2¹⁹² → limb 6, 2⁹⁶ → limb 3, 2⁰ → limb 0).

    /// <summary>The limb where the specialized reduction subtracts <c>r</c> for the <c>−2⁰</c> term.</summary>
    private const int SparseSubtractLimbLow = 0;

    /// <summary>The limb where the specialized reduction subtracts <c>r</c> for the <c>−2²²⁴</c> term.</summary>
    private const int SparseSubtractLimbHigh = 7;

    /// <summary>The limb where the specialized reduction adds <c>r</c> for the <c>+2⁹⁶</c> term (also the accum window start).</summary>
    private const int SparseAddLimbLow = 3;

    /// <summary>The limb where the specialized reduction adds <c>r</c> for the <c>+2¹⁹²</c> term.</summary>
    private const int SparseAddLimbMid = 6;

    /// <summary>The limb where the specialized reduction adds <c>r</c> for the <c>+2²⁵⁶</c> term.</summary>
    private const int SparseAddLimbHigh = 8;


    private static readonly Vector512<ulong> Low32Mask = Vector512.Create(0xFFFFFFFFUL);
    private static readonly Vector512<ulong> NPrime32Broadcast = Vector512.Create((ulong)Fp256MontgomeryParameters.NPrime32);
    private static readonly Vector512<ulong>[] Modulus32Broadcast = BuildBroadcast(Fp256MontgomeryParameters.Modulus32Limbs);


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


    private static Vector512<ulong>[] BuildBroadcast(ReadOnlySpan<uint> limbs32)
    {
        var vectors = new Vector512<ulong>[Limb32Count];
        for(int i = 0; i < Limb32Count; i++)
        {
            vectors[i] = Vector512.Create((ulong)limbs32[i]);
        }

        return vectors;
    }


    private static void BatchMultiplyMontgomery(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        BatchMultiply(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count, curve, useSpecializedReduce: false);
    }


    private static void BatchMultiplyMontgomerySpecializedReduce(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        BatchMultiply(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count, curve, useSpecializedReduce: true);
    }


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


    private static void LoadOctetTo32LimbVectors(ReadOnlySpan<byte> octetBytes, Span<Vector512<ulong>> limbVectors)
    {
        Span<uint> s = stackalloc uint[ElementsPerOctet * Limb32Count];
        int stride = ElementBytes;
        for(int scalarIndex = 0; scalarIndex < ElementsPerOctet; scalarIndex++)
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


    private static void Store32LimbVectorsToOctet(ReadOnlySpan<Vector512<ulong>> limbVectors, Span<byte> octetBytes)
    {
        int stride = ElementBytes;
        Span<uint> scalarLimbs = stackalloc uint[Limb32Count];
        for(int scalarIndex = 0; scalarIndex < ElementsPerOctet; scalarIndex++)
        {
            for(int k = 0; k < Limb32Count; k++)
            {
                scalarLimbs[k] = (uint)limbVectors[k].GetElement(scalarIndex);
            }

            StoreCanonicalFrom32Limbs(scalarLimbs, octetBytes.Slice(scalarIndex * stride, stride));
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
