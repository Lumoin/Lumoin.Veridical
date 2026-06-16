using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// AVX2 lane-parallel batch backend for the P-256 base field Fp256
/// <see cref="ScalarBatchMultiplyDelegate"/>, the Fp256 mirror of the 32-bit-limb CIOS
/// batch-multiply region of <see cref="Bn254Avx2ScalarBackend"/>. It runs four
/// independent Montgomery-domain multiplies per AVX2 quartet (one per 64-bit lane),
/// each 32×32→64 partial product a single <c>vpmuludq</c>, and agrees byte-for-byte
/// with the scalar single-CIOS <see cref="P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery"/>.
/// </summary>
/// <remarks>
/// <para>
/// The public op is a <em>single-CIOS Montgomery-domain</em> multiply: both operands are
/// Montgomery residues (<c>aR</c>, <c>bR mod p</c>), and one CIOS yields
/// <c>abR mod p = mont(ab)</c> — matching <see cref="P256BaseFieldMontgomeryBackend.MultiplyMontgomery"/>
/// residue-in/residue-out. There is deliberately no <c>R²</c> lift (that would emit the
/// canonical <c>a·b mod p</c>, off by <c>R⁻¹</c>); the quartet calls
/// <see cref="MontgomeryMultiplyQuartet"/> once and nothing more.
/// </para>
/// <para>
/// Internal representation is eight little-endian 32-bit limbs per lane, transposed
/// lane-major. <c>R = 2²⁵⁶</c> in both radix-32 (eight limbs) and the scalar radix-64
/// (four limbs), so the Montgomery residue is identical across the two. The conditional
/// subtraction at the end of the kernel is a single constant-time
/// <see cref="Avx2.BlendVariable(Vector256{byte}, Vector256{byte}, Vector256{byte})"/>,
/// so the wrong branch's bits never enter the result. Correctness is pinned by the AVX2
/// agreement gate against the scalar single-CIOS <see cref="P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery"/>.
/// </para>
/// <para>
/// Two CIOS reduction sub-steps live here and produce the identical final Montgomery residue.
/// The live path, <see cref="MontgomeryMultiplyQuartetGenericReduce"/> reached through
/// <see cref="GetBatchMultiplyMontgomery"/>, forms the per-step term <c>r·p</c> through the full
/// <c>m·Modulus32[j]</c> product (the textbook generic Montgomery reduction). The alternative path,
/// <see cref="MontgomeryMultiplyQuartet"/> reached through
/// <see cref="GetBatchMultiplyMontgomerySpecializedReduce"/>, uses the P-256-specialized reduction:
/// because <c>p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1</c> is signed-sparse, the same <c>r·p</c> (with quotient
/// digit <c>r = t[0]</c>, since <c>N'32 = 1</c>) is added by subtracting <c>r</c> at limbs {0, 7} and
/// adding <c>r</c> at limbs {3, 6, 8} with borrow/carry propagation — no multiply by the modulus. It is
/// retained for comparison (see <see cref="MontgomeryMultiplyQuartet"/> for why the generic form is live).
/// Both mirror <c>Fp256Reduce</c> in <c>lib/algebra/fp_p256.h</c> / <c>fp_generic.h</c> respectively.
/// </para>
/// </remarks>
internal static class P256BaseFieldMontgomeryBatchBackendAvx2
{
    /// <summary>Indicates whether the host CPU supports the instructions this backend uses.</summary>
    public static bool IsSupported => Avx2.IsSupported;


    /// <summary>The number of canonical bytes per Fp256 element.</summary>
    private const int ElementBytes = Scalar.SizeBytes;

    /// <summary>The number of independent elements packed into one SIMD quartet (one per 64-bit lane of <see cref="Vector256{T}"/>).</summary>
    private const int ElementsPerQuartet = 4;

    /// <summary>The number of canonical bytes per quartet (four elements, each <see cref="Scalar.SizeBytes"/> bytes).</summary>
    private const int QuartetBytes = ElementsPerQuartet * ElementBytes;

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


    private static readonly Vector256<ulong> Low32Mask = Vector256.Create(0xFFFFFFFFUL);
    private static readonly Vector256<ulong> NPrime32Broadcast = Vector256.Create((ulong)Fp256MontgomeryParameters.NPrime32);
    private static readonly Vector256<ulong>[] Modulus32Broadcast = BuildBroadcast(Fp256MontgomeryParameters.Modulus32Limbs);


    /// <summary>
    /// Returns the lane-interleaved batched Montgomery-domain multiply delegate: a 32-bit-limb single-CIOS
    /// Montgomery multiply running four Montgomery residues per AVX2 quartet (one per 64-bit lane), with the
    /// generic <c>m·Modulus32</c> reduction (the live managed path). The trailing 1–3 elements fall back to the
    /// counter-free scalar single-CIOS core.
    /// </summary>
    public static ScalarBatchMultiplyDelegate GetBatchMultiplyMontgomery() => BatchMultiplyMontgomery;


    /// <summary>
    /// Returns the batched Montgomery-domain multiply delegate that reduces with the P-256-specialized
    /// signed-sparse CIOS step instead of the generic <c>m·Modulus32</c> step. It produces the identical final
    /// Montgomery residue as <see cref="GetBatchMultiplyMontgomery"/>; the agreement gate drives both against the
    /// same scalar oracle to pin that equivalence. Retained as the reference-faithful alternative (see
    /// <see cref="MontgomeryMultiplyQuartet"/>); the generic reduction is the live path.
    /// </summary>
    internal static ScalarBatchMultiplyDelegate GetBatchMultiplyMontgomerySpecializedReduce() => BatchMultiplyMontgomerySpecializedReduce;


    private static Vector256<ulong>[] BuildBroadcast(ReadOnlySpan<uint> limbs32)
    {
        var vectors = new Vector256<ulong>[Limb32Count];
        for(int i = 0; i < Limb32Count; i++)
        {
            vectors[i] = Vector256.Create((ulong)limbs32[i]);
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
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException("P256BaseFieldMontgomeryBatchBackendAvx2 requires AVX2; check IsSupported before wiring it as a delegate.");
        }

        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchMultiply, curve, count);

        int stride = ElementBytes;
        ValidateBatchedLengths(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count, stride);

        int quartets = count / ElementsPerQuartet;
        for(int quartetIndex = 0; quartetIndex < quartets; quartetIndex++)
        {
            int offset = quartetIndex * QuartetBytes;
            MultiplyQuartet(
                leftOperandsConcatenated.Slice(offset, QuartetBytes),
                rightOperandsConcatenated.Slice(offset, QuartetBytes),
                resultsConcatenated.Slice(offset, QuartetBytes),
                useSpecializedReduce);
        }

        int tailStart = quartets * QuartetBytes;
        int tailCount = count % ElementsPerQuartet;
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
    /// Multiplies four independent Montgomery residues in parallel: <c>result = a · b · R⁻¹ mod p</c>
    /// per lane via a single CIOS (no <c>R²</c> lift), which on residue inputs <c>aR, bR</c> yields
    /// <c>abR = mont(ab)</c>. The <paramref name="useSpecializedReduce"/> flag selects the
    /// P-256-specialized signed-sparse reduction or the generic <c>m·Modulus32</c> reduction; both yield
    /// the identical final residue.
    /// </summary>
    private static void MultiplyQuartet(
        ReadOnlySpan<byte> aQuartet,
        ReadOnlySpan<byte> bQuartet,
        Span<byte> resultQuartet,
        bool useSpecializedReduce)
    {
        Span<Vector256<ulong>> a = stackalloc Vector256<ulong>[Limb32Count];
        Span<Vector256<ulong>> b = stackalloc Vector256<ulong>[Limb32Count];
        Span<Vector256<ulong>> product = stackalloc Vector256<ulong>[Limb32Count];

        LoadQuartetTo32LimbVectors(aQuartet, a);
        LoadQuartetTo32LimbVectors(bQuartet, b);

        //SINGLE CIOS, residue-in/residue-out (aR·bR·R⁻¹ = abR = mont(ab)). Do NOT add an R²-lift here — that
        //emits the canonical a·b mod p, off by R⁻¹ from the scalar MultiplyMontgomery this must match
        //byte-for-byte.
        if(useSpecializedReduce)
        {
            MontgomeryMultiplyQuartet(a, b, product);
        }
        else
        {
            MontgomeryMultiplyQuartetGenericReduce(a, b, product);
        }

        Store32LimbVectorsToQuartet(product, resultQuartet);
    }


    /// <summary>
    /// Lane-parallel CIOS Montgomery multiply over 32-bit limbs with the P-256-specialized reduction, retained
    /// as the comparison alternative to the live generic <see cref="MontgomeryMultiplyQuartetGenericReduce"/>:
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
    private static void MontgomeryMultiplyQuartet(
        ReadOnlySpan<Vector256<ulong>> x,
        ReadOnlySpan<Vector256<ulong>> y,
        Span<Vector256<ulong>> result)
    {
        Span<Vector256<ulong>> t = stackalloc Vector256<ulong>[AccumulatorLimbCount];
        for(int k = 0; k < AccumulatorLimbCount; k++)
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

            SpecializedReduceStepQuartet(t, mask);
        }

        ConditionalSubtractModulusQuartet(t, result);
    }


    /// <summary>
    /// Adds <c>r·p</c> for <c>r = t[0]</c> via the signed-sparse form of <c>p</c> and shifts the accumulator
    /// window down one limb (the CIOS divide by <c>2³²</c>). Subtracts <c>r</c> at limbs {0, 7} with
    /// borrow propagation, then adds <c>r</c> at limbs {3, 6, 8} with carry propagation, both across the full
    /// <see cref="AccumulatorLimbCount"/>-limb window; limb 0 cancels to zero and the shift discards it.
    /// </summary>
    private static void SpecializedReduceStepQuartet(Span<Vector256<ulong>> t, Vector256<ulong> mask)
    {
        Vector256<ulong> r = t[0];

        //negaccum: subtract r at limbs {0, 7}, borrow up through the window. Borrow is the lane's sign bit of
        //the 64-bit difference (the >>63 pattern the conditional subtraction also uses).
        Vector256<ulong> borrow = Vector256<ulong>.Zero;
        for(int j = 0; j < AccumulatorLimbCount; j++)
        {
            Vector256<ulong> subtrahend = (j == SparseSubtractLimbLow || j == SparseSubtractLimbHigh) ? r : Vector256<ulong>.Zero;
            Vector256<ulong> difference = Avx2.Subtract(Avx2.Subtract(t[j], subtrahend), borrow);
            t[j] = Avx2.And(difference, mask);
            borrow = Avx2.ShiftRightLogical(difference, 63);
        }

        //accum: add r at limbs {3, 6, 8}, carry up through the window.
        Vector256<ulong> carry = Vector256<ulong>.Zero;
        for(int j = SparseAddLimbLow; j < AccumulatorLimbCount; j++)
        {
            Vector256<ulong> addend = (j == SparseAddLimbLow || j == SparseAddLimbMid || j == SparseAddLimbHigh) ? r : Vector256<ulong>.Zero;
            Vector256<ulong> sum = Avx2.Add(Avx2.Add(t[j], addend), carry);
            t[j] = Avx2.And(sum, mask);
            carry = Avx2.ShiftRightLogical(sum, 32);
        }

        //Shift the window down one limb (limb 0 is zero after the r@0 cancellation); top limb clears.
        for(int j = 1; j < AccumulatorLimbCount; j++)
        {
            t[j - 1] = t[j];
        }

        t[AccumulatorLimbCount - 1] = Vector256<ulong>.Zero;
    }


    /// <summary>
    /// Lane-parallel CIOS Montgomery multiply over 32-bit limbs with the generic <c>m·Modulus32</c>
    /// reduction: <c>result = x · y · R⁻¹ mod p</c> per lane, reduced once. Each outer step forms the quotient
    /// digit <c>m = t[0]·N'32 mod 2³²</c> and adds <c>m·p</c> through the full per-limb modulus product before
    /// shifting the window down. This is the textbook generic Montgomery reduction (the lane-parallel mirror
    /// of <c>FpGeneric</c>'s reduction), kept alongside <see cref="MontgomeryMultiplyQuartet"/> as the
    /// non-specialized reference; both produce the identical final residue.
    /// </summary>
    private static void MontgomeryMultiplyQuartetGenericReduce(
        ReadOnlySpan<Vector256<ulong>> x,
        ReadOnlySpan<Vector256<ulong>> y,
        Span<Vector256<ulong>> result)
    {
        Span<Vector256<ulong>> t = stackalloc Vector256<ulong>[AccumulatorLimbCount];
        for(int k = 0; k < AccumulatorLimbCount; k++)
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


    private static void LoadQuartetTo32LimbVectors(ReadOnlySpan<byte> quartetBytes, Span<Vector256<ulong>> limbVectors)
    {
        Span<uint> scalar0 = stackalloc uint[Limb32Count];
        Span<uint> scalar1 = stackalloc uint[Limb32Count];
        Span<uint> scalar2 = stackalloc uint[Limb32Count];
        Span<uint> scalar3 = stackalloc uint[Limb32Count];

        int stride = ElementBytes;
        LoadCanonicalTo32Limbs(quartetBytes.Slice(0 * stride, stride), scalar0);
        LoadCanonicalTo32Limbs(quartetBytes.Slice(1 * stride, stride), scalar1);
        LoadCanonicalTo32Limbs(quartetBytes.Slice(2 * stride, stride), scalar2);
        LoadCanonicalTo32Limbs(quartetBytes.Slice(3 * stride, stride), scalar3);

        for(int k = 0; k < Limb32Count; k++)
        {
            limbVectors[k] = Vector256.Create((ulong)scalar0[k], scalar1[k], scalar2[k], scalar3[k]);
        }
    }


    private static void Store32LimbVectorsToQuartet(ReadOnlySpan<Vector256<ulong>> limbVectors, Span<byte> quartetBytes)
    {
        int stride = ElementBytes;
        Span<uint> scalarLimbs = stackalloc uint[Limb32Count];
        for(int scalarIndex = 0; scalarIndex < ElementsPerQuartet; scalarIndex++)
        {
            for(int k = 0; k < Limb32Count; k++)
            {
                scalarLimbs[k] = (uint)limbVectors[k].GetElement(scalarIndex);
            }

            StoreCanonicalFrom32Limbs(scalarLimbs, quartetBytes.Slice(scalarIndex * stride, stride));
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
