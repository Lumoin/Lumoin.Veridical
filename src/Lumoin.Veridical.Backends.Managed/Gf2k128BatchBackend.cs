using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The batch and fused-multiply-accumulate arithmetic for <c>GF(2^128) = GF(2)[x] /
/// (x^128 + x^7 + x^2 + x + 1)</c> — the binary field the Longfellow hash side runs over. It is the
/// vectorised counterpart of the per-scalar <see cref="Gf2k128Backend"/>: the same modulus,
/// reduction constant <c>0x87</c>, and canonical 32-byte big-endian slots (GF(2^128) in the low
/// sixteen bytes), exposed through the established batch-delegate seam plus the fused-multiply-
/// accumulate, broadcast, gather, and butterfly primitives.
/// </summary>
/// <remarks>
/// <para>
/// Two structural choices port the longfellow-zk reference's <c>lib/gf2k/sysdep.h</c>:
/// </para>
/// <list type="number">
///   <item><description>
///     <b>Packed two-<see cref="ulong"/> hot representation.</b> Internally an element is the pair
///     <c>(high, low)</c> of 64-bit limbs (the reference's <c>gf2_128_elt_t</c> is the 128-bit
///     value, never a 32-byte slot). The 32-byte canonical slots are unpacked into limbs once on
///     entry to a batch op and packed back once on exit — the conversion is at the field boundary
///     of the call, not per multiply.
///   </description></item>
///   <item><description>
///     <b>Deferred reduction.</b> The dot-product loops accumulate the unreduced carry-less
///     products in a three-lane accumulator (<see cref="Accumulator"/>, the reference's
///     <c>gf2_128_accum_t = std::array&lt;gf2_128_elt_t, 3&gt;</c>) and apply the <c>0x87</c> fold
///     once at the end (<see cref="AccumulateReduce"/>, the reference's <c>gf2_128_accum_reduce</c>),
///     not once per multiply. Reduction is GF(2)-linear, so reducing the XOR-sum of the unreduced
///     products equals XOR-summing the per-product reductions — the deferral is byte-identical to a
///     naive multiply-then-add-then-reduce loop, the gate the agreement tests pin.
///   </description></item>
/// </list>
/// <para>
/// Each 64×64→128 carry-less product is PCLMULQDQ on x86, the ARM PMULL (vmull_p64) intrinsic on
/// AArch64 (<see cref="CarrylessMultiply64"/>), the shared 4-bit-window software path
/// (<see cref="Gf2k128Backend.SoftwareCarrylessMultiply64"/>) otherwise. The paths are
/// byte-identical and all gated by the agreement tests.
/// </para>
/// </remarks>
public static class Gf2k128BatchBackend
{
    private const int ScalarSize = 32;
    private const int ElementOffset = 16;
    private const int LimbSize = 8;

    //The reduction constant for x^128 ≡ x^7 + x^2 + x + 1 (longfellow-zk lib/gf2k modulus).
    private const ulong ReductionPolynomial = 0x87;


    /// <summary>Returns the batched carry-less multiply delegate (<c>result[i] = a[i]·b[i]</c>).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarBatchMultiplyDelegate GetBatchMultiply() => BatchMultiply;

    /// <summary>Returns the batched add delegate (element-wise XOR).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarBatchAddDelegate GetBatchAdd() => BatchAdd;

    /// <summary>Returns the batched subtract delegate (element-wise XOR — characteristic two).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarBatchSubtractDelegate GetBatchSubtract() => BatchSubtract;

    /// <summary>Returns the fused multiply-accumulate delegate (<c>acc[i] += a[i]·b[i]</c>, deferred reduction).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarBatchMultiplyAccumulateDelegate GetBatchMultiplyAccumulate() => BatchMultiplyAccumulate;

    /// <summary>Returns the broadcast-scalar fused multiply-accumulate delegate (<c>acc[i] += scalar·b[i]</c>).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarBroadcastMultiplyAccumulateDelegate GetBroadcastMultiplyAccumulate() => BroadcastMultiplyAccumulate;

    /// <summary>Returns the indexed (gather/scatter) fused multiply-accumulate delegate.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarGatherMultiplyAccumulateDelegate GetGatherMultiplyAccumulate() => GatherMultiplyAccumulate;

    /// <summary>Returns the LCH14 forward-butterfly batch delegate.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static Gf2kButterflyBatchDelegate GetButterflyBatch() => ButterflyBatch;

    /// <summary>Returns the fused <c>bind_quad</c> per-term reduce delegate (three reduced multiplies per term, XOR-accumulated).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarBindQuadReduceDelegate GetBindQuadReduce() => BindQuadReduce;


    private static void BatchAdd(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchAdd, curve, count);
        ValidatePairBuffers(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count);

        for(int i = 0; i < count; i++)
        {
            int offset = i * ScalarSize;
            (ulong leftHigh, ulong leftLow) = Unpack(leftOperandsConcatenated.Slice(offset, ScalarSize));
            (ulong rightHigh, ulong rightLow) = Unpack(rightOperandsConcatenated.Slice(offset, ScalarSize));
            Pack(leftHigh ^ rightHigh, leftLow ^ rightLow, resultsConcatenated.Slice(offset, ScalarSize));
        }
    }


    private static void BatchSubtract(
        ReadOnlySpan<byte> minuendsConcatenated,
        ReadOnlySpan<byte> subtrahendsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        //Subtraction is XOR in characteristic two; it counts as a batch-subtract.
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchSubtract, curve, count);
        ValidatePairBuffers(minuendsConcatenated, subtrahendsConcatenated, resultsConcatenated, count);

        for(int i = 0; i < count; i++)
        {
            int offset = i * ScalarSize;
            (ulong minuendHigh, ulong minuendLow) = Unpack(minuendsConcatenated.Slice(offset, ScalarSize));
            (ulong subtrahendHigh, ulong subtrahendLow) = Unpack(subtrahendsConcatenated.Slice(offset, ScalarSize));
            Pack(minuendHigh ^ subtrahendHigh, minuendLow ^ subtrahendLow, resultsConcatenated.Slice(offset, ScalarSize));
        }
    }


    private static void BatchMultiply(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchMultiply, curve, count);
        ValidatePairBuffers(leftOperandsConcatenated, rightOperandsConcatenated, resultsConcatenated, count);

        for(int i = 0; i < count; i++)
        {
            int offset = i * ScalarSize;
            (ulong leftHigh, ulong leftLow) = Unpack(leftOperandsConcatenated.Slice(offset, ScalarSize));
            (ulong rightHigh, ulong rightLow) = Unpack(rightOperandsConcatenated.Slice(offset, ScalarSize));

            //One product reduces immediately: a single-element accumulator reduce is the same
            //two-stage fold the per-scalar backend does, so plain batch-multiply stays byte-exact.
            Accumulator accumulator = default;
            MultiplyAccumulate(ref accumulator, leftHigh, leftLow, rightHigh, rightLow);
            (ulong resultHigh, ulong resultLow) = AccumulateReduce(accumulator);
            Pack(resultHigh, resultLow, resultsConcatenated.Slice(offset, ScalarSize));
        }
    }


    private static void BatchMultiplyAccumulate(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> accumulatorsConcatenated,
        bool accumulate,
        int count,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchMultiplyAccumulate, curve, count);
        ValidatePairBuffers(leftOperandsConcatenated, rightOperandsConcatenated, accumulatorsConcatenated, count);

        for(int i = 0; i < count; i++)
        {
            int offset = i * ScalarSize;
            (ulong leftHigh, ulong leftLow) = Unpack(leftOperandsConcatenated.Slice(offset, ScalarSize));
            (ulong rightHigh, ulong rightLow) = Unpack(rightOperandsConcatenated.Slice(offset, ScalarSize));

            //Each output slot is independent here (sequential FMA), so the deferral spans exactly
            //the one product going into this slot; the reference's three-lane accumulator still
            //applies — the win over a per-call multiply is the single reduce plus the packed limbs.
            Accumulator accumulator = default;
            MultiplyAccumulate(ref accumulator, leftHigh, leftLow, rightHigh, rightLow);
            (ulong productHigh, ulong productLow) = AccumulateReduce(accumulator);

            Span<byte> slot = accumulatorsConcatenated.Slice(offset, ScalarSize);
            if(accumulate)
            {
                (ulong existingHigh, ulong existingLow) = Unpack(slot);
                Pack(existingHigh ^ productHigh, existingLow ^ productLow, slot);
            }
            else
            {
                Pack(productHigh, productLow, slot);
            }
        }
    }


    private static void BroadcastMultiplyAccumulate(
        ReadOnlySpan<byte> scalar,
        ReadOnlySpan<byte> operandsConcatenated,
        Span<byte> accumulatorsConcatenated,
        bool accumulate,
        int count,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchMultiplyAccumulate, curve, count);
        if(scalar.Length != ScalarSize)
        {
            throw new ArgumentException($"The broadcast scalar must be exactly {ScalarSize} bytes.", nameof(scalar));
        }

        ValidateSpanBuffers(operandsConcatenated, accumulatorsConcatenated, count);

        //The shared multiplier's limbs are read once and reused across the whole span.
        (ulong scalarHigh, ulong scalarLow) = Unpack(scalar);
        for(int i = 0; i < count; i++)
        {
            int offset = i * ScalarSize;
            (ulong operandHigh, ulong operandLow) = Unpack(operandsConcatenated.Slice(offset, ScalarSize));

            Accumulator accumulator = default;
            MultiplyAccumulate(ref accumulator, scalarHigh, scalarLow, operandHigh, operandLow);
            (ulong productHigh, ulong productLow) = AccumulateReduce(accumulator);

            Span<byte> slot = accumulatorsConcatenated.Slice(offset, ScalarSize);
            if(accumulate)
            {
                (ulong existingHigh, ulong existingLow) = Unpack(slot);
                Pack(existingHigh ^ productHigh, existingLow ^ productLow, slot);
            }
            else
            {
                Pack(productHigh, productLow, slot);
            }
        }
    }


    private static void GatherMultiplyAccumulate(
        ReadOnlySpan<byte> coefficientsConcatenated,
        ReadOnlySpan<byte> dataConcatenated,
        ReadOnlySpan<int> inputIndices,
        ReadOnlySpan<int> outputIndices,
        Span<byte> accumulatorsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchMultiplyAccumulate, curve, count);
        if(coefficientsConcatenated.Length != count * ScalarSize)
        {
            throw new ArgumentException($"The coefficient buffer must be exactly {count} * {ScalarSize} bytes for count = {count}.", nameof(coefficientsConcatenated));
        }

        if(inputIndices.Length != count || outputIndices.Length != count)
        {
            throw new ArgumentException($"The index spans must each have length {count}.");
        }

        //A run's reduced sum is written before later runs gather their inputs, so an accumulator slot
        //aliasing a data slot would feed a corrupted value forward. The contract forbids the overlap;
        //rejecting it here turns silent wrong bytes into a caller error at one pointer check per call.
        if(accumulatorsConcatenated.Overlaps(dataConcatenated) || accumulatorsConcatenated.Overlaps(coefficientsConcatenated))
        {
            throw new ArgumentException("The accumulator span must not overlap the data or coefficient spans.", nameof(accumulatorsConcatenated));
        }

        //Terms scattering to one output slot in a consecutive run — the dot-product shape — keep
        //their carry-less products unreduced in the three-lane accumulator across the whole run and
        //fold once when the slot changes (the reference's gf2_128_mac / gf2_128_accum_reduce
        //discipline). Reduction is GF(2)-linear, so the deferral is byte-identical to reducing
        //every product.
        int k = 0;
        while(k < count)
        {
            int slotIndex = outputIndices[k];
            Accumulator accumulator = default;
            do
            {
                (ulong coefficientHigh, ulong coefficientLow) = Unpack(coefficientsConcatenated.Slice(k * ScalarSize, ScalarSize));
                (ulong dataHigh, ulong dataLow) = Unpack(dataConcatenated.Slice(inputIndices[k] * ScalarSize, ScalarSize));
                MultiplyAccumulate(ref accumulator, coefficientHigh, coefficientLow, dataHigh, dataLow);
                k++;
            }
            while(k < count && outputIndices[k] == slotIndex);

            (ulong runHigh, ulong runLow) = AccumulateReduce(accumulator);
            Span<byte> slot = accumulatorsConcatenated.Slice(slotIndex * ScalarSize, ScalarSize);
            (ulong existingHigh, ulong existingLow) = Unpack(slot);
            Pack(existingHigh ^ runHigh, existingLow ^ runLow, slot);
        }
    }


    private static void ButterflyBatch(
        ReadOnlySpan<byte> twiddle,
        Span<byte> lowConcatenated,
        Span<byte> highConcatenated,
        int stride,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchMultiplyAccumulate, curve, stride);
        if(twiddle.Length != ScalarSize)
        {
            throw new ArgumentException($"The twiddle must be exactly {ScalarSize} bytes.", nameof(twiddle));
        }

        if(lowConcatenated.Length != stride * ScalarSize || highConcatenated.Length != stride * ScalarSize)
        {
            throw new ArgumentException($"The low and high halves must each be exactly {stride} * {ScalarSize} bytes for stride = {stride}.");
        }

        //The twiddle is broadcast once for the whole group.
        (ulong twiddleHigh, ulong twiddleLow) = Unpack(twiddle);
        for(int offset = 0; offset < stride; offset++)
        {
            int byteOffset = offset * ScalarSize;
            Span<byte> lowSlot = lowConcatenated.Slice(byteOffset, ScalarSize);
            Span<byte> highSlot = highConcatenated.Slice(byteOffset, ScalarSize);

            (ulong lowHigh, ulong lowLow) = Unpack(lowSlot);
            (ulong highHigh, ulong highLow) = Unpack(highSlot);

            //low += twiddle·high  (reduced product XORed into the low element).
            Accumulator accumulator = default;
            MultiplyAccumulate(ref accumulator, twiddleHigh, twiddleLow, highHigh, highLow);
            (ulong productHigh, ulong productLow) = AccumulateReduce(accumulator);
            ulong newLowHigh = lowHigh ^ productHigh;
            ulong newLowLow = lowLow ^ productLow;

            //high += low  (the just-updated low; characteristic-two XOR).
            ulong newHighHigh = highHigh ^ newLowHigh;
            ulong newHighLow = highLow ^ newLowLow;

            Pack(newLowHigh, newLowLow, lowSlot);
            Pack(newHighHigh, newHighLow, highSlot);
        }
    }


    private static void BindQuadReduce(
        ReadOnlySpan<byte> coefficientTable,
        ReadOnlySpan<int> coefficientIndices,
        ReadOnlySpan<byte> beta,
        ReadOnlySpan<byte> eqgConcatenated,
        ReadOnlySpan<byte> eqh0Concatenated,
        ReadOnlySpan<byte> eqh1Concatenated,
        ReadOnlySpan<int> gateIndices,
        ReadOnlySpan<int> leftIndices,
        ReadOnlySpan<int> rightIndices,
        ReadOnlySpan<byte> isZeroFlags,
        int count,
        Span<byte> accumulator,
        CurveParameterSet curve)
    {
        //Three reduced multiplies per term: the telemetry rolls them all into the FMA kind.
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchMultiplyAccumulate, curve, (long)count * 3);
        if(coefficientIndices.Length != count || gateIndices.Length != count || leftIndices.Length != count || rightIndices.Length != count || isZeroFlags.Length != count)
        {
            throw new ArgumentException($"The index and flag spans must each have length {count}.");
        }

        if(beta.Length != ScalarSize)
        {
            throw new ArgumentException($"The beta slot must be exactly {ScalarSize} bytes.", nameof(beta));
        }

        //beta is unpacked once; the assert-zero terms reuse its limbs without re-reading the slot.
        (ulong betaHigh, ulong betaLow) = Unpack(beta);

        ulong accHigh = 0;
        ulong accLow = 0;
        for(int k = 0; k < count; k++)
        {
            //prep_v: the v == 0 decision selects beta, otherwise the term's deduped coefficient.
            ulong scaledHigh;
            ulong scaledLow;
            if(isZeroFlags[k] != 0)
            {
                scaledHigh = betaHigh;
                scaledLow = betaLow;
            }
            else
            {
                (scaledHigh, scaledLow) = Unpack(coefficientTable.Slice(coefficientIndices[k] * ScalarSize, ScalarSize));
            }

            //The four-way chained product: each factor reduces to a canonical element before the next
            //carry-less multiply consumes it (reduce(a)·b != reduce(a·b) for the limb representation), so
            //the fold is applied once per multiply and never deferred across the chain.
            (ulong eqgHigh, ulong eqgLow) = Unpack(eqgConcatenated.Slice(gateIndices[k] * ScalarSize, ScalarSize));
            (ulong chainHigh, ulong chainLow) = MultiplyReduceOnce(scaledHigh, scaledLow, eqgHigh, eqgLow);

            (ulong eqh0High, ulong eqh0Low) = Unpack(eqh0Concatenated.Slice(leftIndices[k] * ScalarSize, ScalarSize));
            (chainHigh, chainLow) = MultiplyReduceOnce(chainHigh, chainLow, eqh0High, eqh0Low);

            (ulong eqh1High, ulong eqh1Low) = Unpack(eqh1Concatenated.Slice(rightIndices[k] * ScalarSize, ScalarSize));
            (chainHigh, chainLow) = MultiplyReduceOnce(chainHigh, chainLow, eqh1High, eqh1Low);

            //The cross-term accumulation is XOR (GF add).
            accHigh ^= chainHigh;
            accLow ^= chainLow;
        }

        //Read-modify-write the caller's accumulator slot (XOR is GF add into the existing contents).
        (ulong existingHigh, ulong existingLow) = Unpack(accumulator);
        Pack(existingHigh ^ accHigh, existingLow ^ accLow, accumulator);
    }


    //One full GF(2^128) multiply with the 0x87 fold applied immediately: the same single-product
    //reduce the batch multiply uses (one MultiplyAccumulate + one AccumulateReduce), pinned
    //byte-identical to the scalar backend multiply by the BatchMultiply agreement gate.
    private static (ulong High, ulong Low) MultiplyReduceOnce(ulong leftHigh, ulong leftLow, ulong rightHigh, ulong rightLow)
    {
        Accumulator accumulator = default;
        MultiplyAccumulate(ref accumulator, leftHigh, leftLow, rightHigh, rightLow);

        return AccumulateReduce(accumulator);
    }


    /// <summary>
    /// The forced-software twin of <see cref="GetBindQuadReduce"/>: the same four-way chained per-term
    /// product with the reduction applied once per multiply, but every 64×64 carry-less multiply driven
    /// through the portable software path (<see cref="Gf2k128Backend.SoftwareCarrylessMultiply64"/>),
    /// never PCLMULQDQ/PMULL. Public so the agreement test can gate the software CLMUL tier on hardware
    /// that would otherwise always take the intrinsic, mirroring <see cref="SoftwareMultiplyReduce"/>.
    /// </summary>
    /// <param name="coefficientTable">The distinct term coefficients, canonical 32-byte slots.</param>
    /// <param name="coefficientIndices">Length <paramref name="count"/>; indexes <paramref name="coefficientTable"/>.</param>
    /// <param name="beta">One canonical 32-byte slot, the assert-zero coefficient.</param>
    /// <param name="eqgConcatenated">The <c>eqg</c> table; <paramref name="gateIndices"/> selects per term.</param>
    /// <param name="eqh0Concatenated">The <c>eqh0</c> table; <paramref name="leftIndices"/> selects per term.</param>
    /// <param name="eqh1Concatenated">The <c>eqh1</c> table; <paramref name="rightIndices"/> selects per term.</param>
    /// <param name="gateIndices">Length <paramref name="count"/>; indexes <paramref name="eqgConcatenated"/>.</param>
    /// <param name="leftIndices">Length <paramref name="count"/>; indexes <paramref name="eqh0Concatenated"/>.</param>
    /// <param name="rightIndices">Length <paramref name="count"/>; indexes <paramref name="eqh1Concatenated"/>.</param>
    /// <param name="isZeroFlags">Length <paramref name="count"/>; a non-zero byte selects <paramref name="beta"/>.</param>
    /// <param name="count">The number of terms.</param>
    /// <param name="accumulator">One canonical 32-byte slot, XOR-accumulated (caller-cleared, read-modify-write).</param>
    /// <param name="curve">Identifies the field.</param>
    public static void SoftwareBindQuadReduce(
        ReadOnlySpan<byte> coefficientTable,
        ReadOnlySpan<int> coefficientIndices,
        ReadOnlySpan<byte> beta,
        ReadOnlySpan<byte> eqgConcatenated,
        ReadOnlySpan<byte> eqh0Concatenated,
        ReadOnlySpan<byte> eqh1Concatenated,
        ReadOnlySpan<int> gateIndices,
        ReadOnlySpan<int> leftIndices,
        ReadOnlySpan<int> rightIndices,
        ReadOnlySpan<byte> isZeroFlags,
        int count,
        Span<byte> accumulator,
        CurveParameterSet curve)
    {
        if(coefficientIndices.Length != count || gateIndices.Length != count || leftIndices.Length != count || rightIndices.Length != count || isZeroFlags.Length != count)
        {
            throw new ArgumentException($"The index and flag spans must each have length {count}.");
        }

        if(beta.Length != ScalarSize)
        {
            throw new ArgumentException($"The beta slot must be exactly {ScalarSize} bytes.", nameof(beta));
        }

        (ulong betaHigh, ulong betaLow) = Unpack(beta);

        ulong accHigh = 0;
        ulong accLow = 0;
        for(int k = 0; k < count; k++)
        {
            ulong scaledHigh;
            ulong scaledLow;
            if(isZeroFlags[k] != 0)
            {
                scaledHigh = betaHigh;
                scaledLow = betaLow;
            }
            else
            {
                (scaledHigh, scaledLow) = Unpack(coefficientTable.Slice(coefficientIndices[k] * ScalarSize, ScalarSize));
            }

            (ulong eqgHigh, ulong eqgLow) = Unpack(eqgConcatenated.Slice(gateIndices[k] * ScalarSize, ScalarSize));
            (ulong chainHigh, ulong chainLow) = SoftwareMultiplyReduce(scaledHigh, scaledLow, eqgHigh, eqgLow);

            (ulong eqh0High, ulong eqh0Low) = Unpack(eqh0Concatenated.Slice(leftIndices[k] * ScalarSize, ScalarSize));
            (chainHigh, chainLow) = SoftwareMultiplyReduce(chainHigh, chainLow, eqh0High, eqh0Low);

            (ulong eqh1High, ulong eqh1Low) = Unpack(eqh1Concatenated.Slice(rightIndices[k] * ScalarSize, ScalarSize));
            (chainHigh, chainLow) = SoftwareMultiplyReduce(chainHigh, chainLow, eqh1High, eqh1Low);

            accHigh ^= chainHigh;
            accLow ^= chainLow;
        }

        (ulong existingHigh, ulong existingLow) = Unpack(accumulator);
        Pack(existingHigh ^ accHigh, existingLow ^ accLow, accumulator);
    }


    //The three-lane unreduced accumulator: the reference's gf2_128_accum_t. Each lane is one
    //128-bit value as (High, Low) limbs. Lane 0 holds the weight-1 products, lane 1 the
    //weight-x^64 (middle) products, lane 2 the weight-x^128 (top) products — all XOR-accumulated
    //without reduction. The 0x87 fold is applied once, in AccumulateReduce.
    private struct Accumulator
    {
        public ulong Lane0High;
        public ulong Lane0Low;
        public ulong Lane1High;
        public ulong Lane1Low;
        public ulong Lane2High;
        public ulong Lane2Low;
    }


    //gf2_128_mac: the four 64×64 carry-less halves of x·y, XOR-accumulated into the three lanes
    //WITHOUT reducing. t0 = xLo·yLo (weight 1), t1 = xLo·yHi ⊕ xHi·yLo (weight x^64),
    //t2 = xHi·yHi (weight x^128).
    private static void MultiplyAccumulate(ref Accumulator accumulator, ulong leftHigh, ulong leftLow, ulong rightHigh, ulong rightLow)
    {
        (ulong t0High, ulong t0Low) = CarrylessMultiply64(leftLow, rightLow);
        (ulong t1aHigh, ulong t1aLow) = CarrylessMultiply64(leftLow, rightHigh);
        (ulong t1bHigh, ulong t1bLow) = CarrylessMultiply64(leftHigh, rightLow);
        (ulong t2High, ulong t2Low) = CarrylessMultiply64(leftHigh, rightHigh);

        accumulator.Lane0High ^= t0High;
        accumulator.Lane0Low ^= t0Low;
        accumulator.Lane1High ^= t1aHigh ^ t1bHigh;
        accumulator.Lane1Low ^= t1aLow ^ t1bLow;
        accumulator.Lane2High ^= t2High;
        accumulator.Lane2Low ^= t2Low;
    }


    //gf2_128_accum_reduce: fold the three unreduced lanes down to one GF(2^128) element with the
    //two-stage 0x87 reduction. Reduce(lane1, lane2) then Reduce(lane0, that).
    private static (ulong High, ulong Low) AccumulateReduce(Accumulator accumulator)
    {
        (ulong t1High, ulong t1Low) = Reduce(accumulator.Lane1High, accumulator.Lane1Low, accumulator.Lane2High, accumulator.Lane2Low);

        return Reduce(accumulator.Lane0High, accumulator.Lane0Low, t1High, t1Low);
    }


    //gf2_128_reduce: returns the 128-bit value lowValue ⊕ x^64·highValue, folded modulo the poly.
    //Shifting `high` left by 64 bits inside the 128-bit register moves its low limb to the high
    //position (its high limb spills out); the spilled high limb times 0x87 is the carry that folds
    //back. Mirrors the reference's _mm_slli_si128(t1, 8) ⊕ _mm_clmulepi64_si128(t1, poly, 0x01).
    private static (ulong High, ulong Low) Reduce(ulong lowValueHigh, ulong lowValueLow, ulong highValueHigh, ulong highValueLow)
    {
        (ulong carryHigh, ulong carryLow) = CarrylessMultiply64(highValueHigh, ReductionPolynomial);

        ulong resultLow = lowValueLow ^ carryLow;
        ulong resultHigh = lowValueHigh ^ highValueLow ^ carryHigh;

        return (resultHigh, resultLow);
    }


    //One 64×64 carry-less multiply: PCLMULQDQ on x86, the ARM PMULL (vmull_p64) intrinsic on
    //AArch64, the shared 4-bit-window software path otherwise. The paths are gated byte-identical
    //by the agreement tests.
    private static (ulong High, ulong Low) CarrylessMultiply64(ulong a, ulong b)
    {
        if(Pclmulqdq.IsSupported)
        {
            Vector128<ulong> product = Pclmulqdq.CarrylessMultiply(Vector128.CreateScalar(a), Vector128.CreateScalar(b), 0x00);

            return (product.GetElement(1), product.GetElement(0));
        }
        else if(System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            //PolynomialMultiplyWideningLower is vmull_p64 (A64 PMULL Vd.1Q, Vn.1D, Vm.1D): the
            //64×64→128-bit carry-less product of the low lanes, the analog of PCLMULQDQ selector
            //0x00. The Vector128<ulong> lane order matches the x86 path — element 0 is the low 64
            //bits, element 1 the high 64 bits — so the (High, Low) mapping is identical.
            Vector128<ulong> product = System.Runtime.Intrinsics.Arm.Aes.PolynomialMultiplyWideningLower(Vector64.CreateScalar(a), Vector64.CreateScalar(b));

            return (product.GetElement(1), product.GetElement(0));
        }

        return Gf2k128Backend.SoftwareCarrylessMultiply64(a, b);
    }


    /// <summary>
    /// The single full <c>GF(2^128)</c> multiply driven entirely through the portable software
    /// 64×64 carry-less path and the deferred-reduction accumulator — the same lanes and fold the
    /// batch FMA uses, but never touching PCLMULQDQ. Public so the agreement tests can gate the
    /// software path on hardware that would otherwise always take the intrinsic, mirroring
    /// <see cref="Gf2k128Backend.SoftwareCarrylessMultiply64"/>.
    /// </summary>
    /// <param name="leftHigh">The left operand's high limb.</param>
    /// <param name="leftLow">The left operand's low limb.</param>
    /// <param name="rightHigh">The right operand's high limb.</param>
    /// <param name="rightLow">The right operand's low limb.</param>
    /// <returns>The reduced product limbs, high then low.</returns>
    public static (ulong High, ulong Low) SoftwareMultiplyReduce(ulong leftHigh, ulong leftLow, ulong rightHigh, ulong rightLow)
    {
        (ulong t0High, ulong t0Low) = Gf2k128Backend.SoftwareCarrylessMultiply64(leftLow, rightLow);
        (ulong t1aHigh, ulong t1aLow) = Gf2k128Backend.SoftwareCarrylessMultiply64(leftLow, rightHigh);
        (ulong t1bHigh, ulong t1bLow) = Gf2k128Backend.SoftwareCarrylessMultiply64(leftHigh, rightLow);
        (ulong t2High, ulong t2Low) = Gf2k128Backend.SoftwareCarrylessMultiply64(leftHigh, rightHigh);

        var accumulator = new Accumulator
        {
            Lane0High = t0High,
            Lane0Low = t0Low,
            Lane1High = t1aHigh ^ t1bHigh,
            Lane1Low = t1aLow ^ t1bLow,
            Lane2High = t2High,
            Lane2Low = t2Low,
        };

        return AccumulateReduce(accumulator);
    }


    /// <summary>
    /// Unpacks one canonical 32-byte big-endian slot into the packed <c>(High, Low)</c> limb pair —
    /// the GF(2^128) value living in the low sixteen bytes. The conversion the batch ops do once on
    /// entry. Public so the round-trip property test can pin <c>pack→unpack</c> identity.
    /// </summary>
    /// <param name="bytes">A canonical 32-byte big-endian scalar slot.</param>
    /// <returns>The two 64-bit limbs, high then low.</returns>
    public static (ulong High, ulong Low) Unpack(ReadOnlySpan<byte> bytes) =>
        (BinaryPrimitives.ReadUInt64BigEndian(bytes.Slice(ElementOffset, LimbSize)),
         BinaryPrimitives.ReadUInt64BigEndian(bytes.Slice(ElementOffset + LimbSize, LimbSize)));


    /// <summary>
    /// Packs the <c>(High, Low)</c> limb pair back into a canonical 32-byte big-endian slot, the
    /// high sixteen bytes cleared to zero. The conversion the batch ops do once on exit. Public so
    /// the round-trip property test can pin <c>pack→unpack</c> identity.
    /// </summary>
    /// <param name="high">The high 64-bit limb.</param>
    /// <param name="low">The low 64-bit limb.</param>
    /// <param name="destination">The canonical 32-byte slot to write.</param>
    public static void Pack(ulong high, ulong low, Span<byte> destination)
    {
        destination[..ElementOffset].Clear();
        BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(ElementOffset, LimbSize), high);
        BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(ElementOffset + LimbSize, LimbSize), low);
    }


    private static void ValidatePairBuffers(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, ReadOnlySpan<byte> result, int count)
    {
        if(left.Length != count * ScalarSize || right.Length != count * ScalarSize || result.Length != count * ScalarSize)
        {
            throw new ArgumentException($"Batched GF(2^128) buffers must each be exactly {count} * {ScalarSize} bytes for count = {count}.");
        }
    }


    private static void ValidateSpanBuffers(ReadOnlySpan<byte> operands, ReadOnlySpan<byte> accumulators, int count)
    {
        if(operands.Length != count * ScalarSize || accumulators.Length != count * ScalarSize)
        {
            throw new ArgumentException($"The operand and accumulator buffers must each be exactly {count} * {ScalarSize} bytes for count = {count}.");
        }
    }
}
