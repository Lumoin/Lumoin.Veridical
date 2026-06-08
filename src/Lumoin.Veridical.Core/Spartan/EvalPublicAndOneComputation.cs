using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Pure helper computing the MLE evaluation of
/// <c>z_PublicAndU = (u, public_inputs, 0, 0, ..., 0)</c> padded to
/// length <c>n</c> at the column-side challenge point <c>r_y</c>. The
/// verifier uses this to reconcile <c>eval_W</c> against the inner-
/// sumcheck's terminating evaluation: <c>eval_Z = eval_W + eval_PublicAndU</c>
/// by multilinear-extension linearity, where <c>z = (u, public, witness)</c>
/// is the relaxed assignment vector (the constant slot holds the
/// relaxation scalar <c>u</c>, not literal 1; for a raw-prepared
/// instance <c>u = 1</c> and the two coincide).
/// </summary>
/// <remarks>
/// <para>
/// The computation is sparse: only the <c>1 + publicInputCount</c>
/// non-zero slots contribute. For each such slot <c>k</c> with value
/// <c>v_k</c>, the contribution is <c>v_k · eq(r_y, bits(k))</c> where
/// <c>eq(r_y, bits(k)) = Π_b [r_y[b]·bit_b(k) + (1 − r_y[b])·(1 − bit_b(k))]</c>.
/// The constant slot <c>k = 0</c> carries <c>u</c>.
/// </para>
/// <para>
/// Pure helper — no transcript, no shared state, no mutation outside
/// of pool-rented buffers used as local scratch.
/// </para>
/// </remarks>
internal static class EvalPublicAndOneComputation
{
    /// <summary>
    /// Computes the public-and-u MLE evaluation at <paramref name="rY"/>.
    /// </summary>
    /// <param name="uBytes">Canonical big-endian bytes of the relaxation scalar <c>u</c> (the value of the constant slot <c>z[0]</c>); 32 bytes.</param>
    /// <param name="publicInputBytes">Canonical big-endian bytes of the public inputs, length <c>publicInputCount · 32</c>. May be empty when <paramref name="publicInputCount"/> is zero.</param>
    /// <param name="publicInputCount">The number of public inputs.</param>
    /// <param name="columnVariableCount">The MLE's variable count (= <c>log_2(n)</c>).</param>
    /// <param name="rY">The challenge vector; length must equal <paramref name="columnVariableCount"/>.</param>
    /// <param name="scalarAdd">The scalar-add backend.</param>
    /// <param name="scalarSubtract">The scalar-subtract backend.</param>
    /// <param name="scalarMultiply">The scalar-multiply backend.</param>
    /// <param name="pool">The pool to rent scratch and the result buffer from.</param>
    /// <returns>A canonical-form scalar holding the evaluation.</returns>
    /// <exception cref="ArgumentNullException">When any delegate or pool reference is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the public-input byte length disagrees with <paramref name="publicInputCount"/>, <paramref name="uBytes"/> is not a single scalar, or <paramref name="rY"/>'s length does not equal <paramref name="columnVariableCount"/>.</exception>
    public static Scalar Compute(
        ReadOnlySpan<byte> uBytes,
        ReadOnlySpan<byte> publicInputBytes,
        int publicInputCount,
        int columnVariableCount,
        ReadOnlySpan<Scalar> rY,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMultiply,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarSubtract);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(publicInputCount);
        ArgumentOutOfRangeException.ThrowIfNegative(columnVariableCount);

        int scalarSize = Scalar.SizeBytes;

        if(uBytes.Length != scalarSize)
        {
            throw new ArgumentException(
                $"u must be a single canonical scalar of {scalarSize} bytes; received {uBytes.Length}.",
                nameof(uBytes));
        }

        if(publicInputBytes.Length != publicInputCount * scalarSize)
        {
            throw new ArgumentException(
                $"Public-input byte length {publicInputBytes.Length} does not match {publicInputCount} × {scalarSize}.",
                nameof(publicInputBytes));
        }

        if(rY.Length != columnVariableCount)
        {
            throw new ArgumentException(
                $"r_y length {rY.Length} does not match the column variable count {columnVariableCount}.",
                nameof(rY));
        }

        int nonZeroSlots = 1 + publicInputCount;
        int slotCapacity = 1 << columnVariableCount;
        if(nonZeroSlots > slotCapacity)
        {
            throw new ArgumentException(
                $"1 + publicInputCount ({nonZeroSlots}) exceeds 2^columnVariableCount ({slotCapacity}); padding cannot accommodate the layout.");
        }

        CryptographicOperationCounters.Increment(CryptographicOperationKind.EvalPublicAndOneCompute, curve);

        //Precompute per-variable bit factors: for each variable b, store
        //(1 − r_y[b]) at slot 2b and r_y[b] at slot 2b + 1.
        int factorsLength = 2 * columnVariableCount * scalarSize;
        using IMemoryOwner<byte> factorsOwner = pool.Rent(factorsLength == 0 ? scalarSize : factorsLength);
        Span<byte> factors = factorsOwner.Memory.Span[..(factorsLength == 0 ? scalarSize : factorsLength)];

        Span<byte> fieldOne = stackalloc byte[scalarSize];
        fieldOne.Clear();
        fieldOne[^1] = 0x01;

        for(int b = 0; b < columnVariableCount; b++)
        {
            ReadOnlySpan<byte> rb = rY[b].AsReadOnlySpan();
            Span<byte> oneMinusSlot = factors.Slice(b * 2 * scalarSize, scalarSize);
            Span<byte> rSlot = factors.Slice(((b * 2) + 1) * scalarSize, scalarSize);
            scalarSubtract(fieldOne, rb, oneMinusSlot, curve);
            rb.CopyTo(rSlot);
        }

        //Accumulate Σ v_k · eq(r_y, bits(k)) over the non-zero slots
        //k ∈ {0, 1, ..., publicInputCount}.
        using IMemoryOwner<byte> accumulatorOwner = pool.Rent(scalarSize);
        using IMemoryOwner<byte> eqOwner = pool.Rent(scalarSize);
        using IMemoryOwner<byte> termOwner = pool.Rent(scalarSize);
        Span<byte> accumulator = accumulatorOwner.Memory.Span[..scalarSize];
        Span<byte> eq = eqOwner.Memory.Span[..scalarSize];
        Span<byte> term = termOwner.Memory.Span[..scalarSize];
        accumulator.Clear();

        for(int k = 0; k < nonZeroSlots; k++)
        {
            ComputeEqAtIndex(k, columnVariableCount, factors, eq, scalarMultiply, curve);
            ReadOnlySpan<byte> value = k == 0
                ? uBytes
                : publicInputBytes.Slice((k - 1) * scalarSize, scalarSize);
            scalarMultiply(value, eq, term, curve);
            scalarAdd(accumulator, term, accumulator, curve);
        }

        IMemoryOwner<byte> resultOwner = pool.Rent(scalarSize);
        accumulator.CopyTo(resultOwner.Memory.Span[..scalarSize]);
        return new Scalar(resultOwner, curve, WellKnownAlgebraicTags.ScalarFor(curve));
    }


    /// <summary>
    /// Computes <c>eq(r_y, bits(index)) = Π_b factor[b][bit_b(index)]</c>
    /// using the bit factors prebuilt by <see cref="Compute"/>. Writes
    /// the canonical-form scalar into <paramref name="destination"/>.
    /// </summary>
    private static void ComputeEqAtIndex(
        int index,
        int variableCount,
        ReadOnlySpan<byte> bitFactors,
        Span<byte> destination,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        int scalarSize = Scalar.SizeBytes;

        if(variableCount == 0)
        {
            destination.Clear();
            destination[^1] = 0x01;
            return;
        }

        int initialBit = index & 1;
        bitFactors.Slice(initialBit * scalarSize, scalarSize).CopyTo(destination);

        for(int b = 1; b < variableCount; b++)
        {
            int bit = (index >> b) & 1;
            int factorSlotIndex = (b * 2) + bit;
            ReadOnlySpan<byte> factor = bitFactors.Slice(factorSlotIndex * scalarSize, scalarSize);
            multiply(destination, factor, destination, curve);
        }
    }
}