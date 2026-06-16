using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The symbolic constraint accumulator the ZK constraint composition builds per layer, a faithful port
/// of google/longfellow-zk's <c>ZkCommon::ConstraintBuilder</c> together with its <c>Expression</c>
/// (<c>lib/zk/zk_common.h</c>). It represents the running sumcheck claim symbolically as
/// <c>KNOWN + Σ_i SYMBOLIC[i]·dX[i]</c> over the layer's pad witnesses <c>dX</c>, then turns the final
/// quadratic claim relation into one Ligero linear constraint.
/// </summary>
/// <remarks>
/// <para>
/// Each unpadded sumcheck variable <c>X</c> is committed only as <c>Xhat = X − dX</c> (the transcript
/// carries <c>Xhat</c>, the commitment hides <c>dX</c>). The verifier computes linear combinations of
/// the <c>X</c> through the symbolic representation <c>X = KNOWN + Σ_i SYMBOLIC[i]·dX[i]</c>: the
/// constant part lands in <c>KNOWN</c>, the pad dependence in <c>SYMBOLIC</c>. <see cref="First"/> seeds
/// the entering claim <c>cl0 + alpha·cl1</c>; <see cref="Next"/> folds one round's
/// <c>claim_r = ⟨lag_r, p_r⟩</c>; <see cref="Finalize"/> breaks the abstraction to rearrange the
/// quadratic relation <c>claim = eqq·W[R,C]·W[L,C]</c> into <c>A·w = b</c> form and emits the constraint.
/// </para>
/// <para>
/// The arithmetic is field-generic: subtraction threads through the injected delegate (over GF(2^128) it
/// coincides with addition, over Fp256 it is genuine field subtraction). The single pooled buffer (the
/// symbolic array plus the known scalar) is cleared on disposal.
/// </para>
/// </remarks>
internal sealed class LongfellowZkConstraintExpression: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly LongfellowZkPadLayout layout;
    private readonly ScalarAddDelegate add;
    private readonly ScalarSubtractDelegate subtract;
    private readonly ScalarMultiplyDelegate multiply;
    private readonly CurveParameterSet curve;
    private readonly int symbolicCount;

    //The single pooled buffer: [known | symbolic[0] | … | symbolic[symbolicCount-1] | one]. The field
    //multiplicative one (the profile's WorkingOne, sourced in Foundation-A) rides in the trailing slot so the
    //First/Next axpy seeds read it across the layer's lifetime without a separate escaping allocation.
    private IMemoryOwner<byte>? buffer;


    /// <summary>
    /// Constructs the accumulator for a layer with the given pad <paramref name="layout"/>, sized to the
    /// layout's with-overlap symbolic length and seeded to zero.
    /// </summary>
    /// <param name="layout">The layer's pad layout.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction (the <c>axmy</c> folds and the finalize routing).</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="curve">The curve parameter the delegates take.</param>
    /// <param name="one">The field multiplicative one in the working domain (the profile's <c>WorkingOne</c>).</param>
    /// <param name="pool">The pool the symbolic buffer rents from.</param>
    public LongfellowZkConstraintExpression(
        LongfellowZkPadLayout layout,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        ReadOnlySpan<byte> one,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);

        this.layout = layout;
        this.add = add;
        this.subtract = subtract;
        this.multiply = multiply;
        this.curve = curve;
        symbolicCount = layout.OverlapLayerSize;

        //[known | symbolic | one]: symbolicCount + 2 slots, the working one in the trailing slot.
        buffer = pool.Rent((symbolicCount + 2) * ScalarSize);
        buffer.Memory.Span[..((symbolicCount + 2) * ScalarSize)].Clear();
        one.CopyTo(buffer.Memory.Span.Slice((symbolicCount + 1) * ScalarSize, ScalarSize));
    }


    //The known scalar lives at index 0; the symbolic entries follow.
    private Span<byte> Known => Storage[..ScalarSize];

    private Span<byte> SymbolicAt(int index) => Storage.Slice((1 + index) * ScalarSize, ScalarSize);

    private Span<byte> Storage =>
        (buffer ?? throw new ObjectDisposedException(nameof(LongfellowZkConstraintExpression))).Memory.Span[..((symbolicCount + 1) * ScalarSize)];

    //The field multiplicative one in the trailing buffer slot (the profile's WorkingOne).
    private ReadOnlySpan<byte> One =>
        (buffer ?? throw new ObjectDisposedException(nameof(LongfellowZkConstraintExpression))).Memory.Span.Slice((symbolicCount + 1) * ScalarSize, ScalarSize);


    /// <summary>
    /// Seeds the expression to the entering claim <c>claim_{-1} = cl0 + alpha·cl1</c> via the previous
    /// layer's claim pad, the reference's <c>ConstraintBuilder::first</c>.
    /// </summary>
    /// <param name="alpha">The layer's claim-combination coefficient.</param>
    /// <param name="claims">The two entering claims <c>cl0</c>, <c>cl1</c> (two canonical scalars).</param>
    public void First(ReadOnlySpan<byte> alpha, ReadOnlySpan<byte> claims)
    {
        //axpy(ovp_claim_pad_m1(0), cl0, 1); axpy(ovp_claim_pad_m1(1), cl1, alpha).
        Axpy(LongfellowZkPadLayout.OverlapPreviousClaimPad(0), claims[..ScalarSize], One);
        Axpy(LongfellowZkPadLayout.OverlapPreviousClaimPad(1), claims.Slice(ScalarSize, ScalarSize), alpha);
    }


    /// <summary>
    /// Folds one round's reconstruction <c>claim_r = ⟨lag_r, p_r⟩</c> into the expression, the
    /// reference's <c>ConstraintBuilder::next</c>. The transmitted points <c>tr[0]</c>, <c>tr[2]</c> are
    /// read from <paramref name="transmitted"/>; <c>tr[1]</c> is the implied <c>p(1)</c> and is never
    /// read here (it is reconstructed symbolically by the <c>axmy</c> step).
    /// </summary>
    /// <param name="round">The round index <c>r = 2·round + hand</c> the poly pad belongs to.</param>
    /// <param name="lagrange">The three Lagrange weights at the squeezed challenge.</param>
    /// <param name="transmitted">The round polynomial's points <c>(p(0), p(1)=0, p(2))</c> (three canonical scalars).</param>
    public void Next(int round, ReadOnlySpan<byte> lagrange, ReadOnlySpan<byte> transmitted)
    {
        ReadOnlySpan<byte> tr0 = transmitted[..ScalarSize];
        ReadOnlySpan<byte> tr2 = transmitted.Slice(2 * ScalarSize, ScalarSize);
        ReadOnlySpan<byte> lag0 = lagrange[..ScalarSize];
        ReadOnlySpan<byte> lag1 = lagrange.Slice(ScalarSize, ScalarSize);
        ReadOnlySpan<byte> lag2 = lagrange.Slice(2 * ScalarSize, ScalarSize);

        //axmy(ovp_poly_pad(r,0), tr[0], 1): expr = p_r(1) = claim_{r-1} - p_r(0).
        Axmy(LongfellowZkPadLayout.OverlapPolyPad(round, 0), tr0, One);

        //scale(lag[1]): claim_r = p_r(1)*lag[1].
        Scale(lag1);

        //axpy(ovp_poly_pad(r,0), tr[0], lag[0]); axpy(ovp_poly_pad(r,2), tr[2], lag[2]).
        Axpy(LongfellowZkPadLayout.OverlapPolyPad(round, 0), tr0, lag0);
        Axpy(LongfellowZkPadLayout.OverlapPolyPad(round, 2), tr2, lag2);
    }


    /// <summary>
    /// Emits the layer's Ligero constraint from the final symbolic claim and the quadratic relation
    /// <c>claim = eqq·W[R,C]·W[L,C]</c>, the reference's <c>ConstraintBuilder::finalize</c>. It rearranges
    /// to <c>Σ_i SYMBOLIC[i]·dX[i] − (eqq·W[R,C])·dW[L,C] − (eqq·W[L,C])·dW[R,C] − eqq·dW[R,C]·dW[L,C] =
    /// eqq·W[R,C]·W[L,C] − KNOWN</c> and pushes the right-hand side into <paramref name="system"/>'s
    /// targets and the symbolic terms into its sparse <c>A</c>.
    /// </summary>
    /// <param name="wc0">The claim <c>W[R,C]</c> (one canonical scalar).</param>
    /// <param name="wc1">The claim <c>W[L,C]</c> (one canonical scalar).</param>
    /// <param name="eqq">The combined coefficient <c>eqq = eqv·bind_quad</c>.</param>
    /// <param name="layerIndex">The layer index <c>ly</c>; layer 0 does not refer to the previous claim pad.</param>
    /// <param name="padIndex">The without-overlap index of the first pad element of this layer (<c>pi</c>).</param>
    /// <param name="system">The constraint system receiving the term and the target.</param>
    /// <param name="constraintIndex">The constraint index <c>ci</c> the terms belong to.</param>
    public void Finalize(
        ReadOnlySpan<byte> wc0,
        ReadOnlySpan<byte> wc1,
        ReadOnlySpan<byte> eqq,
        int layerIndex,
        int padIndex,
        LongfellowZkConstraintBuilder.ConstraintSystem system,
        int constraintIndex)
    {
        //rhs = eqq*wc0*wc1 - known.
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> rhs = stackalloc byte[ScalarSize];
        multiply(wc0, wc1, product, curve);
        multiply(eqq, product, product, curve);
        subtract(product, Known, rhs, curve);

        //Break the abstraction: lhs = symbolic; subtract the three quadratic-routing coefficients.
        Span<byte> eqqWc1 = stackalloc byte[ScalarSize];
        Span<byte> eqqWc0 = stackalloc byte[ScalarSize];
        multiply(eqq, wc1, eqqWc1, curve);
        multiply(eqq, wc0, eqqWc0, curve);

        //lhs[ovp_claim_pad(0)] -= eqq*wc1; lhs[ovp_claim_pad(1)] -= eqq*wc0; lhs[ovp_claim_pad(2)] -= eqq.
        SubInPlace(SymbolicAt(layout.OverlapClaimPad(0)), eqqWc1);
        SubInPlace(SymbolicAt(layout.OverlapClaimPad(1)), eqqWc0);
        SubInPlace(SymbolicAt(layout.OverlapClaimPad(2)), eqq);

        system.AddTarget(rhs);

        //Layer 0 does not refer to CLAIM_PAD[layer - 1]; later layers start at the previous claim pad.
        int firstIndex = layerIndex == 0 ? LongfellowZkPadLayout.OverlapPolyPad(0, 0) : LongfellowZkPadLayout.OverlapPreviousClaimPad(0);
        int polyPadZero = LongfellowZkPadLayout.OverlapPolyPad(0, 0);

        for(int i = firstIndex; i < symbolicCount; i++)
        {
            int witnessIndex = (padIndex + i) - polyPadZero;
            system.AddTerm(constraintIndex, witnessIndex, SymbolicAt(i));
        }
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        IMemoryOwner<byte>? local = buffer;
        if(local is not null)
        {
            buffer = null;
            local.Memory.Span[..((symbolicCount + 2) * ScalarSize)].Clear();
            local.Dispose();
        }
    }


    //*this += k * (known_value + witness[var]): known += k*known_value; symbolic[var] += k.
    private void Axpy(int var, ReadOnlySpan<byte> knownValue, ReadOnlySpan<byte> k)
    {
        Span<byte> term = stackalloc byte[ScalarSize];
        multiply(k, knownValue, term, curve);
        AddInPlace(Known, term);
        AddInPlace(SymbolicAt(var), k);
    }


    //*this -= k * (known_value + witness[var]): known -= k*known_value; symbolic[var] -= k. The real field
    //subtraction (over GF(2) it coincides with Axpy; over Fp256 it differs).
    private void Axmy(int var, ReadOnlySpan<byte> knownValue, ReadOnlySpan<byte> k)
    {
        Span<byte> term = stackalloc byte[ScalarSize];
        multiply(k, knownValue, term, curve);
        SubInPlace(Known, term);
        SubInPlace(SymbolicAt(var), k);
    }


    //*this *= k: known *= k; each symbolic *= k.
    private void Scale(ReadOnlySpan<byte> k)
    {
        multiply(Known, k, Known, curve);
        for(int i = 0; i < symbolicCount; i++)
        {
            Span<byte> entry = SymbolicAt(i);
            multiply(entry, k, entry, curve);
        }
    }


    private void AddInPlace(Span<byte> destination, ReadOnlySpan<byte> addend)
    {
        Span<byte> scratch = stackalloc byte[ScalarSize];
        add(destination, addend, scratch, curve);
        scratch.CopyTo(destination);
    }


    //destination -= subtrahend, the real field subtraction (over GF(2) it coincides with addition).
    private void SubInPlace(Span<byte> destination, ReadOnlySpan<byte> subtrahend)
    {
        Span<byte> scratch = stackalloc byte[ScalarSize];
        subtract(destination, subtrahend, scratch, curve);
        scratch.CopyTo(destination);
    }
}
