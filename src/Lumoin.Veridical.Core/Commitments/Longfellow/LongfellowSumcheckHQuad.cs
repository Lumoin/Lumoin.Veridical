using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The layer quad after the output variable <c>g</c> has been bound, a faithful port of
/// google/longfellow-zk's <c>HQuad&lt;Field&gt;</c> (<c>lib/sumcheck/hquad.h</c>) together with
/// <c>Quad::bind_g</c> (<c>lib/sumcheck/quad.h</c>). It carries the surviving <c>(h0, h1, v)</c> corners
/// after <c>g = 0</c> is fixed; the sumcheck prover folds the two hand variables out of it round by round
/// (<see cref="BindHand"/>) while reading the quadratic-form weights through
/// <see cref="AccumulateQuadWeighted"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="BindG"/> binds the output point: it folds the layer's <c>Quad</c> terms against the
/// <c>raw_eq2</c> row <c>EQ(G0, g) + alpha·EQ(G1, g)</c> (an assert-zero coefficient <c>v == 0</c> takes
/// <c>beta</c> instead), then coalesces corners that share both hand indices. <see cref="BindHand"/>
/// folds one hand variable via affine interpolation over its low bit, halving the surviving corner count;
/// it handles the sparse case where a corner has only one of the two paired sub-corners present. After
/// all <c>2·logw</c> hand bindings the table holds a single corner at <c>(0, 0)</c> whose value is the
/// fully bound quadratic coefficient.
/// </para>
/// <para>
/// The arithmetic is field-generic: the affine folds subtract through the threaded delegate (over
/// GF(2^128) subtraction coincides with addition, over Fp256 it is genuine field subtraction). The corner
/// storage (the two hand indices and the value scalars) is pool-rented and cleared on disposal.
/// </para>
/// </remarks>
internal sealed class LongfellowSumcheckHQuad: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The two hand indices per corner, stored as two parallel int arrays, and the value scalars.
    private int[] handLeft;
    private int[] handRight;
    private IMemoryOwner<byte>? valuesOwner;
    private int cornerCount;


    private LongfellowSumcheckHQuad(int[] handLeft, int[] handRight, IMemoryOwner<byte> valuesOwner, int cornerCount)
    {
        this.handLeft = handLeft;
        this.handRight = handRight;
        this.valuesOwner = valuesOwner;
        this.cornerCount = cornerCount;
    }


    /// <summary>
    /// Binds the output variable <c>g</c> of <paramref name="layer"/>'s quad against the points
    /// <paramref name="g0"/>, <paramref name="g1"/> folded by <paramref name="alpha"/>, with the
    /// assert-zero coefficient <paramref name="beta"/>, producing the surviving hand corners (the
    /// reference's <c>Quad::bind_g</c>).
    /// </summary>
    /// <param name="layer">The layer whose quad terms are bound; its terms are read in iteration order.</param>
    /// <param name="outputLogCount">The number of output binding rounds (<c>logv</c>).</param>
    /// <param name="g0">The first output point <c>G0</c>, <paramref name="outputLogCount"/> canonical scalars.</param>
    /// <param name="g1">The second output point <c>G1</c>, <paramref name="outputLogCount"/> canonical scalars.</param>
    /// <param name="alpha">The fold coefficient combining the two output claims.</param>
    /// <param name="beta">The assert-zero coefficient applied to <c>v == 0</c> terms.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction (the affine folds and the <c>raw_eq2</c> halves).</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="curve">The curve parameter the delegates take.</param>
    /// <param name="one">The field multiplicative one in the working domain (the profile's <c>WorkingOne</c>).</param>
    /// <param name="pool">The pool the corner storage rents from.</param>
    /// <param name="broadcastMultiplyAccumulate">The optional broadcast-scalar fused multiply primitive the <c>raw_eq2</c> row fill routes through; supplied on the GF(2^128) path, <see langword="null"/> for the Fp256 scalar fallback.</param>
    /// <returns>The bound quad; the caller owns its disposal.</returns>
    public static LongfellowSumcheckHQuad BindG(
        LongfellowSumcheckLayer layer,
        int outputLogCount,
        ReadOnlySpan<byte> g0,
        ReadOnlySpan<byte> g1,
        ReadOnlySpan<byte> alpha,
        ReadOnlySpan<byte> beta,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        ReadOnlySpan<byte> one,
        BaseMemoryPool pool,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null)
    {
        int nv = 1 << outputLogCount;

        //dot[g] = EQ(G0, g) + alpha·EQ(G1, g), the de-recursed raw_eq2. The batched GF path needs a tmp
        //row (nv) plus FillEq's per-level product scratch (ceil(nv/2)); the scalar fallback needs only the
        //tmp row.
        using IMemoryOwner<byte> dotOwner = pool.Rent(nv * ScalarSize);
        Span<byte> dot = dotOwner.Memory.Span[..(nv * ScalarSize)];
        int rawEq2ScratchScalars = broadcastMultiplyAccumulate is not null && curve == CurveParameterSet.None ? nv + ((nv + 1) / 2) : nv;
        using(IMemoryOwner<byte> rawEq2ScratchOwner = pool.Rent(rawEq2ScratchScalars * ScalarSize))
        {
            LongfellowEq.RawEq2(outputLogCount, nv, g0, g1, alpha, add, subtract, multiply, curve, one, dot, broadcastMultiplyAccumulate, rawEq2ScratchOwner.Memory.Span[..(rawEq2ScratchScalars * ScalarSize)]);
        }

        int termCount = layer.QuadTerms.Length;
        int[] handLeft = new int[termCount];
        int[] handRight = new int[termCount];
        IMemoryOwner<byte> valuesOwner = pool.Rent(Math.Max(termCount, 1) * ScalarSize);
        bool transferred = false;
        try
        {
            Span<byte> values = valuesOwner.Memory.Span[..(Math.Max(termCount, 1) * ScalarSize)];
            values.Clear();

            Span<byte> zero = stackalloc byte[ScalarSize];
            zero.Clear();
            Span<byte> preparedValue = stackalloc byte[ScalarSize];

            int write = 0;
            foreach(LongfellowSumcheckQuadTerm term in layer.QuadTerms)
            {
                //prep_v(v, dot[g], beta) = (v == 0 ? beta : v)·dot[g].
                ReadOnlySpan<byte> coefficient = term.Coefficient.Span;
                ReadOnlySpan<byte> scaled = coefficient.SequenceEqual(zero) ? beta : coefficient;
                multiply(scaled, dot.Slice(term.GateIndex * ScalarSize, ScalarSize), preparedValue, curve);

                //Coalesce a corner that shares both hand indices with the previous written corner.
                if(write > 0 && handLeft[write - 1] == term.LeftIndex && handRight[write - 1] == term.RightIndex)
                {
                    Span<byte> previous = values.Slice((write - 1) * ScalarSize, ScalarSize);
                    add(previous, preparedValue, previous, curve);
                }
                else
                {
                    handLeft[write] = term.LeftIndex;
                    handRight[write] = term.RightIndex;
                    preparedValue.CopyTo(values.Slice(write * ScalarSize, ScalarSize));
                    write++;
                }
            }

            var hquad = new LongfellowSumcheckHQuad(handLeft, handRight, valuesOwner, write);
            transferred = true;

            return hquad;
        }
        finally
        {
            if(!transferred)
            {
                valuesOwner.Memory.Span.Clear();
                valuesOwner.Dispose();
            }
        }
    }


    /// <summary>
    /// Accumulates <c>QW[p0] += v · W_other[p1]</c> over the surviving corners, where <c>p0</c> is the
    /// binding hand's index and <c>p1</c> the other hand's, the reference's <c>QW</c> precompute inside
    /// <c>layer()</c>. <paramref name="qw"/> must be cleared by the caller and sized to the binding hand's
    /// current length.
    /// </summary>
    /// <param name="hand">The binding hand (0 = left, 1 = right).</param>
    /// <param name="otherHand">The other hand's wire column (full-width; corner indices stay within it).</param>
    /// <param name="qw">Receives the accumulation, indexed by the binding hand's corner; caller-cleared.</param>
    /// <param name="scratch">A caller-owned scratch scalar (used only by the scalar path).</param>
    /// <param name="add">GF(2^128) addition (XOR).</param>
    /// <param name="multiply">GF(2^128) multiplication.</param>
    /// <param name="curve">The curve parameter the delegates take.</param>
    /// <param name="gatherMultiplyAccumulate">The optional gather/scatter fused multiply-accumulate primitive; supplied on the GF(2^128) path to batch the corner accumulation, <see langword="null"/> for the scalar fallback.</param>
    public void AccumulateQuadWeighted(
        int hand,
        ReadOnlySpan<byte> otherHand,
        Span<byte> qw,
        Span<byte> scratch,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        ScalarGatherMultiplyAccumulateDelegate? gatherMultiplyAccumulate = null)
    {
        Span<byte> values = Values;

        //QW[p0] += v·W_other[p1]: the corner value v (coefficient i) scattered to the binding hand's slot
        //p0, gathering the other hand's wire at p1. This is the gather/scatter FMA's exact shape, so the
        //GF(2^128) path routes the whole corner sweep through the batch primitive: coefficients are the
        //dense corner values, the data is the other hand's column, p1 indexes the gather and p0 the scatter.
        //The corner index arrays are passed as-is (sliced to the surviving count). The primitive's
        //deferred reduction across a consecutive same-slot run is GF(2)-linear, hence byte-identical to the
        //scalar reduce-per-term; qw is caller-cleared so the read-modify-write XORs onto a zero base.
        //The null delegate is the field gate: only the GF hash side supplies the GF-specific primitive.
        if(gatherMultiplyAccumulate is not null && curve == CurveParameterSet.None)
        {
            ReadOnlySpan<int> outputIndices = hand == 0 ? handLeft.AsSpan(0, cornerCount) : handRight.AsSpan(0, cornerCount);
            ReadOnlySpan<int> inputIndices = hand == 0 ? handRight.AsSpan(0, cornerCount) : handLeft.AsSpan(0, cornerCount);
            gatherMultiplyAccumulate(values[..(cornerCount * ScalarSize)], otherHand, inputIndices, outputIndices, qw, cornerCount, curve);

            return;
        }

        for(int i = 0; i < cornerCount; i++)
        {
            int p0 = hand == 0 ? handLeft[i] : handRight[i];
            int p1 = hand == 0 ? handRight[i] : handLeft[i];

            //QW[p0] += v·W_other[p1]. The corner indices never exceed the wire length the binding
            //tracks (binding halves the corner space and the wire length in step), matching the
            //reference's unconditional indexing in layer()'s QW precompute.
            multiply(values.Slice(i * ScalarSize, ScalarSize), otherHand.Slice(p1 * ScalarSize, ScalarSize), scratch, curve);
            Span<byte> destination = qw.Slice(p0 * ScalarSize, ScalarSize);
            add(destination, scratch, destination, curve);
        }
    }


    /// <summary>
    /// Folds the hand variable <paramref name="hand"/> at the challenge <paramref name="challenge"/>, the
    /// reference's <c>HQuad::bind_h&lt;hand&gt;</c>. Corners that pair across the binding hand's low bit
    /// interpolate together; a lone corner folds with its missing partner at zero. The surviving corner
    /// count halves.
    /// </summary>
    /// <param name="hand">The hand to fold (0 = left, 1 = right).</param>
    /// <param name="challenge">The fold point.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction (the affine folds' <c>v1 − v0</c> and <c>v − r·v</c>).</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="curve">The curve parameter the delegates take.</param>
    public void BindHand(
        int hand,
        ReadOnlySpan<byte> challenge,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> values = Values;
        int[] bindHand = hand == 0 ? handLeft : handRight;
        int[] otherHand = hand == 0 ? handRight : handLeft;

        Span<byte> folded = stackalloc byte[ScalarSize];

        int read = 0;
        int write = 0;
        while(read < cornerCount)
        {
            int bindValue = bindHand[read];
            int otherValue = otherHand[read];
            int newBind = bindValue >> 1;

            int next = read + 1;
            bool paired = next < cornerCount
                && otherHand[next] == otherValue
                && (bindHand[next] >> 1) == newBind
                && bindHand[next] == bindValue + 1;

            if(paired)
            {
                //affine_interpolation(r, v0, v1) = v0 + r·(v1 - v0).
                AffineInterpolation(challenge, values.Slice(read * ScalarSize, ScalarSize), values.Slice(next * ScalarSize, ScalarSize), add, subtract, multiply, curve, folded);
                read += 2;
            }
            else if((bindValue & 1) == 0)
            {
                //affine_interpolation_nz_z(r, v) = v - r·v: the second corner is zero.
                AffineInterpolationNonzeroZero(challenge, values.Slice(read * ScalarSize, ScalarSize), subtract, multiply, curve, folded);
                read = next;
            }
            else
            {
                //affine_interpolation_z_nz(r, v) = r·v: the first corner is zero.
                multiply(challenge, values.Slice(read * ScalarSize, ScalarSize), folded, curve);
                read = next;
            }

            bindHand[write] = newBind;
            otherHand[write] = otherValue;
            folded.CopyTo(values.Slice(write * ScalarSize, ScalarSize));
            write++;
        }

        cornerCount = write;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        IMemoryOwner<byte>? local = valuesOwner;
        if(local is not null)
        {
            valuesOwner = null;
            local.Memory.Span.Clear();
            local.Dispose();
        }

        Array.Clear(handLeft);
        Array.Clear(handRight);
    }


    private Span<byte> Values => (valuesOwner ?? throw new ObjectDisposedException(nameof(LongfellowSumcheckHQuad))).Memory.Span;


    //affine_interpolation(r, f0, f1) = f0 + r·(f1 - f0).
    private static void AffineInterpolation(ReadOnlySpan<byte> r, ReadOnlySpan<byte> f0, ReadOnlySpan<byte> f1, ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, CurveParameterSet curve, Span<byte> result)
    {
        Span<byte> difference = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        subtract(f1, f0, difference, curve);
        multiply(r, difference, term, curve);
        add(f0, term, result, curve);
    }


    //affine_interpolation_nz_z(r, f0) = f0 - r·f0 = f0·(1 - r).
    private static void AffineInterpolationNonzeroZero(ReadOnlySpan<byte> r, ReadOnlySpan<byte> f0, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, CurveParameterSet curve, Span<byte> result)
    {
        Span<byte> term = stackalloc byte[ScalarSize];
        multiply(r, f0, term, curve);
        subtract(f0, term, result, curve);
    }
}
