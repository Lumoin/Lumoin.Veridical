using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The multilinear equality-array evaluations the ZK constraint composition needs, faithful ports of
/// google/longfellow-zk's <c>Eq&lt;Field&gt;::eval</c> (<c>lib/arrays/eq.h</c>) and
/// <c>Eqs&lt;Field&gt;</c>'s <c>filleq</c> and <c>raw_eq2</c> (<c>lib/arrays/eqs.h</c>). <c>EQ[i, j]</c>
/// is the diagonal indicator <c>(i == j)</c> as a multilinear polynomial in the binding variables;
/// <see cref="Eval"/> evaluates it at a single point pair, <see cref="FillEq"/> materializes the row
/// <c>EQ[I, j]</c> for fixed <c>I</c> over all <c>j</c>, and <see cref="RawEq2"/> materializes the
/// folded row <c>EQ(G0, j) + alpha·EQ(G1, j)</c>.
/// </summary>
/// <remarks>
/// The arithmetic is field-generic: <c>1 − x</c> is the real subtraction (the <see cref="OneMinus"/>
/// helper threads <paramref name="subtract"/>), which over GF(2^128) coincides with <c>1 ⊕ x</c> and over
/// Fp256 is genuine field subtraction. The delegates are injected to match the library's
/// primitive-agnostic commitment infrastructure.
/// </remarks>
internal static class LongfellowEq
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Evaluates <c>EQ[I, J]</c> for the binding points <paramref name="i"/> and <paramref name="j"/>
    /// over a domain of <paramref name="n"/> diagonal entries with <paramref name="logn"/> binding
    /// rounds, the reference's <c>Eq::eval</c>. <c>EQ</c> is treated as <c>diag([A … A B])</c> with
    /// <c>n − 1</c> generic diagonal entries and one last entry, bound one variable per round.
    /// </summary>
    /// <param name="logn">The number of binding rounds.</param>
    /// <param name="n">The number of diagonal entries.</param>
    /// <param name="i">The first binding point, <paramref name="logn"/> canonical scalars.</param>
    /// <param name="j">The second binding point, <paramref name="logn"/> canonical scalars.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction (the <c>1 − x</c> folds).</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="curve">The curve parameter the delegates take.</param>
    /// <param name="one">The field multiplicative one in the working domain (the profile's <c>WorkingOne</c>).</param>
    /// <param name="result">Receives the single field element <c>EQ[I, J]</c>.</param>
    public static void Eval(
        int logn,
        int n,
        ReadOnlySpan<byte> i,
        ReadOnlySpan<byte> j,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        ReadOnlySpan<byte> one,
        Span<byte> result)
    {
        Span<byte> a = stackalloc byte[ScalarSize];
        Span<byte> b = stackalloc byte[ScalarSize];
        one.CopyTo(a);
        one.CopyTo(b);

        Span<byte> i0 = stackalloc byte[ScalarSize];
        Span<byte> j0 = stackalloc byte[ScalarSize];
        Span<byte> i0j0 = stackalloc byte[ScalarSize];
        Span<byte> i1j1 = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];

        for(int round = 0; round < logn; round++)
        {
            ReadOnlySpan<byte> i1 = i.Slice(round * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> j1 = j.Slice(round * ScalarSize, ScalarSize);
            OneMinus(i1, i0, subtract, curve, one);
            OneMinus(j1, j0, subtract, curve, one);
            multiply(i0, j0, i0j0, curve);
            multiply(i1, j1, i1j1, curve);

            if((n & 1) == 0)
            {
                //b = b*i1j1 + a*i0j0.
                multiply(b, i1j1, b, curve);
                multiply(a, i0j0, scratch, curve);
                add(b, scratch, scratch, curve);
                scratch.CopyTo(b);
            }
            else
            {
                //b = b*i0j0.
                multiply(b, i0j0, b, curve);
            }

            //a = a*(i0j0 + i1j1).
            add(i0j0, i1j1, scratch, curve);
            multiply(a, scratch, a, curve);

            n = (n + 1) / 2;
        }

        b.CopyTo(result);
    }


    /// <summary>
    /// Fills <paramref name="eq"/> with <c>EQ[Q, j]</c> for all <c>0 ≤ j &lt; n</c>, the reference's
    /// <c>Eqs::filleq</c>. The result is the multilinear extension of the indicator <c>j == Q</c>
    /// evaluated over the integer grid.
    /// </summary>
    /// <remarks>
    /// The per-level inner work is the scalar-times-vector product <c>Q[level]·eq[i]</c> over the live
    /// prefix <c>eq[0, iStart)</c>: <c>Q[level]</c> is fixed across the level and the source indices read
    /// are exactly <c>[0, iStart)</c>. When <paramref name="broadcastMultiplyAccumulate"/> is supplied, each
    /// level routes that scalar-times-vector through the batch primitive: it computes every product from the
    /// unclobbered <c>eq</c> prefix into <paramref name="productScratch"/> up front, then runs the same
    /// special-case + descending control flow, reading the precomputed product for slot <c>i</c> instead of
    /// multiplying inline. The primitive's per-product single reduce is byte-identical to the scalar
    /// <paramref name="multiply"/>, and reading <c>eq[i]</c> during the descending write is safe (the
    /// writes target slots <c>≥ 2i ≥ i + 1</c> and never clobber a not-yet-read lower slot), so the
    /// batched path is byte-identical to the scalar path. The scalar path (the default when the delegate is
    /// absent or the scratch is too small) is unchanged.
    /// <para>
    /// The delegate is the field discriminator, NOT <paramref name="curve"/>: the batch primitive is
    /// GF(2^128)-specific and only the GF(2^128) hash callers ever supply it (the Fp256 sig side passes
    /// <see langword="null"/> and stays on the scalar multiply). The <c>curve == CurveParameterSet.None</c>
    /// clause in the gate is a redundant secondary guard mirroring the <c>bind_quad</c> reduce gate — both
    /// fields run with <see cref="CurveParameterSet.None"/> here, so it does not by itself exclude Fp256;
    /// the null default does.
    /// </para>
    /// <para>
    /// The batched path requires <paramref name="productScratch"/> to hold at least <c>ceil(n/2)</c>
    /// scalars (<c>((n + 1) / 2) · Scalar.SizeBytes</c> bytes), which bounds every level's
    /// <c>iStart = CeilShift(nl, 1) ≤ CeilShift(n, 1)</c>; a smaller scratch falls back to the scalar path.
    /// </para>
    /// </remarks>
    /// <param name="logn">The number of binding rounds (the bit length of <paramref name="n"/>).</param>
    /// <param name="n">The number of entries to fill; at least one.</param>
    /// <param name="qq">The fixed binding point <c>Q</c>, <paramref name="logn"/> canonical scalars.</param>
    /// <param name="subtract">Field subtraction (the <c>v − qv</c> low halves).</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="curve">The curve parameter the delegates take.</param>
    /// <param name="one">The field multiplicative one in the working domain (the profile's <c>WorkingOne</c>).</param>
    /// <param name="eq">Receives <paramref name="n"/> canonical scalars.</param>
    /// <param name="broadcastMultiplyAccumulate">The optional broadcast-scalar fused multiply primitive; supplied on the GF(2^128) path to batch the per-level scalar-times-vector products, <see langword="null"/> for the scalar fallback.</param>
    /// <param name="productScratch">The scratch the batched path writes the per-level products into; ignored on the scalar path. Must hold at least <c>((n + 1) / 2) · Scalar.SizeBytes</c> bytes for the batched path to engage.</param>
    public static void FillEq(
        int logn,
        int n,
        ReadOnlySpan<byte> qq,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        ReadOnlySpan<byte> one,
        Span<byte> eq,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null,
        Span<byte> productScratch = default)
    {
        one.CopyTo(eq[..ScalarSize]);

        //Decide the path once. The non-null delegate is the gate: only the GF(2^128) hash callers supply
        //the GF-specific batch primitive, so a present delegate IS the GF path (the curve == None clause is
        //a redundant secondary guard — the Fp256 sig side also runs with curve None but passes null). The
        //scratch must cover every level's product prefix: ceil(n/2) bounds every level's
        //iStart = CeilShift(nl, 1) <= CeilShift(n, 1); a short scratch falls back to scalar.
        int maxProducts = CeilShift(n, 1);
        bool batch = broadcastMultiplyAccumulate is not null
            && curve == CurveParameterSet.None
            && productScratch.Length >= maxProducts * ScalarSize;

        Span<byte> qv = stackalloc byte[ScalarSize];
        for(int level = logn; level-- > 0;)
        {
            int nl = CeilShift(n, level);
            int i = CeilShift(nl, 1);
            ReadOnlySpan<byte> q = qq.Slice(level * ScalarSize, ScalarSize);

            if(batch)
            {
                //Precompute every product Q[level]*eq[i] for i in [0, iStart) from the LIVE eq prefix,
                //before any write clobbers it. accumulate:false overwrites the scratch with the products.
                broadcastMultiplyAccumulate!(q, eq[..(i * ScalarSize)], productScratch[..(i * ScalarSize)], false, i, curve);
            }

            //The first iteration special case: do not write eq[2*i+1] if it would overflow.
            if(((2 * i) - 1) >= nl)
            {
                i--;
                Span<byte> v = eq.Slice(i * ScalarSize, ScalarSize);

                //qv = Q[level]*v; eq[2*i] = v - qv.
                ReadOnlySpan<byte> product = batch ? productScratch.Slice(i * ScalarSize, ScalarSize) : ReadProduct(q, v, multiply, curve, qv);
                Span<byte> dst = eq.Slice(2 * i * ScalarSize, ScalarSize);
                subtract(v, product, dst, curve);
            }

            while(i-- > 0)
            {
                ReadOnlySpan<byte> v = eq.Slice(i * ScalarSize, ScalarSize);

                //qv = Q[level]*v; eq[2*i] = v - qv; eq[2*i+1] = qv.
                ReadOnlySpan<byte> product = batch ? productScratch.Slice(i * ScalarSize, ScalarSize) : ReadProduct(q, v, multiply, curve, qv);
                Span<byte> lo = eq.Slice(2 * i * ScalarSize, ScalarSize);
                Span<byte> hi = eq.Slice(((2 * i) + 1) * ScalarSize, ScalarSize);
                subtract(v, product, lo, curve);
                product.CopyTo(hi);
            }
        }
    }


    //The scalar product qv = Q[level]*v written into the supplied scratch, returned as a read-only view —
    //the inline multiply the batched path replaces with a precomputed-scratch read.
    private static ReadOnlySpan<byte> ReadProduct(ReadOnlySpan<byte> q, ReadOnlySpan<byte> v, ScalarMultiplyDelegate multiply, CurveParameterSet curve, Span<byte> qv)
    {
        multiply(q, v, qv, curve);

        return qv;
    }


    /// <summary>
    /// Fills <paramref name="eq"/> with <c>EQ(G0, j) + alpha·EQ(G1, j)</c> for all <c>0 ≤ j &lt; n</c>,
    /// the reference's <c>Eqs::raw_eq2</c>. This is the row <c>bind_quad</c> folds the layer's
    /// <c>Quad</c> coefficients against at the output point.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The reference materializes this row with a top-down recursion (<c>fill_recursive</c>); this port is
    /// ITERATIVE — it materializes the two single-point rows <c>EQ(G0, ·)</c> and <c>EQ(G1, ·)</c> with
    /// <see cref="FillEq"/> (the reference's own iterative <c>filleq</c>) and combines them with one
    /// <c>alpha</c>-weighted accumulation <c>eq[i] += alpha·EQ(G1, i)</c>. <c>EQ(G, ·)</c> is a
    /// well-defined multilinear value, so <see cref="FillEq"/>'s bottom-up fold and the recursion's
    /// top-down fold reduce to the SAME canonical field element (field multiplication and addition are
    /// associative and commutative) — byte-identical over GF(2^128) and Fp256. Folding <c>alpha</c> in
    /// after the product yields the same field element as the recursion's <c>w1</c> seed (commutativity),
    /// and the combine's single product per slot makes the GF deferred reduction degenerate to one
    /// reduce-then-add, matching the scalar multiply-then-add.
    /// </para>
    /// <para>
    /// When <paramref name="broadcastMultiplyAccumulate"/> is supplied (and <paramref name="scratch"/> is
    /// large enough) both fills and the combine route through the GF(2^128) batch primitive; otherwise
    /// they take the scalar path. The delegate is the GF/Fp discriminator, NOT <paramref name="curve"/>:
    /// only the GF(2^128) hash callers supply it (the Fp256 sig side passes <see langword="null"/> and
    /// stays on the scalar multiply); the <c>curve == CurveParameterSet.None</c> clause is a redundant
    /// secondary guard mirroring <see cref="FillEq"/>. <paramref name="scratch"/> holds the second row
    /// <c>EQ(G1, ·)</c> (<paramref name="n"/> scalars) and, for the batched path, <see cref="FillEq"/>'s
    /// per-level product scratch (<c>ceil(n/2)</c> scalars) after it; the caller owns it (at least
    /// <paramref name="n"/> scalars are required) and the pool clears it on return.
    /// </para>
    /// </remarks>
    /// <param name="logn">The number of binding rounds.</param>
    /// <param name="n">The number of entries to fill.</param>
    /// <param name="g0">The first binding point <c>G0</c>, <paramref name="logn"/> canonical scalars.</param>
    /// <param name="g1">The second binding point <c>G1</c>, <paramref name="logn"/> canonical scalars.</param>
    /// <param name="alpha">The fold coefficient.</param>
    /// <param name="add">Field addition (the <c>EQ(G0) + alpha·EQ(G1)</c> combine on the scalar path).</param>
    /// <param name="subtract">Field subtraction (the <c>w·(1 − G)</c> low halves inside <see cref="FillEq"/>).</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="curve">The curve parameter the delegates take.</param>
    /// <param name="one">The field multiplicative one in the working domain (the profile's <c>WorkingOne</c>).</param>
    /// <param name="eq">Receives <paramref name="n"/> canonical scalars.</param>
    /// <param name="broadcastMultiplyAccumulate">The optional broadcast-scalar fused multiply primitive; supplied on the GF(2^128) path to batch both fills and the combine, <see langword="null"/> for the scalar fallback.</param>
    /// <param name="scratch">The working scratch: at least <paramref name="n"/> scalars for <c>EQ(G1, ·)</c>, plus <c>ceil(n/2)</c> more to engage the batched path. Caller-owned; the pool clears it on return.</param>
    public static void RawEq2(
        int logn,
        int n,
        ReadOnlySpan<byte> g0,
        ReadOnlySpan<byte> g1,
        ReadOnlySpan<byte> alpha,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        ReadOnlySpan<byte> one,
        Span<byte> eq,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null,
        Span<byte> scratch = default)
    {
        //The non-null delegate is the GF/Fp discriminator (the curve == None clause is a redundant
        //secondary guard); the batched path also needs FillEq's per-level product scratch on top of the
        //EQ(G1, ·) row.
        int productScalars = CeilShift(n, 1);
        bool batch = broadcastMultiplyAccumulate is not null
            && curve == CurveParameterSet.None
            && scratch.Length >= (n + productScalars) * ScalarSize;

        //tmp carries EQ(G1, ·); the batched path carves FillEq's product scratch after it.
        Span<byte> tmp = scratch[..(n * ScalarSize)];
        Span<byte> productScratch = batch ? scratch.Slice(n * ScalarSize, productScalars * ScalarSize) : default;
        ScalarBroadcastMultiplyAccumulateDelegate? fillBroadcast = batch ? broadcastMultiplyAccumulate : null;

        //eq[i] = EQ(G0, i); tmp[i] = EQ(G1, i). The two buffers are disjoint, so the G0 fill completes
        //before the G1 fill and neither reads the other.
        FillEq(logn, n, g0, subtract, multiply, curve, one, eq, fillBroadcast, productScratch);
        FillEq(logn, n, g1, subtract, multiply, curve, one, tmp, fillBroadcast, productScratch);

        //eq[i] += alpha·tmp[i]. Batched: one fused multiply-accumulate. Scalar: the multiply-then-add the
        //reference's leaf performs with alpha folded into the w1 seed (alpha·EQ(G1, ·)).
        if(batch)
        {
            broadcastMultiplyAccumulate!(alpha, tmp[..(n * ScalarSize)], eq[..(n * ScalarSize)], true, n, curve);
        }
        else
        {
            Span<byte> product = stackalloc byte[ScalarSize];
            Span<byte> sum = stackalloc byte[ScalarSize];
            for(int i = 0; i < n; i++)
            {
                Span<byte> eqi = eq.Slice(i * ScalarSize, ScalarSize);
                multiply(alpha, tmp.Slice(i * ScalarSize, ScalarSize), product, curve);
                add(eqi, product, sum, curve);
                sum.CopyTo(eqi);
            }
        }
    }


    //ceil(a / 2^n) for a != 0, the reference's ceilshr: 1 + ((a - 1) >> n).
    private static int CeilShift(int a, int shift) => 1 + ((a - 1) >> shift);


    //1 - x: the real field subtraction (over GF(2) this is one XOR x). The one is the working-domain
    //multiplicative one threaded from the profile.
    private static void OneMinus(ReadOnlySpan<byte> x, Span<byte> result, ScalarSubtractDelegate subtract, CurveParameterSet curve, ReadOnlySpan<byte> one)
    {
        subtract(one, x, result, curve);
    }
}
