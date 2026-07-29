using System;
using System.Collections.Generic;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The Logic/BitW gadget surface, a faithful port of google/longfellow-zk's <c>Logic&lt;Field,
/// Backend&gt;</c> (<c>logic.h</c>): arithmetization of boolean logic and bit-vector arithmetic over
/// a <see cref="LongfellowLogicBackend"/>, built on the affine bit representation
/// <see cref="LongfellowBitWire"/> (the reference's <c>BitW</c>, standing for <c>c0 + c1·x</c> in the
/// standard basis where <c>TRUE</c> maps to the field one and <c>FALSE</c> to the field zero).
/// </summary>
/// <remarks>
/// <para>
/// Bit vectors are plain <see cref="LongfellowBitWire"/> arrays rather than a distinct
/// <c>bitvec&lt;N&gt;</c> wrapper type, so the reference's parallel "scalar gate" and "vector gate"
/// families (<c>land</c>/<c>vand</c>, <c>lxor</c>/<c>vxor</c>, and so on) collapse in this port into
/// overloads of one name distinguished by whether the parameter is a single
/// <see cref="LongfellowBitWire"/> or an array of them; likewise the reference's <c>eq</c>/<c>lt</c>/
/// <c>leq</c> and their <c>v</c>-prefixed bitvec-typed twins (<c>veq</c>/<c>vlt</c>/<c>vleq</c>)
/// collapse into <see cref="Equal(LongfellowBitWire[], LongfellowBitWire[])"/>,
/// <see cref="LessThan(LongfellowBitWire[], LongfellowBitWire[])"/> and
/// <see cref="LessThanOrEqual(LongfellowBitWire[], LongfellowBitWire[])"/>, each with a
/// <see cref="ulong"/>-immediate overload standing in for the reference's second bitvec-vs-scalar
/// overload. The reference's fixed-width type aliases (<c>v1</c>, <c>v8</c>, <c>v32</c>, ...) become
/// the named <c>BitWidth*</c> constants on this class, passed explicitly wherever the reference would
/// select a width through the alias.
/// </para>
/// <para>
/// The reference's trivial field/backend re-exports (<c>addf</c>, <c>mulf</c>, <c>negf</c>,
/// <c>zero</c>/<c>one</c>/<c>mone</c>, <c>elt</c>, and the bare <c>add</c>/<c>mul</c>/<c>sub</c>/
/// <c>konst</c>/<c>axpy</c>/<c>apy</c> forwards to the backend) are not re-exported here: they add no
/// behavior beyond what <see cref="Field"/>'s <see cref="LongfellowLogicFieldOperations.Compiler"/>
/// and <see cref="Backend"/> already expose publicly, so downstream code reaches those directly
/// instead of through a duplicate forwarding surface.
/// </para>
/// <para>
/// Every reference recursion whose shape is the midpoint split <c>im = i0 + (i1 - i0) / 2</c> with a
/// post-order combine (the ranged folds, the generic and Sklansky scans, the equality/less-than
/// reductions, parity, and the Karatsuba polynomial multiplier) is rewritten here as an explicit-stack
/// traversal that reproduces the exact association tree the recursion would have built; the shared
/// engine is the private generic <see cref="ReduceRange{T}"/> for the value-producing folds, and a
/// dedicated stack-based traversal apiece for the in-place scans and the array-producing Karatsuba
/// recurrence, since those do not fit the single-value reduction shape.
/// </para>
/// <para>
/// The ranged folds' empty-range base values (<c>konst(0)</c>, <c>konst(1)</c>, <c>bit(1)</c>,
/// <c>bit(0)</c>) are constructed through a deferred <see cref="Func{TResult}"/> factory rather than
/// eagerly, because each of those bases is itself a circuit node: evaluating it unconditionally on
/// every call (even when the range is non-empty and the value is discarded) would touch the
/// compiling backend's common-subexpression table on every invocation, inflating the eliminated-
/// subexpression telemetry beyond what the reference — which only ever evaluates the base case's
/// branch — produces.
/// </para>
/// </remarks>
internal sealed class LongfellowLogic
{
    /// <summary>The reference's <c>v1</c> width alias.</summary>
    public const int BitWidth1 = 1;

    /// <summary>The reference's <c>v4</c> width alias.</summary>
    public const int BitWidth4 = 4;

    /// <summary>The reference's <c>v8</c> width alias.</summary>
    public const int BitWidth8 = 8;

    /// <summary>The reference's <c>v16</c> width alias.</summary>
    public const int BitWidth16 = 16;

    /// <summary>The reference's <c>v32</c> width alias.</summary>
    public const int BitWidth32 = 32;

    /// <summary>The reference's <c>v64</c> width alias.</summary>
    public const int BitWidth64 = 64;

    /// <summary>The reference's <c>v128</c> width alias.</summary>
    public const int BitWidth128 = 128;

    /// <summary>The reference's <c>v129</c> width alias.</summary>
    public const int BitWidth129 = 129;

    /// <summary>The reference's <c>v256</c> width alias.</summary>
    public const int BitWidth256 = 256;

    /// <summary>The widest bit count <see cref="AsScalar"/> and <see cref="Bits"/> accept, matching the reference's <c>check(N &lt;= 64)</c>/<c>check(n &lt;= 64)</c> (both bound to the native <see cref="ulong"/> scalar they encode into or from).</summary>
    private const int MaxNativeScalarBitWidth = 64;

    /// <summary>The wider of the two widths <see cref="Gf2PolynomialMultiplierKaratsuba"/> recurses on (the reference's <c>w == 128</c> arm).</summary>
    private const int KaratsubaHighWidth = 128;

    /// <summary>The narrower of the two widths <see cref="Gf2PolynomialMultiplierKaratsuba"/> recurses on, and the threshold below which it falls back to the schoolbook multiplier (the reference's <c>w == 64</c> arm and <c>w &lt; 64</c> guard).</summary>
    private const int KaratsubaMidWidth = 64;

    private readonly LongfellowLogicBackend backend;
    private readonly LongfellowLogicFieldOperations field;

    /// <summary>
    /// A carry-propagation scan over parallel generate/propagate arrays (the reference's
    /// <c>ripple_scan</c>/<c>sklansky_scan</c>, passed as a member-function pointer to
    /// <c>generic_gp_add</c>/<c>generic_gp_sub</c>).
    /// </summary>
    /// <param name="generate">The generate array, mutated in place over <paramref name="i0"/>..<paramref name="i1"/>.</param>
    /// <param name="propagate">The propagate array, mutated in place over <paramref name="i0"/>..<paramref name="i1"/>.</param>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    private delegate void LongfellowGpScanDelegate(LongfellowBitWire[] generate, LongfellowBitWire[] propagate, int i0, int i1);

    /// <summary>
    /// The 128-row sparse tap table <see cref="Gf2128Multiply"/> folds the Karatsuba product through
    /// (the reference's <c>gf2_128_mul</c> taps array, generated by a sage script over the field
    /// <c>GF(2^128)</c> defined by <c>x^128 + x^7 + x^2 + x + 1</c>): row <c>i</c> lists the indices
    /// into the 256-coefficient Karatsuba product whose parity is bit <c>i</c> of the reduced result.
    /// </summary>
    public static int[][] Gf2128MultiplicationTaps { get; } =
    [
        [0, 128, 249, 254],
        [1, 128, 129, 249, 250, 254],
        [2, 128, 129, 130, 249, 250, 251, 254],
        [3, 129, 130, 131, 250, 251, 252],
        [4, 130, 131, 132, 251, 252, 253],
        [5, 131, 132, 133, 252, 253, 254],
        [6, 132, 133, 134, 253, 254],
        [7, 128, 133, 134, 135, 249],
        [8, 129, 134, 135, 136, 250],
        [9, 130, 135, 136, 137, 251],
        [10, 131, 136, 137, 138, 252],
        [11, 132, 137, 138, 139, 253],
        [12, 133, 138, 139, 140, 254],
        [13, 134, 139, 140, 141],
        [14, 135, 140, 141, 142],
        [15, 136, 141, 142, 143],
        [16, 137, 142, 143, 144],
        [17, 138, 143, 144, 145],
        [18, 139, 144, 145, 146],
        [19, 140, 145, 146, 147],
        [20, 141, 146, 147, 148],
        [21, 142, 147, 148, 149],
        [22, 143, 148, 149, 150],
        [23, 144, 149, 150, 151],
        [24, 145, 150, 151, 152],
        [25, 146, 151, 152, 153],
        [26, 147, 152, 153, 154],
        [27, 148, 153, 154, 155],
        [28, 149, 154, 155, 156],
        [29, 150, 155, 156, 157],
        [30, 151, 156, 157, 158],
        [31, 152, 157, 158, 159],
        [32, 153, 158, 159, 160],
        [33, 154, 159, 160, 161],
        [34, 155, 160, 161, 162],
        [35, 156, 161, 162, 163],
        [36, 157, 162, 163, 164],
        [37, 158, 163, 164, 165],
        [38, 159, 164, 165, 166],
        [39, 160, 165, 166, 167],
        [40, 161, 166, 167, 168],
        [41, 162, 167, 168, 169],
        [42, 163, 168, 169, 170],
        [43, 164, 169, 170, 171],
        [44, 165, 170, 171, 172],
        [45, 166, 171, 172, 173],
        [46, 167, 172, 173, 174],
        [47, 168, 173, 174, 175],
        [48, 169, 174, 175, 176],
        [49, 170, 175, 176, 177],
        [50, 171, 176, 177, 178],
        [51, 172, 177, 178, 179],
        [52, 173, 178, 179, 180],
        [53, 174, 179, 180, 181],
        [54, 175, 180, 181, 182],
        [55, 176, 181, 182, 183],
        [56, 177, 182, 183, 184],
        [57, 178, 183, 184, 185],
        [58, 179, 184, 185, 186],
        [59, 180, 185, 186, 187],
        [60, 181, 186, 187, 188],
        [61, 182, 187, 188, 189],
        [62, 183, 188, 189, 190],
        [63, 184, 189, 190, 191],
        [64, 185, 190, 191, 192],
        [65, 186, 191, 192, 193],
        [66, 187, 192, 193, 194],
        [67, 188, 193, 194, 195],
        [68, 189, 194, 195, 196],
        [69, 190, 195, 196, 197],
        [70, 191, 196, 197, 198],
        [71, 192, 197, 198, 199],
        [72, 193, 198, 199, 200],
        [73, 194, 199, 200, 201],
        [74, 195, 200, 201, 202],
        [75, 196, 201, 202, 203],
        [76, 197, 202, 203, 204],
        [77, 198, 203, 204, 205],
        [78, 199, 204, 205, 206],
        [79, 200, 205, 206, 207],
        [80, 201, 206, 207, 208],
        [81, 202, 207, 208, 209],
        [82, 203, 208, 209, 210],
        [83, 204, 209, 210, 211],
        [84, 205, 210, 211, 212],
        [85, 206, 211, 212, 213],
        [86, 207, 212, 213, 214],
        [87, 208, 213, 214, 215],
        [88, 209, 214, 215, 216],
        [89, 210, 215, 216, 217],
        [90, 211, 216, 217, 218],
        [91, 212, 217, 218, 219],
        [92, 213, 218, 219, 220],
        [93, 214, 219, 220, 221],
        [94, 215, 220, 221, 222],
        [95, 216, 221, 222, 223],
        [96, 217, 222, 223, 224],
        [97, 218, 223, 224, 225],
        [98, 219, 224, 225, 226],
        [99, 220, 225, 226, 227],
        [100, 221, 226, 227, 228],
        [101, 222, 227, 228, 229],
        [102, 223, 228, 229, 230],
        [103, 224, 229, 230, 231],
        [104, 225, 230, 231, 232],
        [105, 226, 231, 232, 233],
        [106, 227, 232, 233, 234],
        [107, 228, 233, 234, 235],
        [108, 229, 234, 235, 236],
        [109, 230, 235, 236, 237],
        [110, 231, 236, 237, 238],
        [111, 232, 237, 238, 239],
        [112, 233, 238, 239, 240],
        [113, 234, 239, 240, 241],
        [114, 235, 240, 241, 242],
        [115, 236, 241, 242, 243],
        [116, 237, 242, 243, 244],
        [117, 238, 243, 244, 245],
        [118, 239, 244, 245, 246],
        [119, 240, 245, 246, 247],
        [120, 241, 246, 247, 248],
        [121, 242, 247, 248, 249],
        [122, 243, 248, 249, 250],
        [123, 244, 249, 250, 251],
        [124, 245, 250, 251, 252],
        [125, 246, 251, 252, 253],
        [126, 247, 252, 253, 254],
        [127, 248, 253, 254],
    ];

    /// <summary>The empty bit-vector shared by <see cref="Gf2PolynomialMultiplierKaratsuba"/>'s combine frames, which carry no operands of their own.</summary>
    private static LongfellowBitWire[] EmptyBitWireVector { get; } = [];

    /// <summary>The backend every gate ultimately lowers to (the reference's <c>bk_</c>).</summary>
    public LongfellowLogicBackend Backend => this.backend;

    /// <summary>The field-operation bundle this gadget runs over (the reference's <c>f_</c>).</summary>
    public LongfellowLogicFieldOperations Field => this.field;


    /// <summary>
    /// Constructs the gadget over a backend and its field-operation bundle.
    /// </summary>
    /// <param name="backend">The backend every gate lowers to.</param>
    /// <param name="field">The field-operation bundle.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="backend"/> or <paramref name="field"/> is <see langword="null"/>.</exception>
    public LongfellowLogic(LongfellowLogicBackend backend, LongfellowLogicFieldOperations field)
    {
        ArgumentNullException.ThrowIfNull(backend);
        ArgumentNullException.ThrowIfNull(field);

        this.backend = backend;
        this.field = field;
    }


    /// <summary>
    /// Reads a bit's affine value <c>c0 + c1·x</c> under a different pair of coefficients without
    /// touching the backend at all (the reference's <c>rebase</c>): given <c>v(x) = c0 + c1·x</c>,
    /// returns the representation of <c>d0 + d1·v(x)</c> over the same underlying wire.
    /// </summary>
    /// <param name="d0">The new constant term, canonical big-endian.</param>
    /// <param name="d1">The new linear coefficient, canonical big-endian.</param>
    /// <param name="v">The bit to rebase.</param>
    /// <returns>The rebased bit, over the same wire as <paramref name="v"/>.</returns>
    public LongfellowBitWire Rebase(ReadOnlySpan<byte> d0, ReadOnlySpan<byte> d1, LongfellowBitWire v)
    {
        byte[] constantTerm = AddConstant(d0, MultiplyConstant(d1, v.ConstantTerm.Span));
        byte[] linearCoefficient = MultiplyConstant(d1, v.LinearCoefficient.Span);

        return new LongfellowBitWire(constantTerm, linearCoefficient, v.Wire);
    }


    /// <summary>
    /// Reads a bit's affine value onto the backend (the reference's <c>eval</c>): always scales the
    /// underlying wire by the linear coefficient, and adds the constant term only when it is nonzero.
    /// </summary>
    /// <param name="v">The bit to read.</param>
    /// <returns>The wire holding the bit's value.</returns>
    public int Eval(LongfellowBitWire v)
    {
        int r = backend.MultiplyScaled(v.LinearCoefficient.Span, v.Wire);
        if (!LongfellowCompilerFieldOperations.ElementIsZero(v.ConstantTerm.Span))
        {
            r = backend.Add(backend.Constant(v.ConstantTerm.Span), r);
        }

        return r;
    }


    /// <summary>
    /// Computes in the circuit what <c>F.of_scalar(Σ v[i]·2^i)</c> would compute out of circuit (the
    /// reference's <c>as_scalar</c>), weighting each bit by <see cref="LongfellowLogicFieldOperations.Beta(int)"/>
    /// rather than a literal power of two, then re-runs the representability check the reference
    /// performs by evaluating <see cref="LongfellowLogicFieldOperations.OfScalar"/> at the all-ones
    /// value out of circuit.
    /// </summary>
    /// <param name="v">The bits, least significant first.</param>
    /// <returns>The wire holding the scalar's value.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="v"/> has more than <see cref="MaxNativeScalarBitWidth"/> bits.</exception>
    public int AsScalar(LongfellowBitWire[] v)
    {
        if (v.Length > MaxNativeScalarBitWidth)
        {
            throw new ArgumentOutOfRangeException(nameof(v), $"as_scalar covers at most {MaxNativeScalarBitWidth} bits.");
        }

        int r = backend.Constant(field.Compiler.Zero.Span);
        ulong allOnes = 0;
        for (int i = 0; i < v.Length; i++)
        {
            r = backend.Axpy(r, field.Beta(i).Span, Eval(v[i]));
            allOnes += 1UL << i;
        }

        _ = field.OfScalar(allOnes);

        return r;
    }


    /// <summary>
    /// A bit in its own basis <c>b + 0·konst(1)</c>, allowing compile-time constant folding (the
    /// reference's <c>bit</c>).
    /// </summary>
    /// <param name="value">The bit value: zero or nonzero.</param>
    /// <returns>The bit, over a real constant-one wire.</returns>
    public LongfellowBitWire Bit(int value)
    {
        ReadOnlyMemory<byte> constantTerm = value == 0 ? field.Compiler.Zero : field.Compiler.One;

        return new LongfellowBitWire(constantTerm, field.Compiler.Zero, backend.Constant(field.Compiler.One.Span));
    }


    /// <summary>
    /// Fills a destination with the bits of a scalar, least significant first (the reference's
    /// <c>bits</c>).
    /// </summary>
    /// <param name="destination">The bits to fill.</param>
    /// <param name="value">The scalar to decompose.</param>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="destination"/> has more than <see cref="MaxNativeScalarBitWidth"/> entries.</exception>
    public void Bits(Span<LongfellowBitWire> destination, ulong value)
    {
        if (destination.Length > MaxNativeScalarBitWidth)
        {
            throw new ArgumentOutOfRangeException(nameof(destination), $"bits covers at most {MaxNativeScalarBitWidth} bits.");
        }

        for (int i = 0; i < destination.Length; i++)
        {
            destination[i] = Bit((int)((value >> i) & 1UL));
        }
    }


    /// <summary>
    /// Allocates and fills a bit vector from a scalar, least significant first (the reference's
    /// <c>vbit&lt;N&gt;</c>).
    /// </summary>
    /// <param name="width">The vector width.</param>
    /// <param name="value">The scalar to decompose.</param>
    /// <returns>The bit vector.</returns>
    public LongfellowBitWire[] BitVector(int width, ulong value)
    {
        var result = new LongfellowBitWire[width];
        Bits(result, value);

        return result;
    }


    /// <summary>The reference's <c>lnot</c>: a pure representation change, <c>1 - x</c> in the standard basis.</summary>
    /// <param name="x">The bit to negate.</param>
    /// <returns>The negated bit.</returns>
    public LongfellowBitWire Not(LongfellowBitWire x) => Rebase(field.Compiler.One.Span, field.Compiler.MinusOne.Span, x);


    /// <summary>The reference's <c>vnot</c>: elementwise <see cref="Not(LongfellowBitWire)"/>.</summary>
    /// <param name="x">The bits to negate.</param>
    /// <returns>The negated bits.</returns>
    public LongfellowBitWire[] Not(LongfellowBitWire[] x)
    {
        var r = new LongfellowBitWire[x.Length];
        for (int i = 0; i < x.Length; i++)
        {
            r[i] = Not(x[i]);
        }

        return r;
    }


    /// <summary>The reference's <c>land</c>: <c>a * b</c> in the standard basis.</summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <returns>The conjunction.</returns>
    public LongfellowBitWire And(LongfellowBitWire a, LongfellowBitWire b) => Mulv(a, b);


    /// <summary>The reference's <c>vand</c>: elementwise <see cref="And(LongfellowBitWire, LongfellowBitWire)"/>.</summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <returns>The elementwise conjunction.</returns>
    public LongfellowBitWire[] And(LongfellowBitWire[] a, LongfellowBitWire[] b)
    {
        var r = new LongfellowBitWire[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            r[i] = And(a[i], b[i]);
        }

        return r;
    }


    /// <summary>The reference's <c>vand(BitW, bitvec)</c>: one bit conjoined against every element of a vector.</summary>
    /// <param name="a">The single operand.</param>
    /// <param name="b">The vector operand.</param>
    /// <returns>The elementwise conjunction.</returns>
    public LongfellowBitWire[] And(LongfellowBitWire a, LongfellowBitWire[] b)
    {
        var r = new LongfellowBitWire[b.Length];
        for (int i = 0; i < b.Length; i++)
        {
            r[i] = And(a, b[i]);
        }

        return r;
    }


    /// <summary>The reference's <c>lor</c>: <c>~(~a &amp; ~b)</c>.</summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <returns>The disjunction.</returns>
    public LongfellowBitWire Or(LongfellowBitWire a, LongfellowBitWire b) => Not(And(Not(a), Not(b)));


    /// <summary>The reference's <c>vor</c>: elementwise <see cref="Or(LongfellowBitWire, LongfellowBitWire)"/>.</summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <returns>The elementwise disjunction.</returns>
    public LongfellowBitWire[] Or(LongfellowBitWire[] a, LongfellowBitWire[] b)
    {
        var r = new LongfellowBitWire[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            r[i] = Or(a[i], b[i]);
        }

        return r;
    }


    /// <summary>The reference's <c>lor_exclusive</c>: the disjunction of two mutually exclusive bits, computed as their sum.</summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <returns>The exclusive disjunction.</returns>
    public LongfellowBitWire OrExclusive(LongfellowBitWire a, LongfellowBitWire b) => Addv(a, b);


    /// <summary>The reference's <c>vor_exclusive</c>: elementwise <see cref="OrExclusive(LongfellowBitWire, LongfellowBitWire)"/>.</summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <returns>The elementwise exclusive disjunction.</returns>
    public LongfellowBitWire[] OrExclusive(LongfellowBitWire[] a, LongfellowBitWire[] b)
    {
        var r = new LongfellowBitWire[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            r[i] = OrExclusive(a[i], b[i]);
        }

        return r;
    }


    /// <summary>
    /// The reference's <c>lxor</c>: over characteristic two, plain <see cref="OrExclusive(LongfellowBitWire, LongfellowBitWire)"/>;
    /// over an odd-prime field, a basis change into the <c>{-1, 1}</c> "xor basis" where xor is
    /// multiplication (<c>mtwo = -2</c>, <c>half = 2⁻¹</c>), a single <see cref="And(LongfellowBitWire, LongfellowBitWire)"/>
    /// in that basis, then a basis change back.
    /// </summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <returns>The exclusive-or.</returns>
    public LongfellowBitWire Xor(LongfellowBitWire a, LongfellowBitWire b)
    {
        if (field.Compiler.IsCharacteristicTwo)
        {
            return Addv(a, b);
        }

        ReadOnlyMemory<byte> minusTwo = field.Negate(field.Two.Span);
        ReadOnlyMemory<byte> half = field.Half;
        ReadOnlyMemory<byte> minusHalf = field.Negate(half.Span);

        LongfellowBitWire a1 = Rebase(field.Compiler.One.Span, minusTwo.Span, a);
        LongfellowBitWire b1 = Rebase(field.Compiler.One.Span, minusTwo.Span, b);
        LongfellowBitWire p = Mulv(a1, b1);

        return Rebase(half.Span, minusHalf.Span, p);
    }


    /// <summary>The reference's <c>vxor</c>: elementwise <see cref="Xor(LongfellowBitWire, LongfellowBitWire)"/>.</summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <returns>The elementwise exclusive-or.</returns>
    public LongfellowBitWire[] Xor(LongfellowBitWire[] a, LongfellowBitWire[] b)
    {
        var r = new LongfellowBitWire[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            r[i] = Xor(a[i], b[i]);
        }

        return r;
    }


    /// <summary>The reference's <c>lxor3</c>: <c>a ^ b ^ c</c>, left-associated exactly as the reference chains it.</summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <param name="c">The third operand.</param>
    /// <returns>The three-way exclusive-or.</returns>
    public LongfellowBitWire Xor(LongfellowBitWire a, LongfellowBitWire b, LongfellowBitWire c) => Xor(Xor(a, b), c);


    /// <summary>The reference's <c>vxor3</c>: elementwise <see cref="Xor(LongfellowBitWire, LongfellowBitWire, LongfellowBitWire)"/>.</summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <param name="c">The third operand.</param>
    /// <returns>The elementwise three-way exclusive-or.</returns>
    public LongfellowBitWire[] Xor(LongfellowBitWire[] a, LongfellowBitWire[] b, LongfellowBitWire[] c)
    {
        var r = new LongfellowBitWire[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            r[i] = Xor(a[i], b[i], c[i]);
        }

        return r;
    }


    /// <summary>The reference's <c>limplies</c>: <c>a =&gt; b</c>, computed as <c>~a | b</c>.</summary>
    /// <param name="a">The antecedent.</param>
    /// <param name="b">The consequent.</param>
    /// <returns>The implication.</returns>
    public LongfellowBitWire Implies(LongfellowBitWire a, LongfellowBitWire b) => Or(Not(a), b);


    /// <summary>The reference's <c>lCh</c> (sha256 <c>Ch</c>): <c>(x &amp; y) ^ (~x &amp; z)</c>.</summary>
    /// <param name="x">The selector.</param>
    /// <param name="y">The value chosen when <paramref name="x"/> is true.</param>
    /// <param name="z">The value chosen when <paramref name="x"/> is false.</param>
    /// <returns>The choice.</returns>
    public LongfellowBitWire Choose(LongfellowBitWire x, LongfellowBitWire y, LongfellowBitWire z) => OrExclusive(And(x, y), And(Not(x), z));


    /// <summary>The reference's <c>vCh</c>: elementwise <see cref="Choose(LongfellowBitWire, LongfellowBitWire, LongfellowBitWire)"/>.</summary>
    /// <param name="x">The selector vector.</param>
    /// <param name="y">The value vector chosen where <paramref name="x"/> is true.</param>
    /// <param name="z">The value vector chosen where <paramref name="x"/> is false.</param>
    /// <returns>The elementwise choice.</returns>
    public LongfellowBitWire[] Choose(LongfellowBitWire[] x, LongfellowBitWire[] y, LongfellowBitWire[] z)
    {
        var r = new LongfellowBitWire[x.Length];
        for (int i = 0; i < x.Length; i++)
        {
            r[i] = Choose(x[i], y[i], z[i]);
        }

        return r;
    }


    /// <summary>The reference's <c>lMaj</c> (sha256 <c>Maj</c>): <c>(x &amp; y) ^ (x &amp; z) ^ (y &amp; z)</c>, computed via the carry-basis identity <c>(x &amp; y) | ((x ^ y) &amp; z)</c>.</summary>
    /// <param name="x">The first operand.</param>
    /// <param name="y">The second operand.</param>
    /// <param name="z">The third operand.</param>
    /// <returns>The majority.</returns>
    public LongfellowBitWire Majority(LongfellowBitWire x, LongfellowBitWire y, LongfellowBitWire z) => OrExclusive(And(x, y), And(Xor(x, y), z));


    /// <summary>The reference's <c>vMaj</c>: elementwise <see cref="Majority(LongfellowBitWire, LongfellowBitWire, LongfellowBitWire)"/>.</summary>
    /// <param name="x">The first operand vector.</param>
    /// <param name="y">The second operand vector.</param>
    /// <param name="z">The third operand vector.</param>
    /// <returns>The elementwise majority.</returns>
    public LongfellowBitWire[] Majority(LongfellowBitWire[] x, LongfellowBitWire[] y, LongfellowBitWire[] z)
    {
        var r = new LongfellowBitWire[x.Length];
        for (int i = 0; i < x.Length; i++)
        {
            r[i] = Majority(x[i], y[i], z[i]);
        }

        return r;
    }


    /// <summary>The reference's <c>lmul(BitW, EltW)</c>: the product of a logic value and a field element.</summary>
    /// <param name="a">The bit.</param>
    /// <param name="b">The field element wire.</param>
    /// <returns>The wire holding the product.</returns>
    public int Multiply(LongfellowBitWire a, int b) => Eval(Mulv(a, new LongfellowBitWire(field, b)));


    /// <summary>The reference's <c>lmul(EltW, BitW)</c> overload: <see cref="Multiply(LongfellowBitWire, int)"/> with the operands swapped.</summary>
    /// <param name="b">The field element wire.</param>
    /// <param name="a">The bit.</param>
    /// <returns>The wire holding the product.</returns>
    public int Multiply(int b, LongfellowBitWire a) => Multiply(a, b);


    /// <summary>The reference's <c>mux(BitW, BitW, BitW)</c>: a logic-valued multiplexer.</summary>
    /// <param name="control">The selector.</param>
    /// <param name="ifTrue">The value chosen when <paramref name="control"/> is true.</param>
    /// <param name="ifFalse">The value chosen when <paramref name="control"/> is false.</param>
    /// <returns>The selected bit.</returns>
    public LongfellowBitWire Mux(LongfellowBitWire control, LongfellowBitWire ifTrue, LongfellowBitWire ifFalse) => OrExclusive(And(control, ifTrue), And(Not(control), ifFalse));


    /// <summary>The reference's <c>mux(BitW, EltW, EltW)</c>: a field-element-valued multiplexer.</summary>
    /// <param name="control">The selector.</param>
    /// <param name="ifTrue">The wire chosen when <paramref name="control"/> is true.</param>
    /// <param name="ifFalse">The wire chosen when <paramref name="control"/> is false.</param>
    /// <returns>The wire holding the selected value.</returns>
    public int Mux(LongfellowBitWire control, int ifTrue, int ifFalse) => backend.Add(Multiply(control, ifTrue), Multiply(Not(control), ifFalse));


    /// <summary>The reference's <c>vmux</c>: elementwise <see cref="Mux(LongfellowBitWire, LongfellowBitWire, LongfellowBitWire)"/> into a destination.</summary>
    /// <param name="control">The selector.</param>
    /// <param name="destination">Receives the selected bits.</param>
    /// <param name="ifTrue">The vector chosen where <paramref name="control"/> is true.</param>
    /// <param name="ifFalse">The vector chosen where <paramref name="control"/> is false.</param>
    public void Mux(LongfellowBitWire control, LongfellowBitWire[] destination, LongfellowBitWire[] ifTrue, LongfellowBitWire[] ifFalse)
    {
        for (int i = 0; i < destination.Length; i++)
        {
            destination[i] = Mux(control, ifTrue[i], ifFalse[i]);
        }
    }


    /// <summary>
    /// The reference's ranged <c>add(i0, i1, f)</c>: <c>Σ f(i)</c> for <c>i0 &lt;= i &lt; i1</c>, folded
    /// over the reference's exact midpoint association tree via an explicit stack.
    /// </summary>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    /// <param name="f">The term at each index.</param>
    /// <returns>The wire holding the sum.</returns>
    public int Add(int i0, int i1, Func<int, int> f) => ReduceRange(i0, i1, f, (left, right) => backend.Add(left, right), () => backend.Constant(field.Compiler.Zero.Span));


    /// <summary>
    /// The reference's ranged <c>mul(i0, i1, f)</c>: <c>Π f(i)</c> for <c>i0 &lt;= i &lt; i1</c>, folded
    /// over the reference's exact midpoint association tree via an explicit stack.
    /// </summary>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    /// <param name="f">The factor at each index.</param>
    /// <returns>The wire holding the product.</returns>
    public int Multiply(int i0, int i1, Func<int, int> f) => ReduceRange(i0, i1, f, (left, right) => backend.Mul(left, right), () => backend.Constant(field.Compiler.One.Span));


    /// <summary>
    /// The reference's ranged <c>land(i0, i1, f)</c>: the conjunction of <c>f(i)</c> for <c>i0 &lt;= i
    /// &lt; i1</c>, folded over the reference's exact midpoint association tree via an explicit stack.
    /// </summary>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    /// <param name="f">The bit at each index.</param>
    /// <returns>The conjunction.</returns>
    public LongfellowBitWire And(int i0, int i1, Func<int, LongfellowBitWire> f) => ReduceRange(i0, i1, f, (left, right) => And(left, right), () => Bit(1));


    /// <summary>
    /// The reference's ranged <c>lor(i0, i1, f)</c>: the disjunction of <c>f(i)</c> for <c>i0 &lt;= i
    /// &lt; i1</c>, folded over the reference's exact midpoint association tree via an explicit stack.
    /// </summary>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    /// <param name="f">The bit at each index.</param>
    /// <returns>The disjunction.</returns>
    public LongfellowBitWire Or(int i0, int i1, Func<int, LongfellowBitWire> f) => ReduceRange(i0, i1, f, (left, right) => Or(left, right), () => Bit(0));


    /// <summary>
    /// The reference's ranged <c>lor_exclusive(i0, i1, f)</c>: the exclusive disjunction of <c>f(i)</c>
    /// for <c>i0 &lt;= i &lt; i1</c>, folded over the reference's exact midpoint association tree via
    /// an explicit stack.
    /// </summary>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    /// <param name="f">The bit at each index.</param>
    /// <returns>The exclusive disjunction.</returns>
    public LongfellowBitWire OrExclusive(int i0, int i1, Func<int, LongfellowBitWire> f) => ReduceRange(i0, i1, f, (left, right) => OrExclusive(left, right), () => Bit(0));


    /// <summary>
    /// The reference's <c>or_of_and</c>: the disjunction, over each clause, of the conjunction of that
    /// clause's bits.
    /// </summary>
    /// <param name="clausesOfAnds">The clauses; each is a list of bits to conjoin.</param>
    /// <returns>The disjunction of the clauses' conjunctions.</returns>
    public LongfellowBitWire OrOfAnd(LongfellowBitWire[][] clausesOfAnds)
    {
        var ands = new LongfellowBitWire[clausesOfAnds.Length];
        for (int i = 0; i < clausesOfAnds.Length; i++)
        {
            LongfellowBitWire[] clause = clausesOfAnds[i];
            ands[i] = And(0, clause.Length, index => clause[index]);
        }

        return Or(0, ands.Length, index => ands[index]);
    }


    /// <summary>The reference's <c>assert0(EltW)</c>: asserts that a wire's value is zero.</summary>
    /// <param name="wire">The wire whose value must be zero.</param>
    /// <returns>The asserted wire, per <see cref="LongfellowLogicBackend.AssertZero"/>.</returns>
    public int AssertZero(int wire) => backend.AssertZero(wire);


    /// <summary>The reference's <c>assert0(BitW)</c>: asserts that a bit's value is zero.</summary>
    /// <param name="bit">The bit that must be zero.</param>
    /// <returns>The asserted wire.</returns>
    public int AssertZero(LongfellowBitWire bit) => AssertZero(Eval(bit));


    /// <summary>The reference's <c>vassert0</c>: asserts every bit in a vector is zero.</summary>
    /// <param name="bits">The bits that must all be zero.</param>
    public void AssertZero(LongfellowBitWire[] bits)
    {
        for (int i = 0; i < bits.Length; i++)
        {
            _ = AssertZero(bits[i]);
        }
    }


    /// <summary>The reference's <c>assert1</c>: asserts that a bit's value is one.</summary>
    /// <param name="bit">The bit that must be one.</param>
    /// <returns>The asserted wire.</returns>
    public int AssertOne(LongfellowBitWire bit) => AssertZero(Not(bit));


    /// <summary>The reference's <c>assert_eq(EltW, EltW)</c>: asserts that two wires hold equal values.</summary>
    /// <param name="left">The first wire.</param>
    /// <param name="right">The second wire.</param>
    /// <returns>The asserted wire.</returns>
    public int AssertEqual(int left, int right) => AssertZero(backend.Sub(left, right));


    /// <summary>The reference's <c>assert_eq(BitW, BitW)</c>: asserts that two bits hold equal values.</summary>
    /// <param name="left">The first bit.</param>
    /// <param name="right">The second bit.</param>
    /// <returns>The asserted wire.</returns>
    public int AssertEqual(LongfellowBitWire left, LongfellowBitWire right) => AssertZero(Xor(left, right));


    /// <summary>The reference's <c>vassert_eq(bitvec, bitvec)</c>: asserts equality elementwise.</summary>
    /// <param name="left">The first vector.</param>
    /// <param name="right">The second vector.</param>
    public void AssertEqual(LongfellowBitWire[] left, LongfellowBitWire[] right)
    {
        for (int i = 0; i < left.Length; i++)
        {
            _ = AssertEqual(left[i], right[i]);
        }
    }


    /// <summary>The reference's <c>vassert_eq(bitvec, uint64_t)</c>: asserts equality against an immediate.</summary>
    /// <param name="left">The vector.</param>
    /// <param name="right">The immediate to compare against.</param>
    public void AssertEqual(LongfellowBitWire[] left, ulong right) => AssertEqual(left, BitVector(left.Length, right));


    /// <summary>The reference's <c>assert_implies</c>: asserts that <paramref name="antecedent"/> implies <paramref name="consequent"/>.</summary>
    /// <param name="antecedent">The antecedent.</param>
    /// <param name="consequent">The consequent.</param>
    /// <returns>The asserted wire.</returns>
    public int AssertImplies(LongfellowBitWire antecedent, LongfellowBitWire consequent) => AssertOne(Implies(antecedent, consequent));


    /// <summary>The reference's <c>assert_is_bit(BitW)</c>: asserts that a bit's evaluated value is genuinely zero or one.</summary>
    /// <param name="bit">The bit to check.</param>
    /// <returns>The asserted wire.</returns>
    public int AssertIsBit(LongfellowBitWire bit) => AssertIsBit(Eval(bit));


    /// <summary>The reference's <c>assert_is_bit(EltW)</c>: asserts <c>v - v·v == 0</c>, equivalent to <c>v ∈ {0, 1}</c> without relying on any specific arithmetization.</summary>
    /// <param name="wire">The wire to check.</param>
    /// <returns>The asserted wire.</returns>
    public int AssertIsBit(int wire)
    {
        int square = backend.Mul(wire, wire);

        return AssertZero(backend.Sub(wire, square));
    }


    /// <summary>The reference's <c>vassert_is_bit</c>: asserts every element of a vector is genuinely zero or one.</summary>
    /// <param name="bits">The bits to check.</param>
    public void AssertIsBit(LongfellowBitWire[] bits)
    {
        for (int i = 0; i < bits.Length; i++)
        {
            _ = AssertIsBit(bits[i]);
        }
    }


    /// <summary>
    /// The reference's <c>assert_sum</c>: asserts that <c>a + b == c</c> in constant depth, without
    /// building an adder. Derives the generate/propagate basis from <paramref name="a"/>/<paramref name="b"/>,
    /// then derives the carry-in sequence from <paramref name="c"/> and the propagate bits and checks
    /// it satisfies the ripple recurrence.
    /// </summary>
    /// <param name="c">The claimed sum, at least two bits: the constant-depth derivation reads the
    /// first carry unconditionally, so a narrower vector has no carry to read (the reference has the
    /// same implicit precondition and never exercises a narrower width).</param>
    /// <param name="a">The first addend.</param>
    /// <param name="b">The second addend.</param>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="c"/> is narrower than two bits.</exception>
    public void AssertSum(ReadOnlySpan<LongfellowBitWire> c, ReadOnlySpan<LongfellowBitWire> a, ReadOnlySpan<LongfellowBitWire> b)
    {
        const int MinimumAssertSumWidth = 2;
        ArgumentOutOfRangeException.ThrowIfLessThan(c.Length, MinimumAssertSumWidth, nameof(c));

        int w = c.Length;
        var generate = new LongfellowBitWire[w];
        var propagate = new LongfellowBitWire[w];
        var carry = new LongfellowBitWire[w];
        for (int i = 0; i < w; i++)
        {
            generate[i] = And(a[i], b[i]);
            propagate[i] = Xor(a[i], b[i]);
        }

        _ = AssertEqual(c[0], propagate[0]);
        for (int i = 1; i < w; i++)
        {
            carry[i - 1] = Xor(c[i], propagate[i]);
        }

        _ = AssertEqual(carry[0], generate[0]);
        for (int i = 1; i + 1 < w; i++)
        {
            _ = AssertEqual(carry[i], OrExclusive(generate[i], And(carry[i - 1], propagate[i])));
        }
    }


    /// <summary>The reference's <c>ripple_carry_add</c>: <c>(carry, c) = a + b</c> via the sequential ripple scan.</summary>
    /// <param name="c">Receives the sum.</param>
    /// <param name="a">The first addend.</param>
    /// <param name="b">The second addend.</param>
    /// <returns>The carry out.</returns>
    public LongfellowBitWire RippleCarryAdd(Span<LongfellowBitWire> c, ReadOnlySpan<LongfellowBitWire> a, ReadOnlySpan<LongfellowBitWire> b) => GenericGpAdd(c, a, b, RippleScan);


    /// <summary>The reference's <c>ripple_carry_sub</c>: <c>(carry, c) = a - b</c> via the sequential ripple scan.</summary>
    /// <param name="c">Receives the difference.</param>
    /// <param name="a">The minuend.</param>
    /// <param name="b">The subtrahend.</param>
    /// <returns>The carry out.</returns>
    public LongfellowBitWire RippleCarrySubtract(Span<LongfellowBitWire> c, ReadOnlySpan<LongfellowBitWire> a, ReadOnlySpan<LongfellowBitWire> b) => GenericGpSub(c, a, b, RippleScan);


    /// <summary>The reference's <c>parallel_prefix_add</c>: <c>(carry, c) = a + b</c> via the Sklansky scan.</summary>
    /// <param name="c">Receives the sum.</param>
    /// <param name="a">The first addend.</param>
    /// <param name="b">The second addend.</param>
    /// <returns>The carry out.</returns>
    public LongfellowBitWire ParallelPrefixAdd(Span<LongfellowBitWire> c, ReadOnlySpan<LongfellowBitWire> a, ReadOnlySpan<LongfellowBitWire> b) => GenericGpAdd(c, a, b, SklanskyScan);


    /// <summary>The reference's <c>parallel_prefix_sub</c>: <c>(carry, c) = a - b</c> via the Sklansky scan.</summary>
    /// <param name="c">Receives the difference.</param>
    /// <param name="a">The minuend.</param>
    /// <param name="b">The subtrahend.</param>
    /// <returns>The carry out.</returns>
    public LongfellowBitWire ParallelPrefixSubtract(Span<LongfellowBitWire> c, ReadOnlySpan<LongfellowBitWire> a, ReadOnlySpan<LongfellowBitWire> b) => GenericGpSub(c, a, b, SklanskyScan);


    /// <summary>The reference's <c>vadd(bitvec, bitvec)</c>: the sum of two bit vectors via <see cref="ParallelPrefixAdd"/>, carry discarded.</summary>
    /// <param name="a">The first addend.</param>
    /// <param name="b">The second addend.</param>
    /// <returns>The sum.</returns>
    public LongfellowBitWire[] Add(LongfellowBitWire[] a, LongfellowBitWire[] b)
    {
        var r = new LongfellowBitWire[a.Length];
        _ = ParallelPrefixAdd(r, a, b);

        return r;
    }


    /// <summary>The reference's <c>vadd(bitvec, uint64_t)</c>: the sum of a bit vector and an immediate.</summary>
    /// <param name="a">The first addend.</param>
    /// <param name="value">The second addend, as an immediate.</param>
    /// <returns>The sum.</returns>
    public LongfellowBitWire[] Add(LongfellowBitWire[] a, ulong value) => Add(a, BitVector(a.Length, value));


    /// <summary>
    /// The reference's <c>multiplier</c>: a <c>w × w -&gt; 2w</c>-bit schoolbook multiplier. Row zero
    /// initializes the low half and the carry-in position; each later row ANDs the multiplicand's bit
    /// into the partial product and ripple-adds it into the running total in place, exactly as the
    /// reference aliases the destination and one addend of each row's add.
    /// </summary>
    /// <param name="c">Receives the <c>2w</c>-bit product.</param>
    /// <param name="a">The multiplicand, <c>w</c> bits.</param>
    /// <param name="b">The multiplier, <c>w</c> bits.</param>
    public void Multiplier(Span<LongfellowBitWire> c, ReadOnlySpan<LongfellowBitWire> a, ReadOnlySpan<LongfellowBitWire> b)
    {
        int w = a.Length;
        var t = new LongfellowBitWire[w];
        for (int i = 0; i < w; i++)
        {
            if (i == 0)
            {
                for (int j = 0; j < w; j++)
                {
                    c[j] = And(a[0], b[j]);
                }

                c[w] = Bit(0);
            }
            else
            {
                for (int j = 0; j < w; j++)
                {
                    t[j] = And(a[i], b[j]);
                }

                Span<LongfellowBitWire> cRow = c.Slice(i, w);
                LongfellowBitWire carry = RippleCarryAdd(cRow, t, cRow);
                c[i + w] = carry;
            }
        }
    }


    /// <summary>The reference's schoolbook <c>gf2_polynomial_multiplier</c>: a <c>w × w -&gt; 2w</c>-bit polynomial multiplier over <c>GF(2)</c>.</summary>
    /// <param name="width">The operand width <c>w</c>.</param>
    /// <param name="a">The first factor, <c>w</c> bits.</param>
    /// <param name="b">The second factor, <c>w</c> bits.</param>
    /// <returns>The <c>2w</c>-bit product.</returns>
    public LongfellowBitWire[] Gf2PolynomialMultiplier(int width, LongfellowBitWire[] a, LongfellowBitWire[] b)
    {
        var c = new LongfellowBitWire[2 * width];
        for (int k = 0; k < 2 * width; k++)
        {
            var terms = new List<LongfellowBitWire>(width);
            for (int i = 0; i < width; i++)
            {
                if (k >= i && k - i < width)
                {
                    terms.Add(And(a[i], b[k - i]));
                }
            }

            c[k] = Parity([.. terms]);
        }

        return c;
    }


    /// <summary>
    /// The reference's <c>gf2_polynomial_multiplier_karat</c>: the same polynomial product via the
    /// Karatsuba recurrence, wired only for width 128, width 64, or any width below 64 (which falls
    /// back to <see cref="Gf2PolynomialMultiplier"/>). The recursion is realized as an explicit stack
    /// of pending splits and a pending stitch per split, reproducing the reference's exact three-call
    /// order (the low-high cross term, then the low product, then the high product) before combining.
    /// </summary>
    /// <param name="width">The operand width.</param>
    /// <param name="a">The first factor, <paramref name="width"/> bits.</param>
    /// <param name="b">The second factor, <paramref name="width"/> bits.</param>
    /// <returns>The <c>2·width</c>-bit product.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="width"/> is not 128, not 64, and not below 64.</exception>
    public LongfellowBitWire[] Gf2PolynomialMultiplierKaratsuba(int width, LongfellowBitWire[] a, LongfellowBitWire[] b)
    {
        if (width != KaratsubaHighWidth && width != KaratsubaMidWidth && width >= KaratsubaMidWidth)
        {
            throw new ArgumentOutOfRangeException(nameof(width), "The Karatsuba recurrence is wired for width 128, width 64, or any width below 64.");
        }

        var pending = new Stack<(int Width, LongfellowBitWire[] A, LongfellowBitWire[] B, bool IsCombine)>();
        var results = new Stack<LongfellowBitWire[]>();
        pending.Push((width, a, b, false));

        while (pending.Count > 0)
        {
            (int taskWidth, LongfellowBitWire[] taskA, LongfellowBitWire[] taskB, bool isCombine) = pending.Pop();
            if (isCombine)
            {
                LongfellowBitWire[] highProduct = results.Pop();
                LongfellowBitWire[] lowProduct = results.Pop();
                LongfellowBitWire[] crossProduct = results.Pop();
                results.Push(KaratsubaStitch(taskWidth, crossProduct, lowProduct, highProduct));

                continue;
            }

            if (taskWidth < KaratsubaMidWidth)
            {
                results.Push(Gf2PolynomialMultiplier(taskWidth, taskA, taskB));

                continue;
            }

            int half = taskWidth / 2;
            var crossA = new LongfellowBitWire[half];
            var crossB = new LongfellowBitWire[half];
            for (int i = 0; i < half; i++)
            {
                crossA[i] = Xor(taskA[i], taskA[i + half]);
                crossB[i] = Xor(taskB[i], taskB[i + half]);
            }

            pending.Push((taskWidth, EmptyBitWireVector, EmptyBitWireVector, true));
            pending.Push((half, taskA[half..], taskB[half..], false));
            pending.Push((half, taskA[..half], taskB[..half], false));
            pending.Push((half, crossA, crossB, false));
        }

        return results.Pop();
    }


    /// <summary>The reference's <c>gf2_128_mul</c>: field multiplication in <c>GF(2^128)</c> via the Karatsuba product folded through <see cref="Gf2128MultiplicationTaps"/>.</summary>
    /// <param name="a">The first factor, 128 bits.</param>
    /// <param name="b">The second factor, 128 bits.</param>
    /// <returns>The 128-bit product.</returns>
    public LongfellowBitWire[] Gf2128Multiply(LongfellowBitWire[] a, LongfellowBitWire[] b) => Gf2FieldMultiply(BitWidth128, a, b, Gf2128MultiplicationTaps);


    /// <summary>The reference's <c>gf2k_mul</c>: field multiplication in <c>GF(2^w)</c> via the Karatsuba product folded through a sparse tap table.</summary>
    /// <param name="width">The field width <c>w</c>.</param>
    /// <param name="a">The first factor, <paramref name="width"/> bits.</param>
    /// <param name="b">The second factor, <paramref name="width"/> bits.</param>
    /// <param name="taps">The per-output-bit tap indices into the <c>2·width</c>-bit Karatsuba product.</param>
    /// <returns>The <paramref name="width"/>-bit product.</returns>
    public LongfellowBitWire[] Gf2FieldMultiply(int width, LongfellowBitWire[] a, LongfellowBitWire[] b, int[][] taps)
    {
        LongfellowBitWire[] t = Gf2PolynomialMultiplierKaratsuba(width, a, b);
        var c = new LongfellowBitWire[width];
        for (int i = 0; i < width; i++)
        {
            int[] row = taps[i];
            var terms = new LongfellowBitWire[row.Length];
            for (int n = 0; n < row.Length; n++)
            {
                terms[n] = t[row[n]];
            }

            c[i] = Parity(terms);
        }

        return c;
    }


    /// <summary>The reference's <c>eq0(w, a)</c>: whether every bit of <paramref name="a"/> is zero.</summary>
    /// <param name="a">The bits to check.</param>
    /// <returns>The bit that is one exactly when <paramref name="a"/> is entirely zero.</returns>
    public LongfellowBitWire EqualZero(LongfellowBitWire[] a) => EqualZeroReduce(0, a.Length, a);


    /// <summary>The reference's <c>eq</c>/<c>veq</c>: whether two bit vectors are equal.</summary>
    /// <param name="a">The first vector.</param>
    /// <param name="b">The second vector.</param>
    /// <returns>The bit that is one exactly when <paramref name="a"/> equals <paramref name="b"/>.</returns>
    public LongfellowBitWire Equal(LongfellowBitWire[] a, LongfellowBitWire[] b) => EqualReduce(0, a.Length, a, b);


    /// <summary>The reference's <c>veq(bitvec, uint64_t)</c>: equality against an immediate.</summary>
    /// <param name="a">The vector.</param>
    /// <param name="value">The immediate to compare against.</param>
    /// <returns>The bit that is one exactly when <paramref name="a"/> equals <paramref name="value"/>.</returns>
    public LongfellowBitWire Equal(LongfellowBitWire[] a, ulong value) => Equal(a, BitVector(a.Length, value));


    /// <summary>The reference's <c>lt</c>/<c>vlt</c>: whether <paramref name="a"/> is strictly less than <paramref name="b"/>, as unsigned bit vectors.</summary>
    /// <param name="a">The left operand.</param>
    /// <param name="b">The right operand.</param>
    /// <returns>The bit that is one exactly when <paramref name="a"/> &lt; <paramref name="b"/>.</returns>
    public LongfellowBitWire LessThan(LongfellowBitWire[] a, LongfellowBitWire[] b)
    {
        if (a.Length == 0)
        {
            return Bit(0);
        }

        (LongfellowBitWire equal, LongfellowBitWire less) = LessThanReduce(0, a.Length, a, b);

        return less;
    }


    /// <summary>The reference's <c>vlt(bitvec, uint64_t)</c>: strict less-than against an immediate.</summary>
    /// <param name="a">The left operand.</param>
    /// <param name="value">The right operand, as an immediate.</param>
    /// <returns>The bit that is one exactly when <paramref name="a"/> &lt; <paramref name="value"/>.</returns>
    public LongfellowBitWire LessThan(LongfellowBitWire[] a, ulong value) => LessThan(a, BitVector(a.Length, value));


    /// <summary>The reference's <c>vlt(uint64_t, bitvec)</c>: strict less-than with an immediate on the left.</summary>
    /// <param name="value">The left operand, as an immediate.</param>
    /// <param name="b">The right operand.</param>
    /// <returns>The bit that is one exactly when <paramref name="value"/> &lt; <paramref name="b"/>.</returns>
    public LongfellowBitWire LessThan(ulong value, LongfellowBitWire[] b) => LessThan(BitVector(b.Length, value), b);


    /// <summary>The reference's <c>leq</c>/<c>vleq</c>: whether <paramref name="a"/> is at most <paramref name="b"/>, computed as <c>~(b &lt; a)</c>.</summary>
    /// <param name="a">The left operand.</param>
    /// <param name="b">The right operand.</param>
    /// <returns>The bit that is one exactly when <paramref name="a"/> &lt;= <paramref name="b"/>.</returns>
    public LongfellowBitWire LessThanOrEqual(LongfellowBitWire[] a, LongfellowBitWire[] b) => Not(LessThan(b, a));


    /// <summary>The reference's <c>vleq(bitvec, uint64_t)</c>: less-than-or-equal against an immediate.</summary>
    /// <param name="a">The left operand.</param>
    /// <param name="value">The right operand, as an immediate.</param>
    /// <returns>The bit that is one exactly when <paramref name="a"/> &lt;= <paramref name="value"/>.</returns>
    public LongfellowBitWire LessThanOrEqual(LongfellowBitWire[] a, ulong value) => LessThanOrEqual(a, BitVector(a.Length, value));


    /// <summary>The reference's <c>(a ^ val) &amp; mask == 0</c> <c>veqmask</c>: equality restricted to the bits selected by a mask.</summary>
    /// <param name="a">The vector to check.</param>
    /// <param name="mask">The bit mask selecting which positions participate.</param>
    /// <param name="value">The vector to compare against.</param>
    /// <returns>The bit that is one exactly when the masked bits of <paramref name="a"/> equal those of <paramref name="value"/>.</returns>
    public LongfellowBitWire EqualMasked(LongfellowBitWire[] a, ulong mask, LongfellowBitWire[] value)
    {
        LongfellowBitWire[] r = Xor(a, value);
        int n = Pack(mask, r);

        return EqualZeroReduce(0, n, r);
    }


    /// <summary>The reference's <c>veqmask(bitvec, uint64_t, uint64_t)</c>: masked equality against an immediate.</summary>
    /// <param name="a">The vector to check.</param>
    /// <param name="mask">The bit mask selecting which positions participate.</param>
    /// <param name="value">The immediate to compare against.</param>
    /// <returns>The bit that is one exactly when the masked bits of <paramref name="a"/> equal those of <paramref name="value"/>.</returns>
    public LongfellowBitWire EqualMasked(LongfellowBitWire[] a, ulong mask, ulong value) => EqualMasked(a, mask, BitVector(a.Length, value));


    /// <summary>The reference's <c>scan_and</c>: a Sklansky scan of <see cref="And(LongfellowBitWire, LongfellowBitWire)"/> over a range.</summary>
    /// <param name="x">The array, mutated in place.</param>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    /// <param name="backward">Whether the scan fans backward.</param>
    public void ScanAnd(LongfellowBitWire[] x, int i0, int i1, bool backward = false) => Scan(x, i0, i1, backward, (left, right) => And(left, right));


    /// <summary>The reference's <c>scan_or</c>: a Sklansky scan of <see cref="Or(LongfellowBitWire, LongfellowBitWire)"/> over a range.</summary>
    /// <param name="x">The array, mutated in place.</param>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    /// <param name="backward">Whether the scan fans backward.</param>
    public void ScanOr(LongfellowBitWire[] x, int i0, int i1, bool backward = false) => Scan(x, i0, i1, backward, (left, right) => Or(left, right));


    /// <summary>The reference's <c>scan_xor</c>: a Sklansky scan of <see cref="Xor(LongfellowBitWire, LongfellowBitWire)"/> over a range.</summary>
    /// <param name="x">The array, mutated in place.</param>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    /// <param name="backward">Whether the scan fans backward.</param>
    public void ScanXor(LongfellowBitWire[] x, int i0, int i1, bool backward = false) => Scan(x, i0, i1, backward, (left, right) => Xor(left, right));


    /// <summary>The reference's <c>slice&lt;I0, I1, N&gt;</c>: a sub-range copy.</summary>
    /// <param name="a">The source vector.</param>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    /// <returns>The sliced vector.</returns>
    public static LongfellowBitWire[] Slice(LongfellowBitWire[] a, int i0, int i1)
    {
        var r = new LongfellowBitWire[i1 - i0];
        Array.Copy(a, i0, r, 0, i1 - i0);

        return r;
    }


    /// <summary>The reference's <c>vappend</c>: a little-endian append, with <paramref name="low"/> occupying the low positions.</summary>
    /// <param name="low">The low vector; its first element is the least significant bit of the result.</param>
    /// <param name="high">The high vector, appended starting at position <c>low.Length</c>.</param>
    /// <returns>The appended vector.</returns>
    public static LongfellowBitWire[] Append(LongfellowBitWire[] low, LongfellowBitWire[] high)
    {
        var r = new LongfellowBitWire[low.Length + high.Length];
        Array.Copy(low, 0, r, 0, low.Length);
        Array.Copy(high, 0, r, low.Length, high.Length);

        return r;
    }


    /// <summary>The reference's <c>vshr</c>: a logical shift right, filling vacated high positions with a constant bit.</summary>
    /// <param name="a">The vector to shift.</param>
    /// <param name="shift">The shift amount.</param>
    /// <param name="fillBit">The bit value filling vacated positions.</param>
    /// <returns>The shifted vector.</returns>
    public LongfellowBitWire[] ShiftRight(LongfellowBitWire[] a, int shift, int fillBit = 0)
    {
        var r = new LongfellowBitWire[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            r[i] = i + shift < a.Length ? a[i + shift] : Bit(fillBit);
        }

        return r;
    }


    /// <summary>The reference's <c>vshl</c>: a logical shift left, filling vacated low positions with a constant bit.</summary>
    /// <param name="a">The vector to shift.</param>
    /// <param name="shift">The shift amount.</param>
    /// <param name="fillBit">The bit value filling vacated positions.</param>
    /// <returns>The shifted vector.</returns>
    public LongfellowBitWire[] ShiftLeft(LongfellowBitWire[] a, int shift, int fillBit = 0)
    {
        var r = new LongfellowBitWire[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            r[i] = i >= shift ? a[i - shift] : Bit(fillBit);
        }

        return r;
    }


    /// <summary>The reference's <c>vrotr</c>: a rotation right, <c>r[i] = a[(i + b) mod N]</c>.</summary>
    /// <param name="a">The vector to rotate.</param>
    /// <param name="amount">The rotation amount.</param>
    /// <returns>The rotated vector.</returns>
    public static LongfellowBitWire[] RotateRight(LongfellowBitWire[] a, int amount)
    {
        var r = new LongfellowBitWire[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            r[i] = a[(i + amount) % a.Length];
        }

        return r;
    }


    /// <summary>The reference's <c>vrotl</c>: a rotation left, <c>r[(i + b) mod N] = a[i]</c>.</summary>
    /// <param name="a">The vector to rotate.</param>
    /// <param name="amount">The rotation amount.</param>
    /// <returns>The rotated vector.</returns>
    public static LongfellowBitWire[] RotateLeft(LongfellowBitWire[] a, int amount)
    {
        var r = new LongfellowBitWire[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            r[(i + amount) % a.Length] = a[i];
        }

        return r;
    }


    /// <summary>The reference's <c>eltw_input</c>: declares a new witness wire without a bitness assertion.</summary>
    /// <returns>The declared wire.</returns>
    public int InputElement() => backend.InputWire();


    /// <summary>The reference's <c>input</c>: declares a new witness bit and asserts it is genuinely zero or one.</summary>
    /// <returns>The declared bit.</returns>
    public LongfellowBitWire Input()
    {
        var bit = new LongfellowBitWire(field, backend.InputWire());
        _ = AssertIsBit(bit);

        return bit;
    }


    /// <summary>The reference's <c>vinput</c>: declares a new witness bit vector, each bit asserted via <see cref="Input"/>.</summary>
    /// <param name="width">The vector width.</param>
    /// <returns>The declared bit vector.</returns>
    public LongfellowBitWire[] InputVector(int width)
    {
        var result = new LongfellowBitWire[width];
        for (int i = 0; i < width; i++)
        {
            result[i] = Input();
        }

        return result;
    }


    /// <summary>The reference's <c>output(EltW, size_t)</c>: registers a wire's value as an output claim.</summary>
    /// <param name="wire">The wire whose value is the output.</param>
    /// <param name="index">The output position the value claims.</param>
    public void Output(int wire, int index) => backend.OutputWire(wire, index);


    /// <summary>The reference's <c>output(BitW, size_t)</c>: registers a bit's evaluated value as an output claim.</summary>
    /// <param name="bit">The bit whose value is the output.</param>
    /// <param name="index">The output position the value claims.</param>
    public void Output(LongfellowBitWire bit, int index) => Output(Eval(bit), index);


    /// <summary>The reference's <c>voutput</c>: registers every bit of a vector as an output claim, starting at a position.</summary>
    /// <param name="bits">The bits to output.</param>
    /// <param name="index">The output position the first bit claims.</param>
    public void OutputVector(LongfellowBitWire[] bits, int index)
    {
        for (int i = 0; i < bits.Length; i++)
        {
            Output(bits[i], i + index);
        }
    }


    /// <summary>
    /// The reference's <c>mulv</c>: one quad gate for the product of two affine bit readings,
    /// optimizing the cases where either operand's linear coefficient is zero.
    /// </summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <returns>The product, over a fresh wire in the general case.</returns>
    private LongfellowBitWire Mulv(LongfellowBitWire a, LongfellowBitWire b)
    {
        if (LongfellowCompilerFieldOperations.ElementIsZero(a.LinearCoefficient.Span))
        {
            return Rebase(field.Compiler.Zero.Span, a.ConstantTerm.Span, b);
        }

        if (LongfellowCompilerFieldOperations.ElementIsZero(b.LinearCoefficient.Span))
        {
            return Mulv(b, a);
        }

        int x = backend.MultiplyScaled(MultiplyConstant(a.LinearCoefficient.Span, b.LinearCoefficient.Span), a.Wire, b.Wire);
        x = backend.Axpy(x, MultiplyConstant(a.ConstantTerm.Span, b.LinearCoefficient.Span), b.Wire);
        x = backend.Axpy(x, MultiplyConstant(a.LinearCoefficient.Span, b.ConstantTerm.Span), a.Wire);
        x = backend.Apy(x, MultiplyConstant(a.ConstantTerm.Span, b.ConstantTerm.Span));

        return new LongfellowBitWire(field, x);
    }


    /// <summary>
    /// The reference's <c>addv</c>: one linear gate for the sum of two affine bit readings, folding
    /// the case where either operand's linear coefficient is zero.
    /// </summary>
    /// <param name="a">The first operand.</param>
    /// <param name="b">The second operand.</param>
    /// <returns>The sum, over a fresh wire in the general case.</returns>
    private LongfellowBitWire Addv(LongfellowBitWire a, LongfellowBitWire b)
    {
        if (LongfellowCompilerFieldOperations.ElementIsZero(a.LinearCoefficient.Span))
        {
            return new LongfellowBitWire(AddConstant(a.ConstantTerm.Span, b.ConstantTerm.Span), b.LinearCoefficient, b.Wire);
        }

        if (LongfellowCompilerFieldOperations.ElementIsZero(b.LinearCoefficient.Span))
        {
            return Addv(b, a);
        }

        int x = backend.MultiplyScaled(a.LinearCoefficient.Span, a.Wire);
        int axb = backend.MultiplyScaled(b.LinearCoefficient.Span, b.Wire);
        x = backend.Add(x, axb);
        x = backend.Apy(x, AddConstant(a.ConstantTerm.Span, b.ConstantTerm.Span));

        return new LongfellowBitWire(field, x);
    }


    /// <summary>The reference's private <c>parity</c>: the exclusive-or fold of an array over its exact midpoint association tree.</summary>
    /// <param name="bits">The bits to fold.</param>
    /// <returns>The parity.</returns>
    private LongfellowBitWire Parity(LongfellowBitWire[] bits) => ReduceRange(0, bits.Length, i => bits[i], (left, right) => Xor(left, right), () => Bit(0));


    /// <summary>The reference's private <c>eq0(i0, i1, a)</c>: the ranged all-zero reduction over its exact midpoint association tree.</summary>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    /// <param name="a">The bits to check.</param>
    /// <returns>The bit that is one exactly when every bit in range is zero.</returns>
    private LongfellowBitWire EqualZeroReduce(int i0, int i1, LongfellowBitWire[] a) => ReduceRange(i0, i1, i => Not(a[i]), (left, right) => And(left, right), () => Bit(1));


    /// <summary>The reference's private <c>eq_reduce</c>: the ranged equality reduction over its exact midpoint association tree.</summary>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    /// <param name="a">The first vector.</param>
    /// <param name="b">The second vector.</param>
    /// <returns>The bit that is one exactly when the two ranges are equal.</returns>
    private LongfellowBitWire EqualReduce(int i0, int i1, LongfellowBitWire[] a, LongfellowBitWire[] b) => ReduceRange(i0, i1, i => Not(Xor(a[i], b[i])), (left, right) => And(left, right), () => Bit(1));


    /// <summary>
    /// The reference's private <c>lt_reduce</c>: the ranged less-than reduction, carrying both the
    /// equality and the less-than bit through the recursion (<c>a == b</c> iff both halves are equal;
    /// <c>a &lt; b</c> iff the high half is strictly less, or the high half is equal and the low half
    /// is strictly less), realized over its exact midpoint association tree.
    /// </summary>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    /// <param name="a">The left operand.</param>
    /// <param name="b">The right operand.</param>
    /// <returns>The equality bit and the less-than bit.</returns>
    private (LongfellowBitWire Eq, LongfellowBitWire Lt) LessThanReduce(int i0, int i1, LongfellowBitWire[] a, LongfellowBitWire[] b)
    {
        return ReduceRange<(LongfellowBitWire Eq, LongfellowBitWire Lt)>(
            i0,
            i1,
            i => (Not(Xor(a[i], b[i])), And(Not(a[i]), b[i])),
            (left, right) => (And(right.Eq, left.Eq), OrExclusive(right.Lt, And(right.Eq, left.Lt))),
            () => throw new InvalidOperationException("lt_reduce is never invoked over an empty range; LessThan handles the zero-width case directly."));
    }


    /// <summary>
    /// The shared explicit-stack engine every midpoint-association ranged fold in this class runs
    /// through: for a non-empty range, splits at <c>im = i0 + (i1 - i0) / 2</c>, folds the left half
    /// <c>[i0, im)</c> and the right half <c>[im, i1)</c>, and combines them in post-order, exactly
    /// reproducing the association tree the reference's matching recursive function builds. The empty
    /// base value is deferred behind <paramref name="emptyValueFactory"/> so it is constructed only
    /// when the range is genuinely empty, matching the reference's own lazy branch evaluation.
    /// </summary>
    /// <typeparam name="T">The folded value type.</typeparam>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    /// <param name="leaf">The value at a singleton range.</param>
    /// <param name="combine">The post-order combine of two adjacent sub-ranges.</param>
    /// <param name="emptyValueFactory">The value for an empty range, evaluated only when needed.</param>
    /// <returns>The folded value.</returns>
    private static T ReduceRange<T>(int i0, int i1, Func<int, T> leaf, Func<T, T, T> combine, Func<T> emptyValueFactory)
    {
        if (i1 <= i0)
        {
            return emptyValueFactory();
        }

        var pending = new Stack<(int Start, int End, bool Combine)>();
        var values = new Stack<T>();
        pending.Push((i0, i1, false));

        while (pending.Count > 0)
        {
            (int start, int end, bool combineStep) = pending.Pop();
            if (combineStep)
            {
                T right = values.Pop();
                T left = values.Pop();
                values.Push(combine(left, right));

                continue;
            }

            if (end == start + 1)
            {
                values.Push(leaf(start));

                continue;
            }

            int mid = start + (end - start) / 2;
            pending.Push((start, end, true));
            pending.Push((mid, end, false));
            pending.Push((start, mid, false));
        }

        return values.Pop();
    }


    /// <summary>
    /// The reference's private <c>gp_reduce</c>: the carry-propagation combine <c>(g0, p0) + (g1, p1)
    /// = (g1 | (g0 &amp; p1), p0 &amp; p1)</c>, accumulated in place into <paramref name="generate1"/>/
    /// <paramref name="propagate1"/>, relying on the mutual exclusivity of <paramref name="generate1"/>
    /// and <paramref name="propagate1"/> to use <see cref="OrExclusive(LongfellowBitWire, LongfellowBitWire)"/>.
    /// </summary>
    /// <param name="generate0">The lower pair's generate bit.</param>
    /// <param name="propagate0">The lower pair's propagate bit.</param>
    /// <param name="generate1">The upper pair's generate bit, updated in place.</param>
    /// <param name="propagate1">The upper pair's propagate bit, updated in place.</param>
    private void GpReduce(LongfellowBitWire generate0, LongfellowBitWire propagate0, ref LongfellowBitWire generate1, ref LongfellowBitWire propagate1)
    {
        generate1 = OrExclusive(generate1, And(generate0, propagate1));
        propagate1 = And(propagate0, propagate1);
    }


    /// <summary>The reference's private <c>ripple_scan</c>: the sequential carry-propagation scan, already iterative in the reference.</summary>
    /// <param name="generate">The generate array, mutated in place.</param>
    /// <param name="propagate">The propagate array, mutated in place.</param>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    private void RippleScan(LongfellowBitWire[] generate, LongfellowBitWire[] propagate, int i0, int i1)
    {
        for (int i = i0 + 1; i < i1; i++)
        {
            GpReduce(generate[i - 1], propagate[i - 1], ref generate[i], ref propagate[i]);
        }
    }


    /// <summary>
    /// The reference's private <c>sklansky_scan</c>: the parallel-prefix carry-propagation scan
    /// [1960]. Recurses over both halves first, then fans the left half's final pair
    /// (<c>generate[im - 1]</c>, <c>propagate[im - 1]</c>) into every position of the right half; the
    /// recursion is realized as an explicit stack that fans only after both halves are fully scanned.
    /// </summary>
    /// <param name="generate">The generate array, mutated in place.</param>
    /// <param name="propagate">The propagate array, mutated in place.</param>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    private void SklanskyScan(LongfellowBitWire[] generate, LongfellowBitWire[] propagate, int i0, int i1)
    {
        var pending = new Stack<(int Start, int End, bool IsFan, int Mid)>();
        pending.Push((i0, i1, false, 0));

        while (pending.Count > 0)
        {
            (int start, int end, bool isFan, int mid) = pending.Pop();
            if (isFan)
            {
                for (int i = mid; i < end; i++)
                {
                    GpReduce(generate[mid - 1], propagate[mid - 1], ref generate[i], ref propagate[i]);
                }

                continue;
            }

            if (end - start > 1)
            {
                int midpoint = start + (end - start) / 2;
                pending.Push((start, end, true, midpoint));
                pending.Push((midpoint, end, false, 0));
                pending.Push((start, midpoint, false, 0));
            }
        }
    }


    /// <summary>
    /// The reference's private <c>scan</c>: a generic parallel-prefix scan over a single array,
    /// mutated in place, with either a forward fan (the last element of the left half fans into every
    /// position of the right half) or a backward fan (the first element of the right half fans into
    /// every position of the left half). Realized as an explicit stack that fans only after both
    /// halves are fully scanned, preserving the exact reference association tree.
    /// </summary>
    /// <param name="x">The array, mutated in place.</param>
    /// <param name="i0">The inclusive range start.</param>
    /// <param name="i1">The exclusive range end.</param>
    /// <param name="backward">Whether the scan fans backward.</param>
    /// <param name="combine">The pairwise combine the fan applies.</param>
    private static void Scan(LongfellowBitWire[] x, int i0, int i1, bool backward, Func<LongfellowBitWire, LongfellowBitWire, LongfellowBitWire> combine)
    {
        var pending = new Stack<(int Start, int End, bool IsFan, int Mid)>();
        pending.Push((i0, i1, false, 0));

        while (pending.Count > 0)
        {
            (int start, int end, bool isFan, int mid) = pending.Pop();
            if (isFan)
            {
                if (backward)
                {
                    for (int i = start; i < mid; i++)
                    {
                        x[i] = combine(x[i], x[mid]);
                    }
                }
                else
                {
                    for (int i = mid; i < end; i++)
                    {
                        x[i] = combine(x[mid - 1], x[i]);
                    }
                }

                continue;
            }

            if (end - start > 1)
            {
                int midpoint = start + (end - start) / 2;
                pending.Push((start, end, true, midpoint));
                pending.Push((midpoint, end, false, 0));
                pending.Push((start, midpoint, false, 0));
            }
        }
    }


    /// <summary>
    /// The reference's private <c>generic_gp_add</c>: derives the generate/propagate basis, seeds
    /// <paramref name="c"/> with the propagate bits before scanning, runs the supplied scan, then folds
    /// the scanned generate bits into <paramref name="c"/> from position one onward. The carry out is
    /// the top generate bit after the scan; a zero-width request returns the zero bit without touching
    /// any array.
    /// </summary>
    /// <param name="c">Receives the sum, seeded and then corrected in place.</param>
    /// <param name="a">The first addend.</param>
    /// <param name="b">The second addend.</param>
    /// <param name="scan">The carry-propagation scan to run.</param>
    /// <returns>The carry out.</returns>
    private LongfellowBitWire GenericGpAdd(Span<LongfellowBitWire> c, ReadOnlySpan<LongfellowBitWire> a, ReadOnlySpan<LongfellowBitWire> b, LongfellowGpScanDelegate scan)
    {
        int w = c.Length;
        if (w == 0)
        {
            return Bit(0);
        }

        var generate = new LongfellowBitWire[w];
        var propagate = new LongfellowBitWire[w];
        for (int i = 0; i < w; i++)
        {
            generate[i] = And(a[i], b[i]);
            propagate[i] = Xor(a[i], b[i]);
            c[i] = propagate[i];
        }

        scan(generate, propagate, 0, w);
        for (int i = 1; i < w; i++)
        {
            c[i] = Xor(c[i], generate[i - 1]);
        }

        return generate[w - 1];
    }


    /// <summary>
    /// The reference's private <c>generic_gp_sub</c>: implements <c>a - b</c> as <c>~(~a + b)</c>,
    /// complementing <paramref name="a"/>, running <see cref="GenericGpAdd"/>, then complementing the
    /// result; the returned carry is the adder's own carry, not complemented.
    /// </summary>
    /// <param name="c">Receives the difference.</param>
    /// <param name="a">The minuend.</param>
    /// <param name="b">The subtrahend.</param>
    /// <param name="scan">The carry-propagation scan to run.</param>
    /// <returns>The carry out.</returns>
    private LongfellowBitWire GenericGpSub(Span<LongfellowBitWire> c, ReadOnlySpan<LongfellowBitWire> a, ReadOnlySpan<LongfellowBitWire> b, LongfellowGpScanDelegate scan)
    {
        int w = c.Length;
        var notA = new LongfellowBitWire[w];
        for (int j = 0; j < w; j++)
        {
            notA[j] = Not(a[j]);
        }

        LongfellowBitWire carry = GenericGpAdd(c, notA, b, scan);
        for (int j = 0; j < w; j++)
        {
            c[j] = Not(c[j]);
        }

        return carry;
    }


    /// <summary>
    /// The reference's private <c>pack</c>: compacts the entries selected by a mask to the front of
    /// the array, preserving their relative order, and returns the compacted count.
    /// </summary>
    /// <param name="mask">The bit mask selecting which entries survive.</param>
    /// <param name="a">The array, compacted in place.</param>
    /// <returns>The number of surviving entries.</returns>
    private static int Pack(ulong mask, LongfellowBitWire[] a)
    {
        int j = 0;
        for (int i = 0; i < a.Length; i++)
        {
            if ((mask & 1UL) != 0UL)
            {
                a[j] = a[i];
                j++;
            }

            mask >>= 1;
        }

        return j;
    }


    /// <summary>
    /// The middle-term correction and four-segment stitch <see cref="Gf2PolynomialMultiplierKaratsuba"/>
    /// applies once a split's three sub-products are known: first the reference's correction fold
    /// <c>ab01[i] = ab01[i] ^ a0b0[i] ^ a1b1[i]</c> over all <c>w</c> positions (the Karatsuba identity
    /// needs the cross term less both half products; the reference writes the loop raw over its
    /// pointers, but it is exactly the elementwise three-way
    /// <see cref="Xor(LongfellowBitWire[], LongfellowBitWire[], LongfellowBitWire[])"/>, which emits
    /// the identical gates in the identical order), then the stitch <c>c[i] = a0b0[i]</c>,
    /// <c>c[i + w/2] = a0b0[i + w/2] ^ ab01[i]</c>, <c>c[i + w] = ab01[i + w/2] ^ a1b1[i]</c>,
    /// <c>c[i + 3w/2] = a1b1[i + w/2]</c>.
    /// </summary>
    /// <param name="width">The split's width <c>w</c> (the sub-products are each <c>w</c> bits wide).</param>
    /// <param name="crossProduct">The low-high cross term (the reference's <c>ab01</c>).</param>
    /// <param name="lowProduct">The low-half product (the reference's <c>a0b0</c>).</param>
    /// <param name="highProduct">The high-half product (the reference's <c>a1b1</c>).</param>
    /// <returns>The stitched <c>2·width</c>-bit product.</returns>
    private LongfellowBitWire[] KaratsubaStitch(int width, LongfellowBitWire[] crossProduct, LongfellowBitWire[] lowProduct, LongfellowBitWire[] highProduct)
    {
        LongfellowBitWire[] correctedCross = Xor(crossProduct, lowProduct, highProduct);

        int half = width / 2;
        var c = new LongfellowBitWire[2 * width];
        for (int i = 0; i < half; i++)
        {
            c[i] = lowProduct[i];
            c[i + half] = Xor(lowProduct[i + half], correctedCross[i]);
            c[i + width] = Xor(correctedCross[i + half], highProduct[i]);
            c[i + (3 * half)] = highProduct[i + half];
        }

        return c;
    }


    /// <summary>Multiplies two field constants out of circuit (the reference's <c>mulf</c>, applied to compile-time coefficients).</summary>
    /// <param name="left">The first factor, canonical big-endian.</param>
    /// <param name="right">The second factor, canonical big-endian.</param>
    /// <returns>The product, canonical big-endian.</returns>
    private byte[] MultiplyConstant(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        var product = new byte[Scalar.SizeBytes];
        field.Compiler.Multiply(left, right, product, field.Compiler.Curve);

        return product;
    }


    /// <summary>Adds two field constants out of circuit (the reference's <c>addf</c>, applied to compile-time coefficients).</summary>
    /// <param name="left">The first addend, canonical big-endian.</param>
    /// <param name="right">The second addend, canonical big-endian.</param>
    /// <returns>The sum, canonical big-endian.</returns>
    private byte[] AddConstant(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        var sum = new byte[Scalar.SizeBytes];
        field.Compiler.Add(left, right, sum, field.Compiler.Curve);

        return sum;
    }
}
