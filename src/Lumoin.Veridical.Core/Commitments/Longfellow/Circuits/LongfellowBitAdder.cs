using System;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// Maps an <c>N</c>-bit vector to a single field element in a way that lets several such encodings be
/// combined cheaply and later checked against a claimed total modulo <c>2^N</c>, a faithful port of
/// google/longfellow-zk's <c>BitAdderAux&lt;Logic, N, kCharacteristicTwo&gt;</c> (<c>bit_adder.h</c>).
/// The reference selects between two template specializations
/// (<c>BitAdderAux&lt;..., false&gt;</c>/<c>BitAdderAux&lt;..., true&gt;</c>) via the alias template
/// <c>BitAdder</c>; this port instead bundles both arithmetizations into one class and selects at
/// construction time by <see cref="LongfellowCompilerFieldOperations.IsCharacteristicTwo"/>.
/// </summary>
/// <remarks>
/// <para>
/// Over an odd-prime field the encoding is additive: bit <c>i</c> contributes weight <c>2^i</c>, the
/// combination of two encodings is genuine field addition, and <see cref="AssertEqualModulo"/> checks
/// the claimed total against <c>A + i·2^N</c> for every candidate carry-out <c>i &lt;
/// candidateCarryCount</c> (the reference's <c>assert_eqmod</c> odd-prime arm).
/// </para>
/// <para>
/// Over a characteristic-two field the encoding is multiplicative: bit <c>i</c> selects between
/// <c>alpha^(2^i)</c> and one, where <c>alpha</c> is <see cref="LongfellowLogicFieldOperations.X"/>, so
/// the combination of two encodings is field multiplication and <see cref="AssertEqualModulo"/> checks
/// the claimed total against <c>alpha^(i·2^N)·A</c> for every candidate <c>i &lt;
/// candidateCarryCount</c>, the powers <c>p[i] = alpha^(i·2^N)</c> built iteratively as <c>p[0] = 1</c>,
/// <c>p[i] = alpha^(2^N)·p[i − 1]</c> (the reference's characteristic-two <c>assert_eqmod</c> arm).
/// </para>
/// </remarks>
internal sealed class LongfellowBitAdder
{
    /// <summary>
    /// The widest bit vector the odd-prime arithmetization carries: the candidate-carry constants in
    /// <see cref="AssertEqualModulo"/> are <c>i·2^Width</c> computed in a native <see cref="ulong"/>,
    /// so <c>Width</c> itself must stay below 64 (a 64-bit shift by 64 wraps to zero in C# and is
    /// undefined behavior in the reference's C++; the reference never instantiates beyond 32).
    /// </summary>
    private const int MaxAdditiveWeightWidth = 63;

    private readonly LongfellowLogic logic;
    private readonly LongfellowLogicBackend backend;
    private readonly LongfellowLogicFieldOperations field;
    private readonly ReadOnlyMemory<byte>[]? alphaPowersOfTwo;
    private readonly ReadOnlyMemory<byte> alphaToPowerOfTwoWidth;

    /// <summary>The bit width <c>N</c> this adder encodes (the reference's template parameter).</summary>
    public int Width { get; }


    /// <summary>
    /// Constructs the adder over a width. When the field has characteristic two this eagerly builds
    /// the power table <c>alpha^(2^i)</c> for <c>i &lt; Width</c> by iterated squaring (the reference's
    /// constructor loop), plus <c>alpha^(2^Width)</c>; the odd-prime arithmetization precomputes
    /// nothing, matching the reference's empty odd-prime constructor.
    /// </summary>
    /// <param name="logic">The gadget layer this adder builds on.</param>
    /// <param name="width">The bit width <c>N</c>.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="logic"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="width"/> is not positive, or exceeds <see cref="MaxAdditiveWeightWidth"/> over an odd-prime field.</exception>
    public LongfellowBitAdder(LongfellowLogic logic, int width)
    {
        ArgumentNullException.ThrowIfNull(logic);
        ArgumentOutOfRangeException.ThrowIfLessThan(width, 1);

        this.logic = logic;
        backend = logic.Backend;
        field = logic.Field;
        Width = width;

        if(field.Compiler.IsCharacteristicTwo)
        {
            var powers = new ReadOnlyMemory<byte>[width];
            byte[] alpha = field.X.ToArray();
            for(int i = 0; i < width; i++)
            {
                powers[i] = alpha;
                alpha = MultiplyFieldConstant(alpha, alpha);
            }

            alphaPowersOfTwo = powers;
            alphaToPowerOfTwoWidth = alpha;

            return;
        }

        ArgumentOutOfRangeException.ThrowIfGreaterThan(width, MaxAdditiveWeightWidth);
    }


    /// <summary>
    /// The reference's <c>as_field_element</c>: encodes a bit vector as a single field element under
    /// this adder's arithmetization.
    /// </summary>
    /// <param name="bits">The bit vector, exactly <see cref="Width"/> bits.</param>
    /// <returns>The wire holding the encoded field element.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="bits"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="bits"/> is not exactly <see cref="Width"/> bits.</exception>
    public int AsFieldElement(LongfellowBitWire[] bits)
    {
        ThrowIfWrongWidth(bits);

        return field.Compiler.IsCharacteristicTwo ? AsFieldElementCharacteristicTwo(bits) : AsFieldElementAdditive(bits);
    }


    /// <summary>
    /// The reference's <c>add(EltW, EltW)</c>: combines two already-encoded field elements — field
    /// addition over an odd-prime field, field multiplication over characteristic two.
    /// </summary>
    /// <param name="a">The first encoded operand.</param>
    /// <param name="b">The second encoded operand.</param>
    /// <returns>The wire holding the combination.</returns>
    public int Add(int a, int b) => field.Compiler.IsCharacteristicTwo ? backend.Mul(a, b) : backend.Add(a, b);


    /// <summary>
    /// The reference's <c>add(BV, BV)</c>: encodes both bit vectors and combines the results via
    /// <see cref="Add(int, int)"/>.
    /// </summary>
    /// <param name="a">The first bit vector, exactly <see cref="Width"/> bits.</param>
    /// <param name="b">The second bit vector, exactly <see cref="Width"/> bits.</param>
    /// <returns>The wire holding the combination.</returns>
    public int Add(LongfellowBitWire[] a, LongfellowBitWire[] b) => Add(AsFieldElement(a), AsFieldElement(b));


    /// <summary>
    /// The reference's <c>add(initializer_list&lt;bitvec_view&lt;N&gt;&gt;)</c>: encodes every bit
    /// vector and folds the results over the Logic gadget layer's ranged fold — the ranged sum over an
    /// odd-prime field, the ranged product over characteristic two — reproducing the reference's exact
    /// midpoint association tree.
    /// </summary>
    /// <param name="vectors">The bit vectors to combine, each exactly <see cref="Width"/> bits.</param>
    /// <returns>The wire holding the combination.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="vectors"/> is <see langword="null"/>.</exception>
    public int Add(LongfellowBitWire[][] vectors)
    {
        ArgumentNullException.ThrowIfNull(vectors);

        return field.Compiler.IsCharacteristicTwo
            ? logic.Multiply(0, vectors.Length, i => AsFieldElement(vectors[i]))
            : logic.Add(0, vectors.Length, i => AsFieldElement(vectors[i]));
    }


    /// <summary>
    /// The reference's <c>assert_eqmod</c>: asserts that <paramref name="claimedSum"/> equals
    /// <paramref name="bits"/>'s encoding plus one of <paramref name="candidateCarryCount"/> candidate
    /// carries, the whole check folded as a single ranged product over the Logic gadget layer's exact
    /// midpoint association tree.
    /// </summary>
    /// <param name="bits">The addend bit vector, exactly <see cref="Width"/> bits.</param>
    /// <param name="claimedSum">The wire holding the claimed total.</param>
    /// <param name="candidateCarryCount">The number of candidate carry values <c>i &lt; candidateCarryCount</c> to check against.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="bits"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="bits"/> is not exactly <see cref="Width"/> bits.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="candidateCarryCount"/> is negative.</exception>
    public void AssertEqualModulo(LongfellowBitWire[] bits, int claimedSum, int candidateCarryCount)
    {
        ThrowIfWrongWidth(bits);
        ArgumentOutOfRangeException.ThrowIfNegative(candidateCarryCount);

        if(field.Compiler.IsCharacteristicTwo)
        {
            AssertEqualModuloCharacteristicTwo(bits, claimedSum, candidateCarryCount);

            return;
        }

        AssertEqualModuloAdditive(bits, claimedSum, candidateCarryCount);
    }


    /// <summary>
    /// The odd-prime <c>as_field_element</c> arm: the weighted sum <c>Σ bits[i]·2^i</c>, folded via
    /// <see cref="LongfellowLogicBackend.Axpy"/> exactly as the reference's loop.
    /// </summary>
    /// <param name="bits">The bit vector, exactly <see cref="Width"/> bits.</param>
    /// <returns>The wire holding the weighted sum.</returns>
    private int AsFieldElementAdditive(LongfellowBitWire[] bits)
    {
        int r = backend.Constant(field.Compiler.Zero.Span);
        for(int i = 0; i < Width; i++)
        {
            r = backend.Axpy(r, field.OfScalar(1UL << i).Span, logic.Eval(bits[i]));
        }

        return r;
    }


    /// <summary>
    /// The characteristic-two <c>as_field_element</c> arm: the ranged product of
    /// <c>mux(bits[i], alpha^(2^i), 1)</c>.
    /// </summary>
    /// <param name="bits">The bit vector, exactly <see cref="Width"/> bits.</param>
    /// <returns>The wire holding the encoded product.</returns>
    private int AsFieldElementCharacteristicTwo(LongfellowBitWire[] bits)
    {
        return logic.Multiply(0, Width, i => logic.Mux(bits[i], backend.Constant(alphaPowersOfTwo![i].Span), backend.Constant(field.Compiler.One.Span)));
    }


    /// <summary>
    /// The odd-prime <c>assert_eqmod</c> arm: asserts <c>claimedSum − A</c> equals <c>i·2^N</c> for
    /// some candidate <c>i</c>, via the product over every candidate.
    /// </summary>
    /// <param name="bits">The addend bit vector.</param>
    /// <param name="claimedSum">The wire holding the claimed total.</param>
    /// <param name="candidateCarryCount">The number of candidates to check.</param>
    private void AssertEqualModuloAdditive(LongfellowBitWire[] bits, int claimedSum, int candidateCarryCount)
    {
        int difference = backend.Sub(claimedSum, AsFieldElement(bits));
        int product = logic.Multiply(0, candidateCarryCount, i => backend.Sub(difference, backend.Constant(field.OfScalar((1UL << Width) * (ulong)i).Span)));

        _ = logic.AssertZero(product);
    }


    /// <summary>
    /// The characteristic-two <c>assert_eqmod</c> arm: builds the powers <c>p[i] = alpha^(i·2^N)</c>
    /// iteratively, then asserts <c>claimedSum − p[i]·A</c> is zero for some candidate <c>i</c>, via
    /// the product over every candidate.
    /// </summary>
    /// <param name="bits">The addend bit vector.</param>
    /// <param name="claimedSum">The wire holding the claimed total.</param>
    /// <param name="candidateCarryCount">The number of candidates to check.</param>
    private void AssertEqualModuloCharacteristicTwo(LongfellowBitWire[] bits, int claimedSum, int candidateCarryCount)
    {
        var powers = new ReadOnlyMemory<byte>[candidateCarryCount];
        if(candidateCarryCount > 0)
        {
            powers[0] = field.Compiler.One;
            for(int i = 1; i < candidateCarryCount; i++)
            {
                powers[i] = MultiplyFieldConstant(alphaToPowerOfTwoWidth.Span, powers[i - 1].Span);
            }
        }

        int encoded = AsFieldElement(bits);
        int product = logic.Multiply(0, candidateCarryCount, i => backend.Sub(claimedSum, backend.Mul(backend.Constant(powers[i].Span), encoded)));

        _ = logic.AssertZero(product);
    }


    /// <summary>Multiplies two field constants out of circuit, used to precompute the characteristic-two power tables.</summary>
    /// <param name="left">The first factor, canonical big-endian.</param>
    /// <param name="right">The second factor, canonical big-endian.</param>
    /// <returns>The product, canonical big-endian.</returns>
    private byte[] MultiplyFieldConstant(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        var product = new byte[Scalar.SizeBytes];
        field.Compiler.Multiply(left, right, product, field.Compiler.Curve);

        return product;
    }


    /// <summary>Rejects a bit vector whose length is not exactly <see cref="Width"/>.</summary>
    /// <param name="bits">The bit vector to check.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="bits"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the length does not match.</exception>
    private void ThrowIfWrongWidth(LongfellowBitWire[] bits)
    {
        ArgumentNullException.ThrowIfNull(bits);

        if(bits.Length != Width)
        {
            throw new ArgumentException($"The bit vector needs exactly {Width} bits.", nameof(bits));
        }
    }
}
