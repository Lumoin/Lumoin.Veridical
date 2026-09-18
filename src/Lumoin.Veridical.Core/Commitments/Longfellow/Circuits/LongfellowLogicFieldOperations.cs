using System;
using System.Buffers;
using System.Buffers.Binary;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The gadget-layer field slice the Logic/BitW gadgets run over, a faithful port of the constant
/// surface google/longfellow-zk's <c>Field</c> concept exposes beyond the compiler kernel's own
/// <see cref="LongfellowCompilerFieldOperations"/> bundle: <c>of_scalar</c>, <c>beta</c>, the
/// characteristic-two generator <c>x</c>, and the odd-prime <c>two</c>/<c>half</c> constants
/// (<c>gf2_128.h</c>, <c>fp_generic.h</c>).
/// </summary>
/// <remarks>
/// <para>
/// Wraps a <see cref="LongfellowCompilerFieldOperations"/> bundle (exposed as
/// <see cref="Compiler"/>) rather than duplicating its constants, and surfaces the field's
/// subtraction and inversion delegates the compiler kernel never needed: subtraction is genuine in
/// the evaluation backend (the reference's <c>subf</c>), and inversion computes <see cref="Half"/>
/// and the gadgets' rebasing coefficients.
/// </para>
/// <para>
/// All returned elements are canonical big-endian <see cref="Scalar.SizeBytes"/>-byte scalars, the
/// same convention <see cref="LongfellowCompilerFieldOperations"/> uses; the low
/// <see cref="LongfellowCompilerFieldOperations.ElementBytes"/> bytes carry the value.
/// </para>
/// </remarks>
internal sealed class LongfellowLogicFieldOperations: IDisposable
{
    /// <summary>The characteristic-two subfield's basis size (<c>kSubFieldBits</c> at the reference's default template parameter, <c>subfield_log_bits = 4</c>): <see cref="OfScalar"/> and <see cref="Beta(int)"/> cover exactly this many bits over GF(2^128).</summary>
    private const int SubfieldBitCount = 16;

    /// <summary>The GF(2^128) on-wire element width in bytes (<c>gf2_128.h</c>'s <c>kBytes</c>).</summary>
    private const int Gf2128ElementBytes = 16;

    /// <summary>The Fp256 on-wire element width in bytes.</summary>
    private const int Fp256ElementBytes = 32;

    /// <summary>The Fp256 field's bit count.</summary>
    private const int Fp256BitCount = 256;

    /// <summary>The sextic-extension on-wire element width in bytes (the reference <c>Fp24_6</c>'s <c>kBytes</c>: six four-byte coefficients).</summary>
    private const int Fp24SexticElementBytes = 24;

    /// <summary>The sextic-extension field's bit count (the reference <c>Fp24_6</c>'s <c>kBits</c>).</summary>
    private const int Fp24SexticBitCount = 192;

    /// <summary>The FIPS 204 prime <c>q = 2^23 − 2^13 + 1</c>: the <c>of_scalar</c> bound of the sextic extension's base field (the reference <c>Fp24</c>'s <c>check(a &lt; m)</c>).</summary>
    private const ulong Fp24SexticScalarBound = 8380417;

    /// <summary>The subfield generator recurrence's lower exponent bound (<c>kSubFieldLogBits</c>): the reference's <c>subfield_generator()</c> loop starts here.</summary>
    private const int SubfieldGeneratorLowLogBits = 4;

    /// <summary>The subfield generator recurrence's exclusive upper exponent bound (<c>kLogBits</c>): the reference's <c>subfield_generator()</c> loop stops here.</summary>
    private const int SubfieldGeneratorHighLogBits = 7;

    /// <summary>The raw bit-embedded low byte of the characteristic-two generator polynomial <c>x</c> (the reference's <c>of_scalar_field(0b10)</c>): bit one of the polynomial representation set, not a beta-basis value.</summary>
    private const byte PolynomialXLowByte = 0x02;

    /// <summary>The odd-prime field's distinguished constant two, embedded through <see cref="WriteCanonicalUInt64"/> before <see cref="Half"/> is computed by inversion.</summary>
    private const ulong TwoScalarValue = 2;

    /// <summary>The odd-prime basis exponent bound (<c>fp_generic.h</c>'s <c>beta</c>: <c>check(i &lt; 64)</c>): <see cref="Beta(int)"/> covers exponents strictly below this over a prime field.</summary>
    private const int PrimeBetaExponentBound = 64;

    /// <summary>The sensitive owner of the field's fixed constants and basis table.</summary>
    private LongfellowCircuitStorage Storage { get; }

    /// <summary>The bounded basis table; its slices remain valid until disposal.</summary>
    private ReadOnlyMemory<byte>[] Basis { get; }

    /// <summary>The caller pool shared by this field and its compiler.</summary>
    public BaseMemoryPool Pool => Compiler.Pool;
    /// <summary>The borrowed characteristic-two polynomial generator.</summary>
    private ReadOnlyMemory<byte> GeneratorPolynomial { get; }
    /// <summary>The borrowed odd-prime embedding of two.</summary>
    private ReadOnlyMemory<byte> TwoConstant { get; }
    /// <summary>The borrowed odd-prime inverse of two.</summary>
    private ReadOnlyMemory<byte> HalfConstant { get; }
    /// <summary>The exclusive small-prime scalar bound, or zero when every ulong fits.</summary>
    private ulong PrimeScalarBound { get; }

    /// <summary>The wrapped compiler-kernel field-operation bundle: addition, multiplication, the field identities, and the element width/characteristic markers.</summary>
    public LongfellowCompilerFieldOperations Compiler { get; }

    /// <summary>The field subtraction the compiler kernel does not carry (the evaluation backend's genuine <c>subf</c>).</summary>
    public ScalarSubtractDelegate Subtract { get; }

    /// <summary>The field inversion the compiler kernel does not carry, used to derive <see cref="Half"/> and the gadgets' rebasing coefficients.</summary>
    public ScalarInvertDelegate Invert { get; }


    /// <summary>
    /// Constructs the bundle from an already-built compiler bundle and the precomputed gadget-layer
    /// constants. Prefer <see cref="CreateGf2128"/> and <see cref="CreateFp256"/>.
    /// </summary>
    /// <param name="compiler">The wrapped compiler-kernel field-operation bundle.</param>
    /// <param name="subtract">The field subtraction.</param>
    /// <param name="invert">The field inversion.</param>
    /// <param name="basis">The bounded field basis, borrowed from the supplied storage or compiler.</param>
    /// <param name="storage">The constant owner transferred with the compiler on successful construction.</param>
    /// <param name="generatorPolynomial">The characteristic-two generator polynomial <c>x</c>, or the default value over an odd-prime field.</param>
    /// <param name="twoConstant">The odd-prime constant two, or the default value over a characteristic-two field.</param>
    /// <param name="halfConstant">The odd-prime constant one-half, or the default value over a characteristic-two field.</param>
    /// <param name="primeScalarBound">The exclusive <see cref="OfScalar"/> bound of an odd-prime field whose base modulus fits <see cref="ulong"/>, or zero when the modulus exceeds 2^64 and every scalar embeds unreduced.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="compiler"/>, <paramref name="subtract"/> or <paramref name="invert"/> is <see langword="null"/>.</exception>
    private LongfellowLogicFieldOperations(
        LongfellowCompilerFieldOperations compiler,
        ScalarSubtractDelegate subtract,
        ScalarInvertDelegate invert,
        ReadOnlyMemory<byte>[] basis,
        LongfellowCircuitStorage storage,
        ReadOnlyMemory<byte> generatorPolynomial,
        ReadOnlyMemory<byte> twoConstant,
        ReadOnlyMemory<byte> halfConstant,
        ulong primeScalarBound = 0)
    {
        ArgumentNullException.ThrowIfNull(compiler);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(invert);

        Compiler = compiler;
        Subtract = subtract;
        Invert = invert;
        this.Basis = basis;
        this.Storage = storage;
        this.GeneratorPolynomial = generatorPolynomial;
        this.TwoConstant = twoConstant;
        this.HalfConstant = halfConstant;
        this.PrimeScalarBound = primeScalarBound;
    }


    /// <summary>
    /// Creates the bundle over GF(2^128), eagerly computing the subfield generator
    /// <c>g = x^((2^128−1)/(2^16−1))</c> by the reference's <c>subfield_generator()</c> recurrence
    /// and the 16-element basis <c>beta[0] = 1, beta[i] = beta[i−1]·g</c>.
    /// </summary>
    /// <param name="add">The field addition.</param>
    /// <param name="subtract">The field subtraction (equal to addition in characteristic two, but a distinct delegate instance may be supplied).</param>
    /// <param name="multiply">The field multiplication.</param>
    /// <param name="invert">The field inversion.</param>
    /// <param name="pool">The caller pool, which must outlive this disposable bundle and all borrowers.</param>
    /// <returns>The bundle owning its compiler and constants.</returns>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    public static LongfellowLogicFieldOperations CreateGf2128(
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(multiply);

        LongfellowCompilerFieldOperations? compiler = null;
        LongfellowCircuitStorage? storage = null;
        try
        {
            compiler = LongfellowCompilerFieldOperations.CreateCharacteristicTwo(
                add, multiply, CurveParameterSet.None, Gf2128ElementBytes, pool);
            storage = new LongfellowCircuitStorage(pool);
            Memory<byte> generator = storage.Allocate(Scalar.SizeBytes);
            generator.Span[Scalar.SizeBytes - 1] = PolynomialXLowByte;

            using IMemoryOwner<byte> generatorOwner = pool.Rent(Scalar.SizeBytes);
            Span<byte> subfieldGenerator = generatorOwner.Memory.Span[..Scalar.SizeBytes];
            ComputeSubfieldGenerator(generator.Span, multiply, compiler.Curve, subfieldGenerator, pool);

            var basis = new ReadOnlyMemory<byte>[SubfieldBitCount];
            basis[0] = compiler.One;
            for(int i = 1; i < SubfieldBitCount; i++)
            {
                Memory<byte> product = storage.Allocate(Scalar.SizeBytes);
                multiply(basis[i - 1].Span, subfieldGenerator, product.Span, compiler.Curve);
                basis[i] = product;
            }

            var result = new LongfellowLogicFieldOperations(compiler, subtract, invert, basis, storage, generator, default, default);
            compiler = null;
            storage = null;

            return result;
        }
        finally
        {
            storage?.Dispose();
            compiler?.Dispose();
        }
    }


    /// <summary>
    /// Creates the bundle over the 256-bit prime field, eagerly computing <see cref="Two"/> and
    /// <see cref="Half"/>.
    /// </summary>
    /// <param name="add">The field addition.</param>
    /// <param name="subtract">The field subtraction.</param>
    /// <param name="multiply">The field multiplication.</param>
    /// <param name="invert">The field inversion.</param>
    /// <param name="minusOne">The modulus less one, canonical big-endian, <see cref="Scalar.SizeBytes"/> bytes.</param>
    /// <param name="pool">The caller pool, which must outlive this disposable bundle and all borrowers.</param>
    /// <returns>The bundle owning its compiler and constants.</returns>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    public static LongfellowLogicFieldOperations CreateFp256(
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ReadOnlyMemory<byte> minusOne,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(invert);

        LongfellowCompilerFieldOperations? compiler = null;
        LongfellowCircuitStorage? storage = null;
        try
        {
            compiler = LongfellowCompilerFieldOperations.CreatePrime(
                add, multiply, CurveParameterSet.None, minusOne, Fp256ElementBytes, Fp256BitCount, pool);
            storage = new LongfellowCircuitStorage(pool);
            Memory<byte> two = storage.Allocate(Scalar.SizeBytes);
            WriteCanonicalUInt64(TwoScalarValue, two.Span);
            Memory<byte> half = storage.Allocate(Scalar.SizeBytes);
            invert(two.Span, half.Span, compiler.Curve);

            var basis = new ReadOnlyMemory<byte>[PrimeBetaExponentBound];
            for(int i = 0; i < basis.Length; i++)
            {
                Memory<byte> value = storage.Allocate(Scalar.SizeBytes);
                WriteCanonicalUInt64(1UL << i, value.Span);
                basis[i] = value;
            }

            var result = new LongfellowLogicFieldOperations(compiler, subtract, invert, basis, storage, default, two, half, 0);
            compiler = null;
            storage = null;

            return result;
        }
        finally
        {
            storage?.Dispose();
            compiler?.Dispose();
        }
    }


    /// <summary>
    /// Creates the bundle over the sextic extension of the FIPS 204 prime field (the reference's
    /// <c>Fp24_6(Fq(), beta = 7)</c>), eagerly computing <see cref="Two"/> and <see cref="Half"/>.
    /// <see cref="OfScalar"/> embeds into the extension's constant coefficient and rejects scalars
    /// at or beyond the base modulus, exactly as the reference's <c>of_scalar</c> panics there.
    /// </summary>
    /// <param name="add">The field addition.</param>
    /// <param name="subtract">The field subtraction.</param>
    /// <param name="multiply">The field multiplication.</param>
    /// <param name="invert">The field inversion.</param>
    /// <param name="minusOne">The base modulus less one in the constant coefficient, canonical big-endian, <see cref="Scalar.SizeBytes"/> bytes.</param>
    /// <param name="pool">The caller pool, which must outlive this disposable bundle and all borrowers.</param>
    /// <returns>The bundle owning its compiler and constants.</returns>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    public static LongfellowLogicFieldOperations CreateFp24Sextic(
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ReadOnlyMemory<byte> minusOne,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(invert);

        LongfellowCompilerFieldOperations? compiler = null;
        LongfellowCircuitStorage? storage = null;
        try
        {
            compiler = LongfellowCompilerFieldOperations.CreatePrime(
                add, multiply, CurveParameterSet.None, minusOne, Fp24SexticElementBytes, Fp24SexticBitCount, pool);
            storage = new LongfellowCircuitStorage(pool);
            Memory<byte> two = storage.Allocate(Scalar.SizeBytes);
            WriteCanonicalUInt64(TwoScalarValue, two.Span);
            Memory<byte> half = storage.Allocate(Scalar.SizeBytes);
            invert(two.Span, half.Span, compiler.Curve);

            var basis = new ReadOnlyMemory<byte>[PrimeBetaExponentBound];
            for(int i = 0; i < basis.Length; i++)
            {
                Memory<byte> value = storage.Allocate(Scalar.SizeBytes);
                WriteCanonicalUInt64(1UL << i, value.Span);
                basis[i] = value;
            }

            var result = new LongfellowLogicFieldOperations(compiler, subtract, invert, basis, storage, default, two, half, Fp24SexticScalarBound);
            compiler = null;
            storage = null;

            return result;
        }
        finally
        {
            storage?.Dispose();
            compiler?.Dispose();
        }
    }


    /// <summary>
    /// The reference's <c>of_scalar</c>: over an odd-prime field the raw canonical embedding of
    /// <paramref name="scalar"/> — unreduced when the modulus exceeds 2^64 (Fp256), and
    /// bounds-checked below the base modulus over the sextic extension, exactly where the
    /// reference's <c>of_scalar</c> panics; over GF(2^128) the beta-basis mapping
    /// <c>Σ scalar_i · beta[i]</c>, defined only for the low 16 bits.
    /// </summary>
    /// <param name="scalar">The value to embed.</param>
    /// <param name="destination">Receives one canonical scalar; no input constant storage may overlap it.</param>
    /// <exception cref="ArgumentOutOfRangeException">When <see cref="Compiler"/> is characteristic two and <paramref name="scalar"/> occupies more than the low 16 bits, or when a bounded odd-prime field cannot represent <paramref name="scalar"/>.</exception>
    public void OfScalar(ulong scalar, Span<byte> destination)
    {
        if(!Compiler.IsCharacteristicTwo)
        {
            if(PrimeScalarBound != 0 && scalar >= PrimeScalarBound)
            {
                throw new ArgumentOutOfRangeException(nameof(scalar), $"The field's of_scalar represents values below {PrimeScalarBound}.");
            }

            WriteCanonicalUInt64(scalar, destination);

            return;
        }

        if(scalar >= (1UL << SubfieldBitCount))
        {
            throw new ArgumentOutOfRangeException(nameof(scalar), "of_scalar over GF(2^128) represents at most the low 16 bits through the subfield basis.");
        }

        Span<byte> accumulated = destination[..Scalar.SizeBytes];
        accumulated.Clear();
        using IMemoryOwner<byte> owner = Pool.Rent(Scalar.SizeBytes);
        Span<byte> sum = owner.Memory.Span[..Scalar.SizeBytes];
        for(int bit = 0; bit < SubfieldBitCount; bit++)
        {
            if(((scalar >> bit) & 1UL) != 0UL)
            {
                sum.Clear();
                Compiler.Add(accumulated, Basis[bit].Span, sum, Compiler.Curve);
                sum.CopyTo(accumulated);
            }
        }
    }


    /// <summary>
    /// The reference's <c>beta(i)</c>: the <c>i</c>-th basis element such that
    /// <c>of_scalar(Σ b_i·2^i) = Σ b_i·beta(i)</c>. Over GF(2^128) this is the cached subfield basis
    /// element (<c>i &lt; 16</c>); over the odd-prime field it is <c>2^i</c> via <see cref="OfScalar"/>
    /// (<c>i &lt; 64</c>).
    /// </summary>
    /// <param name="index">The basis index.</param>
    /// <returns>The canonical basis element, borrowed until this bundle is disposed.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is negative or at or beyond the field's basis bound.</exception>
    public ReadOnlyMemory<byte> Beta(int index)
    {
        if(Compiler.IsCharacteristicTwo)
        {
            if(index < 0 || index >= SubfieldBitCount)
            {
                throw new ArgumentOutOfRangeException(nameof(index), $"The GF(2^128) subfield basis covers indices below {SubfieldBitCount}.");
            }

            return Basis[index];
        }

        if(index < 0 || index >= PrimeBetaExponentBound)
        {
            throw new ArgumentOutOfRangeException(nameof(index), $"The odd-prime basis covers exponents below {PrimeBetaExponentBound}.");
        }

        ulong scalar = 1UL << index;
        if(PrimeScalarBound != 0 && scalar >= PrimeScalarBound)
        {
            throw new ArgumentOutOfRangeException(nameof(index), $"Basis index {index} yields 2^{index}, and the field's of_scalar represents values below {PrimeScalarBound}.");
        }

        return Basis[index];
    }


    /// <summary>The reference's <c>x()</c>: the characteristic-two generator polynomial, raw bit-embedded (not beta-mapped). Defined only over GF(2^128).</summary>
    /// <exception cref="InvalidOperationException">When <see cref="Compiler"/> is not characteristic two.</exception>
    public ReadOnlyMemory<byte> X
    {
        get
        {
            if(!Compiler.IsCharacteristicTwo)
            {
                throw new InvalidOperationException("The generator polynomial x is defined only over the characteristic-two field.");
            }

            return GeneratorPolynomial;
        }
    }


    /// <summary>The reference's <c>two()</c>: the field element two. Defined only over the odd-prime field; characteristic two has no distinguished element two beyond <c>0</c>.</summary>
    /// <exception cref="InvalidOperationException">When <see cref="Compiler"/> is characteristic two.</exception>
    public ReadOnlyMemory<byte> Two
    {
        get
        {
            if(Compiler.IsCharacteristicTwo)
            {
                throw new InvalidOperationException("Two is defined only over the odd-prime field.");
            }

            return TwoConstant;
        }
    }


    /// <summary>The reference's <c>half()</c>: the multiplicative inverse of <see cref="Two"/>. Defined only over the odd-prime field.</summary>
    /// <exception cref="InvalidOperationException">When <see cref="Compiler"/> is characteristic two.</exception>
    public ReadOnlyMemory<byte> Half
    {
        get
        {
            if(Compiler.IsCharacteristicTwo)
            {
                throw new InvalidOperationException("Half is defined only over the odd-prime field.");
            }

            return HalfConstant;
        }
    }


    /// <summary>
    /// Negates a field element by multiplying it by <see cref="LongfellowCompilerFieldOperations.MinusOne"/>, the gadget layer's shared negation helper (the reference composes this inline wherever <c>negf</c> or a subtraction-by-multiplication is needed, for instance the compiler backend's <c>sub</c>).
    /// </summary>
    /// <param name="element">The element to negate, canonical big-endian.</param>
    /// <param name="destination">Receives one canonical scalar without overlapping the input.</param>
    public void Negate(ReadOnlySpan<byte> element, Span<byte> destination)
    {
        Span<byte> negated = destination[..Scalar.SizeBytes];
        negated.Clear();
        Compiler.Multiply(element, Compiler.MinusOne.Span, negated, Compiler.Curve);
    }


    /// <summary>
    /// Computes the GF(2^128) subfield generator (<c>gf2_128.h</c>'s <c>subfield_generator()</c>):
    /// <c>r = x</c>, then for <c>i</c> from <see cref="SubfieldGeneratorLowLogBits"/> up to (excluding)
    /// <see cref="SubfieldGeneratorHighLogBits"/>, <c>s = r</c> squared <c>2^i</c> times, then
    /// <c>r = r·s</c>. This is the reference's iterated identity
    /// <c>(2^{2^n}−1)/(2^{2^k}−1) = Π_{i=k}^{n−1}(2^{2^i}+1)</c> evaluated at <c>r = x</c>.
    /// </summary>
    /// <param name="generatorPolynomial">The generator polynomial <c>x</c>, canonical big-endian.</param>
    /// <param name="multiply">The field multiplication.</param>
    /// <param name="curve">The curve parameter set the multiplication delegate dispatches on.</param>
    /// <param name="destination">Receives the canonical subfield generator.</param>
    /// <param name="pool">The caller pool supplying separate multiplication workspace.</param>
    private static void ComputeSubfieldGenerator(ReadOnlySpan<byte> generatorPolynomial, ScalarMultiplyDelegate multiply, CurveParameterSet curve, Span<byte> destination, BaseMemoryPool pool)
    {
        //Squaring and multiplication use distinct input and output slots for every delegate call.
        const int ScratchScalarCount = 2;
        using IMemoryOwner<byte> owner = pool.Rent(ScratchScalarCount * Scalar.SizeBytes);
        Span<byte> buffer = owner.Memory.Span[..(ScratchScalarCount * Scalar.SizeBytes)];
        Span<byte> s = buffer[..Scalar.SizeBytes];
        Span<byte> product = buffer[Scalar.SizeBytes..];
        Span<byte> r = destination[..Scalar.SizeBytes];
        generatorPolynomial.CopyTo(r);
        for(int i = SubfieldGeneratorLowLogBits; i < SubfieldGeneratorHighLogBits; i++)
        {
            r.CopyTo(s);
            int squarings = 1 << i;
            for(int j = 0; j < squarings; j++)
            {
                product.Clear();
                multiply(s, s, product, curve);
                product.CopyTo(s);
            }

            product.Clear();
            multiply(r, s, product, curve);
            product.CopyTo(r);
        }
    }


    /// <summary>
    /// Writes a raw <see cref="ulong"/> in the zero-padded canonical byte layout shared by
    /// <see cref="OfScalar"/>, <see cref="Two"/>, and the prime basis table. The caller checks any
    /// field-specific bound before exposing the value as a field element.
    /// </summary>
    /// <param name="scalar">The value to embed.</param>
    /// <param name="destination">Receives the zero-padded canonical scalar.</param>
    private static void WriteCanonicalUInt64(ulong scalar, Span<byte> destination)
    {
        Span<byte> canonical = destination[..Scalar.SizeBytes];
        canonical.Clear();
        BinaryPrimitives.WriteUInt64BigEndian(canonical.Slice(Scalar.SizeBytes - sizeof(ulong), sizeof(ulong)), scalar);
    }

    /// <summary>Clears and releases the constants and the owned compiler bundle after all borrowers finish.</summary>
    public void Dispose()
    {
        Storage.Dispose();
        Compiler.Dispose();
    }
}
