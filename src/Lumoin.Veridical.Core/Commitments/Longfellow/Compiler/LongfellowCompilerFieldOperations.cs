using System;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

/// <summary>
/// The field-operation bundle the circuit compiler runs over, the slice of the reference field
/// concept (<c>mulf</c>, <c>addf</c>, <c>zero</c>/<c>one</c>/<c>mone</c>, <c>to_bytes_field</c>,
/// <c>kCharacteristicTwo</c>/<c>kBits</c>) that <c>QuadCircuit</c>, the scheduler's
/// canonicalization and <c>circuit_id</c> consume. Elements are carried as canonical big-endian
/// scalars in <see cref="Scalar.SizeBytes"/>-byte containers, the same convention the parsed
/// circuit's quad-term coefficients use; the low <see cref="ElementBytes"/> bytes hold the value and
/// the leading bytes are zero.
/// </summary>
/// <remarks>
/// The compiler's element ordering (<c>elt_less_than</c>) and the structural circuit id serialize
/// elements as the reference's <c>to_bytes_field</c> does: the canonical value in little-endian
/// order over <see cref="ElementBytes"/> bytes. <see cref="CompareLittleEndian"/> and
/// <see cref="WriteLittleEndian"/> implement that convention over the big-endian containers, so the
/// emitted corner order and the id match the reference byte for byte.
/// </remarks>
internal sealed class LongfellowCompilerFieldOperations
{
    /// <summary>The field addition over canonical big-endian containers.</summary>
    public ScalarAddDelegate Add { get; }

    /// <summary>The field multiplication over canonical big-endian containers.</summary>
    public ScalarMultiplyDelegate Multiply { get; }

    /// <summary>The curve parameter set the scalar delegates dispatch on; <see cref="CurveParameterSet.None"/> for GF(2^128).</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The additive identity, canonical big-endian.</summary>
    public ReadOnlyMemory<byte> Zero { get; }

    /// <summary>The multiplicative identity, canonical big-endian.</summary>
    public ReadOnlyMemory<byte> One { get; }

    /// <summary>The additive inverse of one (<c>mone</c>), canonical big-endian; equals <see cref="One"/> in characteristic two.</summary>
    public ReadOnlyMemory<byte> MinusOne { get; }

    /// <summary>The on-wire element width in bytes (<c>kBytes</c>): 16 for GF(2^128), 32 for Fp256.</summary>
    public int ElementBytes { get; }

    /// <summary>Whether the field has characteristic two, selecting the binary-field marker in the circuit id.</summary>
    public bool IsCharacteristicTwo { get; }

    /// <summary>The field's bit count (<c>kBits</c>), the characteristic-two identity the circuit id absorbs.</summary>
    public int BitCount { get; }


    /// <summary>
    /// Constructs the bundle. Prefer the <see cref="CreateCharacteristicTwo"/> and
    /// <see cref="CreatePrime"/> factories, which pin the identity conventions.
    /// </summary>
    /// <param name="add">The field addition.</param>
    /// <param name="multiply">The field multiplication.</param>
    /// <param name="curve">The curve parameter set for the delegates.</param>
    /// <param name="zero">The additive identity, canonical big-endian, <see cref="Scalar.SizeBytes"/> bytes.</param>
    /// <param name="one">The multiplicative identity, canonical big-endian, <see cref="Scalar.SizeBytes"/> bytes.</param>
    /// <param name="minusOne">The additive inverse of one, canonical big-endian, <see cref="Scalar.SizeBytes"/> bytes.</param>
    /// <param name="elementBytes">The on-wire element width in bytes.</param>
    /// <param name="isCharacteristicTwo">Whether the field has characteristic two.</param>
    /// <param name="bitCount">The field's bit count.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="elementBytes"/> or <paramref name="bitCount"/> is out of range.</exception>
    /// <exception cref="ArgumentException">When a constant has the wrong length.</exception>
    private LongfellowCompilerFieldOperations(
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        ReadOnlyMemory<byte> zero,
        ReadOnlyMemory<byte> one,
        ReadOnlyMemory<byte> minusOne,
        int elementBytes,
        bool isCharacteristicTwo,
        int bitCount)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentOutOfRangeException.ThrowIfLessThan(elementBytes, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(elementBytes, Scalar.SizeBytes);
        ArgumentOutOfRangeException.ThrowIfLessThan(bitCount, 1);

        if(zero.Length != Scalar.SizeBytes || one.Length != Scalar.SizeBytes || minusOne.Length != Scalar.SizeBytes)
        {
            throw new ArgumentException($"The field constants are canonical {Scalar.SizeBytes}-byte scalars.");
        }

        Add = add;
        Multiply = multiply;
        Curve = curve;
        Zero = zero;
        One = one;
        MinusOne = minusOne;
        ElementBytes = elementBytes;
        IsCharacteristicTwo = isCharacteristicTwo;
        BitCount = bitCount;
    }


    /// <summary>
    /// Creates the bundle for a characteristic-two field, where <c>mone == one</c> and the circuit
    /// id identifies the field by its bit count alone.
    /// </summary>
    /// <param name="add">The field addition.</param>
    /// <param name="multiply">The field multiplication.</param>
    /// <param name="curve">The curve parameter set for the delegates.</param>
    /// <param name="elementBytes">The on-wire element width in bytes (16 for GF(2^128)).</param>
    /// <returns>The bundle.</returns>
    public static LongfellowCompilerFieldOperations CreateCharacteristicTwo(
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        int elementBytes)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(elementBytes, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(elementBytes, Scalar.SizeBytes);

        var one = new byte[Scalar.SizeBytes];
        one[Scalar.SizeBytes - 1] = 1;

        const int BitsPerByte = 8;

        return new LongfellowCompilerFieldOperations(
            add,
            multiply,
            curve,
            new byte[Scalar.SizeBytes],
            one,
            one,
            elementBytes,
            isCharacteristicTwo: true,
            bitCount: elementBytes * BitsPerByte);
    }


    /// <summary>
    /// Creates the bundle for an odd prime field, where the circuit id identifies the field by the
    /// serialization of <c>−1</c> (the modulus less one).
    /// </summary>
    /// <param name="add">The field addition.</param>
    /// <param name="multiply">The field multiplication.</param>
    /// <param name="curve">The curve parameter set for the delegates.</param>
    /// <param name="minusOne">The modulus less one, canonical big-endian, <see cref="Scalar.SizeBytes"/> bytes.</param>
    /// <param name="elementBytes">The on-wire element width in bytes (32 for Fp256).</param>
    /// <param name="bitCount">The field's bit count (256 for Fp256).</param>
    /// <returns>The bundle.</returns>
    public static LongfellowCompilerFieldOperations CreatePrime(
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        ReadOnlyMemory<byte> minusOne,
        int elementBytes,
        int bitCount)
    {
        var one = new byte[Scalar.SizeBytes];
        one[Scalar.SizeBytes - 1] = 1;

        return new LongfellowCompilerFieldOperations(
            add,
            multiply,
            curve,
            new byte[Scalar.SizeBytes],
            one,
            minusOne,
            elementBytes,
            isCharacteristicTwo: false,
            bitCount);
    }


    /// <summary>
    /// Whether two canonical big-endian elements are equal.
    /// </summary>
    /// <param name="a">The first element.</param>
    /// <param name="b">The second element.</param>
    /// <returns><see langword="true"/> when equal.</returns>
    public static bool ElementsEqual(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        return a.SequenceEqual(b);
    }


    /// <summary>
    /// Whether the element is the additive identity.
    /// </summary>
    /// <param name="element">The element, canonical big-endian.</param>
    /// <returns><see langword="true"/> when zero.</returns>
    public static bool ElementIsZero(ReadOnlySpan<byte> element)
    {
        return !element.ContainsAnyExcept((byte)0);
    }


    /// <summary>
    /// The reference's canonical element order (<c>elt_less_than</c>): lexicographic comparison of
    /// the little-endian <see cref="ElementBytes"/>-wide serialization. Over the big-endian
    /// containers that is a bytewise walk from the least-significant end.
    /// </summary>
    /// <param name="a">The first element, canonical big-endian.</param>
    /// <param name="b">The second element, canonical big-endian.</param>
    /// <returns><see langword="true"/> when <paramref name="a"/> precedes <paramref name="b"/>.</returns>
    /// <exception cref="InvalidOperationException">When an element does not fit <see cref="ElementBytes"/> bytes.</exception>
    public bool CompareLittleEndian(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        ThrowIfOverWidth(a);
        ThrowIfOverWidth(b);

        for(int i = Scalar.SizeBytes - 1; i >= Scalar.SizeBytes - ElementBytes; i--)
        {
            if(a[i] < b[i])
            {
                return true;
            }

            if(a[i] > b[i])
            {
                return false;
            }
        }

        return false;
    }


    /// <summary>
    /// Serializes a canonical big-endian element into the reference's <c>to_bytes_field</c> layout:
    /// the value in little-endian order over <see cref="ElementBytes"/> bytes.
    /// </summary>
    /// <param name="element">The element, canonical big-endian.</param>
    /// <param name="destination">Receives <see cref="ElementBytes"/> little-endian bytes.</param>
    /// <exception cref="InvalidOperationException">When the element does not fit <see cref="ElementBytes"/> bytes.</exception>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is too short.</exception>
    public void WriteLittleEndian(ReadOnlySpan<byte> element, Span<byte> destination)
    {
        ThrowIfOverWidth(element);

        if(destination.Length < ElementBytes)
        {
            throw new ArgumentException($"The destination needs {ElementBytes} bytes.", nameof(destination));
        }

        for(int i = 0; i < ElementBytes; i++)
        {
            destination[i] = element[Scalar.SizeBytes - 1 - i];
        }
    }


    /// <summary>
    /// Rejects an element whose bytes above <see cref="ElementBytes"/> are not zero; compiler-built
    /// constants always fit, so a violation indicates a corrupted constant table.
    /// </summary>
    /// <param name="element">The element, canonical big-endian.</param>
    /// <exception cref="InvalidOperationException">When the element does not fit.</exception>
    private void ThrowIfOverWidth(ReadOnlySpan<byte> element)
    {
        if(element.Length != Scalar.SizeBytes || element[..(Scalar.SizeBytes - ElementBytes)].ContainsAnyExcept((byte)0))
        {
            throw new InvalidOperationException($"A compiler field element occupies the low {ElementBytes} bytes of a canonical {Scalar.SizeBytes}-byte scalar.");
        }
    }
}
