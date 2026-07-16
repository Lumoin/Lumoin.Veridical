using System;
using System.Numerics;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// The fixed-point encoding convention for supply-chain quantities: it maps a
/// non-negative <see cref="decimal"/> to a non-negative <see cref="BigInteger"/>
/// field integer at a fixed base-10 scale (the factor is
/// <c>10^<see cref="FractionalDigits"/></c>), and back. The encoding is
/// <em>exact-or-reject</em> — a value carrying finer resolution than the scale is
/// refused, never rounded — so encoding cannot move a quantity across a
/// threshold. Because one scale encodes both operands of a comparison,
/// <c>encode(a) ≥ encode(b)</c> in the field holds exactly when <c>a ≥ b</c> as
/// decimals.
/// </summary>
/// <remarks>
/// <para>
/// The convention carries no credential, RDF, or serialization concern: its
/// input is a <see cref="decimal"/> measurement and its output is a field
/// integer for the R1CS predicates. It is a reusable scale — one
/// <see cref="FixedPointScale"/> can back many <see cref="FixedPointDomain"/>s,
/// since recycled-content percentages and carbon masses may share a scale yet
/// have very different maxima.
/// </para>
/// <para>
/// Rounding is intentionally absent. Rounding a measured value up, or a
/// greater-than-or-equal threshold down, is precisely how a sub-threshold
/// quantity would clear the bar; removing rounding removes that failure mode.
/// Any quantisation is a decision the caller makes explicitly upstream, not a
/// silent property of the encoding.
/// </para>
/// </remarks>
public readonly record struct FixedPointScale
{
    /// <summary>The number of base-10 fractional digits the scale preserves; the scale factor is <c>10^FractionalDigits</c>. The <see langword="default"/> value preserves zero digits (factor one), itself a sound integer encoding.</summary>
    public int FractionalDigits { get; }

    /// <summary>The largest supported fractional-digit count: <see cref="decimal"/>'s own scale ceiling. No <see cref="decimal"/> input can carry more fractional digits than this.</summary>
    public const int MaximumFractionalDigits = 28;

    /// <summary>
    /// The largest bit width a derived <see cref="FixedPointDomain"/> may occupy.
    /// It is one below the range check's own 253-bit ceiling on purpose: the
    /// difference range check rejects a negative (false) difference only when
    /// <c>r ≥ 2^(bits+1)</c>, and the smaller wired scalar field
    /// (BN254, <c>r ≈ 2^253.6</c>) satisfies that at 252 bits but not at 253.
    /// </summary>
    public const int MaximumEncodedBits = 252;


    private FixedPointScale(int fractionalDigits) => FractionalDigits = fractionalDigits;


    /// <summary>
    /// Creates a scale preserving <paramref name="fractionalDigits"/> base-10
    /// fractional digits. This is the only constructor; it bounds the exponent to
    /// <c>[0, <see cref="MaximumFractionalDigits"/>]</c>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="fractionalDigits"/> is negative or exceeds <see cref="MaximumFractionalDigits"/>.</exception>
    public static FixedPointScale OfFractionalDigits(int fractionalDigits)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(fractionalDigits);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(fractionalDigits, MaximumFractionalDigits);

        return new FixedPointScale(fractionalDigits);
    }


    /// <summary>The scale factor <c>10^FractionalDigits</c> a decimal is multiplied by to reach its integer encoding.</summary>
    public BigInteger ScaleFactor => BigInteger.Pow(10, FractionalDigits);


    /// <summary>
    /// Encodes <paramref name="value"/> as the exact non-negative integer
    /// <c>value · 10^FractionalDigits</c>. Trailing-zero forms encode identically
    /// (<c>1.230</c> and <c>1.23</c> at two digits both give <c>123</c>); a value
    /// carrying finer resolution than the scale (<c>1.235</c> at two digits) is
    /// rejected rather than rounded.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="value"/> is negative — the domain is non-negative quantities.</exception>
    /// <exception cref="ArgumentException">When <paramref name="value"/> cannot be encoded exactly at this scale.</exception>
    public BigInteger Encode(decimal value)
    {
        EncodeStatus status = TryEncodeCore(value, out BigInteger encoded);
        if(status == EncodeStatus.Negative)
        {
            throw new ArgumentOutOfRangeException(nameof(value), value, "Fixed-point encoding is defined only for non-negative quantities.");
        }

        if(status == EncodeStatus.Inexact)
        {
            throw new ArgumentException($"Value {value} carries finer resolution than the scale of {FractionalDigits} fractional digits; encode it exactly or quantise it upstream.", nameof(value));
        }

        return encoded;
    }


    /// <summary>Encodes <paramref name="value"/> like <see cref="Encode(decimal)"/>, but returns <see langword="false"/> instead of throwing where it would reject.</summary>
    public bool TryEncode(decimal value, out BigInteger encoded) => TryEncodeCore(value, out encoded) == EncodeStatus.Ok;


    /// <summary>
    /// Recovers the decimal <c>encoded / 10^FractionalDigits</c>. This is for
    /// display and tests — it is off the soundness path, which works only with
    /// field integers.
    /// </summary>
    /// <exception cref="OverflowException">When <paramref name="encoded"/> is negative or too large to fit <see cref="decimal"/>'s 96-bit mantissa at this scale.</exception>
    public decimal Decode(BigInteger encoded)
    {
        if(!TryDecode(encoded, out decimal value))
        {
            throw new OverflowException($"Encoded value {encoded} does not fit System.Decimal at a scale of {FractionalDigits} fractional digits.");
        }

        return value;
    }


    /// <summary>Recovers the decimal like <see cref="Decode(BigInteger)"/>, but returns <see langword="false"/> instead of throwing when the value does not fit.</summary>
    public bool TryDecode(BigInteger encoded, out decimal value)
    {
        value = decimal.Zero;
        if(encoded.Sign < 0 || encoded >= BigInteger.One << 96)
        {
            return false;
        }

        int low = unchecked((int)(uint)(encoded & uint.MaxValue));
        int mid = unchecked((int)(uint)((encoded >> 32) & uint.MaxValue));
        int high = unchecked((int)(uint)((encoded >> 64) & uint.MaxValue));
        value = new decimal(low, mid, high, isNegative: false, (byte)FractionalDigits);

        return true;
    }


    /// <summary>
    /// The smallest bit width <c>b</c> with <c>maxEncodedValue &lt; 2^b</c>,
    /// floored at one (the range check rejects a width below one). This pins how a
    /// <see cref="FixedPointDomain"/> sizes its range checks so an honest value
    /// fits and no false difference can wrap the field.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="maxEncodedValue"/> is negative.</exception>
    public static int RequiredBits(BigInteger maxEncodedValue)
    {
        if(maxEncodedValue.Sign < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxEncodedValue), maxEncodedValue, "A domain maximum cannot be negative.");
        }

        return maxEncodedValue.IsZero ? 1 : (int)maxEncodedValue.GetBitLength();
    }


    private EncodeStatus TryEncodeCore(decimal value, out BigInteger encoded)
    {
        encoded = BigInteger.Zero;
        if(value < decimal.Zero)
        {
            return EncodeStatus.Negative;
        }

        Span<int> parts = stackalloc int[4];
        _ = decimal.GetBits(value, parts);
        int valueScale = (parts[3] >> 16) & 0xFF;
        BigInteger mantissa = ((BigInteger)(uint)parts[2] << 64) | ((BigInteger)(uint)parts[1] << 32) | (uint)parts[0];

        if(FractionalDigits >= valueScale)
        {
            encoded = mantissa * BigInteger.Pow(10, FractionalDigits - valueScale);

            return EncodeStatus.Ok;
        }

        BigInteger quotient = BigInteger.DivRem(mantissa, BigInteger.Pow(10, valueScale - FractionalDigits), out BigInteger remainder);
        if(!remainder.IsZero)
        {
            return EncodeStatus.Inexact;
        }

        encoded = quotient;

        return EncodeStatus.Ok;
    }


    private enum EncodeStatus
    {
        Ok,
        Negative,
        Inexact,
    }
}


/// <summary>
/// A comparison unit: one <see cref="FixedPointScale"/> paired with an inclusive
/// maximum, from which it derives the range-check bit width. Every supply-chain
/// predicate takes a domain (never a bare scale) so that both operands of a
/// comparison are encoded at one scale and sized such that no false difference
/// can wrap the field. The <c>2^Bits</c> upper bound stays within
/// <c>2^<see cref="FixedPointScale.MaximumEncodedBits"/></c>, and
/// <c>r ≥ 2^(Bits+1)</c> on both wired curves — the invariant the difference
/// range check rests on.
/// </summary>
/// <remarks>
/// The <see langword="default"/> value has <see cref="Bits"/> zero and fails
/// loudly at the first range check (a width below one is rejected);
/// <see cref="Create"/> is the only constructor that yields a usable domain.
/// </remarks>
public readonly record struct FixedPointDomain
{
    /// <summary>The scale both operands of a comparison over this domain are encoded at.</summary>
    public FixedPointScale Scale { get; }

    /// <summary>The encoding of the inclusive maximum — the largest value the domain admits, and the tightest bound the range checks enforce.</summary>
    public BigInteger MaxEncodedValue { get; }

    /// <summary>The range-check width, <c>FixedPointScale.RequiredBits(MaxEncodedValue)</c>: between one and <see cref="FixedPointScale.MaximumEncodedBits"/> inclusive.</summary>
    public int Bits { get; }


    private FixedPointDomain(FixedPointScale scale, BigInteger maxEncodedValue, int bits)
    {
        Scale = scale;
        MaxEncodedValue = maxEncodedValue;
        Bits = bits;
    }


    /// <summary>
    /// Creates a domain over <paramref name="scale"/> admitting values in
    /// <c>[0, <paramref name="inclusiveMaximum"/>]</c>. The bit width is derived
    /// from the encoded maximum and rejected if it would exceed the field-safe
    /// ceiling.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="inclusiveMaximum"/> is not positive, or needs more than <see cref="FixedPointScale.MaximumEncodedBits"/> bits.</exception>
    /// <exception cref="ArgumentException">When <paramref name="inclusiveMaximum"/> cannot be encoded exactly at <paramref name="scale"/>.</exception>
    public static FixedPointDomain Create(FixedPointScale scale, decimal inclusiveMaximum)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(inclusiveMaximum, decimal.Zero);

        BigInteger maxEncodedValue = scale.Encode(inclusiveMaximum);
        int bits = FixedPointScale.RequiredBits(maxEncodedValue);
        if(bits > FixedPointScale.MaximumEncodedBits)
        {
            throw new ArgumentOutOfRangeException(nameof(inclusiveMaximum), inclusiveMaximum, $"The domain needs {bits} bits, but the field-safe maximum is {FixedPointScale.MaximumEncodedBits}; reduce the scale or the maximum.");
        }

        return new FixedPointDomain(scale, maxEncodedValue, bits);
    }


    /// <summary>
    /// Encodes <paramref name="value"/> at the domain's scale and confirms it lies
    /// within <c>[0, MaxEncodedValue]</c>. The predicates and their witness helper
    /// funnel every measured value and public bound through this method, so
    /// nothing enters a comparison at a mismatched scale or outside the domain.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="value"/> is negative or its encoding exceeds <see cref="MaxEncodedValue"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="value"/> cannot be encoded exactly at the domain's scale.</exception>
    public BigInteger Encode(decimal value)
    {
        BigInteger encoded = Scale.Encode(value);
        if(encoded > MaxEncodedValue)
        {
            throw new ArgumentOutOfRangeException(nameof(value), value, $"Encoded value {encoded} exceeds the domain maximum {MaxEncodedValue}.");
        }

        return encoded;
    }


    /// <summary>Encodes <paramref name="value"/> like <see cref="Encode(decimal)"/>, but returns <see langword="false"/> instead of throwing where it would reject.</summary>
    public bool TryEncode(decimal value, out BigInteger encoded)
    {
        if(!Scale.TryEncode(value, out encoded) || encoded > MaxEncodedValue)
        {
            encoded = BigInteger.Zero;

            return false;
        }

        return true;
    }
}
