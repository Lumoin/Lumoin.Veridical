using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Commitments.Ligero.Gadgets;

/// <summary>
/// Precomputed short-Weierstrass curve constants — the coefficients <c>a</c> and
/// <c>b</c> of <c>y² = x³ + a·x + b</c> as canonical field-element bytes, together
/// with the derived values (<c>3·b</c>, <c>−a</c>) and the small field constants the
/// EC gadget constraints reference as linear coefficients. Built once per field via
/// <see cref="Create"/> so the derived bytes are computed a single time and shared
/// across every gadget call. It carries data only; the constraint logic lives in the
/// <see cref="WeierstrassGadgetExtensions"/> builder extension methods (for the
/// Longfellow ECDSA circuits the field is the P-256 base field and the curve is
/// secp256r1).
/// </summary>
internal sealed class WeierstrassCurve
{
    private const int ScalarSize = Scalar.SizeBytes;

    //Curve coefficients y² = x³ + a·x + b as canonical field-element bytes.
    public ReadOnlyMemory<byte> A { get; }
    public ReadOnlyMemory<byte> B { get; }

    //Derived once: 3·b (the complete addition's k3b term) and −a.
    public ReadOnlyMemory<byte> ThreeB { get; }
    public ReadOnlyMemory<byte> NegativeA { get; }

    //Small field constants used as linear coefficients by the EC constraints.
    public ReadOnlyMemory<byte> Zero { get; }
    public ReadOnlyMemory<byte> One { get; }
    public ReadOnlyMemory<byte> NegativeOne { get; }
    public ReadOnlyMemory<byte> NegativeTwo { get; }
    public ReadOnlyMemory<byte> Three { get; }
    public ReadOnlyMemory<byte> NegativeThree { get; }


    private WeierstrassCurve(
        ReadOnlyMemory<byte> a, ReadOnlyMemory<byte> b, ReadOnlyMemory<byte> threeB, ReadOnlyMemory<byte> negativeA,
        ReadOnlyMemory<byte> zero, ReadOnlyMemory<byte> one, ReadOnlyMemory<byte> negativeOne,
        ReadOnlyMemory<byte> negativeTwo, ReadOnlyMemory<byte> three, ReadOnlyMemory<byte> negativeThree)
    {
        A = a;
        B = b;
        ThreeB = threeB;
        NegativeA = negativeA;
        Zero = zero;
        One = one;
        NegativeOne = negativeOne;
        NegativeTwo = negativeTwo;
        Three = three;
        NegativeThree = negativeThree;
    }


    //Precomputes the curve constants over the builder's field. The builder supplies the
    //field arithmetic (negation, addition) used to derive −a, the negated small constants
    //and 3·b once.
    public static WeierstrassCurve Create(LigeroConstraintSystemBuilder builder, ReadOnlyMemory<byte> curveA, ReadOnlyMemory<byte> curveB)
    {
        ArgumentNullException.ThrowIfNull(builder);

        byte[] one = Encode(1);
        byte[] negativeOne = Negate(builder, one);
        byte[] negativeTwo = Negate(builder, Encode(2));
        byte[] three = Encode(3);
        byte[] negativeThree = Negate(builder, three);

        byte[] a = Canonical(curveA);
        byte[] negativeA = Negate(builder, a);
        byte[] b = Canonical(curveB);

        //3·b, derived once for the complete addition's k3b term.
        Span<byte> twoB = stackalloc byte[ScalarSize];
        builder.AddValues(b, b, twoB);
        byte[] threeB = new byte[ScalarSize];
        builder.AddValues(twoB, b, threeB);

        return new WeierstrassCurve(a, b, threeB, negativeA, new byte[ScalarSize], one, negativeOne, negativeTwo, three, negativeThree);
    }


    private static byte[] Encode(uint value)
    {
        byte[] bytes = new byte[ScalarSize];
        LigeroConstraintSystemBuilder.EncodeConstant(value, bytes);

        return bytes;
    }


    private static byte[] Negate(LigeroConstraintSystemBuilder builder, ReadOnlySpan<byte> value)
    {
        byte[] negated = new byte[ScalarSize];
        builder.Negate(value, negated);

        return negated;
    }


    private static byte[] Canonical(ReadOnlyMemory<byte> value)
    {
        if(value.Length != ScalarSize)
        {
            throw new ArgumentException($"Curve constant must be {ScalarSize} canonical bytes; received {value.Length}.", nameof(value));
        }

        return value.ToArray();
    }
}
