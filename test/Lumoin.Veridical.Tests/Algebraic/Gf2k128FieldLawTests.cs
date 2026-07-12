using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Algebraic-law property tests for <see cref="Gf2k128Backend"/> — no such
/// sweep existed before this file; <see cref="Gf2k128BackendAgreementTests"/>
/// only ever gated byte-identity against the BigInteger oracle on a fixed
/// sample list. Every law is stated as an identity over boundary-blended
/// operands (0, 1, 2, the reduction constant <c>0x87</c>, and the 64-bit
/// limb-boundary patterns of the 128-bit element, blended with uniform
/// 16-byte draws) so carry-chain and fold edges are exercised, not just
/// interior values.
/// </summary>
/// <remarks>
/// Characteristic two means subtraction is addition (XOR), so no separate
/// subtraction law is stated; the additive-inverse law degenerates to
/// <c>a + a = 0</c>, tested directly.
/// </remarks>
[TestClass]
internal sealed class Gf2k128FieldLawTests
{
    private const int ScalarSize = 32;
    private const int ElementSizeBytes = 16;

    private const long IterationCount = 300;

    //Roughly one boundary draw per six uniform draws, matching
    //BoundaryCorpusGen's own weighting.
    private const int UniformDrawWeight = 6;
    private const int BoundaryDrawWeight = 1;

    private static ScalarAddDelegate BackendAdd { get; } = Gf2k128Backend.GetAdd();

    private static ScalarMultiplyDelegate BackendMultiply { get; } = Gf2k128Backend.GetMultiply();

    private static ScalarInvertDelegate BackendInvert { get; } = Gf2k128Backend.GetInvert();

    private static ScalarReduceDelegate BackendReduce { get; } = Gf2k128Backend.GetReduce();

    private static ScalarAddDelegate ReferenceAdd { get; } = Gf2k128Reference.GetAdd();

    private static ScalarMultiplyDelegate ReferenceMultiply { get; } = Gf2k128Reference.GetMultiply();

    private static ScalarReduceDelegate ReferenceReduce { get; } = Gf2k128Reference.GetReduce();

    //0, 1, 2, the reduction constant, the top bit of the whole element, a
    //value spanning both the top bit and the low bit, the all-ones fill, and
    //a single high bit in each of the two 64-bit halves — the limb-boundary
    //patterns a fold-based multiply is most likely to mishandle.
    private static byte[][] BoundaryCorpus { get; } =
    [
        Encode(BigInteger.Zero),
        Encode(BigInteger.One),
        Encode(2),
        Encode(0x87),
        Encode((BigInteger.One << 127) + 1),
        Encode((BigInteger.One << 128) - 1),
        Encode(((BigInteger.One << 64) - 1) << 64),
        Encode((BigInteger.One << 64) - 1),
        Encode(BigInteger.One << 63),
        Encode(BigInteger.One << 127),
    ];

    //Blends uniform 16-byte draws with the element-width boundary corpus
    //above; BoundaryCorpusGen is fixed at the 32-byte scalar width the other
    //fields share, so GF(2^128) — a 128-bit element — builds its own
    //narrower blend rather than force-fitting the shared helper.
    private static Gen<byte[]> BoundaryElementBytesGen { get; } = Gen.Frequency<byte[]>(
        (UniformDrawWeight, Gen.Byte.Array[ElementSizeBytes]),
        (BoundaryDrawWeight, Gen.OneOfConst(BoundaryCorpus)));


    [TestMethod]
    public void AdditionIsItsOwnInverse()
    {
        BoundaryElementBytesGen.Sample(raw =>
        {
            Span<byte> a = stackalloc byte[ScalarSize];
            BackendReduce(raw, a, CurveParameterSet.None);

            Span<byte> sum = stackalloc byte[ScalarSize];
            BackendAdd(a, a, sum, CurveParameterSet.None);

            return sum.IndexOfAnyExcept((byte)0) < 0;
        }, iter: IterationCount);
    }


    [TestMethod]
    public void AdditionIsCommutative()
    {
        Gen.Select(BoundaryElementBytesGen, BoundaryElementBytesGen).Sample((rawA, rawB) =>
        {
            Span<byte> a = stackalloc byte[ScalarSize];
            Span<byte> b = stackalloc byte[ScalarSize];
            BackendReduce(rawA, a, CurveParameterSet.None);
            BackendReduce(rawB, b, CurveParameterSet.None);

            Span<byte> leftThenRight = stackalloc byte[ScalarSize];
            Span<byte> rightThenLeft = stackalloc byte[ScalarSize];
            BackendAdd(a, b, leftThenRight, CurveParameterSet.None);
            BackendAdd(b, a, rightThenLeft, CurveParameterSet.None);

            return leftThenRight.SequenceEqual(rightThenLeft);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void AdditionIsAssociative()
    {
        Gen.Select(BoundaryElementBytesGen, BoundaryElementBytesGen, BoundaryElementBytesGen).Sample((rawA, rawB, rawC) =>
        {
            Span<byte> a = stackalloc byte[ScalarSize];
            Span<byte> b = stackalloc byte[ScalarSize];
            Span<byte> c = stackalloc byte[ScalarSize];
            BackendReduce(rawA, a, CurveParameterSet.None);
            BackendReduce(rawB, b, CurveParameterSet.None);
            BackendReduce(rawC, c, CurveParameterSet.None);

            Span<byte> aPlusB = stackalloc byte[ScalarSize];
            Span<byte> abThenC = stackalloc byte[ScalarSize];
            Span<byte> bPlusC = stackalloc byte[ScalarSize];
            Span<byte> aThenBc = stackalloc byte[ScalarSize];
            BackendAdd(a, b, aPlusB, CurveParameterSet.None);
            BackendAdd(aPlusB, c, abThenC, CurveParameterSet.None);
            BackendAdd(b, c, bPlusC, CurveParameterSet.None);
            BackendAdd(a, bPlusC, aThenBc, CurveParameterSet.None);

            return abThenC.SequenceEqual(aThenBc);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsCommutative()
    {
        Gen.Select(BoundaryElementBytesGen, BoundaryElementBytesGen).Sample((rawA, rawB) =>
        {
            Span<byte> a = stackalloc byte[ScalarSize];
            Span<byte> b = stackalloc byte[ScalarSize];
            BackendReduce(rawA, a, CurveParameterSet.None);
            BackendReduce(rawB, b, CurveParameterSet.None);

            Span<byte> leftThenRight = stackalloc byte[ScalarSize];
            Span<byte> rightThenLeft = stackalloc byte[ScalarSize];
            BackendMultiply(a, b, leftThenRight, CurveParameterSet.None);
            BackendMultiply(b, a, rightThenLeft, CurveParameterSet.None);

            return leftThenRight.SequenceEqual(rightThenLeft);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsAssociative()
    {
        Gen.Select(BoundaryElementBytesGen, BoundaryElementBytesGen, BoundaryElementBytesGen).Sample((rawA, rawB, rawC) =>
        {
            Span<byte> a = stackalloc byte[ScalarSize];
            Span<byte> b = stackalloc byte[ScalarSize];
            Span<byte> c = stackalloc byte[ScalarSize];
            BackendReduce(rawA, a, CurveParameterSet.None);
            BackendReduce(rawB, b, CurveParameterSet.None);
            BackendReduce(rawC, c, CurveParameterSet.None);

            Span<byte> aTimesB = stackalloc byte[ScalarSize];
            Span<byte> abThenC = stackalloc byte[ScalarSize];
            Span<byte> bTimesC = stackalloc byte[ScalarSize];
            Span<byte> aThenBc = stackalloc byte[ScalarSize];
            BackendMultiply(a, b, aTimesB, CurveParameterSet.None);
            BackendMultiply(aTimesB, c, abThenC, CurveParameterSet.None);
            BackendMultiply(b, c, bTimesC, CurveParameterSet.None);
            BackendMultiply(a, bTimesC, aThenBc, CurveParameterSet.None);

            return abThenC.SequenceEqual(aThenBc);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationDistributesOverAddition()
    {
        Gen.Select(BoundaryElementBytesGen, BoundaryElementBytesGen, BoundaryElementBytesGen).Sample((rawA, rawB, rawC) =>
        {
            Span<byte> a = stackalloc byte[ScalarSize];
            Span<byte> b = stackalloc byte[ScalarSize];
            Span<byte> c = stackalloc byte[ScalarSize];
            BackendReduce(rawA, a, CurveParameterSet.None);
            BackendReduce(rawB, b, CurveParameterSet.None);
            BackendReduce(rawC, c, CurveParameterSet.None);

            Span<byte> bPlusC = stackalloc byte[ScalarSize];
            Span<byte> leftSide = stackalloc byte[ScalarSize];
            BackendAdd(b, c, bPlusC, CurveParameterSet.None);
            BackendMultiply(a, bPlusC, leftSide, CurveParameterSet.None);

            Span<byte> aTimesB = stackalloc byte[ScalarSize];
            Span<byte> aTimesC = stackalloc byte[ScalarSize];
            Span<byte> rightSide = stackalloc byte[ScalarSize];
            BackendMultiply(a, b, aTimesB, CurveParameterSet.None);
            BackendMultiply(a, c, aTimesC, CurveParameterSet.None);
            BackendAdd(aTimesB, aTimesC, rightSide, CurveParameterSet.None);

            return leftSide.SequenceEqual(rightSide);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void OneIsTheMultiplicativeIdentity()
    {
        BoundaryElementBytesGen.Sample(rawA =>
        {
            Span<byte> a = stackalloc byte[ScalarSize];
            BackendReduce(rawA, a, CurveParameterSet.None);

            Span<byte> one = stackalloc byte[ScalarSize];
            one[^1] = 1;

            Span<byte> product = stackalloc byte[ScalarSize];
            BackendMultiply(a, one, product, CurveParameterSet.None);

            return product.SequenceEqual(a);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void SquareEqualsMultiplyingByAnEqualButDistinctCopy()
    {
        //Guards against a shortcut that only fires when both operand spans
        //alias the same buffer: multiplying a value against itself in place
        //must equal multiplying it against a separately materialised copy of
        //the same value.
        BoundaryElementBytesGen.Sample(rawA =>
        {
            Span<byte> a = stackalloc byte[ScalarSize];
            BackendReduce(rawA, a, CurveParameterSet.None);

            Span<byte> aliasedSquare = stackalloc byte[ScalarSize];
            BackendMultiply(a, a, aliasedSquare, CurveParameterSet.None);

            Span<byte> distinctCopy = stackalloc byte[ScalarSize];
            a.CopyTo(distinctCopy);
            Span<byte> distinctSquare = stackalloc byte[ScalarSize];
            BackendMultiply(a, distinctCopy, distinctSquare, CurveParameterSet.None);

            return aliasedSquare.SequenceEqual(distinctSquare);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void InverseTimesValueIsOne()
    {
        //Gf2k128Backend exposes GetInvert (Fermat a^(2^128 - 2) over the fast
        //multiply), so the multiplicative-inverse round trip applies; zero
        //has no inverse and is skipped like every other field's law sweep.
        BoundaryElementBytesGen.Sample(rawA =>
        {
            Span<byte> a = stackalloc byte[ScalarSize];
            BackendReduce(rawA, a, CurveParameterSet.None);
            if(a.IndexOfAnyExcept((byte)0) < 0)
            {
                return true;
            }

            Span<byte> inverse = stackalloc byte[ScalarSize];
            BackendInvert(a, inverse, CurveParameterSet.None);
            Span<byte> product = stackalloc byte[ScalarSize];
            BackendMultiply(a, inverse, product, CurveParameterSet.None);

            Span<byte> one = stackalloc byte[ScalarSize];
            one[^1] = 1;

            return product.SequenceEqual(one);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void AddAndMultiplyAgreeWithTheBigIntegerOracleForBoundarySeededOperands()
    {
        Gen.Select(BoundaryElementBytesGen, BoundaryElementBytesGen).Sample((rawA, rawB) =>
        {
            Span<byte> a = stackalloc byte[ScalarSize];
            Span<byte> b = stackalloc byte[ScalarSize];
            ReferenceReduce(rawA, a, CurveParameterSet.None);
            ReferenceReduce(rawB, b, CurveParameterSet.None);

            Span<byte> expectedSum = stackalloc byte[ScalarSize];
            Span<byte> actualSum = stackalloc byte[ScalarSize];
            ReferenceAdd(a, b, expectedSum, CurveParameterSet.None);
            BackendAdd(a, b, actualSum, CurveParameterSet.None);

            Span<byte> expectedProduct = stackalloc byte[ScalarSize];
            Span<byte> actualProduct = stackalloc byte[ScalarSize];
            ReferenceMultiply(a, b, expectedProduct, CurveParameterSet.None);
            BackendMultiply(a, b, actualProduct, CurveParameterSet.None);

            return expectedSum.SequenceEqual(actualSum) && expectedProduct.SequenceEqual(actualProduct);
        }, iter: IterationCount);
    }


    //Right-aligns a hand-picked boundary BigInteger into a 16-byte big-endian
    //element, mirroring BoundaryCorpusGen's own Encode helper at the
    //128-bit width GF(2^128) elements use.
    private static byte[] Encode(BigInteger value)
    {
        var destination = new byte[ElementSizeBytes];
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("A boundary corpus value did not fit in the 128-bit element width.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination.AsSpan(0, written).CopyTo(destination.AsSpan(shift));
            destination.AsSpan(0, shift).Clear();
        }

        return destination;
    }
}
