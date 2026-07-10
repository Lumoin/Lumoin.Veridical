using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Algebraic-law property tests for the P-256 base field Fp, run against both
/// limb backends (<see cref="P256BaseFieldMontgomeryBackend"/> and
/// <see cref="P256BaseFieldSolinasBackend"/>). <see cref="Fp256FieldBackendAgreementTests"/>
/// already gates byte-identity against the BigInteger reference and a fixed
/// edge-case list; this file states the field axioms themselves (add/multiply
/// commutativity and associativity, distributivity, additive and
/// multiplicative inverse) over operands blended with the canonical-domain
/// boundary corpus (0, 1, 2, the midpoint, the two top neighbours, and
/// limb-boundary patterns folded into the field), so a law violation
/// surfaces even if a backend happens to agree with the reference on the
/// specific edge vectors that file enumerates.
/// </summary>
[TestClass]
internal sealed class P256BaseFieldLawTests
{
    private const long IterationCount = 300;
    private static readonly CurveParameterSet Curve = CurveParameterSet.None;
    private static readonly BigInteger FieldOrder = P256BaseFieldReference.FieldOrder;

    private static readonly ScalarReduceDelegate ReferenceReduce = P256BaseFieldReference.GetReduce();

    private static readonly Gen<byte[]> BoundaryFieldBytesGen = BoundaryCorpusGen.CanonicalDomain(FieldOrder);


    [TestMethod]
    public void MontgomeryAdditionIsCommutative() => AssertAdditionIsCommutative(P256BaseFieldMontgomeryBackend.GetAdd());

    [TestMethod]
    public void SolinasAdditionIsCommutative() => AssertAdditionIsCommutative(P256BaseFieldSolinasBackend.GetAdd());


    [TestMethod]
    public void MontgomeryAdditionIsAssociative() => AssertAdditionIsAssociative(P256BaseFieldMontgomeryBackend.GetAdd());

    [TestMethod]
    public void SolinasAdditionIsAssociative() => AssertAdditionIsAssociative(P256BaseFieldSolinasBackend.GetAdd());


    [TestMethod]
    public void MontgomeryMultiplicationIsCommutative() => AssertMultiplicationIsCommutative(P256BaseFieldMontgomeryBackend.GetMultiply());

    [TestMethod]
    public void SolinasMultiplicationIsCommutative() => AssertMultiplicationIsCommutative(P256BaseFieldSolinasBackend.GetMultiply());


    [TestMethod]
    public void MontgomeryMultiplicationIsAssociative() => AssertMultiplicationIsAssociative(P256BaseFieldMontgomeryBackend.GetMultiply());

    [TestMethod]
    public void SolinasMultiplicationIsAssociative() => AssertMultiplicationIsAssociative(P256BaseFieldSolinasBackend.GetMultiply());


    [TestMethod]
    public void MontgomeryMultiplicationDistributesOverAddition() =>
        AssertMultiplicationDistributesOverAddition(P256BaseFieldMontgomeryBackend.GetAdd(), P256BaseFieldMontgomeryBackend.GetMultiply());

    [TestMethod]
    public void SolinasMultiplicationDistributesOverAddition() =>
        AssertMultiplicationDistributesOverAddition(P256BaseFieldSolinasBackend.GetAdd(), P256BaseFieldSolinasBackend.GetMultiply());


    [TestMethod]
    public void MontgomeryHasAdditiveInverse() =>
        AssertHasAdditiveInverse(P256BaseFieldMontgomeryBackend.GetAdd(), P256BaseFieldMontgomeryBackend.GetSubtract());

    [TestMethod]
    public void SolinasHasAdditiveInverse() =>
        AssertHasAdditiveInverse(P256BaseFieldSolinasBackend.GetAdd(), P256BaseFieldSolinasBackend.GetSubtract());


    [TestMethod]
    public void MontgomeryInverseTimesValueIsOne() =>
        AssertInverseTimesValueIsOne(P256BaseFieldMontgomeryBackend.GetMultiply(), P256BaseFieldMontgomeryBackend.GetInvert());

    [TestMethod]
    public void SolinasInverseTimesValueIsOne() =>
        AssertInverseTimesValueIsOne(P256BaseFieldSolinasBackend.GetMultiply(), P256BaseFieldSolinasBackend.GetInvert());


    [TestMethod]
    public void MontgomeryRoundTripIsIdentityForBoundarySeededValues()
    {
        //The sibling agreement test (MontgomeryRoundTripIsIdentity) sweeps
        //uniform draws only; this blends in the canonical-domain boundary
        //corpus so the to/from converters are also checked at 0, 1, p-1 and
        //the limb-boundary patterns.
        BoundaryFieldBytesGen.Sample(rawA =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(rawA, a, Curve);

            Span<byte> montgomery = stackalloc byte[Scalar.SizeBytes];
            Span<byte> back = stackalloc byte[Scalar.SizeBytes];
            P256BaseFieldMontgomeryBackend.ToMontgomery(a, montgomery);
            P256BaseFieldMontgomeryBackend.FromMontgomery(montgomery, back);

            return a.SequenceEqual(back);
        }, iter: IterationCount);
    }


    private static void AssertAdditionIsCommutative(ScalarAddDelegate add)
    {
        Gen.Select(BoundaryFieldBytesGen, BoundaryFieldBytesGen).Sample((rawA, rawB) =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            Span<byte> b = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(rawA, a, Curve);
            ReferenceReduce(rawB, b, Curve);

            Span<byte> leftThenRight = stackalloc byte[Scalar.SizeBytes];
            Span<byte> rightThenLeft = stackalloc byte[Scalar.SizeBytes];
            add(a, b, leftThenRight, Curve);
            add(b, a, rightThenLeft, Curve);

            return leftThenRight.SequenceEqual(rightThenLeft);
        }, iter: IterationCount);
    }


    private static void AssertAdditionIsAssociative(ScalarAddDelegate add)
    {
        Gen.Select(BoundaryFieldBytesGen, BoundaryFieldBytesGen, BoundaryFieldBytesGen).Sample((rawA, rawB, rawC) =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            Span<byte> b = stackalloc byte[Scalar.SizeBytes];
            Span<byte> c = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(rawA, a, Curve);
            ReferenceReduce(rawB, b, Curve);
            ReferenceReduce(rawC, c, Curve);

            Span<byte> aPlusB = stackalloc byte[Scalar.SizeBytes];
            Span<byte> abThenC = stackalloc byte[Scalar.SizeBytes];
            Span<byte> bPlusC = stackalloc byte[Scalar.SizeBytes];
            Span<byte> aThenBc = stackalloc byte[Scalar.SizeBytes];
            add(a, b, aPlusB, Curve);
            add(aPlusB, c, abThenC, Curve);
            add(b, c, bPlusC, Curve);
            add(a, bPlusC, aThenBc, Curve);

            return abThenC.SequenceEqual(aThenBc);
        }, iter: IterationCount);
    }


    private static void AssertMultiplicationIsCommutative(ScalarMultiplyDelegate multiply)
    {
        Gen.Select(BoundaryFieldBytesGen, BoundaryFieldBytesGen).Sample((rawA, rawB) =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            Span<byte> b = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(rawA, a, Curve);
            ReferenceReduce(rawB, b, Curve);

            Span<byte> leftThenRight = stackalloc byte[Scalar.SizeBytes];
            Span<byte> rightThenLeft = stackalloc byte[Scalar.SizeBytes];
            multiply(a, b, leftThenRight, Curve);
            multiply(b, a, rightThenLeft, Curve);

            return leftThenRight.SequenceEqual(rightThenLeft);
        }, iter: IterationCount);
    }


    private static void AssertMultiplicationIsAssociative(ScalarMultiplyDelegate multiply)
    {
        Gen.Select(BoundaryFieldBytesGen, BoundaryFieldBytesGen, BoundaryFieldBytesGen).Sample((rawA, rawB, rawC) =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            Span<byte> b = stackalloc byte[Scalar.SizeBytes];
            Span<byte> c = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(rawA, a, Curve);
            ReferenceReduce(rawB, b, Curve);
            ReferenceReduce(rawC, c, Curve);

            Span<byte> aTimesB = stackalloc byte[Scalar.SizeBytes];
            Span<byte> abThenC = stackalloc byte[Scalar.SizeBytes];
            Span<byte> bTimesC = stackalloc byte[Scalar.SizeBytes];
            Span<byte> aThenBc = stackalloc byte[Scalar.SizeBytes];
            multiply(a, b, aTimesB, Curve);
            multiply(aTimesB, c, abThenC, Curve);
            multiply(b, c, bTimesC, Curve);
            multiply(a, bTimesC, aThenBc, Curve);

            return abThenC.SequenceEqual(aThenBc);
        }, iter: IterationCount);
    }


    private static void AssertMultiplicationDistributesOverAddition(ScalarAddDelegate add, ScalarMultiplyDelegate multiply)
    {
        Gen.Select(BoundaryFieldBytesGen, BoundaryFieldBytesGen, BoundaryFieldBytesGen).Sample((rawA, rawB, rawC) =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            Span<byte> b = stackalloc byte[Scalar.SizeBytes];
            Span<byte> c = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(rawA, a, Curve);
            ReferenceReduce(rawB, b, Curve);
            ReferenceReduce(rawC, c, Curve);

            Span<byte> bPlusC = stackalloc byte[Scalar.SizeBytes];
            Span<byte> leftSide = stackalloc byte[Scalar.SizeBytes];
            add(b, c, bPlusC, Curve);
            multiply(a, bPlusC, leftSide, Curve);

            Span<byte> aTimesB = stackalloc byte[Scalar.SizeBytes];
            Span<byte> aTimesC = stackalloc byte[Scalar.SizeBytes];
            Span<byte> rightSide = stackalloc byte[Scalar.SizeBytes];
            multiply(a, b, aTimesB, Curve);
            multiply(a, c, aTimesC, Curve);
            add(aTimesB, aTimesC, rightSide, Curve);

            return leftSide.SequenceEqual(rightSide);
        }, iter: IterationCount);
    }


    //P256BaseFieldMontgomeryBackend/SolinasBackend expose no Negate delegate,
    //unlike the field's BigInteger reference; the additive inverse is instead
    //stated as -a = 0 - a via each backend's own Subtract, then a + (-a) = 0.
    private static void AssertHasAdditiveInverse(ScalarAddDelegate add, ScalarSubtractDelegate subtract)
    {
        BoundaryFieldBytesGen.Sample(rawA =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(rawA, a, Curve);

            Span<byte> zero = stackalloc byte[Scalar.SizeBytes];
            Span<byte> negatedA = stackalloc byte[Scalar.SizeBytes];
            subtract(zero, a, negatedA, Curve);

            Span<byte> sum = stackalloc byte[Scalar.SizeBytes];
            add(a, negatedA, sum, Curve);

            return sum.IndexOfAnyExcept((byte)0) < 0;
        }, iter: IterationCount);
    }


    private static void AssertInverseTimesValueIsOne(ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert)
    {
        BoundaryFieldBytesGen.Sample(rawA =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(rawA, a, Curve);
            if(a.IndexOfAnyExcept((byte)0) < 0)
            {
                return true;
            }

            Span<byte> inverse = stackalloc byte[Scalar.SizeBytes];
            invert(a, inverse, Curve);
            Span<byte> product = stackalloc byte[Scalar.SizeBytes];
            multiply(a, inverse, product, Curve);

            Span<byte> one = stackalloc byte[Scalar.SizeBytes];
            one[^1] = 1;

            return product.SequenceEqual(one);
        }, iter: IterationCount);
    }
}
