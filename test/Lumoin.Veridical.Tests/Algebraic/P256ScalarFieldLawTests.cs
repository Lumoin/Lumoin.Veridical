using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Algebraic-law property tests for the P-256 scalar field Fn, run against
/// <see cref="P256ScalarMontgomeryBackend"/> — the only scalar-field backend
/// this curve wires (there is no Solinas variant for the scalar field, unlike
/// the base field). <see cref="P256ScalarMontgomeryBackendAgreementTests"/>
/// already gates byte-identity against the BigInteger reference over a
/// deterministic sample block plus three fixed edges (0, 1, n−1); this file
/// states the field axioms themselves over operands blended with the
/// canonical-domain boundary corpus, and separately blends the raw-reduction
/// corpus (n, n+1, an all-<c>0xFF</c> fill) into the reduce round trip.
/// </summary>
[TestClass]
internal sealed class P256ScalarFieldLawTests
{
    private const long IterationCount = 300;
    private static readonly CurveParameterSet Curve = CurveParameterSet.P256;
    private static readonly BigInteger Order = P256BigIntegerScalarReference.FieldOrder;

    private static readonly ScalarReduceDelegate ReferenceReduce = P256BigIntegerScalarReference.GetReduce();

    private static readonly ScalarAddDelegate Add = P256ScalarMontgomeryBackend.GetAdd();
    private static readonly ScalarMultiplyDelegate Multiply = P256ScalarMontgomeryBackend.GetMultiply();
    private static readonly ScalarNegateDelegate Negate = P256ScalarMontgomeryBackend.GetNegate();
    private static readonly ScalarInvertDelegate Invert = P256ScalarMontgomeryBackend.GetInvert();
    private static readonly ScalarReduceDelegate MontgomeryReduce = P256ScalarMontgomeryBackend.GetReduce();

    private static readonly Gen<byte[]> BoundaryFieldBytesGen = BoundaryCorpusGen.CanonicalDomain(Order);
    private static readonly Gen<byte[]> BoundaryRawBytesGen = BoundaryCorpusGen.RawReduction(Order);


    [TestMethod]
    public void AdditionIsCommutative()
    {
        Gen.Select(BoundaryFieldBytesGen, BoundaryFieldBytesGen).Sample((rawA, rawB) =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            Span<byte> b = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(rawA, a, Curve);
            ReferenceReduce(rawB, b, Curve);

            Span<byte> leftThenRight = stackalloc byte[Scalar.SizeBytes];
            Span<byte> rightThenLeft = stackalloc byte[Scalar.SizeBytes];
            Add(a, b, leftThenRight, Curve);
            Add(b, a, rightThenLeft, Curve);

            return leftThenRight.SequenceEqual(rightThenLeft);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void AdditionIsAssociative()
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
            Add(a, b, aPlusB, Curve);
            Add(aPlusB, c, abThenC, Curve);
            Add(b, c, bPlusC, Curve);
            Add(a, bPlusC, aThenBc, Curve);

            return abThenC.SequenceEqual(aThenBc);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsCommutative()
    {
        Gen.Select(BoundaryFieldBytesGen, BoundaryFieldBytesGen).Sample((rawA, rawB) =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            Span<byte> b = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(rawA, a, Curve);
            ReferenceReduce(rawB, b, Curve);

            Span<byte> leftThenRight = stackalloc byte[Scalar.SizeBytes];
            Span<byte> rightThenLeft = stackalloc byte[Scalar.SizeBytes];
            Multiply(a, b, leftThenRight, Curve);
            Multiply(b, a, rightThenLeft, Curve);

            return leftThenRight.SequenceEqual(rightThenLeft);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsAssociative()
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
            Multiply(a, b, aTimesB, Curve);
            Multiply(aTimesB, c, abThenC, Curve);
            Multiply(b, c, bTimesC, Curve);
            Multiply(a, bTimesC, aThenBc, Curve);

            return abThenC.SequenceEqual(aThenBc);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationDistributesOverAddition()
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
            Add(b, c, bPlusC, Curve);
            Multiply(a, bPlusC, leftSide, Curve);

            Span<byte> aTimesB = stackalloc byte[Scalar.SizeBytes];
            Span<byte> aTimesC = stackalloc byte[Scalar.SizeBytes];
            Span<byte> rightSide = stackalloc byte[Scalar.SizeBytes];
            Multiply(a, b, aTimesB, Curve);
            Multiply(a, c, aTimesC, Curve);
            Add(aTimesB, aTimesC, rightSide, Curve);

            return leftSide.SequenceEqual(rightSide);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void NegationIsAdditiveInverse()
    {
        BoundaryFieldBytesGen.Sample(rawA =>
        {
            Span<byte> a = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(rawA, a, Curve);

            Span<byte> negatedA = stackalloc byte[Scalar.SizeBytes];
            Negate(a, negatedA, Curve);

            Span<byte> sum = stackalloc byte[Scalar.SizeBytes];
            Add(a, negatedA, sum, Curve);

            return sum.IndexOfAnyExcept((byte)0) < 0;
        }, iter: IterationCount);
    }


    [TestMethod]
    public void InverseTimesValueIsOne()
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
            Invert(a, inverse, Curve);
            Span<byte> product = stackalloc byte[Scalar.SizeBytes];
            Multiply(a, inverse, product, Curve);

            Span<byte> one = stackalloc byte[Scalar.SizeBytes];
            one[^1] = 1;

            return product.SequenceEqual(one);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void ReduceAgreesWithReferenceForBoundarySeededRawInputs()
    {
        //Unlike the algebraic-law tests above (canonical-domain operands),
        //this blends the raw-reduction corpus — n, n+1, an all-0xFF fill,
        //and single-high-bit limb patterns — none of which are already
        //reduced, so the fold/subtract paths inside Reduce itself are hit
        //at their boundary.
        BoundaryRawBytesGen.Sample(raw =>
        {
            Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
            Span<byte> actual = stackalloc byte[Scalar.SizeBytes];
            ReferenceReduce(raw, expected, Curve);
            MontgomeryReduce(raw, actual, Curve);

            return expected.SequenceEqual(actual);
        }, iter: IterationCount);
    }
}
