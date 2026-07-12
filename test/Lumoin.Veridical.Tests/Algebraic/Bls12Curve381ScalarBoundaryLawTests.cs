using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Boundary-blended companions to the algebraic-law sweep in
/// <see cref="Bls12Curve381ScalarArithmeticTests"/>, which draws its operands
/// uniformly and so essentially never lands on 0, 1, the field's top
/// neighbours, or a limb-boundary carry pattern. This file restates
/// distributivity, the additive inverse, and the multiplicative-inverse
/// round trip over the canonical-domain boundary corpus, without touching
/// the existing file's bodies.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381ScalarBoundaryLawTests
{
    private static readonly ScalarReduceDelegate ReduceDelegate = Bls12Curve381BigIntegerScalarReference.GetReduce();

    private static readonly Gen<byte[]> BoundaryScalarBytesGen =
        BoundaryCorpusGen.CanonicalDomain(Bls12Curve381BigIntegerScalarReference.FieldOrder);


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void MultiplicationDistributesOverAdditionForBoundarySeededScalars()
    {
        ScalarAddDelegate add = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarMultiplyDelegate multiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(BoundaryScalarBytesGen, BoundaryScalarBytesGen, BoundaryScalarBytesGen)
            .Sample((aBytes, bBytes, cBytes) =>
            {
                using Scalar sA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar sB = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar sC = Scalar.FromBytesReduced(cBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar bPlusC = sB.Add(sC, add, pool);
                using Scalar leftSide = sA.Multiply(bPlusC, multiply, pool);

                using Scalar aTimesB = sA.Multiply(sB, multiply, pool);
                using Scalar aTimesC = sA.Multiply(sC, multiply, pool);
                using Scalar rightSide = aTimesB.Add(aTimesC, add, pool);

                return leftSide.AsReadOnlySpan().SequenceEqual(rightSide.AsReadOnlySpan());
            }, time: 1);
    }


    [TestMethod]
    public void NegationIsAdditiveInverseForBoundarySeededScalars()
    {
        ScalarAddDelegate add = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarNegateDelegate negate = Bls12Curve381BigIntegerScalarReference.GetNegate();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        BoundaryScalarBytesGen.Sample(aBytes =>
        {
            using Scalar scalarA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
            using Scalar negatedA = scalarA.Negate(negate, pool);
            using Scalar sum = scalarA.Add(negatedA, add, pool);

            return sum.IsZero;
        }, time: 1);
    }


    [TestMethod]
    public void InverseTimesValueIsOneForBoundarySeededScalars()
    {
        ScalarMultiplyDelegate multiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        ScalarInvertDelegate invert = Bls12Curve381BigIntegerScalarReference.GetInvert();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        BoundaryScalarBytesGen.Sample(aBytes =>
        {
            using Scalar scalarA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
            if(scalarA.IsZero)
            {
                return true;
            }

            using Scalar invA = scalarA.Invert(invert, pool);
            using Scalar product = scalarA.Multiply(invA, multiply, pool);

            return product.IsOne;
        }, time: 1);
    }
}
