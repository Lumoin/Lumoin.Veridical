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
/// <see cref="Bn254ScalarBackendTests"/>, which draws its property-test
/// operands uniformly and so essentially never lands on 0, 1, the field's
/// top neighbours, or a limb-boundary carry pattern. This file restates
/// distributivity, the additive inverse, and the multiplicative-inverse
/// round trip over the canonical-domain boundary corpus, without touching
/// the existing file's bodies.
/// </summary>
[TestClass]
internal sealed class Bn254ScalarBoundaryLawTests
{
    private static readonly ScalarReduceDelegate ReduceDelegate = Bn254BigIntegerScalarReference.GetReduce();

    private static readonly Gen<byte[]> BoundaryScalarBytesGen =
        BoundaryCorpusGen.CanonicalDomain(Bn254BigIntegerScalarReference.FieldOrder);


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void MultiplicationDistributesOverAdditionForBoundarySeededScalars()
    {
        ScalarAddDelegate add = Bn254BigIntegerScalarReference.GetAdd();
        ScalarMultiplyDelegate multiply = Bn254BigIntegerScalarReference.GetMultiply();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(BoundaryScalarBytesGen, BoundaryScalarBytesGen, BoundaryScalarBytesGen)
            .Sample((aBytes, bBytes, cBytes) =>
            {
                using Scalar sA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar sB = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar sC = Scalar.FromBytesReduced(cBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

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
        ScalarAddDelegate add = Bn254BigIntegerScalarReference.GetAdd();
        ScalarNegateDelegate negate = Bn254BigIntegerScalarReference.GetNegate();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        BoundaryScalarBytesGen.Sample(aBytes =>
        {
            using Scalar scalarA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
            using Scalar negatedA = scalarA.Negate(negate, pool);
            using Scalar sum = scalarA.Add(negatedA, add, pool);

            return sum.IsZero;
        }, time: 1);
    }


    [TestMethod]
    public void InverseTimesValueIsOneForBoundarySeededScalars()
    {
        ScalarMultiplyDelegate multiply = Bn254BigIntegerScalarReference.GetMultiply();
        ScalarInvertDelegate invert = Bn254BigIntegerScalarReference.GetInvert();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        BoundaryScalarBytesGen.Sample(aBytes =>
        {
            using Scalar scalarA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
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
