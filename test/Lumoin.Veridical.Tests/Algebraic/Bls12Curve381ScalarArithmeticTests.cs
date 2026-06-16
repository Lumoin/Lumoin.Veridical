using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Provenance;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Property-based tests for BLS12-381 scalar field arithmetic. Each test
/// states an algebraic law (associativity, commutativity, distributivity,
/// inverse) and verifies it holds for randomly sampled scalars. The
/// reference implementation in
/// <see cref="Bls12Curve381BigIntegerScalarReference"/> is wired in exactly
/// as an application would wire a backend.
/// </summary>
/// <remarks>
/// CsCheck's <c>Gen.Byte.Array[n]</c> produces uniform-byte arrays whose
/// values may exceed the field order. Each test converts those raw bytes
/// into valid scalars via <see cref="Scalar.FromBytesReduced"/>,
/// which dispatches to the reference reducer; the test code itself never
/// performs modular arithmetic. The byte arrays from CsCheck are short-lived
/// arguments to the factory, never stored or transformed by test code.
/// </remarks>
[TestClass]
internal sealed class Bls12Curve381ScalarArithmeticTests
{
    private static readonly ScalarReduceDelegate ReduceDelegate =
        Bls12Curve381BigIntegerScalarReference.GetReduce();


    private static readonly Gen<byte[]> RawScalarBytesGen =
        Gen.Byte.Array[Scalar.SizeBytes];


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void AdditionIsCommutative()
    {
        ScalarAddDelegate add = Bls12Curve381BigIntegerScalarReference.GetAdd();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        // Two-arg properties need a tuple-shaped generator. Gen.Select composes
        // the per-operand gen into one Gen<(byte[], byte[])>, and the resulting
        // .Sample overload accepts the two-arg lambda directly.
        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar scalarA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar scalarB = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar leftThenRight = scalarA.Add(scalarB, add, pool);
                using Scalar rightThenLeft = scalarB.Add(scalarA, add, pool);

                return leftThenRight.AsReadOnlySpan().SequenceEqual(rightThenLeft.AsReadOnlySpan());
            }, time: 1);
    }


    [TestMethod]
    public void AdditionIsAssociative()
    {
        ScalarAddDelegate add = Bls12Curve381BigIntegerScalarReference.GetAdd();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes, cBytes) =>
            {
                using Scalar sA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar sB = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar sC = Scalar.FromBytesReduced(cBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar aPlusB = sA.Add(sB, add, pool);
                using Scalar abThenC = aPlusB.Add(sC, add, pool);
                using Scalar bPlusC = sB.Add(sC, add, pool);
                using Scalar aThenBc = sA.Add(bPlusC, add, pool);

                return abThenC.AsReadOnlySpan().SequenceEqual(aThenBc.AsReadOnlySpan());
            }, time: 1);
    }


    [TestMethod]
    public void NegationIsAdditiveInverse()
    {
        ScalarAddDelegate add = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarNegateDelegate negate = Bls12Curve381BigIntegerScalarReference.GetNegate();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        // Single-arg property: .Sample on a single gen takes a one-arg lambda directly.
        RawScalarBytesGen.Sample(aBytes =>
        {
            using Scalar scalarA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
            using Scalar negatedA = scalarA.Negate(negate, pool);
            using Scalar sum = scalarA.Add(negatedA, add, pool);

            return sum.IsZero;
        }, time: 1);
    }


    [TestMethod]
    public void MultiplicationIsCommutative()
    {
        ScalarMultiplyDelegate multiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar sA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar sB = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar leftThenRight = sA.Multiply(sB, multiply, pool);
                using Scalar rightThenLeft = sB.Multiply(sA, multiply, pool);

                return leftThenRight.AsReadOnlySpan().SequenceEqual(rightThenLeft.AsReadOnlySpan());
            }, time: 1);
    }


    [TestMethod]
    public void MultiplicationIsAssociative()
    {
        ScalarMultiplyDelegate multiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes, cBytes) =>
            {
                using Scalar sA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar sB = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar sC = Scalar.FromBytesReduced(cBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar aTimesB = sA.Multiply(sB, multiply, pool);
                using Scalar abThenC = aTimesB.Multiply(sC, multiply, pool);
                using Scalar bTimesC = sB.Multiply(sC, multiply, pool);
                using Scalar aThenBc = sA.Multiply(bTimesC, multiply, pool);

                return abThenC.AsReadOnlySpan().SequenceEqual(aThenBc.AsReadOnlySpan());
            }, time: 1);
    }


    [TestMethod]
    public void MultiplicationDistributesOverAddition()
    {
        ScalarAddDelegate add = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarMultiplyDelegate multiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen, RawScalarBytesGen)
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
    public void InverseTimesValueIsOne()
    {
        ScalarMultiplyDelegate multiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        ScalarInvertDelegate invert = Bls12Curve381BigIntegerScalarReference.GetInvert();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        // The zero scalar has no multiplicative inverse; an iteration that
        // happens to sample bytes reducing to zero is trivially considered to
        // pass. Detecting this post-construction via the scalar's own IsZero
        // is correct in every case, including bytes equal to r or 2r that
        // reduce to zero but are not all-zero at the raw level.
        RawScalarBytesGen.Sample(aBytes =>
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


    [TestMethod]
    public void RandomProducesScalarsCarryingProvenance()
    {
        ScalarRandomDelegate random = Bls12Curve381BigIntegerScalarReference.GetRandom();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Scalar scalar = Scalar.FromRandom(random, CurveParameterSet.Bls12Curve381, pool);

        Assert.IsTrue(scalar.Tag.TryGet(out ProviderClass providerClass),
            "Provenance entries should be present after a boundary operation.");
        Assert.AreEqual(nameof(Bls12Curve381BigIntegerScalarReference), providerClass.Name);

        Assert.AreEqual(AlgebraicRole.Scalar, scalar.Tag.Get<AlgebraicRole>());
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, scalar.Tag.Get<CurveParameterSet>());
    }
}