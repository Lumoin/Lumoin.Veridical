using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Property tests for the MLE leaf type and its BLS12-381 arithmetic
/// extensions. Each test asserts an algebraic identity rather than a
/// hand-computed scalar value: the BigInteger reference is the ground
/// truth, and CsCheck generates random inputs the identity must hold
/// over.
/// </summary>
[TestClass]
internal sealed class MultilinearExtensionEvaluationTests
{
    private static readonly MleFoldDelegate Fold = MultilinearExtensionBigIntegerReference.GetFold();
    private static readonly MleEvaluateDelegate Evaluate = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

    private const long IterationCount = 30;


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void EvaluateOnHypercubeMatchesEvaluationsForOneToFourVariables()
    {
        //The defining property: on {0,1}^n the multilinear extension agrees
        //with the function it interpolates. Choose distinct small scalars
        //for the evaluations so a wrong index would surface as a mismatch.
        foreach(int variableCount in (int[])[1, 2, 3, 4])
        {
            int evaluationCount = 1 << variableCount;
            BigInteger[] evaluationValues = new BigInteger[evaluationCount];
            for(int i = 0; i < evaluationCount; i++)
            {
                //Use 1, 2, 3, ... — distinct and small.
                evaluationValues[i] = i + 1;
            }

            using MultilinearExtension mle = BuildMle(evaluationValues, variableCount);

            for(int hypercubeIndex = 0; hypercubeIndex < evaluationCount; hypercubeIndex++)
            {
                using PointArray point = BuildHypercubePoint(hypercubeIndex, variableCount);
                using Scalar result = mle.Evaluate(point.AsSpan, Evaluate, BaseMemoryPool.Shared);

                BigInteger resultValue = new(result.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
                Assert.AreEqual(
                    evaluationValues[hypercubeIndex],
                    resultValue,
                    $"MLE at hypercube index {hypercubeIndex} (n={variableCount}) should equal evaluations[{hypercubeIndex}].");
            }
        }
    }


    [TestMethod]
    public void FoldThenEvaluateEqualsEvaluateForRandomInputs()
    {
        //The sumcheck identity: folding the first variable against challenge c
        //and then evaluating at (p_2, ..., p_n) yields the same scalar as
        //evaluating the original MLE at (c, p_2, ..., p_n). CsCheck sweeps n,
        //the evaluations, the challenge, and the point.
        Gen.Int[1, 5]
            .SelectMany(n =>
            {
                int evalCount = 1 << n;
                return Gen.Select(
                    Gen.Const(n),
                    Gen.Byte.Array[Scalar.SizeBytes * evalCount],
                    Gen.Byte.Array[Scalar.SizeBytes],
                    Gen.Byte.Array[Scalar.SizeBytes * n]);
            })
            .Sample((n, evalBytes, challengeBytes, pointBytes) =>
            {
                int elementSize = Scalar.SizeBytes;
                int evalCount = 1 << n;

                //Reduce inputs to canonical form so the BigInteger reference's
                //ReadCanonical never sees an above-r value.
                using IMemoryOwner<byte> reducedEvalsOwner = BaseMemoryPool.Shared.Rent(evalCount * elementSize);
                using IMemoryOwner<byte> reducedPointOwner = BaseMemoryPool.Shared.Rent(n * elementSize);
                Span<byte> reducedEvals = reducedEvalsOwner.Memory.Span[..(evalCount * elementSize)];
                Span<byte> reducedPoint = reducedPointOwner.Memory.Span[..(n * elementSize)];
                ReduceSlots(evalBytes, reducedEvals, elementSize);
                ReduceSlots(pointBytes, reducedPoint, elementSize);

                using Scalar challenge = ReduceToScalar(challengeBytes);

                using MultilinearExtension mle = MultilinearExtension.FromEvaluations(
                    reducedEvals,
                    n,
                    CurveParameterSet.Bls12Curve381,
                    BaseMemoryPool.Shared);

                //Path 1: evaluate at (c, p_2, ..., p_n) directly.
                using PointArray fullPoint = AssembleFullPoint(challenge, reducedPoint, n - 1, elementSize);
                using Scalar resultDirect = mle.Evaluate(fullPoint.AsSpan, Evaluate, BaseMemoryPool.Shared);

                //Path 2: fold one variable against c, then evaluate at (p_2, ..., p_n).
                using MultilinearExtension folded = mle.Fold(challenge, Fold, BaseMemoryPool.Shared);
                using PointArray tail = BuildPointFromBytes(reducedPoint, n - 1, elementSize);
                using Scalar resultFolded = folded.Evaluate(tail.AsSpan, Evaluate, BaseMemoryPool.Shared);

                return resultDirect.AsReadOnlySpan().SequenceEqual(resultFolded.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void EvaluationIsLinearInEachVariable()
    {
        //For any MLE, fixing every variable except one and varying that one
        //variable produces a degree-1 polynomial. Check by evaluating at
        //three points along a line in the chosen variable: f(0, fixed) +
        //2*f(1, fixed) - f(0, fixed) - f(1, fixed)*1 = 0 iff the function
        //is linear. Equivalently, f(2, fixed) = 2*f(1, fixed) - f(0, fixed).
        //We assert that the three evaluations are collinear via the slope
        //identity.
        const int VariableCount = 3;
        int evalCount = 1 << VariableCount;
        BigInteger[] evaluations = new BigInteger[evalCount];
        for(int i = 0; i < evalCount; i++)
        {
            evaluations[i] = (i * 17) + 3;
        }

        using MultilinearExtension mle = BuildMle(evaluations, VariableCount);

        //Sweep each variable index.
        for(int variableIndex = 0; variableIndex < VariableCount; variableIndex++)
        {
            BigInteger fixedScalar1 = 11;
            BigInteger fixedScalar2 = 23;
            BigInteger[] axisValues = [BigInteger.Zero, BigInteger.One, new(2)];
            BigInteger[] axisResults = new BigInteger[3];

            for(int k = 0; k < 3; k++)
            {
                BigInteger[] pointValues = new BigInteger[VariableCount];
                for(int j = 0; j < VariableCount; j++)
                {
                    pointValues[j] = j == variableIndex
                        ? axisValues[k]
                        : (j == 0 ? fixedScalar1 : fixedScalar2);
                }

                using PointArray point = BuildPointFromValues(pointValues);
                using Scalar result = mle.Evaluate(point.AsSpan, Evaluate, BaseMemoryPool.Shared);
                axisResults[k] = new(result.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
            }

            //Collinearity in the field: f(2) - f(1) should equal f(1) - f(0).
            BigInteger r = Bls12Curve381BigIntegerScalarReference.FieldOrder;
            BigInteger firstDifference = ((axisResults[1] - axisResults[0]) % r + r) % r;
            BigInteger secondDifference = ((axisResults[2] - axisResults[1]) % r + r) % r;

            Assert.AreEqual(
                firstDifference,
                secondDifference,
                $"MLE should be linear in variable {variableIndex}; the differences at (0,1) and (1,2) along that axis disagreed.");
        }
    }


    [TestMethod]
    public void ZeroMleEvaluatesToZeroAtArbitraryPoint()
    {
        const int VariableCount = 3;
        using MultilinearExtension zeroMle = MultilinearExtension.Zero(VariableCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        Assert.IsTrue(zeroMle.IsZero, "Zero factory should yield an all-zero MLE.");

        BigInteger[] arbitraryPoint = [new(42), new(101), BigInteger.Parse("99999999999999999", CultureInfo.InvariantCulture)];
        using PointArray point = BuildPointFromValues(arbitraryPoint);

        using Scalar result = zeroMle.Evaluate(point.AsSpan, Evaluate, BaseMemoryPool.Shared);
        BigInteger resultValue = new(result.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);

        Assert.AreEqual(BigInteger.Zero, resultValue, "Zero MLE should evaluate to zero at any point.");
    }


    [TestMethod]
    public void FoldRejectsMleWithUnwiredCurve()
    {
        //Fabricate an MLE carrying an unwired curve (Pallas) by invoking the
        //internal constructor directly (the public FromEvaluations factory
        //rejects unsupported curves at the size-lookup step, and that's the
        //wrong layer to test here — we want the arithmetic extension's
        //wired-curve guard to fire). Bls12Curve381 and Bn254 are both wired,
        //so a genuinely unwired curve is needed to exercise the reject path.
        //InternalsVisibleTo on Core makes the constructor reachable here.
        const int VariableCount = 1;
        int elementSize = Scalar.SizeBytes;
        int bufferSize = (1 << VariableCount) * elementSize;

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bufferSize);
        owner.Memory.Span[..bufferSize].Clear();

        Tag pallasTag = Tag.Create(AlgebraicRole.MultilinearExtension)
            .With(CurveParameterSet.Pallas)
            .With(new MultilinearExtensionDimensions(VariableCount, 1 << VariableCount));

        using var pallasMle = new MultilinearExtension(
            owner,
            VariableCount,
            elementSize,
            CurveParameterSet.Pallas,
            pallasTag);

        using Scalar challenge = MakeScalarFromInt(7);

        Assert.ThrowsExactly<ArgumentException>(() =>
            pallasMle.Fold(challenge, Fold, BaseMemoryPool.Shared));
    }


    private static MultilinearExtension BuildMle(BigInteger[] evaluations, int variableCount)
    {
        int elementSize = Scalar.SizeBytes;
        int evaluationCount = 1 << variableCount;
        Assert.HasCount(evaluationCount, evaluations, "Test bug: evaluations array size mismatched variable count.");

        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(evaluationCount * elementSize);
        Span<byte> bytes = owner.Memory.Span[..(evaluationCount * elementSize)];
        for(int i = 0; i < evaluationCount; i++)
        {
            WriteCanonical(evaluations[i], bytes.Slice(i * elementSize, elementSize));
        }


        return MultilinearExtension.FromEvaluations(bytes, variableCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static PointArray BuildHypercubePoint(int hypercubeIndex, int variableCount)
    {
        BigInteger[] coordinates = new BigInteger[variableCount];
        for(int j = 0; j < variableCount; j++)
        {
            coordinates[j] = ((hypercubeIndex >> j) & 1) == 1 ? BigInteger.One : BigInteger.Zero;
        }


        return BuildPointFromValues(coordinates);
    }


    private static PointArray BuildPointFromValues(BigInteger[] values)
    {
        var owners = new IMemoryOwner<byte>[values.Length];
        var scalars = new Scalar[values.Length];
        int elementSize = Scalar.SizeBytes;

        for(int i = 0; i < values.Length; i++)
        {
            owners[i] = BaseMemoryPool.Shared.Rent(elementSize);
            WriteCanonical(values[i], owners[i].Memory.Span[..elementSize]);
            scalars[i] = Scalar.FromCanonical(owners[i].Memory.Span[..elementSize], CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
            owners[i].Dispose();
        }


        return new PointArray(scalars);
    }


    private static PointArray BuildPointFromBytes(ReadOnlySpan<byte> packed, int count, int elementSize)
    {
        var scalars = new Scalar[count];
        for(int i = 0; i < count; i++)
        {
            scalars[i] = Scalar.FromCanonical(packed.Slice(i * elementSize, elementSize), CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        }


        return new PointArray(scalars);
    }


    private static PointArray AssembleFullPoint(Scalar head, ReadOnlySpan<byte> tail, int tailCount, int elementSize)
    {
        var scalars = new Scalar[tailCount + 1];
        scalars[0] = Scalar.FromCanonical(head.AsReadOnlySpan(), CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        for(int i = 0; i < tailCount; i++)
        {
            scalars[i + 1] = Scalar.FromCanonical(tail.Slice(i * elementSize, elementSize), CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        }


        return new PointArray(scalars);
    }


    private static Scalar MakeScalarFromInt(int value)
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
        Span<byte> span = owner.Memory.Span[..Scalar.SizeBytes];
        WriteCanonical(new BigInteger(value), span);
        return Scalar.FromCanonical(span, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static Scalar ReduceToScalar(byte[] rawBytes)
    {
        using IMemoryOwner<byte> reducedOwner = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
        Span<byte> reduced = reducedOwner.Memory.Span[..Scalar.SizeBytes];
        Reduce(rawBytes, reduced, CurveParameterSet.Bls12Curve381);
        return Scalar.FromCanonical(reduced, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static void ReduceSlots(byte[] rawSource, Span<byte> destination, int elementSize)
    {
        int slotCount = destination.Length / elementSize;
        for(int i = 0; i < slotCount; i++)
        {
            Reduce(
                rawSource.AsSpan(i * elementSize, elementSize),
                destination.Slice(i * elementSize, elementSize),
                CurveParameterSet.Bls12Curve381);
        }
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger nonNegative = ((value % Bls12Curve381BigIntegerScalarReference.FieldOrder) + Bls12Curve381BigIntegerScalarReference.FieldOrder) % Bls12Curve381BigIntegerScalarReference.FieldOrder;
        if(!nonNegative.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    /// <summary>
    /// Disposable wrapper around a per-test array of pool-rented scalars
    /// so test methods can express <c>using PointArray point = ...</c>
    /// and have every element returned to the pool together.
    /// </summary>
    private readonly struct PointArray: IDisposable
    {
        private readonly Scalar[] scalars;

        public PointArray(Scalar[] scalars) { this.scalars = scalars; }

        public ReadOnlySpan<Scalar> AsSpan => scalars;

        public void Dispose()
        {
            if(scalars is null)
            {
                return;
            }

            for(int i = 0; i < scalars.Length; i++)
            {
                scalars[i]?.Dispose();
            }
        }
    }
}