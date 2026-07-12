using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The fold-then-evaluate identity — folding the first variable against a
/// challenge and then evaluating at the remaining coordinates equals
/// evaluating directly at (challenge, remaining coordinates) — stated as a
/// CsCheck property over <see cref="ManagedMultilinearExtensionBackend"/>'s
/// batched delegates, with boundary-seeded evaluation tables and point
/// coordinates. <see cref="ManagedMultilinearExtensionBackendTests"/> only
/// ever gates this backend against the BigInteger reference on fixed
/// <c>DataRow</c> sizes; <see cref="MultilinearExtensionEvaluationTests"/>
/// states the identity itself, but against the reference implementation with
/// uniform draws. This file is the missing combination: the identity, over
/// the production batched backend, with a boundary-blended corpus.
/// </summary>
[TestClass]
internal sealed class ManagedMultilinearExtensionFoldEvaluateIdentityTests
{
    private const int MinVariableCount = 1;
    private const int MaxVariableCount = 5;
    private const long IterationCount = 40;
    private const int ElementSize = Scalar.SizeBytes;


    [TestMethod]
    public void FoldThenEvaluateEqualsEvaluateForBoundarySeededInputsOnBls12Curve381() =>
        AssertFoldThenEvaluateEqualsEvaluate(
            CurveParameterSet.Bls12Curve381,
            TestScalarBackends.Bls12Curve381,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            Bls12Curve381BigIntegerScalarReference.FieldOrder);


    [TestMethod]
    public void FoldThenEvaluateEqualsEvaluateForBoundarySeededInputsOnBn254() =>
        AssertFoldThenEvaluateEqualsEvaluate(
            CurveParameterSet.Bn254,
            TestScalarBackends.Bn254,
            Bn254BigIntegerScalarReference.GetReduce(),
            Bn254BigIntegerScalarReference.FieldOrder);


    private static void AssertFoldThenEvaluateEqualsEvaluate(
        CurveParameterSet curve,
        ScalarArithmeticBackend backend,
        ScalarReduceDelegate reduce,
        BigInteger fieldOrder)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        MleFoldDelegate fold = ManagedMultilinearExtensionBackend.CreateFold(backend, pool);
        MleEvaluateDelegate evaluate = ManagedMultilinearExtensionBackend.CreateEvaluate(backend, pool);
        Gen<byte[]> boundaryElementBytesGen = BoundaryCorpusGen.CanonicalDomain(fieldOrder);

        Gen.Int[MinVariableCount, MaxVariableCount]
            .SelectMany(variableCount =>
            {
                int evaluationCount = 1 << variableCount;
                int tailCount = variableCount - 1;
                return Gen.Select(
                    Gen.Const(variableCount),
                    boundaryElementBytesGen.Array[evaluationCount],
                    boundaryElementBytesGen,
                    boundaryElementBytesGen.Array[tailCount]);
            })
            .Sample((variableCount, rawEvaluations, rawChallenge, rawTailPoint) =>
            {
                int evaluationCount = 1 << variableCount;
                int tailCount = variableCount - 1;
                int foldedCount = evaluationCount / 2;

                using IMemoryOwner<byte> evaluationsOwner = pool.Rent(evaluationCount * ElementSize);
                using IMemoryOwner<byte> tailPointOwner = pool.Rent(Math.Max(tailCount, 1) * ElementSize);
                using IMemoryOwner<byte> challengeOwner = pool.Rent(ElementSize);
                using IMemoryOwner<byte> fullPointOwner = pool.Rent(variableCount * ElementSize);
                using IMemoryOwner<byte> foldedOwner = pool.Rent(foldedCount * ElementSize);
                using IMemoryOwner<byte> directResultOwner = pool.Rent(ElementSize);
                using IMemoryOwner<byte> foldedResultOwner = pool.Rent(ElementSize);

                Span<byte> evaluations = evaluationsOwner.Memory.Span[..(evaluationCount * ElementSize)];
                Span<byte> tailPoint = tailPointOwner.Memory.Span[..(tailCount * ElementSize)];
                Span<byte> challenge = challengeOwner.Memory.Span[..ElementSize];
                Span<byte> fullPoint = fullPointOwner.Memory.Span[..(variableCount * ElementSize)];
                Span<byte> folded = foldedOwner.Memory.Span[..(foldedCount * ElementSize)];
                Span<byte> directResult = directResultOwner.Memory.Span[..ElementSize];
                Span<byte> foldedResult = foldedResultOwner.Memory.Span[..ElementSize];

                ReduceEach(rawEvaluations, evaluations, reduce, curve);
                reduce(rawChallenge, challenge, curve);
                ReduceEach(rawTailPoint, tailPoint, reduce, curve);

                challenge.CopyTo(fullPoint[..ElementSize]);
                tailPoint.CopyTo(fullPoint[ElementSize..]);

                //Path 1: evaluate directly at (challenge, tail...).
                evaluate(evaluations, fullPoint, directResult, variableCount, curve);

                //Path 2: fold the first variable against the challenge, then
                //evaluate the folded (one-fewer-variable) table at the tail.
                fold(evaluations, challenge, folded, variableCount, curve);
                evaluate(folded, tailPoint, foldedResult, tailCount, curve);

                return directResult.SequenceEqual(foldedResult);
            }, iter: IterationCount);
    }


    private static void ReduceEach(byte[][] raw, Span<byte> destination, ScalarReduceDelegate reduce, CurveParameterSet curve)
    {
        for(int i = 0; i < raw.Length; i++)
        {
            reduce(raw[i], destination.Slice(i * ElementSize, ElementSize), curve);
        }
    }
}
