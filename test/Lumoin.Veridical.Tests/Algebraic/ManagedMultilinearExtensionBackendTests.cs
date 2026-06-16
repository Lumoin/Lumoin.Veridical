using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Agreement gates for the batched managed MLE fold: byte-identical to the
/// BigInteger reference on both wired curves — the batched identity
/// <c>e[2i] + c·(e[2i+1] − e[2i])</c> equals the reference's
/// <c>(1−c)·e[2i] + c·e[2i+1]</c> exactly in the field, so any divergence is
/// a defect in the gather/block plumbing. Sizes cover a sub-block table, the
/// exact block boundary, and a multi-block table; the in-place case folds
/// over the source buffer's prefix the way the sumcheck drivers do.
/// </summary>
[TestClass]
internal sealed class ManagedMultilinearExtensionBackendTests
{
    private const int ScalarSize = 32;

    private static readonly MleFoldDelegate ReferenceFold = MultilinearExtensionBigIntegerReference.GetFold();


    //3 variables: 4 pairs (sub-block); 11: 1024 pairs (exactly one block);
    //12: 2048 pairs (two blocks).
    [TestMethod]
    [DataRow(3)]
    [DataRow(11)]
    [DataRow(12)]
    public void BatchedFoldMatchesTheReferenceOnBothCurves(int variableCount)
    {
        AssertFoldAgreement(variableCount, CurveParameterSet.Bls12Curve381, TestScalarBackends.Bls12Curve381);
        AssertFoldAgreement(variableCount, CurveParameterSet.Bn254, TestScalarBackends.Bn254);
    }


    [TestMethod]
    public void BatchedFoldIsSafeInPlaceOverTheSourcePrefix()
    {
        //The sumcheck drivers fold a working table into its own prefix; the
        //batched fold must match the reference under the same aliasing.
        const int VariableCount = 12;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarArithmeticBackend backend = TestScalarBackends.Bls12Curve381;
        CurveParameterSet curve = CurveParameterSet.Bls12Curve381;
        MleFoldDelegate batchedFold = ManagedMultilinearExtensionBackend.CreateFold(backend, pool);

        int evaluationCount = 1 << VariableCount;
        int tableBytes = evaluationCount * ScalarSize;
        using IMemoryOwner<byte> referenceOwner = pool.Rent(tableBytes);
        using IMemoryOwner<byte> batchedOwner = pool.Rent(tableBytes);
        Span<byte> referenceTable = referenceOwner.Memory.Span[..tableBytes];
        Span<byte> batchedTable = batchedOwner.Memory.Span[..tableBytes];
        FillCanonical(referenceTable, salt: 311, curve);
        referenceTable.CopyTo(batchedTable);

        Span<byte> challenge = stackalloc byte[ScalarSize];
        FillCanonical(challenge, salt: 313, curve);

        int halfBytes = tableBytes / 2;
        ReferenceFold(referenceTable, challenge, referenceTable[..halfBytes], VariableCount, curve);
        batchedFold(batchedTable, challenge, batchedTable[..halfBytes], VariableCount, curve);

        Assert.IsTrue(
            referenceTable[..halfBytes].SequenceEqual(batchedTable[..halfBytes]),
            "The in-place batched fold must match the in-place reference fold.");
    }


    //12 variables: two batched blocks, the full code path.
    private const int EvaluateVariableCount = 12;


    [TestMethod]
    public void BatchedEvaluateMatchesTheReferenceOnBothCurves()
    {
        AssertEvaluateAgreement(CurveParameterSet.Bls12Curve381, TestScalarBackends.Bls12Curve381);
        AssertEvaluateAgreement(CurveParameterSet.Bn254, TestScalarBackends.Bn254);
    }


    [TestMethod]
    public void BatchedFoldMatchesTheReferenceOnTheExplicitAvx2Backend()
    {
        //"Test them if a suitable backend is available": the facade picks the
        //best ISA implicitly; this pins the explicit AVX2 batch kernel.
        InstructionSetRequirements.RequireAvx2();
        MleFoldDelegate avx2Fold = ManagedMultilinearExtensionBackend.CreateFold(
            Bls12Curve381BigIntegerScalarReference.GetAdd(),
            Bls12Curve381BigIntegerScalarReference.GetSubtract(),
            Bls12Curve381Avx2ScalarBackend.GetBatchMultiply(),
            BaseMemoryPool.Shared);
        AssertFoldAgreementWith(avx2Fold, EvaluateVariableCount, CurveParameterSet.Bls12Curve381);
    }


    [TestMethod]
    public void BatchedFoldMatchesTheReferenceOnTheExplicitAvx512Backend()
    {
        InstructionSetRequirements.RequireAvx512();
        MleFoldDelegate avx512Fold = ManagedMultilinearExtensionBackend.CreateFold(
            Bls12Curve381BigIntegerScalarReference.GetAdd(),
            Bls12Curve381BigIntegerScalarReference.GetSubtract(),
            Bls12Curve381Avx512ScalarBackend.GetBatchMultiply(),
            BaseMemoryPool.Shared);
        AssertFoldAgreementWith(avx512Fold, EvaluateVariableCount, CurveParameterSet.Bls12Curve381);
    }


    private static void AssertEvaluateAgreement(CurveParameterSet curve, ScalarArithmeticBackend backend)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        MleEvaluateDelegate referenceEvaluate = MultilinearExtensionBigIntegerReference.GetEvaluate();
        MleEvaluateDelegate batchedEvaluate = ManagedMultilinearExtensionBackend.CreateEvaluate(backend, pool);

        int evaluationCount = 1 << EvaluateVariableCount;
        int tableBytes = evaluationCount * ScalarSize;
        using IMemoryOwner<byte> tableOwner = pool.Rent(tableBytes);
        using IMemoryOwner<byte> pointOwner = pool.Rent(EvaluateVariableCount * ScalarSize);
        Span<byte> table = tableOwner.Memory.Span[..tableBytes];
        Span<byte> point = pointOwner.Memory.Span[..(EvaluateVariableCount * ScalarSize)];
        FillCanonical(table, salt: 503, curve);
        FillCanonical(point, salt: 509, curve);

        Span<byte> expected = stackalloc byte[ScalarSize];
        Span<byte> actual = stackalloc byte[ScalarSize];
        referenceEvaluate(table, point, expected, EvaluateVariableCount, curve);
        batchedEvaluate(table, point, actual, EvaluateVariableCount, curve);

        Assert.IsTrue(
            expected.SequenceEqual(actual),
            $"The batched evaluate must match the reference over {curve}.");
    }


    private static void AssertFoldAgreementWith(MleFoldDelegate fold, int variableCount, CurveParameterSet curve)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        int evaluationCount = 1 << variableCount;
        int tableBytes = evaluationCount * ScalarSize;
        int foldedBytes = tableBytes / 2;
        using IMemoryOwner<byte> tableOwner = pool.Rent(tableBytes);
        using IMemoryOwner<byte> expectedOwner = pool.Rent(foldedBytes);
        using IMemoryOwner<byte> actualOwner = pool.Rent(foldedBytes);
        Span<byte> table = tableOwner.Memory.Span[..tableBytes];
        Span<byte> expected = expectedOwner.Memory.Span[..foldedBytes];
        Span<byte> actual = actualOwner.Memory.Span[..foldedBytes];
        FillCanonical(table, salt: 601, curve);

        Span<byte> challenge = stackalloc byte[ScalarSize];
        FillCanonical(challenge, salt: 607, curve);

        ReferenceFold(table, challenge, expected, variableCount, curve);
        fold(table, challenge, actual, variableCount, curve);

        Assert.IsTrue(expected.SequenceEqual(actual), "The explicit-ISA batched fold must match the reference.");
    }


    private static void AssertFoldAgreement(int variableCount, CurveParameterSet curve, ScalarArithmeticBackend backend)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        MleFoldDelegate batchedFold = ManagedMultilinearExtensionBackend.CreateFold(backend, pool);

        int evaluationCount = 1 << variableCount;
        int tableBytes = evaluationCount * ScalarSize;
        int foldedBytes = tableBytes / 2;
        using IMemoryOwner<byte> tableOwner = pool.Rent(tableBytes);
        using IMemoryOwner<byte> expectedOwner = pool.Rent(foldedBytes);
        using IMemoryOwner<byte> actualOwner = pool.Rent(foldedBytes);
        Span<byte> table = tableOwner.Memory.Span[..tableBytes];
        Span<byte> expected = expectedOwner.Memory.Span[..foldedBytes];
        Span<byte> actual = actualOwner.Memory.Span[..foldedBytes];
        FillCanonical(table, salt: 401 + variableCount, curve);

        Span<byte> challenge = stackalloc byte[ScalarSize];
        FillCanonical(challenge, salt: 409, curve);

        ReferenceFold(table, challenge, expected, variableCount, curve);
        batchedFold(table, challenge, actual, variableCount, curve);

        Assert.IsTrue(
            expected.SequenceEqual(actual),
            $"The batched fold must match the reference at {variableCount} variables over {curve}.");
    }


    private static void FillCanonical(Span<byte> destination, int salt, CurveParameterSet curve)
    {
        ScalarReduceDelegate reduce = curve.Code == CurveParameterSet.Bn254.Code
            ? Bn254BigIntegerScalarReference.GetReduce()
            : Bls12Curve381BigIntegerScalarReference.GetReduce();

        DeterministicScalarFill.FillCanonical(destination, salt, reduce, curve);
    }
}
