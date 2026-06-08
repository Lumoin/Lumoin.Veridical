using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Provenance;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Tests for the broad-type factory methods on
/// <see cref="MultilinearExtension"/> that do not exercise arithmetic:
/// the shape and tag composition contracts of <see cref="MultilinearExtension.Random"/>
/// and the kinship between it and the existing <see cref="MultilinearExtension.Zero"/>
/// and <see cref="MultilinearExtension.FromEvaluations"/> factories.
/// </summary>
[TestClass]
internal sealed class MultilinearExtensionFactoryTests
{
    private static readonly ScalarRandomDelegate Random = Bls12Curve381BigIntegerScalarReference.GetRandom();
    private static readonly BigInteger FieldOrder = Bls12Curve381BigIntegerScalarReference.FieldOrder;


    [TestMethod]
    public void RandomReturnsMleOfRequestedShape()
    {
        foreach(int variableCount in (int[])[0, 1, 3, 5])
        {
            using MultilinearExtension mle = MultilinearExtension.Random(
                variableCount,
                CurveParameterSet.Bls12Curve381,
                Random,
                SensitiveMemoryPool<byte>.Shared);

            Assert.AreEqual(variableCount, mle.VariableCount, $"VariableCount should match the requested {variableCount}.");
            Assert.AreEqual(1 << variableCount, mle.EvaluationCount, "EvaluationCount should equal 2^variableCount.");
            Assert.AreEqual(Scalar.SizeBytes, mle.FieldElementSizeBytes, "FieldElementSizeBytes should match the BLS12-381 scalar size.");
            Assert.AreEqual(CurveParameterSet.Bls12Curve381.Code, mle.Curve.Code, "Curve should be BLS12-381.");
            Assert.AreEqual(mle.EvaluationCount * mle.FieldElementSizeBytes, mle.AsReadOnlySpan().Length, "Buffer length should be evaluationCount * fieldElementSize.");
        }
    }


    [TestMethod]
    public void RandomReturnsCanonicalScalarsInEverySlot()
    {
        //Every slot must hold a canonical (reduced) scalar — bytes interpreted
        //as an unsigned big-endian integer strictly less than the field order.
        const int VariableCount = 4;
        using MultilinearExtension mle = MultilinearExtension.Random(
            VariableCount,
            CurveParameterSet.Bls12Curve381,
            Random,
            SensitiveMemoryPool<byte>.Shared);

        int elementSize = mle.FieldElementSizeBytes;
        ReadOnlySpan<byte> buffer = mle.AsReadOnlySpan();
        for(int i = 0; i < mle.EvaluationCount; i++)
        {
            ReadOnlySpan<byte> slot = buffer.Slice(i * elementSize, elementSize);
            BigInteger value = new(slot, isUnsigned: true, isBigEndian: true);
            Assert.IsLessThan(FieldOrder, value, $"Slot {i} carried a non-reduced value {value:X}.");
        }
    }


    [TestMethod]
    public void RandomSlotsDifferAcrossTheBuffer()
    {
        //With 32-byte random scalars the probability that any two slots
        //collide is 2^-256 per pair, so an actual collision indicates the
        //random delegate writes are aliased (a single slot replicated, say).
        const int VariableCount = 5;
        using MultilinearExtension mle = MultilinearExtension.Random(
            VariableCount,
            CurveParameterSet.Bls12Curve381,
            Random,
            SensitiveMemoryPool<byte>.Shared);

        int elementSize = mle.FieldElementSizeBytes;
        ReadOnlySpan<byte> buffer = mle.AsReadOnlySpan();
        ReadOnlySpan<byte> firstSlot = buffer[..elementSize];
        for(int i = 1; i < mle.EvaluationCount; i++)
        {
            ReadOnlySpan<byte> otherSlot = buffer.Slice(i * elementSize, elementSize);
            Assert.IsFalse(
                firstSlot.SequenceEqual(otherSlot),
                $"Slot {i} byte-equals slot 0; the random delegate is producing aliased outputs.");
        }
    }


    [TestMethod]
    public void RandomTagCarriesMleAlgebraicIdentityAndScalarBackendProvenance()
    {
        const int VariableCount = 2;
        using MultilinearExtension mle = MultilinearExtension.Random(
            VariableCount,
            CurveParameterSet.Bls12Curve381,
            Random,
            SensitiveMemoryPool<byte>.Shared);

        //MLE algebraic identity entries override any scalar-level role from
        //the inbound tag.
        Assert.AreEqual(AlgebraicRole.MultilinearExtension, mle.Tag.Get<AlgebraicRole>(), "Tag should carry the MLE role, not the scalar role from the inbound tag.");
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, mle.Tag.Get<CurveParameterSet>(), "Tag should carry the BLS12-381 curve.");

        var dimensions = mle.Tag.Get<MultilinearExtensionDimensions>();
        Assert.AreEqual(VariableCount, dimensions.VariableCount, "Dimensions tag entry should match the requested variable count.");
        Assert.AreEqual(1 << VariableCount, dimensions.EvaluationCount, "Dimensions tag entry should match 2^variableCount.");

        //Provenance entries from the random delegate propagate up. The
        //reference backend stamps four provenance entries.
        Assert.IsTrue(mle.Tag.TryGet<ProviderLibrary>(out _), "Tag should carry the provider library from the scalar backend.");
        Assert.IsTrue(mle.Tag.TryGet<CryptoLibrary>(out _), "Tag should carry the crypto library from the scalar backend.");
        Assert.IsTrue(mle.Tag.TryGet<ProviderClass>(out _), "Tag should carry the provider class from the scalar backend.");
        Assert.IsTrue(mle.Tag.TryGet<ProviderOperation>(out _), "Tag should carry the provider operation from the scalar backend.");
    }


    [TestMethod]
    public void RandomRejectsNullDelegate()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
            _ = MultilinearExtension.Random(
                3,
                CurveParameterSet.Bls12Curve381,
                random: null!,
                SensitiveMemoryPool<byte>.Shared));
    }


    [TestMethod]
    public void RandomRejectsOversizedVariableCount()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            _ = MultilinearExtension.Random(
                27,
                CurveParameterSet.Bls12Curve381,
                Random,
                SensitiveMemoryPool<byte>.Shared));
    }
}