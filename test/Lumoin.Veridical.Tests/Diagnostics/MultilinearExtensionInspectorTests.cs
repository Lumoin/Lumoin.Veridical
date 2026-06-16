using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Diagnostics;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Diagnostics;

/// <summary>
/// Tests for the verbose
/// <see cref="MultilinearExtensionInspector"/>. Each test constructs an
/// MLE with known shape and contents and asserts the bundled report
/// reflects every field.
/// </summary>
[TestClass]
internal sealed class MultilinearExtensionInspectorTests
{
    [TestMethod]
    public void InspectingZeroMleReportsIsZeroAndIsConstant()
    {
        using MultilinearExtension mle = MultilinearExtension.Zero(3, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        MultilinearExtensionReport report = MultilinearExtensionInspector.Inspect(mle);

        Assert.AreEqual(3, report.VariableCount);
        Assert.AreEqual(8, report.EvaluationCount);
        Assert.AreEqual(Scalar.SizeBytes, report.FieldElementSizeBytes);
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, report.Curve);
        Assert.IsTrue(report.IsZero);
        Assert.IsTrue(report.IsConstant, "All-zero MLE is constant.");
        Assert.AreEqual(8, report.FirstEvaluationsRendered);
        Assert.Contains("MultilinearExtension", report.TagSummary);
    }


    [TestMethod]
    public void InspectingConstantMleReportsIsConstantButNotIsZero()
    {
        const int VariableCount = 2;
        int elementSize = Scalar.SizeBytes;
        int evalCount = 1 << VariableCount;

        using IMemoryOwner<byte> bufferOwner = BaseMemoryPool.Shared.Rent(evalCount * elementSize);
        Span<byte> buffer = bufferOwner.Memory.Span[..(evalCount * elementSize)];
        for(int i = 0; i < evalCount; i++)
        {
            //Every evaluation is the field element 42.
            WriteCanonical(new(42), buffer.Slice(i * elementSize, elementSize));
        }

        using MultilinearExtension mle = MultilinearExtension.FromEvaluations(buffer, VariableCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        MultilinearExtensionReport report = MultilinearExtensionInspector.Inspect(mle);

        Assert.IsFalse(report.IsZero);
        Assert.IsTrue(report.IsConstant);
        Assert.AreEqual(VariableCount, report.VariableCount);
        Assert.AreEqual(evalCount, report.EvaluationCount);
    }


    [TestMethod]
    public void InspectingDistinctEvaluationsMleReportsNeitherConstantNorZero()
    {
        const int VariableCount = 2;
        int elementSize = Scalar.SizeBytes;
        int evalCount = 1 << VariableCount;

        using IMemoryOwner<byte> bufferOwner = BaseMemoryPool.Shared.Rent(evalCount * elementSize);
        Span<byte> buffer = bufferOwner.Memory.Span[..(evalCount * elementSize)];
        for(int i = 0; i < evalCount; i++)
        {
            WriteCanonical(new(i + 1), buffer.Slice(i * elementSize, elementSize));
        }

        using MultilinearExtension mle = MultilinearExtension.FromEvaluations(buffer, VariableCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        MultilinearExtensionReport report = MultilinearExtensionInspector.Inspect(mle);

        Assert.IsFalse(report.IsZero);
        Assert.IsFalse(report.IsConstant);

        //Hex of four 32-byte scalars: 8 chars per byte × 32 × 4 = 256 chars.
        Assert.AreEqual(256, report.FirstEvaluationsHex.Length);
    }


    [TestMethod]
    public void HexSnippetTruncatesAtEightEvaluations()
    {
        //Build an MLE with > 8 evaluations and confirm the hex snippet
        //covers only the first eight slots.
        const int VariableCount = 4;
        int elementSize = Scalar.SizeBytes;
        int evalCount = 1 << VariableCount;

        using IMemoryOwner<byte> bufferOwner = BaseMemoryPool.Shared.Rent(evalCount * elementSize);
        Span<byte> buffer = bufferOwner.Memory.Span[..(evalCount * elementSize)];
        for(int i = 0; i < evalCount; i++)
        {
            WriteCanonical(new(i + 1), buffer.Slice(i * elementSize, elementSize));
        }

        using MultilinearExtension mle = MultilinearExtension.FromEvaluations(buffer, VariableCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        MultilinearExtensionReport report = MultilinearExtensionInspector.Inspect(mle);

        Assert.AreEqual(8, report.FirstEvaluationsRendered);
        //8 evaluations × 32 bytes × 2 hex chars/byte = 512 chars.
        Assert.AreEqual(512, report.FirstEvaluationsHex.Length);
    }


    [TestMethod]
    public void InspectThrowsOnNullMle()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => MultilinearExtensionInspector.Inspect(null!));
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger r = Bls12Curve381BigIntegerScalarReference.FieldOrder;
        BigInteger nonNegative = ((value % r) + r) % r;
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
}