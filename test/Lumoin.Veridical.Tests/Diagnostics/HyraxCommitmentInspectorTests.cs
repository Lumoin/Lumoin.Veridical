using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Diagnostics;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Diagnostics;

[TestClass]
internal sealed class HyraxCommitmentInspectorTests
{
    private static readonly G1HashToCurveDelegate HashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static readonly G1MultiScalarMultiplyDelegate G1Msm = TestG1Backends.Bls12Curve381Msm;


    [TestMethod]
    public void InspectReportsDimensionsAndHexSnippet()
    {
        const int VariableCount = 4;
        var dimensions = HyraxCommitmentDimensions.ForVariableCount(VariableCount);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, SensitiveMemoryPool<byte>.Shared);

        using MultilinearExtension mle = BuildMle(VariableCount);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(13);
        var (commitment, witness) = key.CommitMultilinearExtension(mle, fixedRandom, G1Msm, SensitiveMemoryPool<byte>.Shared);
        using(commitment)
        using(witness)
        {
            HyraxCommitmentReport report = HyraxCommitmentInspector.Inspect(commitment);

            Assert.AreEqual(dimensions.RowCount, report.RowCount);
            Assert.AreEqual(dimensions.ColumnCount, report.ColumnCount);
            Assert.AreEqual(VariableCount, report.VariableCount);
            Assert.AreEqual(CurveParameterSet.Bls12Curve381, report.Curve);
            Assert.AreEqual(WellKnownCurves.Bls12Curve381G1CompressedSizeBytes * 2, report.FirstRowCommitmentHex.Length, "48 bytes → 96 hex chars.");
            Assert.Contains("Commitment", report.TagSummary);
        }
    }


    [TestMethod]
    public void InspectThrowsOnNullCommitment()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => HyraxCommitmentInspector.Inspect(null!));
    }


    private static MultilinearExtension BuildMle(int variableCount)
    {
        int evalCount = 1 << variableCount;
        int elementSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> bufOwner = SensitiveMemoryPool<byte>.Shared.Rent(evalCount * elementSize);
        Span<byte> buf = bufOwner.Memory.Span[..(evalCount * elementSize)];
        for(int i = 0; i < evalCount; i++)
        {
            WriteCanonical(new BigInteger(i + 1), buf.Slice(i * elementSize, elementSize));
        }


        return MultilinearExtension.FromEvaluations(buf, variableCount, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
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


    private static ScalarRandomDelegate MakeFixedRandom(int seed)
    {
        int counter = 0;
        return Sample;

        Tag Sample(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> hashInput = stackalloc byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hashInput[..4], seed);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hashInput[4..], counter);
            counter++;

            Span<byte> wide = stackalloc byte[32];
            SHA256.HashData(hashInput, wide);
            ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
            reduce(wide, destination, curve);
            return inboundTag;
        }
    }
}