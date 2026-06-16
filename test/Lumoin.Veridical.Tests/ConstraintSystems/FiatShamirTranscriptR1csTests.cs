using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Determinism and domain-separation properties for the R1CS absorb.
/// </summary>
[TestClass]
internal sealed class FiatShamirTranscriptR1csTests
{
    private const string Domain = "veridical.test.r1cs.v1";

    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();


    [TestMethod]
    public void InstanceAbsorbIsDeterministic()
    {
        using RawR1csInstance instance = R1csTestCircuits.BuildMultiplyCircuit();

        using FiatShamirTranscript a = NewTranscript();
        using FiatShamirTranscript b = NewTranscript();

        a.AbsorbR1csInstance(instance, Hash);
        b.AbsorbR1csInstance(instance, Hash);

        Assert.IsTrue(a.AsReadOnlySpan().SequenceEqual(b.AsReadOnlySpan()),
            "Two absorbs of the same R1CS instance must produce identical transcript states.");
    }


    [TestMethod]
    public void DifferentInstancesProduceDifferentStates()
    {
        //Same dimensions, different coefficient values → different absorbs.
        using RawR1csInstance first = R1csTestCircuits.BuildMultiplyCircuit();
        using RawR1csInstance second = BuildAlternativeCircuit();

        using FiatShamirTranscript a = NewTranscript();
        using FiatShamirTranscript b = NewTranscript();

        a.AbsorbR1csInstance(first, Hash);
        b.AbsorbR1csInstance(second, Hash);

        Assert.IsFalse(a.AsReadOnlySpan().SequenceEqual(b.AsReadOnlySpan()),
            "Different instances must produce different post-absorb states.");
    }


    private static FiatShamirTranscript NewTranscript() =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(Domain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    private static RawR1csInstance BuildAlternativeCircuit()
    {
        //Same shape as multiply circuit but coefficients are 2, 3, 5 instead of 1.
        int scalarSize = Scalar.SizeBytes;
        ReadOnlySpan<int> rows = stackalloc int[] { 0 };

        using IMemoryOwner<byte> aValuesOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> aValues = aValuesOwner.Memory.Span[..scalarSize];
        WriteCanonical(new BigInteger(2), aValues);

        using IMemoryOwner<byte> bValuesOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> bValues = bValuesOwner.Memory.Span[..scalarSize];
        WriteCanonical(new BigInteger(3), bValues);

        using IMemoryOwner<byte> cValuesOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> cValues = cValuesOwner.Memory.Span[..scalarSize];
        WriteCanonical(new BigInteger(5), cValues);

        ReadOnlySpan<int> aColumns = stackalloc int[] { 1 };
        ReadOnlySpan<int> bColumns = stackalloc int[] { 2 };
        ReadOnlySpan<int> cColumns = stackalloc int[] { 3 };

        R1csMatrix a = R1csMatrix.FromSortedTriples(rows, aColumns, aValues, 1, 4, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(rows, bColumns, bValues, 1, 4, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(rows, cColumns, cValues, 1, 4, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared);
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