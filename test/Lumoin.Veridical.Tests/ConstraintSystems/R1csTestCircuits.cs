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
/// Helpers that build canonical small R1CS test circuits and the
/// witnesses that satisfy (or fail to satisfy) them. Shared across
/// the constraint-system test classes.
/// </summary>
internal static class R1csTestCircuits
{
    /// <summary>
    /// Builds the canonical <c>x · y = z</c> circuit with 1 constraint
    /// and 4 variables: <c>z = (1, x, y, z)</c>. Zero public inputs;
    /// witness vector is <c>(x, y, z)</c>.
    /// </summary>
    public static RawR1csInstance BuildMultiplyCircuit()
    {
        int scalarSize = Scalar.SizeBytes;
        ReadOnlySpan<int> rows = stackalloc int[] { 0 };

        using IMemoryOwner<byte> aValuesOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> aValues = aValuesOwner.Memory.Span[..scalarSize];
        aValues.Clear();
        aValues[scalarSize - 1] = 0x01;

        using IMemoryOwner<byte> bValuesOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> bValues = bValuesOwner.Memory.Span[..scalarSize];
        bValues.Clear();
        bValues[scalarSize - 1] = 0x01;

        using IMemoryOwner<byte> cValuesOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> cValues = cValuesOwner.Memory.Span[..scalarSize];
        cValues.Clear();
        cValues[scalarSize - 1] = 0x01;

        ReadOnlySpan<int> aColumns = stackalloc int[] { 1 };
        ReadOnlySpan<int> bColumns = stackalloc int[] { 2 };
        ReadOnlySpan<int> cColumns = stackalloc int[] { 3 };

        R1csMatrix a = R1csMatrix.FromSortedTriples(rows, aColumns, aValues, 1, 4, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(rows, bColumns, bValues, 1, 4, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(rows, cColumns, cValues, 1, 4, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Builds the satisfying witness <c>(x, y, x · y)</c> for
    /// <see cref="BuildMultiplyCircuit"/>.
    /// </summary>
    public static RawR1csWitness BuildMultiplyWitness(int x, int y)
    {
        int scalarSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(3 * scalarSize);
        Span<byte> witness = witnessOwner.Memory.Span[..(3 * scalarSize)];
        WriteCanonical(new BigInteger(x), witness.Slice(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(y), witness.Slice(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger((long)x * y), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Builds an unsatisfying witness for <see cref="BuildMultiplyCircuit"/>:
    /// the third element is deliberately set to <c>x · y + 1</c>.
    /// </summary>
    public static RawR1csWitness BuildBrokenMultiplyWitness(int x, int y)
    {
        int scalarSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(3 * scalarSize);
        Span<byte> witness = witnessOwner.Memory.Span[..(3 * scalarSize)];
        WriteCanonical(new BigInteger(x), witness.Slice(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(y), witness.Slice(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(((long)x * y) + 1), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
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