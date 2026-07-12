using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Gates for the canonicity checks on the instance-level construction
/// boundaries: <see cref="RawR1csInstance.Create"/> (public inputs) and
/// <see cref="RelaxedR1csInstance.Create"/> (public inputs and the
/// relaxation scalar <c>u</c>). Public inputs and <c>u</c> are
/// transcript-absorbed as bytes and enter <c>z</c> / the folded relation,
/// so a value at or above the order would diverge between its absorb
/// bytes and its reduced arithmetic value — the same non-canonical
/// second-encoding class the matrix and witness factories reject. The
/// per-curve boundary semantics of the shared helper are pinned in
/// <see cref="NonCanonicalRejectionTests"/>; these tests exercise the
/// BLS12-381 instance paths.
/// </summary>
[TestClass]
internal sealed class R1csInstanceCanonicityTests
{
    //One constraint over four wires — the smallest shape that admits a
    //public input (public-input count + 1 constant must fit the columns).
    private const int RowCount = 1;
    private const int ColumnCount = 4;

    private const int ScalarSize = 32;
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void RawInstanceRejectsAPublicInputAtTheScalarFieldOrder()
    {
        using IMemoryOwner<byte> publicOwner = BaseMemoryPool.Shared.Rent(ScalarSize);
        WriteOrderPlus(0, publicOwner.Memory.Span[..ScalarSize]);

        R1csMatrix a = BuildOneEntryMatrix();
        R1csMatrix b = BuildOneEntryMatrix();
        R1csMatrix c = BuildOneEntryMatrix();

        try
        {
            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
                _ = RawR1csInstance.Create(a, b, c, publicOwner.Memory.Span[..ScalarSize], BaseMemoryPool.Shared));
            Assert.Contains("Public input 0", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            //Create takes matrix ownership only on success; the throw path
            //leaves them with the caller.
            a.Dispose();
            b.Dispose();
            c.Dispose();
        }
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "RawR1csInstance.Create takes ownership of the matrices and disposes them through its own Dispose chain.")]
    public void RawInstanceAcceptsAPublicInputAtOrderMinusOne()
    {
        using IMemoryOwner<byte> publicOwner = BaseMemoryPool.Shared.Rent(ScalarSize);
        WriteOrderPlus(-1, publicOwner.Memory.Span[..ScalarSize]);

        using RawR1csInstance instance = RawR1csInstance.Create(
            BuildOneEntryMatrix(), BuildOneEntryMatrix(), BuildOneEntryMatrix(),
            publicOwner.Memory.Span[..ScalarSize], BaseMemoryPool.Shared);

        Assert.AreEqual(1, instance.PublicInputCount);
    }


    [TestMethod]
    public void RelaxedInstanceRejectsUAtTheScalarFieldOrder()
    {
        using IMemoryOwner<byte> uOwner = BaseMemoryPool.Shared.Rent(ScalarSize);
        WriteOrderPlus(0, uOwner.Memory.Span[..ScalarSize]);

        R1csMatrix a = BuildOneEntryMatrix();
        R1csMatrix b = BuildOneEntryMatrix();
        R1csMatrix c = BuildOneEntryMatrix();
        PolynomialCommitment errorCommitment = BuildDummyCommitment();

        try
        {
            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
                _ = RelaxedR1csInstance.Create(
                    a, b, c, ReadOnlySpan<byte>.Empty, uOwner.Memory.Span[..ScalarSize], errorCommitment, BaseMemoryPool.Shared));
            Assert.Contains("u encodes an integer at or above", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            a.Dispose();
            b.Dispose();
            c.Dispose();
            errorCommitment.Dispose();
        }
    }


    [TestMethod]
    public void RelaxedInstanceRejectsAPublicInputAtTheScalarFieldOrder()
    {
        using IMemoryOwner<byte> bytesOwner = BaseMemoryPool.Shared.Rent(2 * ScalarSize);
        Span<byte> publicInput = bytesOwner.Memory.Span[..ScalarSize];
        Span<byte> u = bytesOwner.Memory.Span.Slice(ScalarSize, ScalarSize);
        WriteOrderPlus(0, publicInput);
        u.Clear();
        u[^1] = 1;

        R1csMatrix a = BuildOneEntryMatrix();
        R1csMatrix b = BuildOneEntryMatrix();
        R1csMatrix c = BuildOneEntryMatrix();
        PolynomialCommitment errorCommitment = BuildDummyCommitment();

        try
        {
            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
                _ = RelaxedR1csInstance.Create(
                    a, b, c, bytesOwner.Memory.Span[..ScalarSize], bytesOwner.Memory.Span.Slice(ScalarSize, ScalarSize), errorCommitment, BaseMemoryPool.Shared));
            Assert.Contains("Public input 0", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            a.Dispose();
            b.Dispose();
            c.Dispose();
            errorCommitment.Dispose();
        }
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "RelaxedR1csInstance.Create takes ownership of the matrices and the commitment and disposes them through its own Dispose chain.")]
    public void RelaxedInstanceAcceptsCanonicalUAndPublicInput()
    {
        using IMemoryOwner<byte> bytesOwner = BaseMemoryPool.Shared.Rent(2 * ScalarSize);
        Span<byte> publicInput = bytesOwner.Memory.Span[..ScalarSize];
        Span<byte> u = bytesOwner.Memory.Span.Slice(ScalarSize, ScalarSize);
        WriteOrderPlus(-1, publicInput);
        u.Clear();
        u[^1] = 1;

        using RelaxedR1csInstance instance = RelaxedR1csInstance.Create(
            BuildOneEntryMatrix(), BuildOneEntryMatrix(), BuildOneEntryMatrix(),
            bytesOwner.Memory.Span[..ScalarSize], bytesOwner.Memory.Span.Slice(ScalarSize, ScalarSize),
            BuildDummyCommitment(), BaseMemoryPool.Shared);

        Assert.AreEqual(1, instance.PublicInputCount);
    }


    //Writes the BLS12-381 scalar field order plus the (possibly negative)
    //offset as 32 canonical big-endian bytes; offset 0 yields the first
    //non-canonical value, -1 the largest canonical one.
    private static void WriteOrderPlus(int offset, Span<byte> destination)
    {
        destination.Clear();
        BigInteger value = WellKnownCurves.GetScalarFieldOrder(Curve) + offset;
        value.TryWriteBytes(destination, out _, isUnsigned: true, isBigEndian: true);
    }


    private static R1csMatrix BuildOneEntryMatrix()
    {
        ReadOnlySpan<int> rows = [0];
        ReadOnlySpan<int> columns = [0];
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 1;

        return R1csMatrix.FromSortedTriples(rows, columns, one, RowCount, ColumnCount, Curve, BaseMemoryPool.Shared);
    }


    private static PolynomialCommitment BuildDummyCommitment()
    {
        //One compressed-G1-sized row with the BLS infinity flag set — enough
        //shape for the instance factory, which stores the commitment opaquely.
        Span<byte> buffer = stackalloc byte[WellKnownCurves.Bls12Curve381G1CompressedSizeBytes];
        buffer.Clear();
        buffer[0] = 0xc0;

        return PolynomialCommitment.FromBytes(buffer, Curve, CommitmentScheme.Hyrax, BaseMemoryPool.Shared);
    }
}
