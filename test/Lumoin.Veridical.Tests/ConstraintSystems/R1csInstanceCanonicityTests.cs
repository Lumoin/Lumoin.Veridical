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
    /// <summary>The constraint-row count: one constraint, the smallest shape that admits a public input.</summary>
    private const int RowCount = 1;
    /// <summary>The witness-column count: four wires, so the public-input count plus the 1-constant still fits.</summary>
    private const int ColumnCount = 4;

    /// <summary>The byte width of one canonical scalar this test's public inputs and relaxation scalar use.</summary>
    private const int ScalarSize = 32;
    /// <summary>The curve this test's instances and matrices operate over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;

    /// <summary>Two public inputs, so a non-canonical input can sit behind a canonical one.</summary>
    private const int PublicInputPairCount = 2;

    /// <summary>The index of the non-canonical input in the pair, which the refusal names.</summary>
    private const int SecondPublicInputIndex = 1;

    /// <summary>The offset from the scalar field order that gives the largest canonical value.</summary>
    private const int LargestCanonicalOffset = -1;

    /// <summary>The offset from the scalar field order that gives the smallest non-canonical value, the order itself.</summary>
    private const int SmallestNonCanonicalOffset = 0;


    /// <summary>Verifies that <see cref="RawR1csInstance.Create"/> rejects a public input encoding the scalar-field order itself, naming the offending input's index.</summary>
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


    /// <summary>Verifies that <see cref="RawR1csInstance.Create"/> accepts a public input encoding the largest canonical value, one below the scalar-field order.</summary>
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


    /// <summary>
    /// Each public input is checked at its own offset, so a non-canonical input behind a canonical one is refused
    /// and the refusal names its index. The first input is the largest canonical value and the second is the scalar
    /// field order itself: a check that read the first slot for every index would accept the pair. The two inputs are
    /// whole scalars and leave room for the constant in four columns, so only the canonicity check can refuse them.
    /// </summary>
    [TestMethod]
    public void RawInstanceRejectsANonCanonicalSecondPublicInput()
    {
        using IMemoryOwner<byte> publicOwner = BaseMemoryPool.Shared.Rent(PublicInputPairCount * ScalarSize);
        WriteOrderPlus(LargestCanonicalOffset, publicOwner.Memory.Span[..ScalarSize]);
        WriteOrderPlus(SmallestNonCanonicalOffset, publicOwner.Memory.Span.Slice(SecondPublicInputIndex * ScalarSize, ScalarSize));

        R1csMatrix a = BuildOneEntryMatrix();
        R1csMatrix b = BuildOneEntryMatrix();
        R1csMatrix c = BuildOneEntryMatrix();

        try
        {
            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
                RawR1csInstance.Create(a, b, c, publicOwner.Memory.Span[..(PublicInputPairCount * ScalarSize)], BaseMemoryPool.Shared).Dispose());
            Assert.Contains($"Public input {SecondPublicInputIndex} encodes", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            a.Dispose();
            b.Dispose();
            c.Dispose();
        }
    }


    /// <summary>Verifies that <see cref="RelaxedR1csInstance.Create"/> rejects a relaxation scalar <c>u</c> encoding the scalar-field order itself.</summary>
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


    /// <summary>Verifies that <see cref="RelaxedR1csInstance.Create"/> rejects a public input encoding the scalar-field order itself, even with a canonical <c>u</c>.</summary>
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


    /// <summary>Verifies that <see cref="RelaxedR1csInstance.Create"/> accepts a canonical public input and a canonical relaxation scalar <c>u</c>.</summary>
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


    /// <summary>Writes the BLS12-381 scalar-field order plus the (possibly negative) offset as 32 canonical big-endian bytes; offset 0 yields the first non-canonical value, -1 the largest canonical one.</summary>
    private static void WriteOrderPlus(int offset, Span<byte> destination)
    {
        destination.Clear();
        BigInteger value = WellKnownCurves.GetScalarFieldOrder(Curve) + offset;
        value.TryWriteBytes(destination, out _, isUnsigned: true, isBigEndian: true);
    }


    /// <summary>Builds a single-entry matrix (coefficient 1 at row 0, column 0) of this test's shape, for the instance factories to bind.</summary>
    private static R1csMatrix BuildOneEntryMatrix()
    {
        ReadOnlySpan<int> rows = [0];
        ReadOnlySpan<int> columns = [0];
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 1;

        return R1csMatrix.FromSortedTriples(rows, columns, one, RowCount, ColumnCount, Curve, BaseMemoryPool.Shared);
    }


    /// <summary>Builds a shape-only error commitment (a compressed-G1-sized row with the BLS infinity flag set) for the relaxed-instance factory, which stores the commitment opaquely.</summary>
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
