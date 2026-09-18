using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Threading;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Tests for the public ZkInterface reader delegate: the format-label
/// guard, the decoder swap seam (<see cref="ZkInterfaceR1csReader.CreateReader"/>),
/// and the end-to-end pipe path. The vendored example.zkif uses a toy
/// field with no <c>field_maximum</c>, so a wired-curve read of it is
/// rejected at field reconciliation; the matrix-assembly happy path is
/// covered directly in <see cref="ZkInterfaceR1csInstanceBuilderTests"/>
/// (and end-to-end over a real curve by <see cref="ZkInterfaceFixtureTests"/>).
/// </summary>
[TestClass]
internal sealed class ZkInterfaceR1csReaderTests
{
    /// <summary>Checks that reader rejects wrong format label.</summary>
    [TestMethod]
    public void ReaderRejectsWrongFormatLabel()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            Read(ZkInterfaceR1csReader.Reader, ZkInterfaceExampleFixture.ExampleBytes(), WellKnownR1csFormatLabel.CircomBinary, BaseMemoryPool.Shared).Dispose());
    }


    /// <summary>Checks that reader rejects example toy field against wired curve.</summary>
    [TestMethod]
    public void ReaderRejectsExampleToyFieldAgainstWiredCurve()
    {
        //example.zkif declares no field_maximum (toy field), so it cannot be
        //reconciled with BLS12-381; the full pipe path (drain + decode +
        //reconcile) surfaces that as R1csUnsupportedFieldException.
        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() =>
            Read(ZkInterfaceR1csReader.Reader, ZkInterfaceExampleFixture.ExampleBytes(), WellKnownR1csFormatLabel.ZkInterface, BaseMemoryPool.Shared).Dispose());
    }


    /// <summary>The custom decoder receives the exact pool supplied by the reader caller.</summary>
    [TestMethod]
    public void CreateReaderUsesTheSuppliedDecoder()
    {
        //An alternate decoder is the swap seam: this one ignores the bytes and
        //pushes a single satisfied 1*1=1 constraint over the curve's field, so a
        //successful read proves CreateReader wired the decoder into the assembly.
        using BaseMemoryPool expectedPool = new();
        ZkInterfaceMessageDecoderDelegate decoder = (source, sink, pool, cancellationToken) =>
        {
            Assert.AreSame(expectedPool, pool);
            sink.OnFreeVariableId(1);

            Span<byte> fieldMaximum = stackalloc byte[ZkInterfaceTestFields.FieldElementSizeBytes];
            ZkInterfaceTestFields.WriteFieldMaximumLittleEndian(CurveParameterSet.Bls12Curve381, fieldMaximum);
            sink.OnFieldMaximum(fieldMaximum);

            Span<byte> one = stackalloc byte[] { 1 };
            sink.BeginConstraint();
            sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.A, 0, one);
            sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.B, 0, one);
            sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.C, 0, one);
            sink.EndConstraint();
        };

        R1csPipeReaderDelegate reader = ZkInterfaceR1csReader.CreateReader(decoder);

        using RawR1csInstance instance = Read(reader, ReadOnlyMemory<byte>.Empty, WellKnownR1csFormatLabel.ZkInterface, expectedPool);

        Assert.AreEqual(1, instance.A.RowCount, "A.RowCount");
        Assert.AreEqual(1, instance.A.ColumnCount, "A.ColumnCount");
        Assert.AreEqual(0, instance.PublicInputCount, "PublicInputCount");
    }


    /// <summary>Runs the reader over caller-supplied bytes and pool.</summary>
    /// <param name="reader">The configured reader.</param>
    /// <param name="streamBytes">The complete stream bytes.</param>
    /// <param name="format">The format label.</param>
    /// <param name="pool">The caller's pool.</param>
    /// <returns>The decoded artifact, owned by the caller.</returns>
    private static RawR1csInstance Read(R1csPipeReaderDelegate reader, ReadOnlyMemory<byte> streamBytes, WellKnownR1csFormatLabel format, BaseMemoryPool pool)
    {
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(streamBytes));

        return reader(
            pipe,
            format,
            CurveParameterSet.Bls12Curve381,
            pool,
            CancellationToken.None);
    }
}
