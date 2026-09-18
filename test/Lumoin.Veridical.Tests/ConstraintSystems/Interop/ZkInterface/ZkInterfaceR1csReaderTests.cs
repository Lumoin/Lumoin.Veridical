using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
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
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);
    }


    /// <summary>One byte less than a fixture's length, the largest intake ceiling that still rejects it.</summary>
    private const int CeilingBelowFixtureLengthDelta = 1;

    /// <summary>
    /// The throwaway stream length fed to <see cref="SyntheticSatisfiedConstraintDecoder"/>, which never reads the
    /// stream's content; only its byte count gives the intake ceiling something nonzero to bound.
    /// </summary>
    private const int SyntheticStreamLength = 8;

    /// <summary>A negative intake ceiling; only its sign matters to the argument check under test.</summary>
    private const long NegativeMaximumIntakeBytes = -1L;

    /// <summary>The row count of the single constraint <see cref="SyntheticSatisfiedConstraintDecoder"/> pushes.</summary>
    private const int SyntheticConstraintRowCount = 1;

    /// <summary>The column count of the single free variable <see cref="SyntheticSatisfiedConstraintDecoder"/> references.</summary>
    private const int SyntheticConstraintColumnCount = 1;

    /// <summary>The public input count <see cref="SyntheticSatisfiedConstraintDecoder"/> declares: none.</summary>
    private const int SyntheticPublicInputCount = 0;

    /// <summary>
    /// A decoder that ignores its source bytes entirely and pushes a single satisfied <c>1*1=1</c> constraint over
    /// BLS12-381, so a read through it succeeds regardless of the stream's content; only the stream's length can
    /// make the intake ceiling reject it.
    /// </summary>
    private static ZkInterfaceMessageDecoderDelegate SyntheticSatisfiedConstraintDecoder { get; } = (source, sink, pool, cancellationToken) =>
    {
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


    /// <summary>
    /// An intake ceiling below the input length rejects the read with <see cref="R1csIntakeLimitExceededException"/>,
    /// whose <see cref="R1csIntakeLimitExceededException.MaximumIntakeBytes"/>,
    /// <see cref="R1csIntakeLimitExceededException.ObservedIntakeBytes"/> and message all name the declared ceiling
    /// and the buffered length that exceeded it. The rejection happens while the pipe is drained, before the
    /// built-in decoder ever inspects the toy-field example bytes.
    /// </summary>
    [TestMethod]
    public void ReaderRejectsMaximumIntakeBytesBelowInputLength()
    {
        byte[] exampleBytes = ZkInterfaceExampleFixture.ExampleBytes();
        long belowCeiling = exampleBytes.Length - CeilingBelowFixtureLengthDelta;
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(exampleBytes));

        R1csIntakeLimitExceededException exception = Assert.ThrowsExactly<R1csIntakeLimitExceededException>(() =>
        {
            using RawR1csInstance parsed = ZkInterfaceR1csReader.Reader(
                pipe,
                WellKnownR1csFormatLabel.ZkInterface,
                CurveParameterSet.Bls12Curve381,
                BaseMemoryPool.Shared,
                belowCeiling,
                CancellationToken.None);
        });

        Assert.AreEqual(belowCeiling, exception.MaximumIntakeBytes, "MaximumIntakeBytes");
        Assert.AreEqual((long)exampleBytes.Length, exception.ObservedIntakeBytes, "ObservedIntakeBytes");
        Assert.Contains($"ceiling of {belowCeiling} byte(s) was exceeded; the buffered input reached {exampleBytes.Length} byte(s).", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>An intake ceiling exactly equal to the input length is accepted, proving the ceiling comparison is inclusive rather than strict.</summary>
    [TestMethod]
    public void ReaderAcceptsMaximumIntakeBytesEqualToInputLength()
    {
        using IMemoryOwner<byte> streamOwner = BaseMemoryPool.Shared.Rent(SyntheticStreamLength);
        ReadOnlyMemory<byte> streamBytes = streamOwner.Memory[..SyntheticStreamLength];
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(streamBytes));
        R1csPipeReaderDelegate reader = ZkInterfaceR1csReader.CreateReader(SyntheticSatisfiedConstraintDecoder);

        using RawR1csInstance instance = reader(
            pipe,
            WellKnownR1csFormatLabel.ZkInterface,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            SyntheticStreamLength,
            CancellationToken.None);

        AssertSyntheticSatisfiedConstraintShape(instance);
    }


    /// <summary>
    /// <see cref="WellKnownR1csIntakeLimits.Unbounded"/> parses the same synthetic stream into the same shape as an
    /// explicit ceiling set to the stream's exact length, so declaring no budget changes nothing about a
    /// well-formed read.
    /// </summary>
    [TestMethod]
    public void ReaderAcceptsUnboundedMaximumIntakeBytes()
    {
        using IMemoryOwner<byte> streamOwner = BaseMemoryPool.Shared.Rent(SyntheticStreamLength);
        ReadOnlyMemory<byte> streamBytes = streamOwner.Memory[..SyntheticStreamLength];
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(streamBytes));
        R1csPipeReaderDelegate reader = ZkInterfaceR1csReader.CreateReader(SyntheticSatisfiedConstraintDecoder);

        using RawR1csInstance instance = reader(
            pipe,
            WellKnownR1csFormatLabel.ZkInterface,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);

        AssertSyntheticSatisfiedConstraintShape(instance);
    }


    /// <summary>
    /// A negative intake ceiling is rejected by the reader's own argument check with an
    /// <see cref="ArgumentOutOfRangeException"/> naming the parameter, before the pipe is read at all.
    /// </summary>
    [TestMethod]
    public void ReaderRejectsNegativeMaximumIntakeBytesBeforeReadingThePipe()
    {
        byte[] exampleBytes = ZkInterfaceExampleFixture.ExampleBytes();
        StrictChunkedPipeReader pipe = new(exampleBytes, exampleBytes.Length);

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
        {
            using RawR1csInstance parsed = ZkInterfaceR1csReader.Reader(
                pipe,
                WellKnownR1csFormatLabel.ZkInterface,
                CurveParameterSet.Bls12Curve381,
                BaseMemoryPool.Shared,
                NegativeMaximumIntakeBytes,
                CancellationToken.None);
        });

        Assert.AreEqual("maximumIntakeBytes", exception.ParamName);
        Assert.IsFalse(pipe.HasBeenRead, "The intake-ceiling check must reject the call before the pipe is read.");
    }


    /// <summary>Asserts that <paramref name="instance"/> has the synthetic decoder's single-row, single-column satisfied shape.</summary>
    /// <param name="instance">The instance built by <see cref="SyntheticSatisfiedConstraintDecoder"/>.</param>
    private static void AssertSyntheticSatisfiedConstraintShape(RawR1csInstance instance)
    {
        Assert.AreEqual(SyntheticConstraintRowCount, instance.A.RowCount, "A.RowCount");
        Assert.AreEqual(SyntheticConstraintColumnCount, instance.A.ColumnCount, "A.ColumnCount");
        Assert.AreEqual(SyntheticPublicInputCount, instance.PublicInputCount, "PublicInputCount");
    }
}
