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
/// Tests for the public ZkInterface witness reader delegate: the
/// format-label guard, the toy-field rejection on the vendored
/// example.zkif, and the decoder swap seam. The instance+witness
/// satisfaction happy path is in <see cref="ZkInterfaceWitnessBuilderTests"/>;
/// end-to-end over a real curve through the pipe is covered by
/// <see cref="ZkInterfaceFixtureTests"/>.
/// </summary>
[TestClass]
internal sealed class ZkInterfaceWitnessReaderTests
{
    /// <summary>A source length with a few bytes more than the three columns the seam decoder in <see cref="CreateReaderUsesTheSuppliedDecoder"/> fabricates, so the reader's source-length column ceiling does not reject that legitimate synthetic read.</summary>
    private const int SourceLongerThanColumns = 16;

    /// <summary>A short source length that cannot justify the huge declared column space <see cref="HugeFreeVariableId"/> implies.</summary>
    private const int SmallSourceByteLength = 32;

    /// <summary>A <c>free_variable_id</c> whose dense witness (at 32 bytes per scalar) is about 2 GB — the shape of the real fuzz finding. It sits below the <see cref="int"/> dense-buffer addressability threshold (a column count of about 67.1 million or more), so only the source-length ceiling can reject it, isolating the reader's buffer-length wiring: revert that wiring and this test goes red.</summary>
    private const ulong HugeFreeVariableId = 64_000_000;


    /// <summary>Verifies that the reader throws when given a format label other than <see cref="WellKnownR1csFormatLabel.ZkInterface"/>.</summary>
    [TestMethod]
    public void ReaderRejectsWrongFormatLabel()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            Read(ZkInterfaceWitnessReader.Reader, ZkInterfaceExampleFixture.ExampleBytes(), WellKnownR1csFormatLabel.CircomWitness, BaseMemoryPool.Shared).Dispose());
    }


    /// <summary>Verifies that reading the vendored <c>example.zkif</c> fixture is rejected: it declares no <c>field_maximum</c>, so the witness read fails at field reconciliation against the wired curve, exactly as the instance read does.</summary>
    [TestMethod]
    public void ReaderRejectsExampleToyFieldAgainstWiredCurve()
    {
        //example.zkif declares no field_maximum, so the witness read is rejected
        //at field reconciliation, exactly as the instance read is.
        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() =>
            Read(ZkInterfaceWitnessReader.Reader, ZkInterfaceExampleFixture.ExampleBytes(), WellKnownR1csFormatLabel.ZkInterface, BaseMemoryPool.Shared).Dispose());
    }


    /// <summary>The custom decoder receives the exact pool supplied by the reader caller.</summary>
    [TestMethod]
    public void CreateReaderUsesTheSuppliedDecoder()
    {
        //An alternate decoder pushes a header (field + free_variable_id) plus one
        //public and one private value; a successful read proves CreateReader wired
        //the decoder into the witness assembly.
        using BaseMemoryPool expectedPool = new();
        ZkInterfaceMessageDecoderDelegate decoder = (source, sink, pool, cancellationToken) =>
        {
            Assert.AreSame(expectedPool, pool);
            sink.OnFreeVariableId(3);

            Span<byte> fieldMaximum = stackalloc byte[ZkInterfaceTestFields.FieldElementSizeBytes];
            ZkInterfaceTestFields.WriteFieldMaximumLittleEndian(CurveParameterSet.Bls12Curve381, fieldMaximum);
            sink.OnFieldMaximum(fieldMaximum);

            Span<byte> seven = stackalloc byte[] { 7 };
            Span<byte> nine = stackalloc byte[] { 9 };
            sink.OnInstanceVariable(1, seven);
            sink.OnWitnessVariable(2, nine);
        };

        R1csWitnessPipeReaderDelegate reader = ZkInterfaceWitnessReader.CreateReader(decoder);

        //The reader caps the declared column space at the source byte length, so
        //the source must be at least as large as the three columns this decoder
        //fabricates; a handful of (ignored) bytes clears that ceiling.
        using IMemoryOwner<byte> sourceOwner = expectedPool.Rent(SourceLongerThanColumns);
        sourceOwner.Memory.Span[..SourceLongerThanColumns].Clear();
        using RawR1csWitness witness = Read(reader, sourceOwner.Memory[..SourceLongerThanColumns], WellKnownR1csFormatLabel.ZkInterface, expectedPool);

        //free_variable_id = 3 → z[1..] has 2 variables (columns 1 and 2).
        Assert.AreEqual(2, witness.WitnessVariableCount, "WitnessVariableCount");
    }


    /// <summary>Verifies that a decoder declaring a free-variable id whose dense witness would need about 2 GB, over a small source, is rejected with a documented exception rather than attempting the unbounded allocation — the reader caps the column space at the source byte length.</summary>
    [TestMethod]
    public void ReaderRejectsColumnSpaceExceedingSourceLength()
    {
        //A decoder that ignores its short source and declares a sixty-four-million-column
        //variable space models the zkinterface-wtns fuzz finding: sizing the dense
        //witness from the declared free_variable_id would rent ~2 GB. The reader caps the
        //column space at the source byte length, so the read is a documented
        //ArgumentException rejection rather than an unbounded allocation.
        ZkInterfaceMessageDecoderDelegate decoder = (source, sink, pool, cancellationToken) =>
        {
            Span<byte> fieldMaximum = stackalloc byte[ZkInterfaceTestFields.FieldElementSizeBytes];
            ZkInterfaceTestFields.WriteFieldMaximumLittleEndian(CurveParameterSet.Bls12Curve381, fieldMaximum);
            sink.OnFieldMaximum(fieldMaximum);
            sink.OnFreeVariableId(HugeFreeVariableId);
        };

        R1csWitnessPipeReaderDelegate reader = ZkInterfaceWitnessReader.CreateReader(decoder);

        using IMemoryOwner<byte> sourceOwner = BaseMemoryPool.Shared.Rent(SmallSourceByteLength);
        sourceOwner.Memory.Span[..SmallSourceByteLength].Clear();

        Assert.ThrowsExactly<ArgumentException>(() =>
            Read(reader, sourceOwner.Memory[..SmallSourceByteLength], WellKnownR1csFormatLabel.ZkInterface, BaseMemoryPool.Shared).Dispose());
    }


    /// <summary>Runs the reader over caller-supplied bytes and pool.</summary>
    /// <param name="reader">The configured reader.</param>
    /// <param name="streamBytes">The complete stream bytes.</param>
    /// <param name="format">The format label.</param>
    /// <param name="pool">The caller's pool.</param>
    /// <returns>The decoded artifact, owned by the caller.</returns>
    private static RawR1csWitness Read(R1csWitnessPipeReaderDelegate reader, ReadOnlyMemory<byte> streamBytes, WellKnownR1csFormatLabel format, BaseMemoryPool pool)
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
}
