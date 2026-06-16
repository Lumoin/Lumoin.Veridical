using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using Lumoin.Veridical.Core.Memory;
using System;
using System.IO;
using System.IO.Pipelines;
using System.Threading;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Tests for the public ZkInterface witness reader delegate: the
/// format-label guard, the toy-field rejection on the vendored
/// example.zkif, and the decoder swap seam. The instance+witness
/// satisfaction happy path is in <see cref="ZkInterfaceWitnessBuilderTests"/>;
/// end-to-end over a real curve through the pipe arrives with the owned
/// fixtures in W.4.
/// </summary>
[TestClass]
internal sealed class ZkInterfaceWitnessReaderTests
{
    [TestMethod]
    public void ReaderRejectsWrongFormatLabel()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness _ = Read(ZkInterfaceWitnessReader.Reader, ZkInterfaceExampleFixture.ExampleBytes(), WellKnownR1csFormatLabel.CircomWitness);
        });
    }


    [TestMethod]
    public void ReaderRejectsExampleToyFieldAgainstWiredCurve()
    {
        //example.zkif declares no field_maximum, so the witness read is rejected
        //at field reconciliation, exactly as the instance read is.
        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() =>
        {
            using RawR1csWitness _ = Read(ZkInterfaceWitnessReader.Reader, ZkInterfaceExampleFixture.ExampleBytes(), WellKnownR1csFormatLabel.ZkInterface);
        });
    }


    [TestMethod]
    public void CreateReaderUsesTheSuppliedDecoder()
    {
        //An alternate decoder pushes a header (field + free_variable_id) plus one
        //public and one private value; a successful read proves CreateReader wired
        //the decoder into the witness assembly.
        ZkInterfaceMessageDecoderDelegate decoder = (source, sink, cancellationToken) =>
        {
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

        using RawR1csWitness witness = Read(reader, [], WellKnownR1csFormatLabel.ZkInterface);

        //free_variable_id = 3 → z[1..] has 2 variables (columns 1 and 2).
        Assert.AreEqual(2, witness.WitnessVariableCount, "WitnessVariableCount");
    }


    private static RawR1csWitness Read(R1csWitnessPipeReaderDelegate reader, byte[] streamBytes, WellKnownR1csFormatLabel format)
    {
        var stream = new MemoryStream(streamBytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);
        return reader(
            pipe,
            format,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            CancellationToken.None);
    }
}
