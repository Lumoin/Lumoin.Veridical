using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.Circom;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Pipelines;
using System.Numerics;
using System.Threading;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.Circom;

/// <summary>
/// End-to-end rejection tests for the Circom binary readers against the two
/// non-canonical categories recently closed:
/// (1) witness elements at or above the scalar field order — a non-canonical
/// second encoding that must not reach the transcript or arithmetic;
/// (2) the unchecked-uint32 wrap in the R1CS header consistency sum that let
/// a crafted nPubOut = 0xFFFFFFFF, nPubIn = 1 header slip past the
/// nPubOut + nPubIn + nPrvIn + 1 &lt;= nWires check before the fix promoted the
/// sum to ulong.
/// </summary>
[TestClass]
internal sealed class CircomNonCanonicalRejectionTests
{
    //The .wtns file layout (version 2, BLS12-381, per FIXTURES.md):
    // File header: magic(4) + version(4) + sectionCount(4)          = 12 bytes
    // Section 1:  type(4)  + size(8)   + fieldSize(4) + prime(32)
    //                                  + nWitness(4)                = 52 bytes
    // Section 2:  type(4)  + size(8)   + witness data (nWitness×32) = 12 + 128 bytes
    // All multi-byte integers are little-endian.
    private const int WtnsFileHeaderBytes = 12;      //magic + version + sectionCount
    private const int WtnsSectionPrefixBytes = 12;   //type(4) + size(8)
    private const int WtnsFieldSizeBytes = 4;
    private const int WtnsScalarSizeBytes = 32;      //BLS12-381 field element width
    private const int WtnsPrimeSizeBytes = WtnsScalarSizeBytes;
    private const int WtnsNWitnessBytes = 4;
    //Section 1 payload = fieldSize + prime + nWitness = 40 bytes.
    private const int WtnsSection1PayloadBytes =
        WtnsFieldSizeBytes + WtnsPrimeSizeBytes + WtnsNWitnessBytes;

    //Byte offset of nWitness in the file (inside section 1 payload).
    private const int WtnsNWitnessOffset =
        WtnsFileHeaderBytes + WtnsSectionPrefixBytes + WtnsFieldSizeBytes + WtnsPrimeSizeBytes;

    //Byte offset of the witness data payload (section 2 payload start).
    private const int WtnsDataPayloadOffset =
        WtnsFileHeaderBytes + WtnsSectionPrefixBytes + WtnsSection1PayloadBytes + WtnsSectionPrefixBytes;


    //The .r1cs file layout (version 1, per FIXTURES.md):
    // File header: magic(4) + version(4) + sectionCount(4)          = 12 bytes
    // Section 1:  type(4)  + size(8)  = 12-byte prefix, then 64-byte payload:
    //   fieldSize(4) + prime(32) + nWires(4) + nPubOut(4) + nPubIn(4)
    //   + nPrvIn(4) + nLabels(8) + nConstraints(4)
    // All multi-byte integers are little-endian.
    private const int R1csFileHeaderBytes = 12;
    private const int R1csSectionPrefixBytes = 12;
    private const int R1csFieldSizeBytes = 4;
    private const int R1csScalarSizeBytes = 32;
    private const int R1csPrimeSizeBytes = R1csScalarSizeBytes;
    private const int R1csNWiresSizeBytes = 4;

    //Byte offset of nPubOut in the file (header section payload).
    private const int R1csNPubOutOffset =
        R1csFileHeaderBytes + R1csSectionPrefixBytes +
        R1csFieldSizeBytes + R1csPrimeSizeBytes + R1csNWiresSizeBytes;

    //nPubIn immediately follows nPubOut (each 4 bytes).
    private const int R1csNPubInOffset = R1csNPubOutOffset + sizeof(uint);
    private const int R1csNPrvInOffset = R1csNPubInOffset + sizeof(uint);


    [TestMethod]
    public void WitnessNonCanonicalElementIsRejectedEndToEnd()
    {
        //Baseline: the committed multiplier2 .wtns fixture parses cleanly.
        byte[] fixture = CircomWitnessFixtures.Multiplier2Bytes;
        using RawR1csWitness baseline = ReadWitness(fixture);
        //The reader drops z[0] = 1; the remaining elements are z[1..3].
        Assert.AreEqual(3, baseline.WitnessVariableCount, "Baseline fixture must parse to 3 witness elements.");

        //Derive the mutation offset: the last witness element ends the file and
        //lives at the start of the data payload + (nWitness-1)*scalarSize.
        //Read nWitness from the fixture bytes (LE uint32 at WtnsNWitnessOffset).
        uint nWitness = BinaryPrimitives.ReadUInt32LittleEndian(fixture.AsSpan(WtnsNWitnessOffset, sizeof(uint)));
        int lastElementOffset = WtnsDataPayloadOffset + (int)(nWitness - 1) * WtnsScalarSizeBytes;

        //Assert that the computed offset is inside the witness data section and
        //that the last 32 bytes end exactly at the file boundary.
        Assert.AreEqual(fixture.Length, lastElementOffset + WtnsScalarSizeBytes,
            "Last element offset must place the 32 bytes flush with the end of the fixture.");

        //Mutation: overwrite the last element with the BLS12-381 scalar field
        //order in little-endian (the format .wtns stores scalars in). The
        //reader reverses to big-endian before calling RawR1csWitness.FromCanonical,
        //which rejects any value >= r.
        byte[] mutated = (byte[])fixture.Clone();
        BigInteger r = WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.Bls12Curve381);
        Span<byte> orderBe = stackalloc byte[WtnsScalarSizeBytes];
        orderBe.Clear();
        r.TryWriteBytes(orderBe, out int written, isUnsigned: true, isBigEndian: true);
        if(written < WtnsScalarSizeBytes)
        {
            //Right-align with leading zero bytes.
            int shift = WtnsScalarSizeBytes - written;
            orderBe[..written].CopyTo(orderBe[shift..]);
            orderBe[..shift].Clear();
        }

        //Reverse BE -> LE for the on-wire mutation.
        for(int i = 0; i < WtnsScalarSizeBytes; i++)
        {
            mutated[lastElementOffset + i] = orderBe[WtnsScalarSizeBytes - 1 - i];
        }

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness _ = ReadWitness(mutated);
        });

        Assert.Contains("scalar field order", ex.Message, StringComparison.Ordinal,
            "The exception message must identify the scalar field order violation.");
    }


    [TestMethod]
    public void HeaderNPubOutWrapRegressionIsRejected()
    {
        //Regression for the unchecked-uint32 wrap: a header with
        //nPubOut = 0xFFFFFFFF, nPubIn = 1, nPrvIn = 0 produced the sum
        //0xFFFFFFFF + 1 + 0 + 1 = 0x100000001, which truncated to 1 mod 2^32,
        //passing the nWires check with any nWires >= 1. The fix promotes the
        //summation to ulong so 0x100000001 > any uint32 nWires.
        byte[] mutated = (byte[])CircomR1csFixtures.Multiplier2Bytes.Clone();

        //Overwrite nPubOut = 0xFFFFFFFF, nPubIn = 1, nPrvIn = 0 in little-endian.
        BinaryPrimitives.WriteUInt32LittleEndian(mutated.AsSpan(R1csNPubOutOffset, sizeof(uint)), 0xFFFFFFFF);
        BinaryPrimitives.WriteUInt32LittleEndian(mutated.AsSpan(R1csNPubInOffset, sizeof(uint)), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(mutated.AsSpan(R1csNPrvInOffset, sizeof(uint)), 0);

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance _ = ReadR1cs(mutated);
        });

        Assert.Contains("inconsistency", ex.Message, StringComparison.Ordinal,
            "The exception must report the header inconsistency (sum exceeds nWires).");
    }


    private static RawR1csWitness ReadWitness(byte[] bytes)
    {
        var stream = new MemoryStream(bytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);

        return CircomWitnessReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomWitness,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            CancellationToken.None);
    }


    private static RawR1csInstance ReadR1cs(byte[] bytes)
    {
        var stream = new MemoryStream(bytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);

        return CircomR1csReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomBinary,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            CancellationToken.None);
    }
}
