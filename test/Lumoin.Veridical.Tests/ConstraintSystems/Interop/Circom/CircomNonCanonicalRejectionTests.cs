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
/// End-to-end rejection tests for the Circom binary readers against two non-canonical
/// categories:
/// (1) witness elements at or above the scalar field order — a non-canonical
/// second encoding that must not reach the transcript or arithmetic;
/// (2) an R1CS header whose nPubOut + nPubIn + nPrvIn + 1 consistency sum must be computed in
/// ulong, so a crafted nPubOut = 0xFFFFFFFF, nPubIn = 1 header cannot wrap a 32-bit accumulator
/// and slip past the nWires check.
/// </summary>
[TestClass]
internal sealed class CircomNonCanonicalRejectionTests
{
    /// <summary>
    /// Byte length of the .wtns file header: magic(4) + version(4) + sectionCount(4). In the
    /// version-2 BLS12-381 .wtns layout, the header is followed by a 52-byte section 1 of
    /// fieldSize(4) + prime(32) + nWitness(4), then a section 2 of a 12-byte prefix plus witness
    /// data of nWitness×32 bytes; all multi-byte integers are little-endian.
    /// </summary>
    private const int WtnsFileHeaderBytes = 12;

    /// <summary>Byte length of a .wtns section prefix: type(4) + size(8).</summary>
    private const int WtnsSectionPrefixBytes = 12;

    /// <summary>Byte length of the field-size field in a .wtns section 1 payload.</summary>
    private const int WtnsFieldSizeBytes = 4;

    /// <summary>Byte width of a BLS12-381 scalar field element, and of the prime field in a .wtns section 1 payload.</summary>
    private const int WtnsScalarSizeBytes = 32;

    /// <summary>Byte length of the prime field in a .wtns section 1 payload; equal to the scalar width.</summary>
    private const int WtnsPrimeSizeBytes = WtnsScalarSizeBytes;

    /// <summary>Byte length of the witness-count field in a .wtns section 1 payload.</summary>
    private const int WtnsNWitnessBytes = 4;

    /// <summary>Byte length of the .wtns section 1 payload: fieldSize + prime + nWitness.</summary>
    private const int WtnsSection1PayloadBytes =
        WtnsFieldSizeBytes + WtnsPrimeSizeBytes + WtnsNWitnessBytes;

    /// <summary>Byte offset of nWitness within the .wtns file, inside the section 1 payload.</summary>
    private const int WtnsNWitnessOffset =
        WtnsFileHeaderBytes + WtnsSectionPrefixBytes + WtnsFieldSizeBytes + WtnsPrimeSizeBytes;

    /// <summary>Byte offset of the witness data payload within the .wtns file: the start of the section 2 payload.</summary>
    private const int WtnsDataPayloadOffset =
        WtnsFileHeaderBytes + WtnsSectionPrefixBytes + WtnsSection1PayloadBytes + WtnsSectionPrefixBytes;


    /// <summary>
    /// Byte length of the .r1cs file header: magic(4) + version(4) + sectionCount(4). In the
    /// version-1 layout, the header is followed by a section 1 with a 12-byte prefix and a
    /// 64-byte payload of fieldSize(4) + prime(32) + nWires(4) + nPubOut(4) + nPubIn(4) +
    /// nPrvIn(4) + nLabels(8) + nConstraints(4); all multi-byte integers are little-endian.
    /// </summary>
    private const int R1csFileHeaderBytes = 12;

    /// <summary>Byte length of the .r1cs section 1 prefix: type(4) + size(8).</summary>
    private const int R1csSectionPrefixBytes = 12;

    /// <summary>Byte length of the field-size field in the .r1cs section 1 payload.</summary>
    private const int R1csFieldSizeBytes = 4;

    /// <summary>Byte width of a BLS12-381 scalar field element, and of the prime field in the .r1cs section 1 payload.</summary>
    private const int R1csScalarSizeBytes = 32;

    /// <summary>Byte length of the prime field in the .r1cs section 1 payload; equal to the scalar width.</summary>
    private const int R1csPrimeSizeBytes = R1csScalarSizeBytes;

    /// <summary>Byte length of the nWires field in the .r1cs section 1 payload.</summary>
    private const int R1csNWiresSizeBytes = 4;

    /// <summary>Byte offset of nPubOut within the .r1cs file, in the section 1 header payload.</summary>
    private const int R1csNPubOutOffset =
        R1csFileHeaderBytes + R1csSectionPrefixBytes +
        R1csFieldSizeBytes + R1csPrimeSizeBytes + R1csNWiresSizeBytes;

    /// <summary>Byte offset of nPubIn within the .r1cs file; immediately follows nPubOut.</summary>
    private const int R1csNPubInOffset = R1csNPubOutOffset + sizeof(uint);

    /// <summary>Byte offset of nPrvIn within the .r1cs file; immediately follows nPubIn.</summary>
    private const int R1csNPrvInOffset = R1csNPubInOffset + sizeof(uint);


    /// <summary>
    /// A .wtns witness whose last element equals the BLS12-381 scalar field order — a
    /// non-canonical second encoding of zero — is rejected end to end by the Circom witness
    /// reader rather than reaching the transcript or arithmetic.
    /// </summary>
    [TestMethod]
    public void WitnessNonCanonicalElementIsRejectedEndToEnd()
    {
        //Baseline: the multiplier2 .wtns fixture parses cleanly.
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


    /// <summary>
    /// An R1CS header with nPubOut = 0xFFFFFFFF, nPubIn = 1, nPrvIn = 0 is rejected: the
    /// consistency sum nPubOut + nPubIn + nPrvIn + 1 must be computed in ulong so it cannot wrap
    /// a 32-bit accumulator and slip past the nWires check.
    /// </summary>
    [TestMethod]
    public void HeaderNPubOutWrapRegressionIsRejected()
    {
        //Regression guard for the unchecked-uint32 wrap: a header with
        //nPubOut = 0xFFFFFFFF, nPubIn = 1, nPrvIn = 0 produces the sum
        //0xFFFFFFFF + 1 + 0 + 1 = 0x100000001, which truncates to 1 mod 2^32 if computed in
        //uint32, passing the nWires check with any nWires >= 1. The reader must sum in ulong so
        //0x100000001 > any uint32 nWires.
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


    /// <summary>Reads a Circom witness from <paramref name="bytes"/> over the BLS12-381 scalar field.</summary>
    private static RawR1csWitness ReadWitness(byte[] bytes)
    {
        var stream = new MemoryStream(bytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);

        return CircomWitnessReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomWitness,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);
    }


    /// <summary>Reads a Circom R1CS instance from <paramref name="bytes"/> over the BLS12-381 scalar field.</summary>
    private static RawR1csInstance ReadR1cs(byte[] bytes)
    {
        var stream = new MemoryStream(bytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);

        return CircomR1csReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomBinary,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);
    }
}
