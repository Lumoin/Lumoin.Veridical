using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.Circom;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Pipelines;
using System.Numerics;
using System.Threading;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.Circom;

/// <summary>
/// Conformance tests for the Circom <c>.wtns</c> reader, plus the
/// end-to-end gate that combines the parsed <c>.r1cs</c> and parsed
/// <c>.wtns</c> through both Spartan provers.
/// </summary>
[TestClass]
internal sealed class CircomWitnessReaderTests
{
    /// <summary>The 32-byte canonical scalar width of the BLS12-381 fixtures.</summary>
    private const int ScalarSize = WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>The byte offset of the prime modulus, immediately after the four-byte field width.</summary>
    private const int PrimeOffset = FieldSizeOffset + sizeof(uint);

    /// <summary>The divisor that cuts the fixture in half, leaving a section payload incomplete.</summary>
    private const int FixtureHalves = 2;

    /// <summary>The Hyrax vector length for the four-column Multiplier2 witness, split into two columns.</summary>
    private const int Multiplier2HyraxVectorLength = 2;

    /// <summary>The BN254 scalar modulus substituted into a BLS12-381 header to exercise field mismatch rejection.</summary>
    private const string Bn254ScalarFieldModulusHex = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

    /// <summary>A witness count requiring roughly 3.2 GB of canonical scalars, beyond the maximum array length.</summary>
    private const uint NWitnessAboveAddressableRange = 100000000u;

    /// <summary>The four wire columns of Multiplier2, including the constant omitted from the returned witness.</summary>
    private const int Multiplier2ColumnCount = Multiplier2WitnessElementCount;

    /// <summary>The four trailing bytes that hold each small fixture scalar when read as a signed integer.</summary>
    private const int ScalarIntegerTailBytes = sizeof(int);

    /// <summary>The length of the ASCII <c>wtns</c> magic that opens every <c>.wtns</c> file.</summary>
    private const int MagicBytes = 4;

    /// <summary>The byte offset of the little-endian <c>version</c> field, which directly follows the magic.</summary>
    private const int VersionOffset = MagicBytes;

    /// <summary>The length of the file header: the magic, the 4-byte <c>version</c> field and the 4-byte section count.</summary>
    private const int FileHeaderBytes = MagicBytes + sizeof(uint) + sizeof(uint);

    /// <summary>The length of the prefix every section carries: a 4-byte section type and an 8-byte payload size.</summary>
    private const int SectionPrefixBytes = sizeof(uint) + sizeof(ulong);

    /// <summary>The byte offset of the type field of the header section, which is the first section of the Multiplier2 fixture.</summary>
    private const int HeaderSectionTypeOffset = FileHeaderBytes;

    /// <summary>The byte offset of the 8-byte payload size field of the header section.</summary>
    private const int HeaderSectionSizeOffset = HeaderSectionTypeOffset + sizeof(uint);

    /// <summary>The byte offset of <c>field_size</c>, the first field of the header section payload.</summary>
    private const int FieldSizeOffset = FileHeaderBytes + SectionPrefixBytes;

    /// <summary>The byte offset of <c>nWitness</c>, which follows <c>field_size</c> and the 32-byte prime modulus in the header section payload.</summary>
    private const int NWitnessOffset = FieldSizeOffset + sizeof(uint) + WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>The byte offset of the type field of the witness data section, which follows the header section payload.</summary>
    private const int DataSectionTypeOffset = NWitnessOffset + sizeof(uint);

    /// <summary>The byte offset of the 8-byte payload size field of the witness data section.</summary>
    private const int DataSectionSizeOffset = DataSectionTypeOffset + sizeof(uint);

    /// <summary>The byte offset of the witness data section payload, which stores <c>z[0]</c> first.</summary>
    private const int DataSectionPayloadOffset = DataSectionTypeOffset + SectionPrefixBytes;

    /// <summary>The number of witness elements the Multiplier2 fixture stores, <c>z = (1, 33, 3, 11)</c>.</summary>
    private const int Multiplier2WitnessElementCount = 4;

    /// <summary>The length of the witness data section payload of the Multiplier2 fixture.</summary>
    private const int Multiplier2DataSectionBytes = Multiplier2WitnessElementCount * WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>The total length of the Multiplier2 fixture.</summary>
    private const int Multiplier2FileBytes = DataSectionPayloadOffset + Multiplier2DataSectionBytes;

    /// <summary>The only <c>.wtns</c> file version the reader accepts.</summary>
    private const uint SupportedFileVersion = 2u;

    /// <summary>A <c>.wtns</c> file version other than the supported one.</summary>
    private const uint UnsupportedFileVersion = 1u;

    /// <summary>A section type that is neither the header (type 1) nor the witness data (type 2), so the reader reads past the section without interpreting it.</summary>
    private const uint UnknownSectionType = 3u;

    /// <summary>An input length one byte short of the 4-byte magic.</summary>
    private const int MagicBytesPresent = 3;

    /// <summary>The number of <c>version</c> bytes present when the file ends halfway through that 4-byte field.</summary>
    private const int VersionBytesPresent = 2;

    /// <summary>An input length that ends halfway through the <c>version</c> field.</summary>
    private const int VersionTruncatedLength = MagicBytes + VersionBytesPresent;

    /// <summary>The number of section size bytes present when the file ends halfway through that 8-byte field.</summary>
    private const int SectionSizeBytesPresent = 4;

    /// <summary>An input length that ends halfway through the payload size field of the header section.</summary>
    private const int SectionSizeTruncatedLength = HeaderSectionSizeOffset + SectionSizeBytesPresent;

    /// <summary>A <c>field_size</c> of zero, which is not a positive multiple of 8.</summary>
    private const uint ZeroFieldSize = 0u;

    /// <summary>A <c>field_size</c> that is a positive multiple of 8 not exceeding 256, yet narrower than the 32-byte BLS12-381 scalar.</summary>
    private const uint HalfWidthFieldSizeBytes = 16u;

    /// <summary>A header section payload size that covers <c>field_size</c> and none of the prime modulus after it.</summary>
    private const ulong FieldSizeOnlyHeaderPayloadBytes = sizeof(uint);

    /// <summary>An <c>nWitness</c> of zero, which omits even the constant <c>z[0] = 1</c>.</summary>
    private const uint ZeroNWitness = 0u;

    /// <summary>An <c>nWitness</c> one fewer than the four elements the witness data section of the fixture stores.</summary>
    private const uint UnderstatedNWitness = 3u;

    /// <summary>An <c>nWitness</c> that declares only the constant <c>z[0] = 1</c>.</summary>
    private const uint ConstantOnlyNWitness = 1u;

    /// <summary>A witness data section payload size that holds exactly one scalar, the constant <c>z[0] = 1</c>.</summary>
    private const ulong ConstantOnlyDataSectionBytes = WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>The length of the Multiplier2 fixture cut directly after <c>z[0]</c>, the whole file of a constant-only witness.</summary>
    private const int ConstantOnlyFileBytes = DataSectionPayloadOffset + WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>The byte offset of the first magic byte, the ASCII <c>w</c>.</summary>
    private const int MagicLeadByteOffset = 0;

    /// <summary>The byte offset of the little-endian section count, which follows the <c>version</c> field.</summary>
    private const int SectionCountOffset = VersionOffset + sizeof(uint);

    /// <summary>The number of section count bytes present when the file ends halfway through that 4-byte field.</summary>
    private const int SectionCountBytesPresent = 2;

    /// <summary>An input length that ends halfway through the section count field.</summary>
    private const int SectionCountTruncatedLength = SectionCountOffset + SectionCountBytesPresent;

    /// <summary>The number of section type bytes present when the file ends halfway through that 4-byte field.</summary>
    private const int SectionTypeBytesPresent = 2;

    /// <summary>An input length that ends halfway through the type field of the header section.</summary>
    private const int SectionTypeTruncatedLength = HeaderSectionTypeOffset + SectionTypeBytesPresent;

    /// <summary>The zero-based position of the witness data section among the sections of the Multiplier2 fixture.</summary>
    private const uint DataSectionIndex = 1u;

    /// <summary>The number of trailing bytes cut from the Multiplier2 fixture, so its witness data section runs past the end of the file.</summary>
    private const int CutTrailingBytes = 1;

    /// <summary>A byte written over the leading ASCII <c>w</c>, turning the magic into ASCII <c>xtns</c>.</summary>
    private const byte ForeignMagicLeadByte = (byte)'x';

    /// <summary>The upper-case hex of the ASCII <c>xtns</c> magic, as the reader reports the bytes it found.</summary>
    private const string ForeignMagicHex = "78746E73";

    /// <summary>A header section payload size that covers only half of the 4-byte <c>field_size</c>.</summary>
    private const ulong HalfFieldSizeHeaderPayloadBytes = 2ul;

    /// <summary>A <c>field_size</c> not exceeding 256 that is not a multiple of 8, so only the multiple-of-8 rule rejects it.</summary>
    private const uint NonMultipleOfEightFieldSize = 33u;

    /// <summary>The largest <c>field_size</c> the shape check admits, a multiple of 8 equal to the 256 bound and wider than the 32-byte BLS12-381 scalar.</summary>
    private const uint LargestShapeValidFieldSize = 256u;

    /// <summary>The number of <c>nWitness</c> bytes present when the header section payload ends halfway through that 4-byte field.</summary>
    private const int NWitnessBytesPresent = 2;

    /// <summary>A header section payload size that covers <c>field_size</c>, the 32-byte prime modulus and half of <c>nWitness</c>.</summary>
    private const ulong NWitnessTruncatedHeaderPayloadBytes = sizeof(uint) + WellKnownCurves.Bls12Curve381ScalarSizeBytes + NWitnessBytesPresent;

    /// <summary>The byte offset of the most significant byte of the little-endian prime modulus, the last byte before <c>nWitness</c>.</summary>
    private const int PrimeMostSignificantByteOffset = NWitnessOffset - sizeof(byte);

    /// <summary>The top bit of a byte; set in the most significant prime byte it makes the declared modulus exceed 2^255.</summary>
    private const byte TopBitMask = 0x80;

    /// <summary>The BLS12-381 scalar field order as lower-case big-endian hex, the modulus the reader expects for that curve.</summary>
    private const string Bls12Curve381ScalarFieldModulusHex = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

    /// <summary>
    /// The BLS12-381 scalar field order with its top bit set, as lower-case big-endian hex. The hex form of a positive
    /// integer whose leading digit is 8 or above carries a leading zero, which tells it apart from a negative value.
    /// </summary>
    private const string TopBitSetModulusHex = "0f3eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

    /// <summary>The number of witness variables the reader returns for the Multiplier2 fixture: every stored element but the constant.</summary>
    private const int Multiplier2WitnessVariableCount = Multiplier2WitnessElementCount - (int)ConstantOnlyNWitness;

    /// <summary>The Multiplier2 output <c>c = a * b = 33</c>, the first returned witness variable.</summary>
    private const int Multiplier2OutputValue = 33;

    /// <summary>The Multiplier2 left factor <c>a = 3</c>, the second returned witness variable.</summary>
    private const int Multiplier2LeftFactorValue = 3;

    /// <summary>The Multiplier2 right factor <c>b = 11</c>, the third returned witness variable.</summary>
    private const int Multiplier2RightFactorValue = 11;

    /// <summary>The byte offset of the output <c>c</c> within the returned big-endian witness bytes.</summary>
    private const int OutputValueOffset = 0;

    /// <summary>The byte offset of the left factor <c>a</c> within the returned big-endian witness bytes.</summary>
    private const int LeftFactorValueOffset = OutputValueOffset + WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>The byte offset of the right factor <c>b</c> within the returned big-endian witness bytes.</summary>
    private const int RightFactorValueOffset = LeftFactorValueOffset + WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>The number of further file bytes each read of the chunked pipe uncovers, so the 204-byte fixture arrives over four reads.</summary>
    private const int DeliveryChunkBytes = 64;


    /// <summary>
    /// The largest <c>nWitness</c> whose dense witness vector still fits in one array: its <c>nWitness - 1</c> scalars of
    /// 32 bytes stay within <see cref="Array.MaxLength"/>, while one scalar more would exceed it.
    /// </summary>
    private static uint LargestAddressableNWitness { get; } = (uint)(Array.MaxLength / WellKnownCurves.Bls12Curve381ScalarSizeBytes) + ConstantOnlyNWitness;


    /// <summary>The pooled rentals opened during a test, released together in cleanup.</summary>
    private List<IDisposable> Disposables { get; } = [];


    /// <summary>Disposes every rental the test opened, most recent first.</summary>
    [TestCleanup]
    public void DisposeRentals()
    {
        for(int i = Disposables.Count - 1; i >= 0; i--)
        {
            Disposables[i].Dispose();
        }

        Disposables.Clear();
    }


    /// <summary>The Multiplier2 witness omits the constant and returns the output and both factors in canonical scalar slots.</summary>
    [TestMethod]
    public void Multiplier2WitnessParsesIntoExpectedValues()
    {
        using RawR1csWitness witness = ReadWitnessFixture(CircomWitnessFixtures.Multiplier2Bytes);

        //RawR1csWitness contains z[1..nWitness] = (c, a, b) = (33, 3, 11)
        //in canonical big-endian, 32 bytes each. (The constant z[0] = 1
        //is dropped by the reader per the CircomWitnessReader convention.)
        Assert.AreEqual(Multiplier2WitnessVariableCount, witness.WitnessVariableCount);

        ReadOnlySpan<byte> bytes = witness.GetWitnessBytes();
        Assert.HasCount(Multiplier2WitnessVariableCount * ScalarSize, bytes);

        Assert.AreEqual(33, ReadBigEndianInt(bytes.Slice(OutputValueOffset, ScalarSize)), "The Multiplier2 output c is 33.");
        Assert.AreEqual(3, ReadBigEndianInt(bytes.Slice(LeftFactorValueOffset, ScalarSize)), "The Multiplier2 left factor a is 3.");
        Assert.AreEqual(11, ReadBigEndianInt(bytes.Slice(RightFactorValueOffset, ScalarSize)), "The Multiplier2 right factor b is 11.");
    }


    /// <summary>The witness reader rejects the R1CS binary format label with an argument exception naming the format.</summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsWrongFormatLabel()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessFixture(
                CircomWitnessFixtures.Multiplier2Bytes,
                WellKnownR1csFormatLabel.CircomBinary);
        });

        Assert.AreEqual("format", exception.ParamName, "The rejection must name the format parameter.");
    }


    /// <summary>The witness reader rejects a fixture whose leading magic byte is not the expected ASCII character.</summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsWrongMagic()
    {
        byte[] mutated = (byte[])CircomWitnessFixtures.Multiplier2Bytes.Clone();
        mutated[MagicLeadByteOffset] = ForeignMagicLeadByte;

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessFixture(mutated);
        });
    }


    /// <summary>A BLS12-381 witness read rejects a header declaring the BN254 scalar field.</summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsBn254Field()
    {
        byte[] mutated = (byte[])CircomWitnessFixtures.Multiplier2Bytes.Clone();
        byte[] bn254Be = Convert.FromHexString(Bn254ScalarFieldModulusHex);
        for(int i = 0; i < bn254Be.Length; i++)
        {
            mutated[PrimeOffset + i] = bn254Be[bn254Be.Length - 1 - i];
        }

        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessFixture(mutated);
        });
    }


    /// <summary>The witness reader rejects a fixture cut in half inside its declared witness data section.</summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsTruncatedFile()
    {
        byte[] full = CircomWitnessFixtures.Multiplier2Bytes;
        byte[] truncated = full.AsSpan(0, full.Length / FixtureHalves).ToArray();

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessFixture(truncated);
        });
    }


    /// <summary>A witness count whose dense scalar vector exceeds the maximum array length is rejected by the header range check.</summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsNWitnessAboveAddressableRange()
    {
        byte[] mutated = (byte[])CircomWitnessFixtures.Multiplier2Bytes.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(mutated.AsSpan(NWitnessOffset), NWitnessAboveAddressableRange);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessFixture(mutated);
        });

        Assert.Contains("exceeds the maximum addressable size", exception.Message, "the nWitness range guard must be what rejects the header");
    }


    /// <summary>
    /// An input shorter than the 4-byte magic is rejected by the magic length check with an
    /// <see cref="ArgumentException"/> that names the magic, before any cursor advance can run past the input.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsInputShorterThanMagic()
    {
        Memory<byte> file = RentFixturePrefix(MagicBytesPresent);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"shorter than the {MagicBytes}-byte magic", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A file that ends inside the 4-byte <c>version</c> field is rejected by the 32-bit field read with an
    /// <see cref="ArgumentException"/> that names the field, its width and the number of bytes left.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsTruncationInsideVersionField()
    {
        Memory<byte> file = RentFixturePrefix(VersionTruncatedLength);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"truncated while reading version ({sizeof(uint)} bytes); only {VersionBytesPresent} bytes remained.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// An otherwise valid file that declares a version other than the supported one is rejected with an
    /// <see cref="ArgumentException"/> naming both the supported and the declared version, rather than parsed.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsUnsupportedVersion()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[VersionOffset..], UnsupportedFileVersion);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"supports only .wtns file version {SupportedFileVersion}; file declares version {UnsupportedFileVersion}.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A file that ends inside the 8-byte payload size field of its first section is rejected by the 64-bit
    /// field read with an <see cref="ArgumentException"/> that names the field, its width and the number of bytes left.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsTruncationInsideSectionSizeField()
    {
        Memory<byte> file = RentFixturePrefix(SectionSizeTruncatedLength);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"truncated while reading section size ({sizeof(ulong)} bytes); only {SectionSizeBytesPresent} bytes remained.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A file whose header section is retagged to an unknown section type has that section read past, and is
    /// then rejected with an <see cref="ArgumentException"/> reporting the missing header section, rather than
    /// failing on the absent witness length.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsMissingHeaderSection()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[HeaderSectionTypeOffset..], UnknownSectionType);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains("missing the header section (type 1).", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A file with a valid header section whose witness data section is retagged to an unknown section type is
    /// rejected with an <see cref="ArgumentException"/> reporting the missing witness data section, rather than
    /// failing on the absent witness bytes.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsMissingWitnessDataSection()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[DataSectionTypeOffset..], UnknownSectionType);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains("missing the witness data section (type 2).", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header declaring <c>field_size = 0</c> is rejected by the field size shape check, whose message states
    /// the positive-multiple-of-8 rule, before the comparison against the curve scalar width runs.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsZeroFieldSize()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[FieldSizeOffset..], ZeroFieldSize);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"field_size = {ZeroFieldSize}; must be a positive multiple of 8 not exceeding 256.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header declaring a well-shaped <c>field_size</c> that differs from the 32-byte scalar width of the curve
    /// is rejected with an <see cref="ArgumentException"/> naming the declared and the expected width, rather
    /// than parsed at the curve width.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsFieldSizeNotMatchingCurveWidth()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[FieldSizeOffset..], HalfWidthFieldSizeBytes);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"field_size = {HalfWidthFieldSizeBytes} bytes but curve", exception.Message, StringComparison.Ordinal);
        Assert.Contains($"expects {WellKnownCurves.Bls12Curve381ScalarSizeBytes} bytes per scalar.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header section whose declared payload covers only <c>field_size</c> is rejected when the prime modulus
    /// read runs past the payload, with an <see cref="ArgumentException"/> naming the prime modulus and its width.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsHeaderSectionTooShortForPrime()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        BinaryPrimitives.WriteUInt64LittleEndian(file.Span[HeaderSectionSizeOffset..], FieldSizeOnlyHeaderPayloadBytes);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"truncated while reading the prime modulus ({WellKnownCurves.Bls12Curve381ScalarSizeBytes} bytes).", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header declaring <c>nWitness = 0</c> is rejected by the zero-count check, whose message states that the
    /// witness must hold at least the constant, before the addressable-size check sees the wrapped element count.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsZeroNWitness()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[NWitnessOffset..], ZeroNWitness);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"nWitness = {ZeroNWitness}; witness must have at least the constant.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header whose <c>nWitness</c> accounts for fewer elements than the witness data section holds is
    /// rejected by the exact section length check, rather than parsed with the trailing elements ignored.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsDataSectionLongerThanDeclared()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[NWitnessOffset..], UnderstatedNWitness);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"witness section has {Multiplier2DataSectionBytes} bytes but the header declares {UnderstatedNWitness}", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A witness holding only the constant <c>z[0] = 1</c>, declared consistently by the header and the witness
    /// data section, is rejected by the reader with a message naming the constant, before any witness is built.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsConstantOnlyWitness()
    {
        Memory<byte> file = RentFixturePrefix(ConstantOnlyFileBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[NWitnessOffset..], ConstantOnlyNWitness);
        BinaryPrimitives.WriteUInt64LittleEndian(file.Span[DataSectionSizeOffset..], ConstantOnlyDataSectionBytes);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains("contains only the constant z[0] = 1;", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A read cancelled through <see cref="PipeReader.CancelPendingRead"/> surfaces as
    /// <see cref="OperationCanceledException"/> instead of being retried into a parsed witness. The fixture array
    /// is read through a <see cref="MemoryStream"/>, the byte-array stream shape the fixture readers of this class use.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessReadSurfacesPendingReadCancellation()
    {
        using MemoryStream stream = new(CircomWitnessFixtures.Multiplier2Bytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);
        pipe.CancelPendingRead();

        Assert.ThrowsExactly<OperationCanceledException>(() =>
        {
            using RawR1csWitness witness = CircomWitnessReader.Reader(
                pipe,
                WellKnownR1csFormatLabel.CircomWitness,
                CurveParameterSet.Bls12Curve381,
                BaseMemoryPool.Shared,
                WellKnownR1csIntakeLimits.Unbounded,
                CancellationToken.None);
        });
    }


    /// <summary>
    /// A null pipe is rejected by the reader's own argument check with an <see cref="ArgumentNullException"/> naming
    /// the pipe, rather than failing with a dereference when the pipe is drained.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsNullPipe()
    {
        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            using RawR1csWitness witness = CircomWitnessReader.Reader(
                null!,
                WellKnownR1csFormatLabel.CircomWitness,
                CurveParameterSet.Bls12Curve381,
                BaseMemoryPool.Shared,
                WellKnownR1csIntakeLimits.Unbounded,
                CancellationToken.None);
        });

        Assert.AreEqual("pipe", exception.ParamName);
    }


    /// <summary>
    /// A null pool is rejected with an <see cref="ArgumentNullException"/> naming the pool before the pipe is read at
    /// all, so a well-formed file is not drained and parsed only to fail when the witness buffer is rented.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsNullPoolBeforeReadingThePipe()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        StrictChunkedPipeReader pipe = new(file, Multiplier2FileBytes);

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            using RawR1csWitness witness = CircomWitnessReader.Reader(
                pipe,
                WellKnownR1csFormatLabel.CircomWitness,
                CurveParameterSet.Bls12Curve381,
                null!,
                WellKnownR1csIntakeLimits.Unbounded,
                CancellationToken.None);
        });

        Assert.AreEqual("pool", exception.ParamName);
        Assert.IsFalse(pipe.HasBeenRead, "The pool check must reject the call before the pipe is read.");
    }


    /// <summary>
    /// A format label other than the Circom witness label is rejected with an <see cref="ArgumentException"/> on the
    /// format parameter whose message names the accepted label and the label received.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsWrongFormatLabelNamingTheReceivedLabel()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessFixture(
                CircomWitnessFixtures.Multiplier2Bytes,
                WellKnownR1csFormatLabel.CircomBinary);
        });

        Assert.AreEqual("format", exception.ParamName);
        Assert.Contains($"handles only WellKnownR1csFormatLabel.CircomWitness; received '{WellKnownR1csFormatLabel.CircomBinary.Identifier}'.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A curve without reference support is rejected by the wired-curve gate, whose message lists the wired curves,
    /// before any pipe read or scalar width lookup occurs.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsUnwiredCurveBeforeParsing()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        StrictChunkedPipeReader pipe = new(file, Multiplier2FileBytes);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = CircomWitnessReader.Reader(
                pipe,
                WellKnownR1csFormatLabel.CircomWitness,
                CurveParameterSet.P256,
                BaseMemoryPool.Shared,
                WellKnownR1csIntakeLimits.Unbounded,
                CancellationToken.None);
        });

        Assert.AreEqual("curve", exception.ParamName);
        Assert.Contains("is not wired; the wired curves are Bls12Curve381 and Bn254.", exception.Message, StringComparison.Ordinal);
        Assert.IsFalse(pipe.HasBeenRead, "The curve check must reject the call before the pipe is read.");
    }


    /// <summary>
    /// A successful read advances the pipe past every byte of the file, so the caller's pipe does not still hold the
    /// parsed file as unread input.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessReadConsumesTheWholeFile()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        StrictChunkedPipeReader pipe = new(file, Multiplier2FileBytes);

        using RawR1csWitness witness = ReadWitnessPipe(pipe);

        Assert.AreEqual(Multiplier2WitnessVariableCount, witness.WitnessVariableCount);
        Assert.AreEqual(Multiplier2FileBytes, pipe.ConsumedBytes);
    }


    /// <summary>
    /// A file that arrives over several reads is drained until the pipe reports completion, advancing past each partial
    /// buffer before reading again and stopping at the completed read, and then parses into the same witness values as
    /// a file that arrives in one read.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessParsesAFileDeliveredInChunks()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        StrictChunkedPipeReader pipe = new(file, DeliveryChunkBytes);

        using RawR1csWitness witness = ReadWitnessPipe(pipe);

        ReadOnlySpan<byte> bytes = witness.GetWitnessBytes();
        Assert.AreEqual(Multiplier2WitnessVariableCount, witness.WitnessVariableCount);
        Span<byte> expected = stackalloc byte[ScalarSize];
        expected.Clear();
        BinaryPrimitives.WriteInt32BigEndian(expected[^ScalarIntegerTailBytes..], Multiplier2OutputValue);
        Assert.IsTrue(expected.SequenceEqual(bytes.Slice(OutputValueOffset, ScalarSize)), "The full output scalar must be canonical 33.");
        BinaryPrimitives.WriteInt32BigEndian(expected[^ScalarIntegerTailBytes..], Multiplier2LeftFactorValue);
        Assert.IsTrue(expected.SequenceEqual(bytes.Slice(LeftFactorValueOffset, ScalarSize)), "The full left-factor scalar must be canonical 3.");
        BinaryPrimitives.WriteInt32BigEndian(expected[^ScalarIntegerTailBytes..], Multiplier2RightFactorValue);
        Assert.IsTrue(expected.SequenceEqual(bytes.Slice(RightFactorValueOffset, ScalarSize)), "The full right-factor scalar must be canonical 11.");
    }


    /// <summary>
    /// A file that ends inside the 4-byte section count field is rejected by the 32-bit field read with an
    /// <see cref="ArgumentException"/> that names the section count, its width and the number of bytes left.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsTruncationInsideSectionCountField()
    {
        Memory<byte> file = RentFixturePrefix(SectionCountTruncatedLength);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"truncated while reading section count ({sizeof(uint)} bytes); only {SectionCountBytesPresent} bytes remained.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A file that ends inside the 4-byte type field of its first section is rejected by the 32-bit field read with an
    /// <see cref="ArgumentException"/> that names the section type, its width and the number of bytes left.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsTruncationInsideSectionTypeField()
    {
        Memory<byte> file = RentFixturePrefix(SectionTypeTruncatedLength);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"truncated while reading section type ({sizeof(uint)} bytes); only {SectionTypeBytesPresent} bytes remained.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A file cut one byte short of its witness data section is rejected by the section length check with an
    /// <see cref="ArgumentException"/> naming the section, its declared size and the bytes actually left in the file.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsSectionLongerThanTheRemainingFile()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes - CutTrailingBytes);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"Section {DataSectionIndex} declares size {Multiplier2DataSectionBytes} bytes but only {Multiplier2DataSectionBytes - CutTrailingBytes} bytes remain in the file.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A file whose magic is not ASCII <c>wtns</c> is rejected with an <see cref="ArgumentException"/> whose message
    /// gives the expected magic and the hex of the four bytes found in its place.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsWrongMagicNamingTheFoundBytes()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        file.Span[MagicLeadByteOffset] = ForeignMagicLeadByte;

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"magic mismatch. Expected ASCII 'wtns' (77 74 6e 73); found {ForeignMagicHex}.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header section whose declared payload ends halfway through <c>field_size</c> is rejected by the 32-bit field
    /// read over that payload, with an <see cref="ArgumentException"/> naming the header field and the bytes left.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsTruncationInsideFieldSizeField()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        BinaryPrimitives.WriteUInt64LittleEndian(file.Span[HeaderSectionSizeOffset..], HalfFieldSizeHeaderPayloadBytes);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"truncated while reading header.fieldSize ({sizeof(uint)} bytes); only {HalfFieldSizeHeaderPayloadBytes} bytes remained.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header declaring a <c>field_size</c> within the 256 bound that is not a multiple of 8 is rejected by the field
    /// size shape check on the multiple-of-8 rule alone, before the comparison against the curve scalar width runs.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsFieldSizeNotMultipleOfEight()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[FieldSizeOffset..], NonMultipleOfEightFieldSize);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"field_size = {NonMultipleOfEightFieldSize}; must be a positive multiple of 8 not exceeding 256.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header declaring <c>field_size = 256</c> passes the shape check, since the bound is inclusive, and is then
    /// rejected only because it differs from the 32-byte scalar width of the curve.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsLargestShapeValidFieldSizeOnCurveWidth()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[FieldSizeOffset..], LargestShapeValidFieldSize);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"field_size = {LargestShapeValidFieldSize} bytes but curve", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header section whose declared payload ends halfway through <c>nWitness</c> is rejected by the 32-bit field
    /// read over that payload, with an <see cref="ArgumentException"/> naming the header field and the bytes left.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessRejectsTruncationInsideNWitnessField()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        BinaryPrimitives.WriteUInt64LittleEndian(file.Span[HeaderSectionSizeOffset..], NWitnessTruncatedHeaderPayloadBytes);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"truncated while reading header.nWitness ({sizeof(uint)} bytes); only {NWitnessBytesPresent} bytes remained.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// The largest <c>nWitness</c> whose dense witness vector is still addressable passes the header range check, which
    /// counts only the <c>nWitness - 1</c> scalars after the constant, and is rejected by the section length check instead.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessAdmitsLargestAddressableNWitnessPastTheRangeCheck()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[NWitnessOffset..], LargestAddressableNWitness);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.Contains($"witness section has {Multiplier2DataSectionBytes} bytes but the header declares {LargestAddressableNWitness}", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A prime modulus with its top bit set is read as an unsigned integer and rejected with an
    /// <see cref="R1csUnsupportedFieldException"/> that carries both the expected and the found modulus as
    /// lower-case hex, the found one positive and therefore written with its leading zero.
    /// </summary>
    [TestMethod]
    public void Multiplier2WitnessReportsExpectedAndFoundModulusAsUnsignedHex()
    {
        Memory<byte> file = RentFixturePrefix(Multiplier2FileBytes);
        file.Span[PrimeMostSignificantByteOffset] |= TopBitMask;

        R1csUnsupportedFieldException exception = Assert.ThrowsExactly<R1csUnsupportedFieldException>(() =>
        {
            using RawR1csWitness witness = ReadWitnessMemory(file);
        });

        Assert.AreEqual(Bls12Curve381ScalarFieldModulusHex, exception.ExpectedModulusHex);
        Assert.AreEqual(TopBitSetModulusHex, exception.FoundModulusHex);
    }


    /// <summary>The parsed Multiplier2 circuit and witness produce a standard Spartan proof accepted by the verifier.</summary>
    [TestMethod]
    public void Multiplier2EndToEndProvesAndVerifiesWithStandardSpartan()
    {
        using RawR1csWitness witness = ReadWitnessFixture(CircomWitnessFixtures.Multiplier2Bytes);
        using SpartanProver prover = BuildBaseProver(Multiplier2ColumnCount);
        using SpartanVerifier verifier = BuildBaseVerifier(Multiplier2ColumnCount);

        using RawR1csInstance proverInstance = ReadR1csFixture(CircomR1csFixtures.Multiplier2Bytes);
        using RawR1csInstance verifierInstance = ReadR1csFixture(CircomR1csFixtures.Multiplier2Bytes);

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using SpartanProof proof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            BaseMemoryPool.Shared);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            proof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze,
            BaseMemoryPool.Shared);

        Assert.IsTrue(verified, "Base Spartan failed end-to-end on Circom-parsed multiplier2 .r1cs + .wtns.");
    }


    /// <summary>The parsed Multiplier2 circuit and witness produce a masked Spartan proof accepted by the verifier.</summary>
    [TestMethod]
    public void Multiplier2EndToEndProvesAndVerifiesWithMaskedSpartan()
    {
        using RawR1csWitness witness = ReadWitnessFixture(CircomWitnessFixtures.Multiplier2Bytes);
        using MaskedSpartanProver prover = BuildMaskedProver(Multiplier2HyraxVectorLength);
        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(Multiplier2HyraxVectorLength);

        using RawR1csInstance proverInstance = ReadR1csFixture(CircomR1csFixtures.Multiplier2Bytes);
        using RawR1csInstance verifierInstance = ReadR1csFixture(CircomR1csFixtures.Multiplier2Bytes);

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof proof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            BaseMemoryPool.Shared);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            proof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze,
            BaseMemoryPool.Shared);

        Assert.IsTrue(verified, "Masked Spartan failed end-to-end on Circom-parsed multiplier2 .r1cs + .wtns.");
    }


    /// <summary>Parses fixture bytes as a BLS12-381 witness under the Circom witness format label.</summary>
    private static RawR1csWitness ReadWitnessFixture(byte[] fixtureBytes) =>
        ReadWitnessFixture(fixtureBytes, WellKnownR1csFormatLabel.CircomWitness);


    /// <summary>Parses fixture bytes as a BLS12-381 witness using the supplied format label.</summary>
    private static RawR1csWitness ReadWitnessFixture(byte[] fixtureBytes, WellKnownR1csFormatLabel format)
    {
        var stream = new MemoryStream(fixtureBytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);

        return CircomWitnessReader.Reader(
            pipe,
            format,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);
    }


    /// <summary>
    /// Rents a pooled buffer, tracks it for cleanup and fills it with the leading bytes of the Multiplier2
    /// fixture, so a test can cut the file short or overwrite a field without touching the fixture itself.
    /// </summary>
    /// <param name="length">The number of leading fixture bytes to copy.</param>
    /// <returns>The pooled copy, exactly <paramref name="length"/> bytes long.</returns>
    private Memory<byte> RentFixturePrefix(int length)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Disposables.Add(owner);

        Memory<byte> file = owner.Memory[..length];
        CircomWitnessFixtures.Multiplier2Bytes.AsSpan(0, length).CopyTo(file.Span);

        return file;
    }


    /// <summary>Runs the <c>.wtns</c> reader for BLS12-381 over complete in-memory file bytes.</summary>
    /// <param name="file">The file bytes the pipe yields before it reports completion.</param>
    /// <returns>The parsed witness, which the caller disposes.</returns>
    private static RawR1csWitness ReadWitnessMemory(ReadOnlyMemory<byte> file)
    {
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(file));

        return CircomWitnessReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomWitness,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);
    }


    /// <summary>Runs the <c>.wtns</c> reader for BLS12-381 over a caller-supplied pipe.</summary>
    /// <param name="pipe">The pipe that yields the file bytes.</param>
    /// <returns>The parsed witness, which the caller disposes.</returns>
    private static RawR1csWitness ReadWitnessPipe(PipeReader pipe)
    {
        return CircomWitnessReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomWitness,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);
    }


    /// <summary>Parses fixture bytes as a BLS12-381 Circom R1CS instance.</summary>
    private static RawR1csInstance ReadR1csFixture(byte[] fixtureBytes)
    {
        var stream = new MemoryStream(fixtureBytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);

        return CircomR1csReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomBinary,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);
    }


    /// <summary>Reads the trailing signed integer from a canonical scalar whose fixture value fits in that integer width.</summary>
    private static int ReadBigEndianInt(ReadOnlySpan<byte> bytes)
    {
        //The scalar's value is small enough to fit in a 32-bit int —
        //the witness elements are 1, 33, 3, 11. The leading 28 bytes
        //are zeroes; we read only the trailing four-byte big-endian
        //tail.
        ReadOnlySpan<byte> tail = bytes[(bytes.Length - ScalarIntegerTailBytes)..];

        return BinaryPrimitives.ReadInt32BigEndian(tail);
    }


    /// <summary>Builds a standard Spartan prover with a commitment key sized for the fixture columns.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver via its constructor chain.")]
    private static SpartanProver BuildBaseProver(int columnCount)
    {
        int columnVariableCount = BitOperations.Log2((uint)columnCount);
        HyraxCommitmentDimensions commitmentDims = HyraxCommitmentDimensions.ForVariableCount(columnVariableCount);

        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            commitmentDims.ColumnCount,
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var provingKey = new SpartanProvingKey(BuildProvider(commitmentKey));

        return new SpartanProver(provingKey);
    }


    /// <summary>Builds a standard Spartan verifier with a commitment key sized for the fixture columns.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanVerifier via its constructor chain.")]
    private static SpartanVerifier BuildBaseVerifier(int columnCount)
    {
        int columnVariableCount = BitOperations.Log2((uint)columnCount);
        HyraxCommitmentDimensions commitmentDims = HyraxCommitmentDimensions.ForVariableCount(columnVariableCount);

        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            commitmentDims.ColumnCount,
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var verifyingKey = new SpartanVerifyingKey(BuildProvider(commitmentKey));

        return new SpartanVerifier(verifyingKey);
    }


    /// <summary>Builds a masked Spartan prover with enough commitment generators for the witness and statistical masks.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned MaskedSpartanProver via its constructor chain.")]
    private static MaskedSpartanProver BuildMaskedProver(int hyraxVectorLength)
    {
        //The statistical masks' single-row vector commitments need more
        //generators than the small witness matrix; flooring is byte-neutral
        //(generators derive per index from the seed).
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            Math.Max(hyraxVectorLength, Spartan.MaskedSpartanTestFixtures.MaskedVectorLengthFloor),
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var provingKey = new SpartanProvingKey(BuildProvider(commitmentKey));

        return new MaskedSpartanProver(provingKey);
    }


    /// <summary>Builds a masked Spartan verifier with enough commitment generators for the witness and statistical masks.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned MaskedSpartanVerifier via its constructor chain.")]
    private static MaskedSpartanVerifier BuildMaskedVerifier(int hyraxVectorLength)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            Math.Max(hyraxVectorLength, Spartan.MaskedSpartanTestFixtures.MaskedVectorLengthFloor),
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var verifyingKey = new SpartanVerifyingKey(BuildProvider(commitmentKey));

        return new MaskedSpartanVerifier(verifyingKey);
    }


    /// <summary>Creates the Hyrax commitment provider and transfers ownership of the supplied key to it.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey)
    {
        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            CurveParameterSet.Bls12Curve381,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup,
            ownsKey: true);
    }


    /// <summary>The BLAKE3 transcript hash backend used by the Spartan proofs.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The BLAKE3 transcript squeeze backend used by the Spartan proofs.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The BLS12-381 reference scalar reduction backend.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The BLS12-381 reference scalar addition backend.</summary>
    private static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();

    /// <summary>The BLS12-381 reference scalar subtraction backend.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Bls12Curve381BigIntegerScalarReference.GetSubtract();

    /// <summary>The BLS12-381 reference scalar multiplication backend.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();

    /// <summary>The BLS12-381 reference scalar inversion backend.</summary>
    private static ScalarInvertDelegate Invert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();

    /// <summary>The BLS12-381 reference random scalar backend.</summary>
    private static ScalarRandomDelegate ScalarRandom { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();

    /// <summary>The BLS12-381 reference G1 addition backend.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();

    /// <summary>The BLS12-381 reference G1 scalar multiplication backend.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>The BLS12-381 test G1 multiscalar multiplication backend.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;

    /// <summary>The BLS12-381 reference G1 curve membership backend.</summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();

    /// <summary>The BLS12-381 reference G1 prime-order subgroup membership backend.</summary>
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();

    /// <summary>The BLS12-381 reference hash-to-G1 backend for deriving commitment generators.</summary>
    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();

    /// <summary>The reference multilinear extension evaluation backend.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The reference multilinear extension folding backend.</summary>
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();


    /// <summary>Creates a fresh BLAKE3 transcript under the Spartan protocol domain.</summary>
    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }
}
