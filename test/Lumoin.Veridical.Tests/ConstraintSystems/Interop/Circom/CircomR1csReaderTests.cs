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
/// Conformance tests for the Circom <c>.r1cs</c> reader: structural
/// parse, error-path validation, and end-to-end prove-and-verify
/// against both the base and masked Spartan provers on the parsed
/// instance.
/// </summary>
[TestClass]
internal sealed class CircomR1csReaderTests
{
    /// <summary>The length of the ASCII <c>r1cs</c> magic that opens every <c>.r1cs</c> file.</summary>
    private const int MagicBytes = 4;

    /// <summary>The byte offset of the little-endian <c>version</c> field, which directly follows the magic.</summary>
    private const int VersionOffset = MagicBytes;

    /// <summary>The byte offset of the little-endian section count, which follows the <c>version</c> field.</summary>
    private const int SectionCountOffset = VersionOffset + sizeof(uint);

    /// <summary>The length of the file header: the magic, the 4-byte <c>version</c> field and the 4-byte section count.</summary>
    private const int FileHeaderBytes = SectionCountOffset + sizeof(uint);

    /// <summary>The length of the prefix every section carries: a 4-byte section type and an 8-byte payload size.</summary>
    private const int SectionPrefixBytes = sizeof(uint) + sizeof(ulong);

    /// <summary>The byte offset of the type field of the header section, which is the first section of the Multiplier2 fixture.</summary>
    private const int HeaderSectionTypeOffset = FileHeaderBytes;

    /// <summary>The byte offset of the 8-byte payload size field of the header section.</summary>
    private const int HeaderSectionSizeOffset = HeaderSectionTypeOffset + sizeof(uint);

    /// <summary>The byte offset of <c>field_size</c>, the first field of the header section payload.</summary>
    private const int FieldSizeOffset = FileHeaderBytes + SectionPrefixBytes;

    /// <summary>The number of 32-bit wire count fields in the header section payload: <c>nWires</c>, <c>nPubOut</c>, <c>nPubIn</c> and <c>nPrvIn</c>.</summary>
    private const int HeaderWireCountFieldCount = 4;

    /// <summary>
    /// The length of the header section payload: <c>field_size</c>, the 32-byte prime modulus, the four 32-bit wire
    /// counts, the 64-bit <c>nLabels</c> and the 32-bit <c>nConstraints</c>.
    /// </summary>
    private const int HeaderSectionPayloadBytes = sizeof(uint) + WellKnownCurves.Bls12Curve381ScalarSizeBytes + (HeaderWireCountFieldCount * sizeof(uint)) + sizeof(ulong) + sizeof(uint);

    /// <summary>The byte offset of the type field of the constraint section, which follows the header section payload.</summary>
    private const int ConstraintSectionTypeOffset = FieldSizeOffset + HeaderSectionPayloadBytes;

    /// <summary>The byte offset of the 8-byte payload size field of the constraint section.</summary>
    private const int ConstraintSectionSizeOffset = ConstraintSectionTypeOffset + sizeof(uint);

    /// <summary>The byte offset of the wire index of the first term of the first linear combination, which follows the 4-byte <c>nTerms</c> of that combination.</summary>
    private const int FirstTermWireIndexOffset = ConstraintSectionTypeOffset + SectionPrefixBytes + sizeof(uint);

    /// <summary>The only <c>.r1cs</c> file version the reader accepts.</summary>
    private const uint SupportedFileVersion = 1u;

    /// <summary>A <c>.r1cs</c> file version other than the supported one.</summary>
    private const uint UnsupportedFileVersion = 2u;

    /// <summary>A section type that is neither the header (type 1) nor the constraint section (type 2), so the reader reads past the section without interpreting it.</summary>
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

    /// <summary>A <c>field_size</c> of zero, which is not positive.</summary>
    private const uint ZeroFieldSize = 0u;

    /// <summary>A positive <c>field_size</c> not exceeding 256 that is not a multiple of 8.</summary>
    private const uint UnalignedFieldSize = 33u;

    /// <summary>A <c>field_size</c> that is a multiple of 8 but exceeds 256.</summary>
    private const uint OversizedFieldSize = 264u;

    /// <summary>A <c>field_size</c> that is a positive multiple of 8 not exceeding 256, yet narrower than the 32-byte BLS12-381 scalar.</summary>
    private const uint HalfWidthFieldSizeBytes = 16u;

    /// <summary>A header section payload size that covers <c>field_size</c> and none of the prime modulus after it.</summary>
    private const ulong FieldSizeOnlyHeaderPayloadBytes = sizeof(uint);

    /// <summary>A header count of zero, which the <c>nWires</c> and <c>nConstraints</c> checks reject.</summary>
    private const uint ZeroHeaderCount = 0u;

    /// <summary>The <c>nWires</c> the Multiplier2 fixture declares: the constant wire, <c>c</c>, <c>a</c> and <c>b</c>.</summary>
    private const uint Multiplier2WireCount = 4u;

    /// <summary>A wire index equal to <c>nWires</c>, the smallest index outside the wires of the Multiplier2 circuit.</summary>
    private const uint WireIndexAtWireCount = Multiplier2WireCount;

    /// <summary>The row index of the first constraint of the Multiplier2 fixture, <c>a * b = c</c>.</summary>
    private const int FirstConstraintRow = 0;

    /// <summary>The wire index the single A term of the first constraint names, wire <c>a</c>.</summary>
    private const uint FirstTermWireIndex = 2u;

    /// <summary>A section count that covers the header and constraint sections and leaves the trailing wire-to-label map section unread.</summary>
    private const uint HeaderAndConstraintSectionCount = 2u;

    /// <summary>A constraint section payload size that holds the <c>nTerms</c> count and the wire index of the first term, and none of its coefficient.</summary>
    private const ulong WireIndexOnlyConstraintPayloadBytes = sizeof(uint) + sizeof(uint);

    /// <summary>The number of constraints the Multiplier2 fixture declares: <c>a * b = c</c> and the padding constraint.</summary>
    private const int Multiplier2ConstraintCount = 2;

    /// <summary>The number of linear combinations every constraint carries: A, B and C.</summary>
    private const int LinearCombinationsPerConstraint = 3;

    /// <summary>The length of a single-term linear combination: the 4-byte <c>nTerms</c>, the 4-byte wire index and the 32-byte coefficient.</summary>
    private const int SingleTermLinearCombinationBytes = sizeof(uint) + sizeof(uint) + WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>The length of the constraint section payload of the Multiplier2 fixture, whose linear combinations all hold a single term.</summary>
    private const int Multiplier2ConstraintSectionPayloadBytes = Multiplier2ConstraintCount * LinearCombinationsPerConstraint * SingleTermLinearCombinationBytes;

    /// <summary>The length of the wire-to-label map section payload of the Multiplier2 fixture: one 8-byte label per wire.</summary>
    private const int Multiplier2LabelMapPayloadBytes = (int)Multiplier2WireCount * sizeof(ulong);

    /// <summary>The total length of the Multiplier2 fixture, which ends with the payload of its wire-to-label map section.</summary>
    private const int Multiplier2FileBytes = ConstraintSectionTypeOffset + SectionPrefixBytes + Multiplier2ConstraintSectionPayloadBytes + SectionPrefixBytes + Multiplier2LabelMapPayloadBytes;

    /// <summary>The zero-based position of the wire-to-label map section, the last of the three sections of the Multiplier2 fixture.</summary>
    private const uint LabelMapSectionIndex = 2u;

    /// <summary>The number of trailing bytes cut from the Multiplier2 fixture, so its wire-to-label map section runs past the end of the file.</summary>
    private const int CutTrailingBytes = 1;

    /// <summary>The number of bytes present when the input ends halfway through a 4-byte field.</summary>
    private const int UInt32FieldBytesPresent = 2;

    /// <summary>The number of bytes present when the input ends halfway through an 8-byte field.</summary>
    private const int UInt64FieldBytesPresent = 4;

    /// <summary>The offset of <c>field_size</c> within the header section payload.</summary>
    private const int FieldSizePayloadOffset = 0;

    /// <summary>The offset of <c>nWires</c> within the header section payload, after <c>field_size</c> and the 32-byte prime modulus.</summary>
    private const int NWiresPayloadOffset = sizeof(uint) + WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>The offset of <c>nPubOut</c> within the header section payload.</summary>
    private const int NPubOutPayloadOffset = NWiresPayloadOffset + sizeof(uint);

    /// <summary>The offset of <c>nPubIn</c> within the header section payload.</summary>
    private const int NPubInPayloadOffset = NPubOutPayloadOffset + sizeof(uint);

    /// <summary>The offset of <c>nPrvIn</c> within the header section payload.</summary>
    private const int NPrvInPayloadOffset = NPubInPayloadOffset + sizeof(uint);

    /// <summary>The offset of the 8-byte <c>nLabels</c> within the header section payload.</summary>
    private const int NLabelsPayloadOffset = NPrvInPayloadOffset + sizeof(uint);

    /// <summary>The offset of <c>nConstraints</c> within the header section payload, after the 8-byte <c>nLabels</c>.</summary>
    private const int NConstraintsPayloadOffset = NLabelsPayloadOffset + sizeof(ulong);

    /// <summary>The byte offset of <c>nPubIn</c> in the file.</summary>
    private const int NPubInOffset = FieldSizeOffset + NPubInPayloadOffset;

    /// <summary>The <c>nPubOut</c> the Multiplier2 fixture declares: the output wire <c>c</c>.</summary>
    private const uint Multiplier2PublicOutputCount = 1u;

    /// <summary>The <c>nPrvIn</c> the Multiplier2 fixture declares: the input wires <c>a</c> and <c>b</c>.</summary>
    private const uint Multiplier2PrivateInputCount = 2u;

    /// <summary>
    /// An <c>nPubIn</c> of one, which together with the one public output, the two private inputs and the constant wire of
    /// the fixture accounts for five wires, one more than the four the header declares.
    /// </summary>
    private const uint OverstatedPublicInputCount = 1u;

    /// <summary>The byte offset of the first magic byte, the ASCII <c>r</c>.</summary>
    private const int MagicLeadByteOffset = 0;

    /// <summary>A byte written over the leading ASCII <c>r</c>, turning the magic into ASCII <c>x1cs</c>.</summary>
    private const byte ForeignMagicLeadByte = (byte)'x';

    /// <summary>The upper-case hex of the ASCII <c>x1cs</c> magic, as the reader reports the bytes it found.</summary>
    private const string ForeignMagicHex = "78316373";

    /// <summary>The largest <c>field_size</c> the shape check admits, a multiple of 8 equal to the 256 bound and wider than the 32-byte BLS12-381 scalar.</summary>
    private const uint LargestShapeValidFieldSize = 256u;

    /// <summary>The byte offset of the most significant byte of the little-endian prime modulus, the last byte before <c>nWires</c>.</summary>
    private const int PrimeMostSignificantByteOffset = FieldSizeOffset + sizeof(uint) + WellKnownCurves.Bls12Curve381ScalarSizeBytes - sizeof(byte);

    /// <summary>The top bit of a byte; set in the most significant prime byte it makes the declared modulus exceed 2^255.</summary>
    private const byte TopBitMask = 0x80;

    /// <summary>The BLS12-381 scalar field order as lower-case big-endian hex, the modulus the reader expects for that curve.</summary>
    private const string Bls12Curve381ScalarFieldModulusHex = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

    /// <summary>
    /// The BLS12-381 scalar field order with its top bit set, as lower-case big-endian hex. The hex form of a positive
    /// integer whose leading digit is 8 or above carries a leading zero, which tells it apart from a negative value.
    /// </summary>
    private const string TopBitSetModulusHex = "0f3eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

    /// <summary>A header count above <see cref="int.MaxValue"/>, which the <c>nWires</c> and <c>nConstraints</c> range checks reject.</summary>
    private const uint HeaderCountAboveInt32Range = uint.MaxValue;

    /// <summary>The largest header count the <c>nWires</c> and <c>nConstraints</c> range checks admit.</summary>
    private const uint LargestAdmittedHeaderCount = int.MaxValue;

    /// <summary>The number of bytes left in the constraint section once the two constraints the fixture stores have been read.</summary>
    private const int ExhaustedBytesRemaining = 0;

    /// <summary>A constraint section payload size that holds the <c>nTerms</c> count of the first linear combination and half of the wire index of its first term.</summary>
    private const ulong WireIndexTruncatedConstraintPayloadBytes = sizeof(uint) + UInt32FieldBytesPresent;

    /// <summary>The index of the first stored triple of a matrix.</summary>
    private const int FirstTripleIndex = 0;

    /// <summary>The number of further file bytes each read of the chunked pipe uncovers, so the 384-byte fixture arrives over three reads.</summary>
    private const int DeliveryChunkBytes = 128;


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


    [TestMethod]
    public void Multiplier2R1csParsesIntoExpectedShape()
    {
        using RawR1csInstance instance = ReadFixture(CircomR1csFixtures.Multiplier2Bytes);

        //Multiplier2 (padded): 2 constraints, 4 variables, no public
        //inputs in the Veridical sense (all wires routed into the
        //witness — see CircomR1csReader's remarks on the public-input
        //convention).
        Assert.AreEqual(2, instance.A.RowCount, "A.RowCount");
        Assert.AreEqual(2, instance.B.RowCount, "B.RowCount");
        Assert.AreEqual(2, instance.C.RowCount, "C.RowCount");

        Assert.AreEqual(4, instance.A.ColumnCount, "A.ColumnCount");
        Assert.AreEqual(4, instance.B.ColumnCount, "B.ColumnCount");
        Assert.AreEqual(4, instance.C.ColumnCount, "C.ColumnCount");

        Assert.AreEqual(0, instance.PublicInputCount, "PublicInputCount");

        //Each matrix has exactly 2 non-zeros: one per constraint row.
        Assert.AreEqual(2, instance.A.NonzeroCount, "A.NonzeroCount");
        Assert.AreEqual(2, instance.B.NonzeroCount, "B.NonzeroCount");
        Assert.AreEqual(2, instance.C.NonzeroCount, "C.NonzeroCount");

        //Triples — C0: a*b=c, C1: 1*1=1 padding.
        (int aRow0, int aCol0) = instance.A.GetTriplePosition(0);
        (int aRow1, int aCol1) = instance.A.GetTriplePosition(1);
        Assert.AreEqual((0, 2), (aRow0, aCol0), "A[0] expected at constraint 0, wire 2 (a)");
        Assert.AreEqual((1, 0), (aRow1, aCol1), "A[1] expected at padding constraint, constant wire");

        (int bRow0, int bCol0) = instance.B.GetTriplePosition(0);
        (int cRow0, int cCol0) = instance.C.GetTriplePosition(0);
        Assert.AreEqual((0, 3), (bRow0, bCol0), "B[0] expected at constraint 0, wire 3 (b)");
        Assert.AreEqual((0, 1), (cRow0, cCol0), "C[0] expected at constraint 0, wire 1 (c)");
    }


    //The .r1cs header section stores nWires as a little-endian uint32 at byte offset 60
    //(12 file header + 12 section header + 4 field_size + 32 prime) and nConstraints at
    //offset 84. Both are attacker-controlled; a value above int.MaxValue must be rejected
    //as malformed rather than overflow the checked (int) cast during construction. Offsets
    //are the ones a fuzz sweep of this committed fixture triggered the overflow through.
    private const int NWiresLittleEndianOffset = 60;
    private const int NConstraintsLittleEndianOffset = 84;


    [TestMethod]
    [DataRow(NWiresLittleEndianOffset)]
    [DataRow(NConstraintsLittleEndianOffset)]
    public void R1csRejectsHeaderCountAboveInt32Range(int littleEndianOffset)
    {
        //Sanity: the untampered fixture parses, so the single tamper below is the only
        //change under test (and a fixture drift that moved the field would fail loudly here).
        using(RawR1csInstance _ = ReadFixture(CircomR1csFixtures.Multiplier2Bytes))
        {
        }

        byte[] tampered = CircomR1csFixtures.Multiplier2Bytes;
        BinaryPrimitives.WriteUInt32LittleEndian(tampered.AsSpan(littleEndianOffset, sizeof(uint)), uint.MaxValue);

        //Before the upper-bound guard this surfaced as an OverflowException from the
        //checked (int) cast; ThrowsExactly<ArgumentException> pins the documented rejection.
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance _ = ReadFixture(tampered);
        });
    }


    [TestMethod]
    public void Multiplier2R1csRejectsWrongFormatLabel()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance _ = ReadFixture(
                CircomR1csFixtures.Multiplier2Bytes,
                WellKnownR1csFormatLabel.CircomWitness);
        });
    }


    [TestMethod]
    public void Multiplier2R1csRejectsWrongMagic()
    {
        byte[] mutated = (byte[])CircomR1csFixtures.Multiplier2Bytes.Clone();
        mutated[0] = (byte)'x'; //corrupt the 'r' of "r1cs"

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance _ = ReadFixture(mutated);
        });
    }


    [TestMethod]
    public void Multiplier2R1csRejectsBn254Field()
    {
        //Construct a header with BN254's scalar prime in place of
        //BLS12-381's. BN254 r =
        //  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
        byte[] bn254FieldFixture = MutatePrimeBytes(
            CircomR1csFixtures.Multiplier2Bytes,
            replacementPrimeBigEndianHex:
                "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");

        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() =>
        {
            using RawR1csInstance _ = ReadFixture(bn254FieldFixture);
        });
    }


    [TestMethod]
    public void Multiplier2R1csRejectsTruncatedFile()
    {
        //Cut the fixture in half — guaranteed to land mid-section.
        byte[] full = CircomR1csFixtures.Multiplier2Bytes;
        byte[] truncated = full.AsSpan(0, full.Length / 2).ToArray();

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance _ = ReadFixture(truncated);
        });
    }


    /// <summary>
    /// An input shorter than the 4-byte magic is rejected by the magic length check with an
    /// <see cref="ArgumentException"/> that names the magic, before any cursor advance can run past the input.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsInputShorterThanMagic()
    {
        Memory<byte> file = RentFixtureCopy();

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file[..MagicBytesPresent]);
        });

        Assert.Contains($"shorter than the {MagicBytes}-byte magic.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A file that ends inside the 4-byte <c>version</c> field is rejected by the 32-bit field read with an
    /// <see cref="ArgumentException"/> that names the field, its width and the number of bytes left.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsTruncationInsideVersionField()
    {
        Memory<byte> file = RentFixtureCopy();

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file[..VersionTruncatedLength]);
        });

        Assert.Contains($"truncated while reading version ({sizeof(uint)} bytes); only {VersionBytesPresent} bytes remained.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// An otherwise valid file that declares a version other than the supported one is rejected with an
    /// <see cref="ArgumentException"/> naming both the supported and the declared version, rather than parsed.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsUnsupportedVersion()
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[VersionOffset..], UnsupportedFileVersion);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"supports only .r1cs file version {SupportedFileVersion}; file declares version {UnsupportedFileVersion}.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A file that ends inside the 8-byte payload size field of its first section is rejected by the 64-bit
    /// field read with an <see cref="ArgumentException"/> that names the field, its width and the number of bytes left.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsTruncationInsideSectionSizeField()
    {
        Memory<byte> file = RentFixtureCopy();

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file[..SectionSizeTruncatedLength]);
        });

        Assert.Contains($"truncated while reading section size ({sizeof(ulong)} bytes); only {SectionSizeBytesPresent} bytes remained.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A file whose header section is retagged to an unknown section type has that section read past, and is
    /// then rejected with an <see cref="ArgumentException"/> reporting the missing header section, rather than
    /// failing on the absent header values while the constraint section is still present.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsMissingHeaderSection()
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[HeaderSectionTypeOffset..], UnknownSectionType);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains("missing the header section (type 1).", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A file with a valid header section whose constraint section is retagged to an unknown section type is
    /// rejected with an <see cref="ArgumentException"/> reporting the missing constraint section, rather than
    /// failing on the absent constraint payload.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsMissingConstraintSection()
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[ConstraintSectionTypeOffset..], UnknownSectionType);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains("missing the constraint section (type 2).", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header declaring a <c>field_size</c> that is zero, not a multiple of 8, or above 256 is rejected by the
    /// field size shape check, whose message states the positive-multiple-of-8 rule, before the comparison against
    /// the curve scalar width runs.
    /// </summary>
    /// <param name="fieldSize">The <c>field_size</c> written over the one the fixture declares.</param>
    [TestMethod]
    [DataRow(ZeroFieldSize)]
    [DataRow(UnalignedFieldSize)]
    [DataRow(OversizedFieldSize)]
    public void Multiplier2R1csRejectsFieldSizeOutsideByteAlignedRange(uint fieldSize)
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[FieldSizeOffset..], fieldSize);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"field_size = {fieldSize}; must be a positive multiple of 8 not exceeding 256.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header declaring a well-shaped <c>field_size</c> that differs from the 32-byte scalar width of the curve
    /// is rejected with an <see cref="ArgumentException"/> naming the declared and the expected width, rather
    /// than parsed at the curve width.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsFieldSizeNotMatchingCurveWidth()
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[FieldSizeOffset..], HalfWidthFieldSizeBytes);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"field_size = {HalfWidthFieldSizeBytes} bytes but curve", exception.Message, StringComparison.Ordinal);
        Assert.Contains($"expects {WellKnownCurves.Bls12Curve381ScalarSizeBytes} bytes per scalar.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header section whose declared payload covers only <c>field_size</c> is rejected when the prime modulus
    /// read runs past the payload, with an <see cref="ArgumentException"/> naming the prime modulus and its width.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsHeaderSectionTooShortForPrime()
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt64LittleEndian(file.Span[HeaderSectionSizeOffset..], FieldSizeOnlyHeaderPayloadBytes);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"truncated while reading the prime modulus ({WellKnownCurves.Bls12Curve381ScalarSizeBytes} bytes).", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header declaring <c>nWires = 0</c> is rejected by the zero wire count check, whose message states that a
    /// circuit holds at least the constant wire, before the public and private input counts are compared against it.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsZeroWireCount()
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[NWiresLittleEndianOffset..], ZeroHeaderCount);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"nWires = {ZeroHeaderCount}; circuits must have at least the constant wire.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header declaring <c>nConstraints = 0</c> is rejected by the zero constraint count check, whose message
    /// states that the constraint section is mandatory, rather than the constraint section being read as trailing bytes.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsZeroConstraintCount()
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[NConstraintsLittleEndianOffset..], ZeroHeaderCount);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"nConstraints = {ZeroHeaderCount}; constraint section is mandatory.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A linear-combination term naming a wire index equal to <c>nWires</c> is rejected by the wire range check of
    /// the reader with an <see cref="ArgumentException"/> naming the constraint row, the wire and the wire count,
    /// rather than surfacing later from matrix construction.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsWireIndexAtWireCount()
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[FirstTermWireIndexOffset..], WireIndexAtWireCount);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"Constraint row {FirstConstraintRow} references wire {WireIndexAtWireCount} but the circuit has only {Multiplier2WireCount} wires.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A constraint section whose declared payload ends after the wire index of its first term is rejected when the
    /// coefficient read runs past the payload, with an <see cref="ArgumentException"/> naming the constraint row and
    /// the wire. The section count is lowered to two so the bytes after the shortened payload are not read as a
    /// further section.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsConstraintSectionTooShortForCoefficient()
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[SectionCountOffset..], HeaderAndConstraintSectionCount);
        BinaryPrimitives.WriteUInt64LittleEndian(file.Span[ConstraintSectionSizeOffset..], WireIndexOnlyConstraintPayloadBytes);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"truncated while reading coefficient at constraint {FirstConstraintRow}, wire {FirstTermWireIndex}.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A read cancelled through <see cref="PipeReader.CancelPendingRead"/> surfaces as
    /// <see cref="OperationCanceledException"/> instead of the buffered file being parsed into an instance.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csReadSurfacesPendingReadCancellation()
    {
        Memory<byte> file = RentFixtureCopy();
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(file));
        pipe.CancelPendingRead();

        Assert.ThrowsExactly<OperationCanceledException>(() =>
        {
            using RawR1csInstance parsed = ReadPipe(pipe);
        });
    }


    /// <summary>
    /// A null pipe is rejected by the reader's own argument check with an <see cref="ArgumentNullException"/> naming
    /// the pipe, rather than failing with a dereference when the pipe is drained.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsNullPipe()
    {
        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            using RawR1csInstance parsed = CircomR1csReader.Reader(
                null!,
                WellKnownR1csFormatLabel.CircomBinary,
                CurveParameterSet.Bls12Curve381,
                BaseMemoryPool.Shared,
                CancellationToken.None);
        });

        Assert.AreEqual("pipe", exception.ParamName);
    }


    /// <summary>
    /// A null pool is rejected with an <see cref="ArgumentNullException"/> naming the pool before the pipe is read at
    /// all, so a well-formed file is not drained and parsed only to fail when the first matrix is built.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsNullPoolBeforeReadingThePipe()
    {
        Memory<byte> file = RentFixtureCopy();
        StrictChunkedPipeReader pipe = new(file, Multiplier2FileBytes);

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            using RawR1csInstance parsed = CircomR1csReader.Reader(
                pipe,
                WellKnownR1csFormatLabel.CircomBinary,
                CurveParameterSet.Bls12Curve381,
                null!,
                CancellationToken.None);
        });

        Assert.AreEqual("pool", exception.ParamName);
        Assert.IsFalse(pipe.HasBeenRead, "The pool check must reject the call before the pipe is read.");
    }


    /// <summary>
    /// A format label other than the Circom binary label is rejected with an <see cref="ArgumentException"/> on the
    /// format parameter whose message names the accepted label and the label received.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsWrongFormatLabelNamingTheReceivedLabel()
    {
        Memory<byte> file = RentFixtureCopy();
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(file));

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = CircomR1csReader.Reader(
                pipe,
                WellKnownR1csFormatLabel.CircomWitness,
                CurveParameterSet.Bls12Curve381,
                BaseMemoryPool.Shared,
                CancellationToken.None);
        });

        Assert.AreEqual("format", exception.ParamName);
        Assert.Contains($"handles only WellKnownR1csFormatLabel.CircomBinary; received '{WellKnownR1csFormatLabel.CircomWitness.Identifier}'.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A curve without reference support is rejected by the wired-curve gate, whose message lists the wired curves,
    /// before the file is parsed and the scalar width lookup could reject the curve on its own terms.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsUnwiredCurveBeforeParsing()
    {
        Memory<byte> file = RentFixtureCopy();
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(file));

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = CircomR1csReader.Reader(
                pipe,
                WellKnownR1csFormatLabel.CircomBinary,
                CurveParameterSet.P256,
                BaseMemoryPool.Shared,
                CancellationToken.None);
        });

        Assert.AreEqual("curve", exception.ParamName);
        Assert.Contains("is not wired; the wired curves are Bls12Curve381 and Bn254.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A successful read advances the pipe past every byte of the file, so the caller's pipe does not still hold the
    /// parsed file as unread input.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csReadConsumesTheWholeFile()
    {
        Memory<byte> file = RentFixtureCopy();
        StrictChunkedPipeReader pipe = new(file, Multiplier2FileBytes);

        using RawR1csInstance instance = ReadPipe(pipe);

        Assert.AreEqual(Multiplier2ConstraintCount, instance.A.RowCount);
        Assert.AreEqual(Multiplier2FileBytes, pipe.ConsumedBytes);
    }


    /// <summary>
    /// A file that arrives over several reads is drained until the pipe reports completion, advancing past each partial
    /// buffer before reading again and stopping at the completed read, and then parses into the same shape as a file
    /// that arrives in one read.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csParsesAFileDeliveredInChunks()
    {
        Memory<byte> file = RentFixtureCopy();
        StrictChunkedPipeReader pipe = new(file, DeliveryChunkBytes);

        using RawR1csInstance instance = ReadPipe(pipe);

        Assert.AreEqual(Multiplier2ConstraintCount, instance.A.RowCount);
        Assert.AreEqual((int)Multiplier2WireCount, instance.A.ColumnCount);
        Assert.AreEqual((FirstConstraintRow, (int)FirstTermWireIndex), instance.A.GetTriplePosition(FirstTripleIndex));
    }


    /// <summary>
    /// A file that ends halfway through the 4-byte section count, or through the 4-byte type field of its first section,
    /// is rejected by the 32-bit field read with an <see cref="ArgumentException"/> that names that field, its width and
    /// the number of bytes left.
    /// </summary>
    /// <param name="fieldOffset">The byte offset of the field the file ends inside.</param>
    /// <param name="fieldName">The field name the reader reports.</param>
    [TestMethod]
    [DataRow(SectionCountOffset, "section count")]
    [DataRow(HeaderSectionTypeOffset, "section type")]
    public void Multiplier2R1csRejectsFileEndingInsideSectionField(int fieldOffset, string fieldName)
    {
        Memory<byte> file = RentFixtureCopy();

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file[..(fieldOffset + UInt32FieldBytesPresent)]);
        });

        Assert.Contains($"truncated while reading {fieldName} ({sizeof(uint)} bytes); only {UInt32FieldBytesPresent} bytes remained.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A file cut one byte short of its wire-to-label map section is rejected by the section length check with an
    /// <see cref="ArgumentException"/> naming the section, its declared size and the bytes actually left in the file.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsSectionLongerThanTheRemainingFile()
    {
        Memory<byte> file = RentFixtureCopy();

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file[..(Multiplier2FileBytes - CutTrailingBytes)]);
        });

        Assert.Contains($"Section {LabelMapSectionIndex} declares size {Multiplier2LabelMapPayloadBytes} bytes but only {Multiplier2LabelMapPayloadBytes - CutTrailingBytes} bytes remain in the file.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A file whose magic is not ASCII <c>r1cs</c> is rejected with an <see cref="ArgumentException"/> whose message
    /// gives the expected magic and the hex of the four bytes found in its place.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsWrongMagicNamingTheFoundBytes()
    {
        Memory<byte> file = RentFixtureCopy();
        file.Span[MagicLeadByteOffset] = ForeignMagicLeadByte;

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"magic mismatch. Expected ASCII 'r1cs' (72 31 63 73); found {ForeignMagicHex}.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header section whose declared payload ends halfway through one of its fields is rejected by the field read over
    /// that payload, with an <see cref="ArgumentException"/> naming the header field, its width and the bytes left.
    /// </summary>
    /// <param name="fieldPayloadOffset">The offset within the header section payload of the field the payload ends inside.</param>
    /// <param name="fieldName">The header field name the reader reports.</param>
    /// <param name="fieldWidthBytes">The width of the field.</param>
    /// <param name="bytesPresent">The number of field bytes the shortened payload still holds.</param>
    [TestMethod]
    [DataRow(FieldSizePayloadOffset, "header.fieldSize", sizeof(uint), UInt32FieldBytesPresent)]
    [DataRow(NWiresPayloadOffset, "header.nWires", sizeof(uint), UInt32FieldBytesPresent)]
    [DataRow(NPubOutPayloadOffset, "header.nPubOut", sizeof(uint), UInt32FieldBytesPresent)]
    [DataRow(NPubInPayloadOffset, "header.nPubIn", sizeof(uint), UInt32FieldBytesPresent)]
    [DataRow(NPrvInPayloadOffset, "header.nPrvIn", sizeof(uint), UInt32FieldBytesPresent)]
    [DataRow(NLabelsPayloadOffset, "header.nLabels", sizeof(ulong), UInt64FieldBytesPresent)]
    [DataRow(NConstraintsPayloadOffset, "header.nConstraints", sizeof(uint), UInt32FieldBytesPresent)]
    public void Multiplier2R1csRejectsHeaderSectionEndingInsideField(int fieldPayloadOffset, string fieldName, int fieldWidthBytes, int bytesPresent)
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt64LittleEndian(file.Span[HeaderSectionSizeOffset..], (ulong)(fieldPayloadOffset + bytesPresent));

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"truncated while reading {fieldName} ({fieldWidthBytes} bytes); only {bytesPresent} bytes remained.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header declaring <c>field_size = 256</c> passes the shape check, since the bound is inclusive, and is then
    /// rejected only because it differs from the 32-byte scalar width of the curve.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsLargestShapeValidFieldSizeOnCurveWidth()
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[FieldSizeOffset..], LargestShapeValidFieldSize);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"field_size = {LargestShapeValidFieldSize} bytes but curve", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A prime modulus with its top bit set is read as an unsigned integer and rejected with an
    /// <see cref="R1csUnsupportedFieldException"/> that carries both the expected and the found modulus as
    /// lower-case hex, the found one positive and therefore written with its leading zero.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csReportsExpectedAndFoundModulusAsUnsignedHex()
    {
        Memory<byte> file = RentFixtureCopy();
        file.Span[PrimeMostSignificantByteOffset] |= TopBitMask;

        R1csUnsupportedFieldException exception = Assert.ThrowsExactly<R1csUnsupportedFieldException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.AreEqual(Bls12Curve381ScalarFieldModulusHex, exception.ExpectedModulusHex);
        Assert.AreEqual(TopBitSetModulusHex, exception.FoundModulusHex);
    }


    /// <summary>
    /// A header declaring <c>nWires</c> or <c>nConstraints</c> above <see cref="int.MaxValue"/> is rejected by the range
    /// check of that count, whose message names the count, the declared value and the largest supported value.
    /// </summary>
    /// <param name="littleEndianOffset">The byte offset of the count written over the one the fixture declares.</param>
    /// <param name="countName">The header field name the reader reports.</param>
    /// <param name="countNoun">The noun the reader uses for what the field counts.</param>
    [TestMethod]
    [DataRow(NWiresLittleEndianOffset, "nWires", "wire")]
    [DataRow(NConstraintsLittleEndianOffset, "nConstraints", "constraint")]
    public void Multiplier2R1csRejectsHeaderCountAboveInt32RangeNamingTheCount(int littleEndianOffset, string countName, string countNoun)
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[littleEndianOffset..], HeaderCountAboveInt32Range);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"declares {countName} = {HeaderCountAboveInt32Range}, exceeding the maximum supported {countNoun} count ({int.MaxValue}).", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header declaring <c>nWires</c> and <c>nConstraints</c> of exactly <see cref="int.MaxValue"/> passes both range
    /// checks, whose bounds are inclusive. The parse then reads the two constraints the file stores and is rejected when
    /// the term count of the third runs past the end of the constraint section, before any buffer is sized by either count.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csAdmitsHeaderCountsAtInt32MaxPastTheRangeChecks()
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[NWiresLittleEndianOffset..], LargestAdmittedHeaderCount);
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[NConstraintsLittleEndianOffset..], LargestAdmittedHeaderCount);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"truncated while reading linearCombination.nTerms ({sizeof(uint)} bytes); only {ExhaustedBytesRemaining} bytes remained.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A header whose public outputs, public inputs, private inputs and constant wire add up to one more than
    /// <c>nWires</c> is rejected by the header consistency check with a message giving each count. One wire over is the
    /// smallest overstatement the check must catch, so every count and the constant wire must add into the sum.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsWireCountsOneBeyondNWires()
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[NPubInOffset..], OverstatedPublicInputCount);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"inconsistency: nPubOut ({Multiplier2PublicOutputCount}) + nPubIn ({OverstatedPublicInputCount}) + nPrvIn ({Multiplier2PrivateInputCount}) + 1 (constant) exceeds nWires ({Multiplier2WireCount}).", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A constraint section whose declared payload ends halfway through the wire index of its first term is rejected by
    /// the 32-bit field read with an <see cref="ArgumentException"/> naming the wire index field and the bytes left. The
    /// section count is lowered to two so the bytes after the shortened payload are not read as a further section.
    /// </summary>
    [TestMethod]
    public void Multiplier2R1csRejectsConstraintSectionEndingInsideWireIndex()
    {
        Memory<byte> file = RentFixtureCopy();
        BinaryPrimitives.WriteUInt32LittleEndian(file.Span[SectionCountOffset..], HeaderAndConstraintSectionCount);
        BinaryPrimitives.WriteUInt64LittleEndian(file.Span[ConstraintSectionSizeOffset..], WireIndexTruncatedConstraintPayloadBytes);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance parsed = ReadMemory(file);
        });

        Assert.Contains($"truncated while reading linearCombination.wireIndex ({sizeof(uint)} bytes); only {UInt32FieldBytesPresent} bytes remained.", exception.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void Multiplier2R1csParsedInstanceProvesAndVerifiesWithStandardSpartan()
    {
        //Build proving + verifying keys against the parsed instance,
        //feed a satisfying witness (a=3, b=11, c=33), prove with the
        //base Spartan prover, verify with the base Spartan verifier.
        const int rowCount = 2;
        const int columnCount = 4;

        using RawR1csWitness witness = BuildMultiplier2Witness();

        using SpartanProver prover = BuildBaseProver(rowCount, columnCount);
        using SpartanVerifier verifier = BuildBaseVerifier(rowCount, columnCount);

        using RawR1csInstance proverInstance = ReadFixture(CircomR1csFixtures.Multiplier2Bytes);
        using RawR1csInstance verifierInstance = ReadFixture(CircomR1csFixtures.Multiplier2Bytes);

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

        Assert.IsTrue(verified, "Base Spartan failed to verify a Circom-parsed multiplier2 instance.");
    }


    [TestMethod]
    public void Multiplier2R1csParsedInstanceProvesAndVerifiesWithMaskedSpartan()
    {
        const int hyraxVectorLength = 2;

        using RawR1csWitness witness = BuildMultiplier2Witness();

        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength);
        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(hyraxVectorLength);

        using RawR1csInstance proverInstance = ReadFixture(CircomR1csFixtures.Multiplier2Bytes);
        using RawR1csInstance verifierInstance = ReadFixture(CircomR1csFixtures.Multiplier2Bytes);

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

        Assert.IsTrue(verified, "Masked Spartan failed to verify a Circom-parsed multiplier2 instance.");
    }


    private static RawR1csInstance ReadFixture(byte[] fixtureBytes) =>
        ReadFixture(fixtureBytes, WellKnownR1csFormatLabel.CircomBinary);


    private static RawR1csInstance ReadFixture(byte[] fixtureBytes, WellKnownR1csFormatLabel format)
    {
        var stream = new MemoryStream(fixtureBytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);
        return CircomR1csReader.Reader(
            pipe,
            format,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            CancellationToken.None);
    }


    /// <summary>
    /// Rents a pooled buffer, tracks it for cleanup and copies the Multiplier2 fixture into it, so a test can
    /// overwrite a field, or cut the file short by slicing, without touching the fixture itself.
    /// </summary>
    /// <returns>The pooled copy, exactly as long as the fixture.</returns>
    private Memory<byte> RentFixtureCopy()
    {
        byte[] fixture = CircomR1csFixtures.Multiplier2Bytes;
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(fixture.Length);
        Disposables.Add(owner);

        Memory<byte> file = owner.Memory[..fixture.Length];
        fixture.CopyTo(file.Span);

        return file;
    }


    /// <summary>Runs the <c>.r1cs</c> reader for BLS12-381 over complete in-memory file bytes.</summary>
    /// <param name="file">The file bytes the pipe yields before it reports completion.</param>
    /// <returns>The parsed instance, which the caller disposes.</returns>
    private static RawR1csInstance ReadMemory(ReadOnlyMemory<byte> file)
    {
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(file));

        return ReadPipe(pipe);
    }


    /// <summary>Runs the <c>.r1cs</c> reader for BLS12-381 over the supplied pipe.</summary>
    /// <param name="pipe">The pipe carrying the file bytes.</param>
    /// <returns>The parsed instance, which the caller disposes.</returns>
    private static RawR1csInstance ReadPipe(PipeReader pipe)
    {
        return CircomR1csReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomBinary,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            CancellationToken.None);
    }


    /// <summary>
    /// Returns a copy of <paramref name="fixtureBytes"/> with the
    /// header section's prime modulus (32 little-endian bytes at offset
    /// <c>20</c>: 12 file header + 12 section header + 4 field_size)
    /// replaced by the bytes of <paramref name="replacementPrimeBigEndianHex"/>
    /// (reversed to little-endian on the way in).
    /// </summary>
    private static byte[] MutatePrimeBytes(byte[] fixtureBytes, string replacementPrimeBigEndianHex)
    {
        const int primeOffset = 12 + 12 + 4;
        byte[] mutated = (byte[])fixtureBytes.Clone();
        byte[] replacementBe = Convert.FromHexString(replacementPrimeBigEndianHex);
        //File stores prime little-endian; reverse on the way in.
        for(int i = 0; i < replacementBe.Length; i++)
        {
            mutated[primeOffset + i] = replacementBe[replacementBe.Length - 1 - i];
        }

        return mutated;
    }


    private static RawR1csWitness BuildMultiplier2Witness()
    {
        //z = (1, c, a, b) = (1, 33, 3, 11) — satisfies a * b = c with
        //a = 3, b = 11. PublicInputCount = 0 means z[1..] is the
        //entire witness, in Veridical order matching Circom's wire
        //ordering.
        int scalarSize = WellKnownCurves.Bls12Curve381ScalarSizeBytes;
        byte[] witnessBytes = new byte[3 * scalarSize];
        WriteCanonical(new BigInteger(33), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(11), witnessBytes.AsSpan(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver via its constructor chain.")]
    private static SpartanProver BuildBaseProver(int rowCount, int columnCount)
    {
        using(RawR1csInstance instance = ReadFixture(CircomR1csFixtures.Multiplier2Bytes))
        {
            Assert.AreEqual(rowCount, instance.A.RowCount);
            Assert.AreEqual(columnCount, instance.A.ColumnCount);
        }

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


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanVerifier via its constructor chain.")]
    private static SpartanVerifier BuildBaseVerifier(int rowCount, int columnCount)
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


    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static ScalarSubtractDelegate Subtract { get; } = Bls12Curve381BigIntegerScalarReference.GetSubtract();
    private static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    private static ScalarInvertDelegate Invert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();
    private static ScalarRandomDelegate ScalarRandom { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();
    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
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