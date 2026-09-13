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
    public void Multiplier2WitnessParsesIntoExpectedValues()
    {
        using RawR1csWitness witness = ReadWitnessFixture(CircomWitnessFixtures.Multiplier2Bytes);

        //RawR1csWitness contains z[1..nWitness] = (c, a, b) = (33, 3, 11)
        //in canonical big-endian, 32 bytes each. (The constant z[0] = 1
        //is dropped by the reader per the CircomWitnessReader convention.)
        Assert.AreEqual(3, witness.WitnessVariableCount);

        ReadOnlySpan<byte> bytes = witness.GetWitnessBytes();
        int scalarSize = WellKnownCurves.Bls12Curve381ScalarSizeBytes;
        Assert.HasCount(3 * scalarSize, bytes);

        Assert.AreEqual(33, ReadBigEndianInt(bytes.Slice(0 * scalarSize, scalarSize)));
        Assert.AreEqual(3, ReadBigEndianInt(bytes.Slice(1 * scalarSize, scalarSize)));
        Assert.AreEqual(11, ReadBigEndianInt(bytes.Slice(2 * scalarSize, scalarSize)));
    }


    [TestMethod]
    public void Multiplier2WitnessRejectsWrongFormatLabel()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness _ = ReadWitnessFixture(
                CircomWitnessFixtures.Multiplier2Bytes,
                WellKnownR1csFormatLabel.CircomBinary);
        });
    }


    [TestMethod]
    public void Multiplier2WitnessRejectsWrongMagic()
    {
        byte[] mutated = (byte[])CircomWitnessFixtures.Multiplier2Bytes.Clone();
        mutated[0] = (byte)'x';

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness _ = ReadWitnessFixture(mutated);
        });
    }


    [TestMethod]
    public void Multiplier2WitnessRejectsBn254Field()
    {
        //Same prime-mutation pattern as the .r1cs test; the prime sits
        //at offset 12 (file header) + 12 (section header) + 4 (field_size) = 28.
        const int primeOffset = 12 + 12 + 4;
        byte[] mutated = (byte[])CircomWitnessFixtures.Multiplier2Bytes.Clone();
        byte[] bn254Be = Convert.FromHexString(
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
        for(int i = 0; i < bn254Be.Length; i++)
        {
            mutated[primeOffset + i] = bn254Be[bn254Be.Length - 1 - i];
        }

        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() =>
        {
            using RawR1csWitness _ = ReadWitnessFixture(mutated);
        });
    }


    [TestMethod]
    public void Multiplier2WitnessRejectsTruncatedFile()
    {
        byte[] full = CircomWitnessFixtures.Multiplier2Bytes;
        byte[] truncated = full.AsSpan(0, full.Length / 2).ToArray();

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness _ = ReadWitnessFixture(truncated);
        });
    }


    [TestMethod]
    public void Multiplier2WitnessRejectsNWitnessAboveAddressableRange()
    {
        //nWitness sits at file header (12) + section header (12) + field_size (4) + prime (32) = 60.
        //A declared nWitness whose (nWitness - 1) * 32-byte dense vector exceeds the maximum array
        //size is rejected at header parse with the reader's documented ArgumentException, not an
        //OverflowException from the allocation. Asserting the guard's OWN message distinguishes it
        //from the section-length mismatch that also rejects this (small) input.
        const int nWitnessOffset = 12 + 12 + 4 + 32;
        const uint hugeNWitness = 100_000_000;   //(nWitness - 1) * 32 ~= 3.2 GB > Array.MaxLength.

        byte[] mutated = (byte[])CircomWitnessFixtures.Multiplier2Bytes.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(mutated.AsSpan(nWitnessOffset), hugeNWitness);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness _ = ReadWitnessFixture(mutated);
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
            using RawR1csWitness _ = ReadWitnessMemory(file);
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
            using RawR1csWitness _ = ReadWitnessMemory(file);
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
            using RawR1csWitness _ = ReadWitnessMemory(file);
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
            using RawR1csWitness _ = ReadWitnessMemory(file);
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
            using RawR1csWitness _ = ReadWitnessMemory(file);
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
            using RawR1csWitness _ = ReadWitnessMemory(file);
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
            using RawR1csWitness _ = ReadWitnessMemory(file);
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
            using RawR1csWitness _ = ReadWitnessMemory(file);
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
            using RawR1csWitness _ = ReadWitnessMemory(file);
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
            using RawR1csWitness _ = ReadWitnessMemory(file);
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
            using RawR1csWitness _ = ReadWitnessMemory(file);
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
            using RawR1csWitness _ = ReadWitnessMemory(file);
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
            using RawR1csWitness _ = CircomWitnessReader.Reader(
                pipe,
                WellKnownR1csFormatLabel.CircomWitness,
                CurveParameterSet.Bls12Curve381,
                BaseMemoryPool.Shared,
                CancellationToken.None);
        });
    }


    [TestMethod]
    public void Multiplier2EndToEndProvesAndVerifiesWithStandardSpartan()
    {
        //The capability gate: both files parsed through the adapter,
        //prove with base Spartan, verify with base Spartan, accept.
        const int columnCount = 4;
        using RawR1csWitness witness = ReadWitnessFixture(CircomWitnessFixtures.Multiplier2Bytes);
        using SpartanProver prover = BuildBaseProver(columnCount);
        using SpartanVerifier verifier = BuildBaseVerifier(columnCount);

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


    [TestMethod]
    public void Multiplier2EndToEndProvesAndVerifiesWithMaskedSpartan()
    {
        const int hyraxVectorLength = 2;
        using RawR1csWitness witness = ReadWitnessFixture(CircomWitnessFixtures.Multiplier2Bytes);
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength);
        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(hyraxVectorLength);

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


    private static RawR1csWitness ReadWitnessFixture(byte[] fixtureBytes) =>
        ReadWitnessFixture(fixtureBytes, WellKnownR1csFormatLabel.CircomWitness);


    private static RawR1csWitness ReadWitnessFixture(byte[] fixtureBytes, WellKnownR1csFormatLabel format)
    {
        var stream = new MemoryStream(fixtureBytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);
        return CircomWitnessReader.Reader(
            pipe,
            format,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
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
            CancellationToken.None);
    }


    private static RawR1csInstance ReadR1csFixture(byte[] fixtureBytes)
    {
        var stream = new MemoryStream(fixtureBytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);
        return CircomR1csReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomBinary,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            CancellationToken.None);
    }


    private static int ReadBigEndianInt(ReadOnlySpan<byte> bytes)
    {
        //The scalar's value is small enough to fit in a 32-bit int —
        //the witness elements are 1, 33, 3, 11. The leading 28 bytes
        //are zeroes; we read only the trailing four-byte big-endian
        //tail.
        ReadOnlySpan<byte> tail = bytes[(bytes.Length - 4)..];
        return BinaryPrimitives.ReadInt32BigEndian(tail);
    }


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
}