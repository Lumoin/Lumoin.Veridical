using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Mdoc;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The REAL-CIRCUIT PROVE GATE (conformance step C.11): our C.9 ZK prover over the imported one-attribute
/// version-7 GF(2^128) hash circuit, fed the C.11 witness column (the deterministic regions reproduced by
/// <see cref="MdocHashWitnessFiller"/> with the thirteen reference MAC-randomness slots spliced from the
/// dump), verified by our C.8 verifier.
/// </summary>
/// <remarks>
/// <para>
/// The imported hash circuit is the one C.10 parses: 17 layers, up to ~900k wires and ~3.5M terms per
/// layer. The C# Ligero-over-the-whole-R1CS prove over it measures ~56 s (prove) on developer hardware
/// (an ~148 KB proof), so it is gated under <c>[TestCategory("Slow")]</c> and runs — the multi-hour figure
/// quoted around the original 6.6 h problem was the reference's instrumentation, not our managed prover.
/// The column itself is gated byte-exactly by the C.11 filler tests; this gate exercises the import path
/// and the C.9 prover / C.8 verifier over the genuine 85118-wire circuit. Wall times vary with hardware.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowRealHashCircuitProveTests
{
    private const string CredentialRelativePath = "TestMaterial/Mdoc/mdoc-00.cbor";
    private const string WitnessGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-hash-witness.gz";
    private const string RawGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-raw.gz";

    private const int Point256FieldId = 1;
    private const int Point256ElementBytes = 32;
    private const int Gf2128FieldId = 4;
    private const int Gf2128ElementBytes = 16;

    private const int ScalarSize = 32;
    private const int ElementBytes = 16;
    private const int FieldBytes = 16;
    private const int Production16SubFieldBytes = 2;
    private const int InverseRate = 7;
    private const int OpenedColumnCount = 132;

    //The reference's ZkProver rebases subfield_boundary by npub_in: 85112 - 952 (kLigeroRatev7 / kLigeroNreqv7
    //and the v7 rate/nreq pair the mdoc prover uses for the hash circuit).
    private const int SubfieldBoundary = 85112 - 952;
    private const int TranscriptVersion = 7;

    private const int MacPublicStart = 945;
    private const int MacPublicEnd = 952;
    private const int MacKeysStart = 85112;
    private const int InputCount = 85118;

    private static readonly byte[] Now = Encoding.ASCII.GetBytes("2024-01-30T09:00:00Z");

    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("mdoc-hash");

    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void OurProverOverTheImportedHashCircuitProducesAProofOurVerifierAccepts()
    {
        LongfellowSumcheckCircuit circuit = ParseHashCircuit();
        byte[] column = BuildColumn();

        Assert.AreEqual(circuit.InputCount, column.Length / ScalarSize, "The column width must equal the imported circuit's input count.");

        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, FieldBytes, Production16SubFieldBytes);

        byte[] proof = ProduceProof(circuit, parameters, column);
        bool accepted = Verify(circuit, parameters, proof, PublicInputBytes(circuit, column));

        Assert.IsTrue(accepted, "Our verifier must accept our proof over the imported real hash circuit.");
    }


    private static byte[] ProduceProof(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] column)
    {
        using Lch14AdditiveFft fft = NewFft();
        using LongfellowTranscript transcript = NewTranscript(TranscriptSeed);
        LongfellowRandomByteSource random = NewCounterSource();

        return LongfellowZkProver.Prove(
            circuit, parameters, column, Production16SubFieldBytes, SubfieldBoundary, random, transcript, fft,
            Add, Subtract, Multiply, Invert, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, BaseMemoryPool.Shared,
            Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate(), Gf2k128BatchBackend.GetBindQuadReduce(), Gf2k128BatchBackend.GetGatherMultiplyAccumulate());
    }


    private static bool Verify(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] proof, byte[] publicInputs)
    {
        using Lch14AdditiveFft fft = NewFft();
        using LongfellowTranscript transcript = NewTranscript(TranscriptSeed);

        return LongfellowZkVerifier.Verify(
            circuit, parameters, proof, publicInputs, Production16SubFieldBytes, transcript, fft,
            Add, Subtract, Multiply, Invert, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, BaseMemoryPool.Shared,
            out _, Gf2k128BatchBackend.GetBindQuadReduce(), Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate());
    }


    //The full satisfying column: the deterministic regions from the filler plus the thirteen MAC-randomness
    //slots spliced from the reference dump (the dual-field commit that regenerates av is C.12's envelope).
    private static byte[] BuildColumn()
    {
        byte[] credential = ReadFixture(CredentialRelativePath);
        byte[] reference = DecompressGzip(ReadFixture(WitnessGzipRelativePath));

        using Lch14AdditiveFft fft = NewFft();
        var filler = new MdocHashWitnessFiller(fft, Add);
        byte[] column = filler.Fill(credential, MdocRequestedAttribute.AgeOver18, Now);

        SpliceReferenceElements(column, reference, MacPublicStart, MacPublicEnd);
        SpliceReferenceElements(column, reference, MacKeysStart, InputCount);

        return column;
    }


    private static void SpliceReferenceElements(byte[] column, byte[] reference, int startElement, int endElement)
    {
        for(int i = startElement; i < endElement; i++)
        {
            ReadOnlySpan<byte> littleEndian = reference.AsSpan(i * ElementBytes, ElementBytes);
            Span<byte> destination = column.AsSpan(i * ScalarSize, ScalarSize);
            destination.Clear();
            for(int b = 0; b < ElementBytes; b++)
            {
                destination[ScalarSize - 1 - b] = littleEndian[b];
            }
        }
    }


    private static LongfellowSumcheckCircuit ParseHashCircuit()
    {
        byte[] raw = DecompressGzip(ReadFixture(RawGzipRelativePath));
        bool signatureParsed = LongfellowCircuitReader.TryRead(raw, Point256FieldId, Point256ElementBytes, out _, out _, out int signatureBytes);
        Assert.IsTrue(signatureParsed);

        bool hashParsed = LongfellowCircuitReader.TryRead(raw.AsSpan(signatureBytes), Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? hash, out _, out _);
        Assert.IsTrue(hashParsed);
        Assert.IsNotNull(hash);

        return hash;
    }


    private static byte[] PublicInputBytes(LongfellowSumcheckCircuit circuit, byte[] column)
    {
        byte[] publicInputs = new byte[circuit.PublicInputCount * ElementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            ToBytesField(column.AsSpan(i * ScalarSize, ScalarSize), publicInputs.AsSpan(i * ElementBytes, ElementBytes));
        }

        return publicInputs;
    }


    private static LongfellowRandomByteSource NewCounterSource()
    {
        ulong counter = 0;

        return destination =>
        {
            for(int i = 0; i < destination.Length; i++)
            {
                destination[i] = (byte)(counter & 0xFF);
                counter++;
            }
        };
    }


    private static void ToBytesField(ReadOnlySpan<byte> canonical, Span<byte> littleEndian)
    {
        for(int i = 0; i < ElementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }


    private static byte[] ReadFixture(string relativePath) => File.ReadAllBytes($"../../../{relativePath}");


    private static byte[] DecompressGzip(byte[] gzip)
    {
        using var input = new MemoryStream(gzip);
        using var gzipStream = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzipStream.CopyTo(output);

        return output.ToArray();
    }


    private static LongfellowTranscript NewTranscript(byte[] seed) =>
        new(seed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) => SHA256.HashData(input, output);


    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[left.Length + right.Length];
        left.CopyTo(combined);
        right.CopyTo(combined[left.Length..]);
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }
}
