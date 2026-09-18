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
/// The REAL-CIRCUIT PROVE GATE: our end-to-end ZK prover over the imported one-attribute
/// version-7 GF(2^128) hash circuit, fed the witness-filler step's witness column (the deterministic regions
/// reproduced by <see cref="MdocHashWitnessFiller"/> with the thirteen reference MAC-randomness slots spliced
/// from the recorded values), verified by our end-to-end verifier.
/// </summary>
/// <remarks>
/// <para>
/// The imported hash circuit is the one the circuit-import reader parses: 17 layers, up to ~900k wires and
/// ~3.5M terms per layer. The C# Ligero-over-the-whole-R1CS prove over it measures ~56 s (prove, an
/// ~148 KB proof), so it is gated under <c>[TestCategory("Slow")]</c> and runs — the multi-hour
/// figure sometimes cited for a 6.6 h reference run reflects the reference implementation's own instrumentation
/// overhead, not a property of this managed prover. The column itself is gated byte-exactly by the
/// witness-filler step's own tests; this gate exercises the import path and the end-to-end prover / end-to-end
/// verifier over the genuine 85118-wire circuit. Wall times vary with hardware.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowRealHashCircuitProveTests: IDisposable
{
    /// <summary>The independent compiler and circuit lifetime for this test.</summary>
    private LongfellowCircuitTestScope CircuitScope { get; } = new();

    /// <summary>Calls <see cref="Dispose"/> after each test, including when an assertion fails.</summary>
    [TestCleanup]
    public void DisposeCircuits()
    {
        Dispose();
    }


    /// <summary>Releases this test's compiler and circuit storage. Repeated calls have no effect.</summary>
    public void Dispose()
    {
        CircuitScope.Dispose();
    }


    /// <summary>The repository-relative path to the mdoc credential fixture this test parses.</summary>
    private const string CredentialRelativePath = "TestMaterial/Mdoc/mdoc-00.cbor";
    /// <summary>The repository-relative path to the gzip-compressed reference witness column fixture, whose MAC-randomness slots are spliced into the locally filled column.</summary>
    private const string WitnessGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-hash-witness.gz";
    /// <summary>The repository-relative path to the gzip-compressed serialized dual-circuit fixture this test parses.</summary>
    private const string RawGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-raw.gz";

    /// <summary>The field identifier the circuit-import reader uses for the P-256 base field, read as the first circuit in the dual-circuit stream.</summary>
    private const int Point256FieldId = 1;
    /// <summary>The element width, in bytes, of the P-256 base field.</summary>
    private const int Point256ElementBytes = 32;
    /// <summary>The field identifier the circuit-import reader uses for GF(2^128), read as the second circuit in the dual-circuit stream.</summary>
    private const int Gf2128FieldId = 4;
    /// <summary>The element width, in bytes, of GF(2^128).</summary>
    private const int Gf2128ElementBytes = 16;

    /// <summary>The width, in bytes, of one canonical field-element scalar in the witness column this test builds.</summary>
    private const int ScalarSize = 32;
    /// <summary>The width, in bytes, of one little-endian GF(2^128) element as the reference fixtures and public inputs store it.</summary>
    private const int ElementBytes = 16;
    /// <summary>The field width, in bytes, passed to <see cref="LongfellowZkVerifier.DeriveParameters(LongfellowSumcheckCircuit, int, int, int, int)"/> for the GF(2^128) hash circuit.</summary>
    private const int FieldBytes = 16;
    /// <summary>The subfield width, in bytes, of the production GF(2^16) subfield the additive FFT operates over.</summary>
    private const int Production16SubFieldBytes = 2;
    /// <summary>The Ligero inverse rate this test derives its parameters with.</summary>
    private const int InverseRate = 7;
    /// <summary>The number of Ligero columns opened per query, used when deriving this test's parameters.</summary>
    private const int OpenedColumnCount = 132;

    /// <summary>
    /// The reference's ZkProver rebases subfield_boundary by npub_in: 85112 - 952 (kLigeroRatev7 /
    /// kLigeroNreqv7 and the v7 rate/nreq pair the mdoc prover uses for the hash circuit).
    /// </summary>
    private const int SubfieldBoundary = 85112 - 952;
    /// <summary>The transcript version passed to <see cref="NewTranscript"/>, matching the version the imported circuit was produced under.</summary>
    private const int TranscriptVersion = 7;

    /// <summary>The first column index of the public MAC-randomness slots spliced in from the reference's recorded values.</summary>
    private const int MacPublicStart = 945;
    /// <summary>The index one past the last public MAC-randomness slot spliced in from the reference's recorded values.</summary>
    private const int MacPublicEnd = 952;
    /// <summary>The first column index of the MAC-key slots spliced in from the reference's recorded values.</summary>
    private const int MacKeysStart = 85112;
    /// <summary>The total number of scalar elements in the witness column, matching the imported circuit's input count.</summary>
    private const int InputCount = 85118;

    /// <summary>The fixed verification timestamp the witness filler treats as "now" when evaluating the age predicate.</summary>
    private static byte[] Now { get; } = Encoding.ASCII.GetBytes("2024-01-30T09:00:00Z");

    /// <summary>The Fiat–Shamir transcript seed shared by the prover and verifier in this test.</summary>
    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("mdoc-hash");

    /// <summary>The GF(2^128) addition delegate this test proves and verifies over.</summary>
    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) subtraction delegate this test proves and verifies over.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) multiplication delegate this test proves and verifies over.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) inversion delegate this test proves and verifies over.</summary>
    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();


    /// <summary>Verifies that, over the imported real GF(2^128) hash circuit and a genuine witness column, this library's own prover produces a proof that this library's own verifier accepts.</summary>
    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void OurProverOverTheImportedHashCircuitProducesAProofOurVerifierAccepts()
    {
        using LongfellowSumcheckCircuit circuit = ParseHashCircuit();
        byte[] column = BuildColumn();

        Assert.AreEqual(circuit.InputCount, column.Length / ScalarSize, "The column width must equal the imported circuit's input count.");

        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, FieldBytes, Production16SubFieldBytes);

        using LongfellowZkProofEnvelope proof = ProduceProof(circuit, parameters, column);
        bool accepted = Verify(circuit, parameters, proof.Bytes, PublicInputBytes(circuit, column));

        Assert.IsTrue(accepted, "Our verifier must accept our proof over the imported real hash circuit.");
    }


    /// <summary>Produces the ZK proof envelope for the given circuit, parameters, and witness column, returning the pooled envelope for the caller to dispose.</summary>
    private static LongfellowZkProofEnvelope ProduceProof(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] column)
    {
        using Lch14AdditiveFft fft = NewFft();
        using LongfellowTranscript transcript = NewTranscript(TranscriptSeed);
        LongfellowRandomByteSource random = NewCounterSource();

        return LongfellowZkProver.Prove(
            circuit, parameters, column, Production16SubFieldBytes, SubfieldBoundary, random, transcript, fft,
            Add, Subtract, Multiply, Invert, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, BaseMemoryPool.Shared,
            Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate(), Gf2k128BatchBackend.GetBindQuadReduce(), Gf2k128BatchBackend.GetGatherMultiplyAccumulate());
    }


    /// <summary>Verifies a proof against the given circuit, parameters, public inputs, and this test's transcript seed.</summary>
    private static bool Verify(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, ReadOnlySpan<byte> proof, byte[] publicInputs)
    {
        using Lch14AdditiveFft fft = NewFft();
        using LongfellowTranscript transcript = NewTranscript(TranscriptSeed);

        return LongfellowZkVerifier.Verify(
            circuit, parameters, proof, publicInputs, Production16SubFieldBytes, transcript, fft,
            Add, Subtract, Multiply, Invert, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, BaseMemoryPool.Shared,
            out _, Gf2k128BatchBackend.GetBindQuadReduce(), Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate());
    }


    /// <summary>Builds the full satisfying witness column: the deterministic regions from <see cref="MdocHashWitnessFiller"/> plus the thirteen MAC-randomness slots spliced from the reference's recorded values (the dual-field commit that regenerates av is the dual-field envelope's job).</summary>
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


    /// <summary>Overwrites a range of column elements with the reference's recorded little-endian values, converted to this column's big-endian canonical encoding.</summary>
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


    /// <summary>Parses the dual-circuit fixture, asserting both the P-256 signature circuit and the GF(2^128) hash circuit decode successfully, and returns the hash circuit with its storage released at test cleanup.</summary>
    private LongfellowSumcheckCircuit ParseHashCircuit()
    {
        byte[] raw = DecompressGzip(ReadFixture(RawGzipRelativePath));
        bool signatureParsed = CircuitScope.TryRead(raw, Point256FieldId, Point256ElementBytes, out _, out _, out int signatureBytes);
        Assert.IsTrue(signatureParsed);

        bool hashParsed = CircuitScope.TryRead(raw.AsSpan(signatureBytes), Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? hash, out _, out _);
        Assert.IsTrue(hashParsed);
        Assert.IsNotNull(hash);

        return hash;
    }


    /// <summary>Extracts the circuit's declared public inputs from the witness column and converts them to little-endian element bytes.</summary>
    private static byte[] PublicInputBytes(LongfellowSumcheckCircuit circuit, byte[] column)
    {
        byte[] publicInputs = new byte[circuit.PublicInputCount * ElementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            ToBytesField(column.AsSpan(i * ScalarSize, ScalarSize), publicInputs.AsSpan(i * ElementBytes, ElementBytes));
        }

        return publicInputs;
    }


    /// <summary>Creates a deterministic, non-cryptographic random-byte source that fills each request with successive low bytes of an incrementing counter, so a proof run is reproducible.</summary>
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


    /// <summary>Converts one canonical big-endian scalar to its little-endian element encoding.</summary>
    private static void ToBytesField(ReadOnlySpan<byte> canonical, Span<byte> littleEndian)
    {
        for(int i = 0; i < ElementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }


    /// <summary>Reads a fixture file's bytes from the test project's output-relative path.</summary>
    private static byte[] ReadFixture(string relativePath) => File.ReadAllBytes($"../../../{relativePath}");


    /// <summary>Decompresses a gzip-compressed byte array in memory.</summary>
    private static byte[] DecompressGzip(byte[] gzip)
    {
        using var input = new MemoryStream(gzip);
        using var gzipStream = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzipStream.CopyTo(output);

        return output.ToArray();
    }


    /// <summary>Creates a fresh Fiat–Shamir transcript seeded and configured to match the imported circuit's transcript version.</summary>
    private static LongfellowTranscript NewTranscript(byte[] seed) =>
        new(seed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Creates the additive FFT this test's prover and verifier use over the production GF(2^16) subfield.</summary>
    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>Computes the SHA-256 digest of a single input, ignoring the caller-supplied hash-function label.</summary>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) => SHA256.HashData(input, output);


    /// <summary>Computes the SHA-256 digest of two concatenated inputs, for a Merkle two-to-one compression step.</summary>
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[left.Length + right.Length];
        left.CopyTo(combined);
        right.CopyTo(combined[left.Length..]);
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>Encrypts one AES-256 block in ECB mode with no padding, for the transcript's block-cipher-based squeeze.</summary>
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }
}
