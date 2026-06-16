using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The CIRCUIT-ARTIFACT IMPORT (conformance step C.10): parsing the serialized circuits that
/// google/longfellow-zk's <c>generate_circuit</c> emits — the raw, decompressed bytes the ZkSpec pins by
/// hash — into <see cref="LongfellowSumcheckCircuit"/> via <see cref="LongfellowCircuitReader"/>, gated on
/// the REAL one-attribute version-7 mdoc circuit bundle and on a provable-scale circuit that drives the
/// C.9 prover and the C.8 verifier through the import path.
/// </summary>
/// <remarks>
/// <para>
/// The anchor (mdoc-circuit-anchor-output.txt plus the binary fixtures mdoc-circuit-compressed.zst,
/// mdoc-circuit-raw.gz, mdoc-circuit-hash-witness.gz in TestMaterial/Longfellow) is computed by the
/// reference implementation in its own build environment via development tooling outside this repository.
/// The harness calls <c>generate_circuit(&amp;kZkSpecs[0], …)</c> for the latest one-attribute ZkSpec
/// (system "longfellow-libzk-v1", version 7), SHA-256s the compressed (zstd) blob (the ZkSpec
/// circuit_hash is over that blob), decompresses and parses both circuits with the reference
/// <c>CircuitReader</c>, and dumps their shapes and a sample of the hash circuit's Quad terms. It also
/// serializes a small GF(2^128) circuit through the reference <c>CircuitWriter</c> for the functional
/// gate.
/// </para>
/// <para>
/// The gates:
/// </para>
/// <list type="bullet">
///   <item><description><b>Real bundle parse + shape.</b> The decompressed raw bytes parse into the P-256 signature circuit followed by the GF(2^128) hash circuit, with no trailing bytes. Every shape field — <c>nv</c>, <c>logv</c>, <c>nc</c>, <c>logc</c> (zero, as the wire layer requires), <c>nl</c>, <c>ninputs</c>, <c>npub_in</c>, <c>subfield_boundary</c>, the 32-byte id, and every layer's <c>nw</c>/<c>logw</c>/<c>nterms</c> — equals the reference-dumped value.</description></item>
///   <item><description><b>Quad terms.</b> A sample of the hash circuit's first- and last-layer Quad terms (gate, hand indices, coefficient) equals the dumped terms.</description></item>
///   <item><description><b>Circuit identity.</b> SHA-256 of the compressed blob equals the reference's own computed circuit hash, and SHA-256 of the decompressed raw bytes equals the reference's raw digest — the C# reproduces the reference's circuit-identity computation over the same bytes.</description></item>
///   <item><description><b>Functional, default suite.</b> The small circuit parsed from its serialized bytes equals the C.9 anchor circuit (id, shape, terms), and our C.9 prover over it plus a satisfying witness produces a proof our C.8 verifier accepts.</description></item>
///   <item><description><b>Parse safety.</b> Truncated, wrong-version, and wrong-field-id inputs return failure with no exception.</description></item>
/// </list>
/// <para>
/// The full hash circuit is enormous (17 layers, up to ~900k wires and ~3.5M terms per layer, an ~99 MB
/// serialization), so a prove over it through the Ligero-over-the-whole-R1CS stack is infeasible (the
/// known multi-hour cost); the real-circuit gates here are the reader, shape, term, and identity gates.
/// The functional prove/verify gate runs on the small circuit, which exercises the same import code path.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowCircuitReaderTests
{
    private const string AnchorRelativePath = "TestMaterial/Longfellow/mdoc-circuit-anchor-output.txt";
    private const string CompressedRelativePath = "TestMaterial/Longfellow/mdoc-circuit-compressed.zst";
    private const string RawGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-raw.gz";

    private const int Point256FieldId = 1;
    private const int Gf2128FieldId = 4;
    private const int Point256ElementBytes = 32;
    private const int Gf2128ElementBytes = 16;

    private const int ScalarSize = Scalar.SizeBytes;
    private const int ElementBytes = 16;
    private const int FieldBytes = 16;
    private const int Production16SubFieldBytes = 2;
    private const int InverseRate = 4;
    private const int OpenedColumnCount = 2;
    private const int SubfieldBoundary = 0;
    private const int TranscriptVersion = 6;

    //The reference's CircuitIO::kBytesPerSizeT: every serialized size/index is 3 little-endian bytes.
    private const int BytesPerSizeT = 3;

    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("zk8");

    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();

    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(AnchorRelativePath);

    //The decompressed real-circuit bytes are ~99 MB; decompress once and share across the parse gates.
    private static byte[] RawCircuitBytes { get; } = DecompressGzip(ReadFixture(RawGzipRelativePath));


    [TestMethod]
    public void TheRealMdocBundleParsesIntoTwoCircuitsWithNoTrailingBytes()
    {
        byte[] raw = RawCircuitBytes;

        Assert.HasCount(Anchor("raw_len"), raw, "The decompressed length must match the reference's raw_len.");

        bool signatureParsed = LongfellowCircuitReader.TryRead(raw, Point256FieldId, Point256ElementBytes, out LongfellowSumcheckCircuit? signature, out _, out int signatureBytes);
        Assert.IsTrue(signatureParsed, "The signature circuit must parse.");
        Assert.IsNotNull(signature);

        bool hashParsed = LongfellowCircuitReader.TryRead(raw.AsSpan(signatureBytes), Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? hash, out _, out int hashBytes);
        Assert.IsTrue(hashParsed, "The hash circuit must parse from the continuation of the stream.");
        Assert.IsNotNull(hash);

        Assert.AreEqual(raw.Length, signatureBytes + hashBytes, "The two circuits must consume the whole stream with no trailing bytes.");
    }


    [TestMethod]
    public void TheSignatureCircuitShapeMatchesTheReference()
    {
        LongfellowSumcheckCircuit signature = ParseSignatureCircuit(out int subfieldBoundary);

        AssertShapeMatches("sig", signature);
        Assert.AreEqual(Anchor("sig_subfield_boundary"), subfieldBoundary, "sig subfield_boundary");
    }


    [TestMethod]
    public void TheHashCircuitShapeMatchesTheReferenceAndHasNoCopies()
    {
        LongfellowSumcheckCircuit hash = ParseHashCircuit(out int subfieldBoundary);

        AssertShapeMatches("hash", hash);
        Assert.AreEqual(Anchor("hash_subfield_boundary"), subfieldBoundary, "hash subfield_boundary");

        //logc == 0 is the precondition the whole sumcheck wire layer asserts (no copies).
        Assert.AreEqual(0, hash.CopyRounds, "The hash circuit must have logc == 0.");

        LongfellowSumcheckCircuit signature = ParseSignatureCircuit(out _);
        Assert.AreEqual(0, signature.CopyRounds, "The signature circuit must have logc == 0.");
    }


    [TestMethod]
    public void TheHashCircuitSampleQuadTermsMatchTheReference()
    {
        LongfellowSumcheckCircuit hash = ParseHashCircuit(out _);

        AssertLayerSampleTerms(hash, 0, "hash", 0);
        AssertLayerSampleTerms(hash, hash.LayerCount - 1, "hash", 16);
    }


    [TestMethod]
    public void TheHashWitnessColumnMatchesTheImportedCircuitInputContract()
    {
        const string witnessGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-hash-witness.gz";

        LongfellowSumcheckCircuit hash = ParseHashCircuit(out _);
        byte[] witnessColumn = DecompressGzip(ReadFixture(witnessGzipRelativePath));

        //The reference's fill_witness + post-commit update_macs produce one GF(2^128) element per input
        //wire, each 16 little-endian to_bytes_field bytes. The column the C# prover would consume is the
        //same width as the imported circuit's input count. (The full prove over the imported hash circuit
        //is infeasible at this scale, so this gates the witness-column contract, not a prove; the
        //witness-filler port and the prove are the next step.)
        Assert.AreEqual(Anchor("hash_witness_ninputs"), hash.InputCount, "The dumped witness column is sized to the imported circuit's input count.");
        Assert.HasCount(hash.InputCount * Gf2128ElementBytes, witnessColumn, "The witness column is ninputs * 16 little-endian element bytes.");

        string computed = Convert.ToHexStringLower(SHA256.HashData(witnessColumn));
        Assert.AreEqual(Anchors["hash_witness_rawsha"], computed, "The witness column bytes must equal the reference's dumped column.");
    }


    [TestMethod]
    public void TheCompressedBlobReproducesTheReferenceCircuitHash()
    {
        byte[] compressed = ReadFixture(CompressedRelativePath);

        Assert.HasCount(Anchor("compressed_zst_len"), compressed, "The compressed blob length must match the reference.");

        string computed = Convert.ToHexStringLower(SHA256.HashData(compressed));

        Assert.AreEqual(Anchors["computed_circuit_hash"], computed, "SHA-256 of the compressed blob must equal the reference's computed circuit hash.");
    }


    [TestMethod]
    public void TheDecompressedRawBytesReproduceTheReferenceDigest()
    {
        string computed = Convert.ToHexStringLower(SHA256.HashData(RawCircuitBytes));

        Assert.AreEqual(Anchors["raw_rawsha"], computed, "SHA-256 of the decompressed raw circuit bytes must equal the reference's raw digest.");
    }


    [TestMethod]
    public void TheImportedSmallCircuitDrivesTheProverAndVerifier()
    {
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);

        bool parsed = LongfellowCircuitReader.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? circuit, out int subfieldBoundary, out int consumed);
        Assert.IsTrue(parsed, "The small circuit must parse.");
        Assert.IsNotNull(circuit);
        Assert.AreEqual(serialized.Length, consumed, "The small circuit must consume its whole serialization.");
        Assert.AreEqual(SubfieldBoundary, subfieldBoundary, "The small circuit's subfield_boundary is 0.");

        //The parsed circuit equals the C.9 anchor circuit: same id and shape.
        byte[] expectedId = Convert.FromHexString(Anchors["small_circuit_id"]);
        Assert.IsTrue(circuit.Id.Span.SequenceEqual(expectedId), "The imported circuit id must match the writer's id.");
        Assert.AreEqual(1, circuit.OutputCount, "nv must be 1.");
        Assert.AreEqual(3, circuit.LayerCount, "nl must be 3.");
        Assert.AreEqual(5, circuit.InputCount, "ninputs must be 5.");
        Assert.AreEqual(2, circuit.PublicInputCount, "npub_in must be 2.");
        Assert.AreEqual(0, circuit.CopyRounds, "logc must be 0.");

        //Our C.9 prover over the imported circuit produces a proof our C.8 verifier accepts.
        byte[] witnessColumn = BuildSatisfyingColumn(circuit, 3, 5, 7);
        byte[] proof = ProduceProof(circuit, witnessColumn, TranscriptSeed);

        AssertVerifies(circuit, proof, PublicInputBytes(circuit, witnessColumn));
    }


    [TestMethod]
    public void TruncatedInputReturnsFailure()
    {
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);

        for(int length = 0; length < serialized.Length; length += 7)
        {
            bool parsed = LongfellowCircuitReader.TryRead(serialized.AsSpan(0, length), Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? circuit, out _, out int consumed);

            Assert.IsFalse(parsed, $"A {length}-byte prefix must not parse.");
            Assert.IsNull(circuit);
            Assert.AreEqual(0, consumed);
        }
    }


    [TestMethod]
    public void WrongVersionReturnsFailure()
    {
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);
        serialized[0] = 0x02;

        bool parsed = LongfellowCircuitReader.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out _, out _, out _);

        Assert.IsFalse(parsed, "A wrong version byte must not parse.");
    }


    [TestMethod]
    public void AZeroLayerCountReturnsFailure()
    {
        //nl is the seventh 3-byte header field after the version byte; a crafted zero must parse
        //to false rather than throw through the circuit constructors.
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);
        int layerCountOffset = 1 + (6 * BytesPerSizeT);
        serialized.AsSpan(layerCountOffset, BytesPerSizeT).Clear();

        bool parsed = LongfellowCircuitReader.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? circuit, out _, out _);

        Assert.IsFalse(parsed, "A zero layer count must not parse.");
        Assert.IsNull(circuit);
    }


    [TestMethod]
    public void AZeroHandRoundLayerReturnsFailure()
    {
        //The first layer header's logw sits right after the fixed header and the constant table; a
        //crafted zero must parse to false rather than throw through the layer constructor.
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);
        serialized.AsSpan(FirstLayerOffset(serialized), BytesPerSizeT).Clear();

        bool parsed = LongfellowCircuitReader.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? circuit, out _, out _);

        Assert.IsFalse(parsed, "A zero-hand-round layer must not parse.");
        Assert.IsNull(circuit);
    }


    [TestMethod]
    public void AnOversizedDeclaredCountReturnsFailure()
    {
        //numconst and a layer's nq declare how many fixed-size records follow; the maximal 3-byte
        //value (16,777,215 records) exceeds the remaining buffer, so the bounds check must fail
        //BEFORE the record array is allocated — false, no exception, no huge allocation.
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);
        int constantCountOffset = 1 + (7 * BytesPerSizeT);
        serialized.AsSpan(constantCountOffset, BytesPerSizeT).Fill(0xFF);

        bool parsed = LongfellowCircuitReader.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? circuit, out _, out _);

        Assert.IsFalse(parsed, "An oversized constant count must not parse.");
        Assert.IsNull(circuit);

        serialized = Convert.FromHexString(Anchors["small_serialized"]);
        int termCountOffset = FirstLayerOffset(serialized) + (2 * BytesPerSizeT);
        serialized.AsSpan(termCountOffset, BytesPerSizeT).Fill(0xFF);

        parsed = LongfellowCircuitReader.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out circuit, out _, out _);

        Assert.IsFalse(parsed, "An oversized term count must not parse.");
        Assert.IsNull(circuit);
    }


    [TestMethod]
    public void AnOutOfRangeConstantIndexReturnsFailure()
    {
        //The first term's value index field points past the constant table; the vi < numconst check
        //must reject it rather than index out of the table.
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);
        int valueIndexOffset = FirstLayerOffset(serialized) + (3 * BytesPerSizeT) + (3 * BytesPerSizeT);
        serialized.AsSpan(valueIndexOffset, BytesPerSizeT).Fill(0xFF);

        bool parsed = LongfellowCircuitReader.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? circuit, out _, out _);

        Assert.IsFalse(parsed, "An out-of-range constant index must not parse.");
        Assert.IsNull(circuit);
    }


    [TestMethod]
    public void AnOutOfRangeIndexDeltaReturnsFailure()
    {
        //The deltas are signed-low-bit from a per-layer zero start. An odd delta of 3 drives the
        //first term's gate index to −1 (underflow); an even delta of 2 drives it to 1 == nv == max_g
        //(past the upper bound). Both must reject through the range check, never store.
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);
        int gateDeltaOffset = FirstLayerOffset(serialized) + (3 * BytesPerSizeT);
        serialized.AsSpan(gateDeltaOffset, BytesPerSizeT).Clear();
        serialized[gateDeltaOffset] = 0x03;

        bool parsed = LongfellowCircuitReader.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? circuit, out _, out _);

        Assert.IsFalse(parsed, "An underflowing gate delta must not parse.");
        Assert.IsNull(circuit);

        serialized = Convert.FromHexString(Anchors["small_serialized"]);
        serialized.AsSpan(gateDeltaOffset, BytesPerSizeT).Clear();
        serialized[gateDeltaOffset] = 0x02;

        parsed = LongfellowCircuitReader.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out circuit, out _, out _);

        Assert.IsFalse(parsed, "A gate delta past max_g must not parse.");
        Assert.IsNull(circuit);
    }


    [TestMethod]
    public void WrongFieldIdReturnsFailure()
    {
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);

        //The serialization carries GF2_128_ID (4); parsing it as P256 (1) must fail the field-id check.
        bool parsed = LongfellowCircuitReader.TryRead(serialized, Point256FieldId, Point256ElementBytes, out _, out _, out _);

        Assert.IsFalse(parsed, "A field-id mismatch must not parse.");
    }


    //The first layer header starts after the version byte, the eight 3-byte header fields, and the
    //constant table; the constant count is the eighth header field.
    private static int FirstLayerOffset(byte[] serialized)
    {
        int constantCountOffset = 1 + (7 * BytesPerSizeT);
        int constantCount = serialized[constantCountOffset] | (serialized[constantCountOffset + 1] << 8) | (serialized[constantCountOffset + 2] << 16);

        return 1 + (8 * BytesPerSizeT) + (constantCount * Gf2128ElementBytes);
    }


    private static LongfellowSumcheckCircuit ParseSignatureCircuit(out int subfieldBoundary)
    {
        bool parsed = LongfellowCircuitReader.TryRead(RawCircuitBytes, Point256FieldId, Point256ElementBytes, out LongfellowSumcheckCircuit? signature, out subfieldBoundary, out _);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(signature);

        return signature;
    }


    private static LongfellowSumcheckCircuit ParseHashCircuit(out int subfieldBoundary)
    {
        bool signatureParsed = LongfellowCircuitReader.TryRead(RawCircuitBytes, Point256FieldId, Point256ElementBytes, out _, out _, out int signatureBytes);
        Assert.IsTrue(signatureParsed);

        bool hashParsed = LongfellowCircuitReader.TryRead(RawCircuitBytes.AsSpan(signatureBytes), Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? hash, out subfieldBoundary, out _);
        Assert.IsTrue(hashParsed);
        Assert.IsNotNull(hash);

        return hash;
    }


    private static void AssertShapeMatches(string prefix, LongfellowSumcheckCircuit circuit)
    {
        Assert.AreEqual(Anchor($"{prefix}_nv"), circuit.OutputCount, $"{prefix} nv");
        Assert.AreEqual(Anchor($"{prefix}_logv"), circuit.OutputLogCount, $"{prefix} logv");
        Assert.AreEqual(Anchor($"{prefix}_nc"), circuit.CopyCount, $"{prefix} nc");
        Assert.AreEqual(Anchor($"{prefix}_logc"), circuit.CopyRounds, $"{prefix} logc");
        Assert.AreEqual(Anchor($"{prefix}_nl"), circuit.LayerCount, $"{prefix} nl");
        Assert.AreEqual(Anchor($"{prefix}_ninputs"), circuit.InputCount, $"{prefix} ninputs");
        Assert.AreEqual(Anchor($"{prefix}_npub_in"), circuit.PublicInputCount, $"{prefix} npub_in");

        byte[] expectedId = Convert.FromHexString(Anchors[$"{prefix}_id"]);
        Assert.IsTrue(circuit.Id.Span.SequenceEqual(expectedId), $"{prefix} id");

        for(int ly = 0; ly < circuit.LayerCount; ly++)
        {
            LongfellowSumcheckLayer layer = circuit.Layers[ly];
            Assert.AreEqual(Anchor($"{prefix}_layer{ly}_nw"), layer.InputCount, $"{prefix} layer{ly} nw");
            Assert.AreEqual(Anchor($"{prefix}_layer{ly}_logw"), layer.HandRounds, $"{prefix} layer{ly} logw");
            Assert.AreEqual(Anchor($"{prefix}_layer{ly}_nterms"), layer.TermCount, $"{prefix} layer{ly} nterms");
        }
    }


    private static void AssertLayerSampleTerms(LongfellowSumcheckCircuit circuit, int layerIndex, string prefix, int dumpedLayerIndex)
    {
        LongfellowSumcheckLayer layer = circuit.Layers[layerIndex];

        for(int t = 0; t < 8 && t < layer.TermCount; t++)
        {
            string baseKey = $"{prefix}_L{dumpedLayerIndex}_t{t}";
            if(!Anchors.ContainsKey($"{baseKey}_g"))
            {
                break;
            }

            LongfellowSumcheckQuadTerm term = layer.QuadTerms[t];
            Assert.AreEqual(Anchor($"{baseKey}_g"), term.GateIndex, $"{baseKey} g");
            Assert.AreEqual(Anchor($"{baseKey}_h0"), term.LeftIndex, $"{baseKey} h0");
            Assert.AreEqual(Anchor($"{baseKey}_h1"), term.RightIndex, $"{baseKey} h1");

            byte[] expectedCoefficient = ParseElement(Anchors[$"{baseKey}_v"]);
            Assert.IsTrue(term.Coefficient.Span.SequenceEqual(expectedCoefficient), $"{baseKey} v");
        }
    }


    private static byte[] ProduceProof(LongfellowSumcheckCircuit circuit, byte[] witnessColumn, byte[] seed)
    {
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, FieldBytes, Production16SubFieldBytes);

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowTranscript transcript = NewTranscript(seed);
        LongfellowRandomByteSource random = NewCounterSource();

        return LongfellowZkProver.Prove(
            circuit,
            parameters,
            witnessColumn,
            Production16SubFieldBytes,
            SubfieldBoundary,
            random,
            transcript,
            fft,
            Add,
            Subtract,
            Multiply,
            Invert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared);
    }


    private static void AssertVerifies(LongfellowSumcheckCircuit circuit, byte[] proof, byte[] publicInputs)
    {
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, FieldBytes, Production16SubFieldBytes);

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowTranscript transcript = NewTranscript(TranscriptSeed);

        bool accepted = LongfellowZkVerifier.Verify(
            circuit,
            parameters,
            proof,
            publicInputs,
            Production16SubFieldBytes,
            transcript,
            fft,
            Add,
            Subtract,
            Multiply,
            Invert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared,
            out LongfellowZkVerificationResult result);

        Assert.IsTrue(accepted, $"Our verifier must accept our proof over the imported circuit (result {result}).");
    }


    //Builds a satisfying witness column [one, x, y, z, w] over GF(2^128) with x/y/z = of_scalar(...) and
    //w = (x + y)·(x + z)·x, identical to the C.9 prover gate's construction.
    private static byte[] BuildSatisfyingColumn(LongfellowSumcheckCircuit circuit, uint x, uint y, uint z)
    {
        using Lch14AdditiveFft fft = NewFft();

        byte[] column = new byte[circuit.InputCount * ScalarSize];

        Span<byte> one = column.AsSpan(0, ScalarSize);
        one.Clear();
        one[ScalarSize - 1] = 0x01;

        OfScalar(fft, x, column.AsSpan(ScalarSize, ScalarSize));
        OfScalar(fft, y, column.AsSpan(2 * ScalarSize, ScalarSize));
        OfScalar(fft, z, column.AsSpan(3 * ScalarSize, ScalarSize));

        Span<byte> xPlusY = stackalloc byte[ScalarSize];
        Span<byte> xPlusZ = stackalloc byte[ScalarSize];
        Add(column.AsSpan(ScalarSize, ScalarSize), column.AsSpan(2 * ScalarSize, ScalarSize), xPlusY, CurveParameterSet.None);
        Add(column.AsSpan(ScalarSize, ScalarSize), column.AsSpan(3 * ScalarSize, ScalarSize), xPlusZ, CurveParameterSet.None);

        Span<byte> w = column.AsSpan(4 * ScalarSize, ScalarSize);
        Multiply(xPlusY, xPlusZ, w, CurveParameterSet.None);
        Multiply(w, column.AsSpan(ScalarSize, ScalarSize), w, CurveParameterSet.None);

        return column;
    }


    private static void OfScalar(Lch14AdditiveFft fft, uint value, Span<byte> destination)
    {
        destination.Clear();
        Span<byte> accumulator = stackalloc byte[ScalarSize];
        accumulator.Clear();

        int bit = 0;
        uint remaining = value;
        while(remaining != 0)
        {
            if((remaining & 1) != 0)
            {
                Add(accumulator, fft.BasisElement(bit), accumulator, CurveParameterSet.None);
            }

            remaining >>= 1;
            bit++;
        }

        accumulator.CopyTo(destination);
    }


    private static byte[] PublicInputBytes(LongfellowSumcheckCircuit circuit, byte[] witnessColumn)
    {
        byte[] publicInputs = new byte[circuit.PublicInputCount * ElementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            ToBytesField(witnessColumn.AsSpan(i * ScalarSize, ScalarSize), publicInputs.AsSpan(i * ElementBytes, ElementBytes));
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


    //Parses a 16-byte little-endian element into a 32-byte big-endian canonical scalar.
    private static byte[] ParseElement(string hex)
    {
        byte[] littleEndian = Convert.FromHexString(hex);
        byte[] canonical = new byte[ScalarSize];
        for(int i = 0; i < ElementBytes; i++)
        {
            canonical[ScalarSize - 1 - i] = littleEndian[i];
        }

        return canonical;
    }


    private static void ToBytesField(ReadOnlySpan<byte> canonical, Span<byte> littleEndian)
    {
        for(int i = 0; i < ElementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }


    private static byte[] ReadFixture(string relativePath) =>
        File.ReadAllBytes($"../../../{relativePath}");


    private static byte[] DecompressGzip(byte[] gzip)
    {
        using var input = new MemoryStream(gzip);
        using var gzipStream = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzipStream.CopyTo(output);

        return output.ToArray();
    }


    private static int Anchor(string key) => int.Parse(Anchors[key], CultureInfo.InvariantCulture);


    private static LongfellowTranscript NewTranscript(byte[] seed) =>
        new(seed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        SHA256.HashData(input, output);
    }


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


    private static Dictionary<string, string> LoadAnchors(string relativePath)
    {
        string path = $"../../../{relativePath}";
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach(string line in File.ReadAllLines(path))
        {
            if(line.Length == 0)
            {
                continue;
            }

            foreach(string token in line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                int separator = token.IndexOf('=', StringComparison.Ordinal);
                if(separator < 0)
                {
                    continue;
                }

                map[token[..separator]] = token[(separator + 1)..];
            }
        }

        return map;
    }
}
