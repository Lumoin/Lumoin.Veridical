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
/// The CIRCUIT-ARTIFACT IMPORT: parsing the serialized circuits that
/// google/longfellow-zk's <c>generate_circuit</c> emits — the raw, decompressed bytes the ZkSpec pins by
/// hash — into <see cref="LongfellowSumcheckCircuit"/> via <see cref="LongfellowCircuitReader"/>, gated on
/// the REAL one-attribute version-7 mdoc circuit bundle and on a provable-scale circuit that drives the
/// end-to-end ZK prover and verifier through the import path.
/// </summary>
/// <remarks>
/// <para>
/// The anchor (mdoc-circuit-anchor-output.txt plus the binary fixtures mdoc-circuit-compressed.zst,
/// mdoc-circuit-raw.gz, mdoc-circuit-hash-witness.gz in TestMaterial/Longfellow) corresponds to the
/// latest one-attribute ZkSpec (system "longfellow-libzk-v1", version 7), whose <c>circuit_hash</c> is
/// over the compressed (zstd) blob. The anchor text records both circuits' shapes and a sample of the
/// hash circuit's Quad terms.
/// </para>
/// <para>
/// The gates:
/// </para>
/// <list type="bullet">
///   <item><description><b>Real bundle parse + shape.</b> The decompressed raw bytes parse into the P-256 signature circuit followed by the GF(2^128) hash circuit, with no trailing bytes. Every shape field — <c>nv</c>, <c>logv</c>, <c>nc</c>, <c>logc</c> (zero, as the wire layer requires), <c>nl</c>, <c>ninputs</c>, <c>npub_in</c>, <c>subfield_boundary</c>, the 32-byte id, and every layer's <c>nw</c>/<c>logw</c>/<c>nterms</c> — equals the anchor's recorded value.</description></item>
///   <item><description><b>Quad terms.</b> A sample of the hash circuit's first- and last-layer Quad terms (gate, hand indices, coefficient) equals the anchor's recorded terms.</description></item>
///   <item><description><b>Circuit identity.</b> SHA-256 of the compressed blob equals the reference's own computed circuit hash, and SHA-256 of the decompressed raw bytes equals the reference's raw digest — the C# reproduces the reference's circuit-identity computation over the same bytes.</description></item>
///   <item><description><b>Functional, default suite.</b> The small circuit parsed from its serialized bytes equals the end-to-end-prove anchor circuit (id, shape, terms), and our end-to-end ZK prover over it plus a satisfying witness produces a proof our end-to-end ZK verifier accepts.</description></item>
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
internal sealed class LongfellowCircuitReaderTests: IDisposable
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


    /// <summary>The relative path to the real mdoc circuit bundle's reference-computed anchor values.</summary>
    private const string AnchorRelativePath = "TestMaterial/Longfellow/mdoc-circuit-anchor-output.txt";

    /// <summary>The relative path to the compressed (zstd) real mdoc circuit bundle fixture.</summary>
    private const string CompressedRelativePath = "TestMaterial/Longfellow/mdoc-circuit-compressed.zst";

    /// <summary>The relative path to the gzip-compressed decompressed-raw real mdoc circuit bundle fixture.</summary>
    private const string RawGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-raw.gz";

    /// <summary>The wire field-id tag for the P-256 base field.</summary>
    private const int Point256FieldId = 1;

    /// <summary>The wire field-id tag for GF(2^128).</summary>
    private const int Gf2128FieldId = 4;

    /// <summary>The on-wire element width of a P-256 field element, in bytes.</summary>
    private const int Point256ElementBytes = 32;

    /// <summary>The on-wire element width of a GF(2^128) field element, in bytes.</summary>
    private const int Gf2128ElementBytes = 16;

    /// <summary>The width in bytes of one field element in its canonical scalar representation.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The on-wire element width this test's witness and public-input byte columns use (GF(2^128), 16 bytes).</summary>
    private const int ElementBytes = 16;

    /// <summary>The field's canonical element width passed to the prove/verify parameter derivation.</summary>
    private const int FieldBytes = 16;

    /// <summary>The subfield element width of the production-16 subfield code the prove/verify gate's parameters are derived over.</summary>
    private const int Production16SubFieldBytes = 2;

    /// <summary>The Ligero code's inverse rate used to derive the prove/verify gate's parameters.</summary>
    private const int InverseRate = 4;

    /// <summary>The number of Ligero columns the prove/verify gate's parameters open.</summary>
    private const int OpenedColumnCount = 2;

    /// <summary>The subfield boundary the small functional circuit parses with: zero, since it carries no subfield-encoded elements.</summary>
    private const int SubfieldBoundary = 0;

    /// <summary>The transcript wire-format version the functional prove/verify gate's transcript is seeded with.</summary>
    private const int TranscriptVersion = 6;

    /// <summary>The reference's <c>CircuitIO::kBytesPerSizeT</c>: every serialized size or index is 3 little-endian bytes.</summary>
    private const int BytesPerSizeT = 3;

    /// <summary>The fixed transcript seed ("zk8") the functional prove/verify gate uses, so the transcript's driven values are deterministic across runs.</summary>
    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("zk8");

    /// <summary>The GF(2^128) field addition delegate every gate in this file drives the circuit reader, prover and verifier through.</summary>
    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) field subtraction delegate every gate in this file drives the circuit reader, prover and verifier through.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) field multiplication delegate every gate in this file drives the circuit reader, prover and verifier through.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) field inversion delegate every gate in this file drives the circuit reader, prover and verifier through.</summary>
    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>The reference-computed values loaded from <see cref="AnchorRelativePath"/>, keyed by field name.</summary>
    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(AnchorRelativePath);

    /// <summary>The decompressed real-circuit bytes, ~99 MB; decompressed once and shared across every parse gate.</summary>
    private static byte[] RawCircuitBytes { get; } = DecompressGzip(ReadFixture(RawGzipRelativePath));


    /// <summary>
    /// Verifies that the decompressed real mdoc circuit bundle parses as exactly two circuits back
    /// to back — the P-256 signature circuit followed by the GF(2^128) hash circuit — consuming the
    /// whole stream with no trailing bytes, and that the decompressed length matches the reference's
    /// own.
    /// </summary>
    [TestMethod]
    public void TheRealMdocBundleParsesIntoTwoCircuitsWithNoTrailingBytes()
    {
        byte[] raw = RawCircuitBytes;

        Assert.HasCount(Anchor("raw_len"), raw, "The decompressed length must match the reference's raw_len.");

        bool signatureParsed = CircuitScope.TryRead(raw, Point256FieldId, Point256ElementBytes, out LongfellowSumcheckCircuit? signature, out _, out int signatureBytes);
        using LongfellowSumcheckCircuit? signatureOwner = signature;
        Assert.IsTrue(signatureParsed, "The signature circuit must parse.");
        Assert.IsNotNull(signature);

        bool hashParsed = CircuitScope.TryRead(raw.AsSpan(signatureBytes), Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? hash, out _, out int hashBytes);
        using LongfellowSumcheckCircuit? hashOwner = hash;
        Assert.IsTrue(hashParsed, "The hash circuit must parse from the continuation of the stream.");
        Assert.IsNotNull(hash);

        Assert.AreEqual(raw.Length, signatureBytes + hashBytes, "The two circuits must consume the whole stream with no trailing bytes.");
    }


    /// <summary>Verifies that the parsed P-256 signature circuit's shape and subfield boundary equal the reference's recorded values.</summary>
    [TestMethod]
    public void TheSignatureCircuitShapeMatchesTheReference()
    {
        using LongfellowSumcheckCircuit signature = ParseSignatureCircuit(out int subfieldBoundary);

        AssertShapeMatches("sig", signature);
        Assert.AreEqual(Anchor("sig_subfield_boundary"), subfieldBoundary, "sig subfield_boundary");
    }


    /// <summary>
    /// Verifies that the parsed GF(2^128) hash circuit's shape and subfield boundary equal the
    /// reference's recorded values, and that both the hash and signature circuits satisfy
    /// <c>logc == 0</c> (no copies), the precondition the sumcheck wire layer requires.
    /// </summary>
    [TestMethod]
    public void TheHashCircuitShapeMatchesTheReferenceAndHasNoCopies()
    {
        using LongfellowSumcheckCircuit hash = ParseHashCircuit(out int subfieldBoundary);

        AssertShapeMatches("hash", hash);
        Assert.AreEqual(Anchor("hash_subfield_boundary"), subfieldBoundary, "hash subfield_boundary");

        //logc == 0 is the precondition the whole sumcheck wire layer asserts (no copies).
        Assert.AreEqual(0, hash.CopyRounds, "The hash circuit must have logc == 0.");

        using LongfellowSumcheckCircuit signature = ParseSignatureCircuit(out _);
        Assert.AreEqual(0, signature.CopyRounds, "The signature circuit must have logc == 0.");
    }


    /// <summary>Verifies that a sample of the hash circuit's first- and last-layer quad terms (gate, hand indices, coefficient) equal the reference's recorded terms.</summary>
    [TestMethod]
    public void TheHashCircuitSampleQuadTermsMatchTheReference()
    {
        using LongfellowSumcheckCircuit hash = ParseHashCircuit(out _);

        AssertLayerSampleTerms(hash, 0, "hash", 0);
        AssertLayerSampleTerms(hash, hash.LayerCount - 1, "hash", 16);
    }


    /// <summary>
    /// Verifies that the reference's recorded hash-circuit witness column is sized to the imported
    /// circuit's input count (one GF(2^128) element per input wire) and that its SHA-256 equals the
    /// reference's own digest, gating the witness-column contract without performing a full prove
    /// over the (infeasibly large) real hash circuit.
    /// </summary>
    [TestMethod]
    public void TheHashWitnessColumnMatchesTheImportedCircuitInputContract()
    {
        const string witnessGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-hash-witness.gz";

        using LongfellowSumcheckCircuit hash = ParseHashCircuit(out _);
        byte[] witnessColumn = DecompressGzip(ReadFixture(witnessGzipRelativePath));

        //The reference's fill_witness + post-commit update_macs produce one GF(2^128) element per input
        //wire, each 16 little-endian to_bytes_field bytes. The column the C# prover would consume is the
        //same width as the imported circuit's input count. (The full prove over the imported hash circuit
        //is infeasible at this scale, so this test gates the witness-column contract rather than
        //performing a full prove.)
        Assert.AreEqual(Anchor("hash_witness_ninputs"), hash.InputCount, "The witness column is sized to the imported circuit's input count.");
        Assert.HasCount(hash.InputCount * Gf2128ElementBytes, witnessColumn, "The witness column is ninputs * 16 little-endian element bytes.");

        string computed = Convert.ToHexStringLower(SHA256.HashData(witnessColumn));
        Assert.AreEqual(Anchors["hash_witness_rawsha"], computed, "The witness column bytes must equal the reference's recorded column.");
    }


    /// <summary>Verifies that the compressed real-circuit blob's length and SHA-256 equal the reference's own computed circuit hash.</summary>
    [TestMethod]
    public void TheCompressedBlobReproducesTheReferenceCircuitHash()
    {
        byte[] compressed = ReadFixture(CompressedRelativePath);

        Assert.HasCount(Anchor("compressed_zst_len"), compressed, "The compressed blob length must match the reference.");

        string computed = Convert.ToHexStringLower(SHA256.HashData(compressed));

        Assert.AreEqual(Anchors["computed_circuit_hash"], computed, "SHA-256 of the compressed blob must equal the reference's computed circuit hash.");
    }


    /// <summary>Verifies that the SHA-256 of the decompressed real circuit bytes equals the reference's raw digest.</summary>
    [TestMethod]
    public void TheDecompressedRawBytesReproduceTheReferenceDigest()
    {
        string computed = Convert.ToHexStringLower(SHA256.HashData(RawCircuitBytes));

        Assert.AreEqual(Anchors["raw_rawsha"], computed, "SHA-256 of the decompressed raw circuit bytes must equal the reference's raw digest.");
    }


    /// <summary>
    /// Verifies that the small functional circuit parses from its serialization with the expected
    /// id, shape and subfield boundary, and that a proof built from a satisfying witness column over
    /// the parsed circuit is accepted by the verifier driven through the same import path.
    /// </summary>
    [TestMethod]
    public void TheImportedSmallCircuitDrivesTheProverAndVerifier()
    {
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);

        bool parsed = CircuitScope.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? circuit, out int subfieldBoundary, out int consumed);
        using LongfellowSumcheckCircuit? circuitOwner = circuit;
        Assert.IsTrue(parsed, "The small circuit must parse.");
        Assert.IsNotNull(circuit);
        Assert.AreEqual(serialized.Length, consumed, "The small circuit must consume its whole serialization.");
        Assert.AreEqual(SubfieldBoundary, subfieldBoundary, "The small circuit's subfield_boundary is 0.");

        //The parsed circuit equals the end-to-end-prove anchor circuit: same id and shape.
        byte[] expectedId = Convert.FromHexString(Anchors["small_circuit_id"]);
        Assert.IsTrue(circuit.Id.Span.SequenceEqual(expectedId), "The imported circuit id must match the writer's id.");
        Assert.AreEqual(1, circuit.OutputCount, "nv must be 1.");
        Assert.AreEqual(3, circuit.LayerCount, "nl must be 3.");
        Assert.AreEqual(5, circuit.InputCount, "ninputs must be 5.");
        Assert.AreEqual(2, circuit.PublicInputCount, "npub_in must be 2.");
        Assert.AreEqual(0, circuit.CopyRounds, "logc must be 0.");

        //Our end-to-end ZK prover over the imported circuit produces a proof our end-to-end ZK verifier accepts.
        byte[] witnessColumn = BuildSatisfyingColumn(circuit, 3, 5, 7);
        using LongfellowZkProofEnvelope proof = ProduceProof(circuit, witnessColumn, TranscriptSeed);

        AssertVerifies(circuit, proof.Bytes, PublicInputBytes(circuit, witnessColumn));
    }


    /// <summary>Verifies that every truncated prefix of the small circuit's serialization fails to parse, producing no circuit and consuming zero bytes.</summary>
    [TestMethod]
    public void TruncatedInputReturnsFailure()
    {
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);

        for(int length = 0; length < serialized.Length; length += 7)
        {
            bool parsed = CircuitScope.TryRead(serialized.AsSpan(0, length), Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? circuit, out _, out int consumed);
            using LongfellowSumcheckCircuit? circuitOwner = circuit;

            Assert.IsFalse(parsed, $"A {length}-byte prefix must not parse.");
            Assert.IsNull(circuit);
            Assert.AreEqual(0, consumed);
        }
    }


    /// <summary>Verifies that a serialization whose version byte does not match the reader's expected version fails to parse.</summary>
    [TestMethod]
    public void WrongVersionReturnsFailure()
    {
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);
        serialized[0] = 0x02;

        bool parsed = CircuitScope.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out _, out _, out _);

        Assert.IsFalse(parsed, "A wrong version byte must not parse.");
    }


    /// <summary>Checks rejection after all constants and terms have been parsed releases the only coefficient slab.</summary>
    [TestMethod]
    public void ATruncatedIdentifierReleasesParsedConstantStorage()
    {
        using BaseMemoryPool pool = new();
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);
        bool parsed = LongfellowCircuitReader.TryRead(serialized.AsSpan(0, serialized.Length - 1), Gf2128FieldId, Gf2128ElementBytes, pool, out LongfellowSumcheckCircuit? circuit, out int boundary, out int consumed);
        using LongfellowSumcheckCircuit? circuitOwner = circuit;

        Assert.IsFalse(parsed);
        Assert.IsNull(circuit);
        Assert.AreEqual(0, boundary);
        Assert.AreEqual(0, consumed);
        Assert.AreEqual(1, pool.TrimExcess(), "The small fixture's single coefficient slab must have no active rentals after rejection.");
    }


    /// <summary>Checks a throwing range callback releases parser storage and propagates the original exception.</summary>
    [TestMethod]
    public void AThrowingConstantRangeReleasesParsedStorage()
    {
        using BaseMemoryPool pool = new();
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);
        var expected = new InvalidOperationException("The constant range callback failed.");
        LongfellowSumcheckCircuit? circuit = null;
        try
        {
            InvalidOperationException actual = Assert.ThrowsExactly<InvalidOperationException>(() =>
                LongfellowCircuitReader.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, pool, out circuit, out _, out _, canonical => throw expected));

            Assert.AreSame(expected, actual);
            Assert.IsNull(circuit);
            Assert.AreEqual(1, pool.TrimExcess(), "The range callback's exception must release the parser's coefficient slab.");
        }
        finally
        {
            circuit?.Dispose();
        }
    }


    /// <summary>Checks an empty constant table reaches term-index rejection without renting storage.</summary>
    [TestMethod]
    public void AnEmptyConstantTableRejectsWithoutARental()
    {
        using BaseMemoryPool pool = new();
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);
        int constantsOffset = 1 + (8 * BytesPerSizeT);
        int layersOffset = FirstLayerOffset(serialized);
        serialized.AsSpan(layersOffset).CopyTo(serialized.AsSpan(constantsOffset));
        serialized.AsSpan(constantsOffset - BytesPerSizeT, BytesPerSizeT).Clear();
        int length = serialized.Length - (layersOffset - constantsOffset);
        bool parsed = LongfellowCircuitReader.TryRead(serialized.AsSpan(0, length), Gf2128FieldId, Gf2128ElementBytes, pool, out LongfellowSumcheckCircuit? circuit, out _, out _);
        using LongfellowSumcheckCircuit? circuitOwner = circuit;

        Assert.IsFalse(parsed);
        Assert.IsNull(circuit);
        Assert.AreEqual(0, pool.TrimExcess(), "The empty table must reach rejection without allocating a coefficient slab.");
    }


    /// <summary>Verifies that a serialization whose declared layer count (<c>nl</c>) is zero fails to parse rather than throwing through the circuit constructors.</summary>
    [TestMethod]
    public void AZeroLayerCountReturnsFailure()
    {
        //nl is the seventh 3-byte header field after the version byte; a crafted zero must parse
        //to false rather than throw through the circuit constructors.
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);
        int layerCountOffset = 1 + (6 * BytesPerSizeT);
        serialized.AsSpan(layerCountOffset, BytesPerSizeT).Clear();

        bool parsed = CircuitScope.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? circuit, out _, out _);
        using LongfellowSumcheckCircuit? circuitOwner = circuit;

        Assert.IsFalse(parsed, "A zero layer count must not parse.");
        Assert.IsNull(circuit);
    }


    /// <summary>Verifies that a serialization whose first layer declares zero hand rounds (<c>logw</c>) fails to parse rather than throwing through the layer constructor.</summary>
    [TestMethod]
    public void AZeroHandRoundLayerReturnsFailure()
    {
        //The first layer header's logw sits right after the fixed header and the constant table; a
        //crafted zero must parse to false rather than throw through the layer constructor.
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);
        serialized.AsSpan(FirstLayerOffset(serialized), BytesPerSizeT).Clear();

        bool parsed = CircuitScope.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? circuit, out _, out _);
        using LongfellowSumcheckCircuit? circuitOwner = circuit;

        Assert.IsFalse(parsed, "A zero-hand-round layer must not parse.");
        Assert.IsNull(circuit);
    }


    /// <summary>Verifies that a maximal 3-byte declared count — the constant count, then a layer's term count — fails the bounds check before any record array is allocated, for both the constant table and a layer's term list.</summary>
    [TestMethod]
    public void AnOversizedDeclaredCountReturnsFailure()
    {
        //numconst and a layer's nq declare how many fixed-size records follow; the maximal 3-byte
        //value (16,777,215 records) exceeds the remaining buffer, so the bounds check must fail
        //BEFORE the record array is allocated — false, no exception, no huge allocation.
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);
        int constantCountOffset = 1 + (7 * BytesPerSizeT);
        serialized.AsSpan(constantCountOffset, BytesPerSizeT).Fill(0xFF);

        bool parsed = CircuitScope.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? circuit, out _, out _);
        using LongfellowSumcheckCircuit? circuitOwner = circuit;

        Assert.IsFalse(parsed, "An oversized constant count must not parse.");
        Assert.IsNull(circuit);

        serialized = Convert.FromHexString(Anchors["small_serialized"]);
        int termCountOffset = FirstLayerOffset(serialized) + (2 * BytesPerSizeT);
        serialized.AsSpan(termCountOffset, BytesPerSizeT).Fill(0xFF);

        parsed = CircuitScope.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out circuit, out _, out _);
        using LongfellowSumcheckCircuit? circuitUpdatedOwner = circuit;

        Assert.IsFalse(parsed, "An oversized term count must not parse.");
        Assert.IsNull(circuit);
    }


    /// <summary>Verifies that a term whose value-index field points past the end of the constant table fails to parse rather than indexing out of the table.</summary>
    [TestMethod]
    public void AnOutOfRangeConstantIndexReturnsFailure()
    {
        //The first term's value index field points past the constant table; the vi < numconst check
        //must reject it rather than index out of the table.
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);
        int valueIndexOffset = FirstLayerOffset(serialized) + (3 * BytesPerSizeT) + (3 * BytesPerSizeT);
        serialized.AsSpan(valueIndexOffset, BytesPerSizeT).Fill(0xFF);

        bool parsed = CircuitScope.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? circuit, out _, out _);
        using LongfellowSumcheckCircuit? circuitOwner = circuit;

        Assert.IsFalse(parsed, "An out-of-range constant index must not parse.");
        Assert.IsNull(circuit);
    }


    /// <summary>Verifies that a gate-index delta driving the first term's gate index below zero (underflow) or to <c>nv</c> (past the upper bound) fails to parse rather than being stored.</summary>
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

        bool parsed = CircuitScope.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? circuit, out _, out _);
        using LongfellowSumcheckCircuit? circuitOwner = circuit;

        Assert.IsFalse(parsed, "An underflowing gate delta must not parse.");
        Assert.IsNull(circuit);

        serialized = Convert.FromHexString(Anchors["small_serialized"]);
        serialized.AsSpan(gateDeltaOffset, BytesPerSizeT).Clear();
        serialized[gateDeltaOffset] = 0x02;

        parsed = CircuitScope.TryRead(serialized, Gf2128FieldId, Gf2128ElementBytes, out circuit, out _, out _);
        using LongfellowSumcheckCircuit? circuitUpdatedOwner = circuit;

        Assert.IsFalse(parsed, "A gate delta past max_g must not parse.");
        Assert.IsNull(circuit);
    }


    /// <summary>Verifies that parsing a GF(2^128)-encoded serialization while requesting the P-256 field id fails the field-id check.</summary>
    [TestMethod]
    public void WrongFieldIdReturnsFailure()
    {
        byte[] serialized = Convert.FromHexString(Anchors["small_serialized"]);

        //The serialization carries GF2_128_ID (4); parsing it as P256 (1) must fail the field-id check.
        bool parsed = CircuitScope.TryRead(serialized, Point256FieldId, Point256ElementBytes, out _, out _, out _);

        Assert.IsFalse(parsed, "A field-id mismatch must not parse.");
    }


    /// <summary>Computes the byte offset of the first layer header: after the version byte, the eight 3-byte header fields, and the constant table (sized by the eighth header field, the constant count).</summary>
    private static int FirstLayerOffset(byte[] serialized)
    {
        int constantCountOffset = 1 + (7 * BytesPerSizeT);
        int constantCount = serialized[constantCountOffset] | (serialized[constantCountOffset + 1] << 8) | (serialized[constantCountOffset + 2] << 16);

        return 1 + (8 * BytesPerSizeT) + (constantCount * Gf2128ElementBytes);
    }


    /// <summary>Parses the P-256 signature circuit out of <see cref="RawCircuitBytes"/>, asserting the parse succeeds; the caller disposes the returned circuit.</summary>
    private LongfellowSumcheckCircuit ParseSignatureCircuit(out int subfieldBoundary)
    {
        bool parsed = CircuitScope.TryRead(RawCircuitBytes, Point256FieldId, Point256ElementBytes, out LongfellowSumcheckCircuit? signature, out subfieldBoundary, out _);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(signature);

        return signature;
    }


    /// <summary>Parses the signature circuit and then the GF(2^128) hash circuit out of <see cref="RawCircuitBytes"/>, asserting both parses succeed; the caller disposes the returned hash circuit.</summary>
    private LongfellowSumcheckCircuit ParseHashCircuit(out int subfieldBoundary)
    {
        bool signatureParsed = CircuitScope.TryRead(RawCircuitBytes, Point256FieldId, Point256ElementBytes, out _, out _, out int signatureBytes);
        Assert.IsTrue(signatureParsed);

        bool hashParsed = CircuitScope.TryRead(RawCircuitBytes.AsSpan(signatureBytes), Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? hash, out subfieldBoundary, out _);
        Assert.IsTrue(hashParsed);
        Assert.IsNotNull(hash);

        return hash;
    }


    /// <summary>Asserts that every shape field of <paramref name="circuit"/> — <c>nv</c>, <c>logv</c>, <c>nc</c>, <c>logc</c>, <c>nl</c>, <c>ninputs</c>, <c>npub_in</c>, the id, and every layer's <c>nw</c>/<c>logw</c>/<c>nterms</c> — equals the anchor's recorded value keyed by <paramref name="prefix"/>.</summary>
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


    /// <summary>Asserts that the sampled quad terms of the layer at <paramref name="layerIndex"/> equal the anchor's recorded terms keyed by <paramref name="prefix"/> and <paramref name="anchorLayerIndex"/>, for as many terms as both the layer and the anchor carry.</summary>
    private static void AssertLayerSampleTerms(LongfellowSumcheckCircuit circuit, int layerIndex, string prefix, int anchorLayerIndex)
    {
        LongfellowSumcheckLayer layer = circuit.Layers[layerIndex];

        for(int t = 0; t < 8 && t < layer.TermCount; t++)
        {
            string baseKey = $"{prefix}_L{anchorLayerIndex}_t{t}";
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


    /// <summary>Derives Ligero parameters for <paramref name="circuit"/> and produces a proof over <paramref name="witnessColumn"/>; the caller disposes the returned pooled proof envelope.</summary>
    private static LongfellowZkProofEnvelope ProduceProof(LongfellowSumcheckCircuit circuit, byte[] witnessColumn, byte[] seed)
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


    /// <summary>Asserts that <paramref name="proof"/> is accepted by the verifier for <paramref name="circuit"/> against <paramref name="publicInputs"/>.</summary>
    private static void AssertVerifies(LongfellowSumcheckCircuit circuit, ReadOnlySpan<byte> proof, byte[] publicInputs)
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


    /// <summary>
    /// Builds a satisfying witness column <c>[one, x, y, z, w]</c> over GF(2^128) with
    /// <c>x</c>/<c>y</c>/<c>z</c> = <c>of_scalar(...)</c> of the like-named parameters and
    /// <c>w = (x + y)·(x + z)·x</c>, identical to the end-to-end ZK prover gate's construction.
    /// </summary>
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


    /// <summary>Computes the GF(2^128) field element for <paramref name="value"/> via <paramref name="fft"/>'s basis elements (the reference's <c>of_scalar</c>), summing the basis elements at the value's set bits.</summary>
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


    /// <summary>Builds the on-wire public-input byte column for <paramref name="circuit"/> from the leading public elements of <paramref name="witnessColumn"/>.</summary>
    private static byte[] PublicInputBytes(LongfellowSumcheckCircuit circuit, byte[] witnessColumn)
    {
        byte[] publicInputs = new byte[circuit.PublicInputCount * ElementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            ToBytesField(witnessColumn.AsSpan(i * ScalarSize, ScalarSize), publicInputs.AsSpan(i * ElementBytes, ElementBytes));
        }

        return publicInputs;
    }


    /// <summary>Creates a deterministic <see cref="LongfellowRandomByteSource"/> that fills its output with an incrementing byte counter.</summary>
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


    /// <summary>Parses a 16-byte little-endian element into a 32-byte big-endian canonical scalar.</summary>
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


    /// <summary>Writes <paramref name="canonical"/> out as the on-wire little-endian element bytes, the reverse of the canonical big-endian scalar layout.</summary>
    private static void ToBytesField(ReadOnlySpan<byte> canonical, Span<byte> littleEndian)
    {
        for(int i = 0; i < ElementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }


    /// <summary>Reads a test-fixture file's raw bytes given its path relative to the test project.</summary>
    private static byte[] ReadFixture(string relativePath) =>
        File.ReadAllBytes($"../../../{relativePath}");


    /// <summary>Decompresses a gzip-compressed byte array.</summary>
    private static byte[] DecompressGzip(byte[] gzip)
    {
        using var input = new MemoryStream(gzip);
        using var gzipStream = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzipStream.CopyTo(output);

        return output.ToArray();
    }


    /// <summary>Parses the reference-computed anchor value keyed by <paramref name="key"/> as an integer.</summary>
    private static int Anchor(string key) => int.Parse(Anchors[key], CultureInfo.InvariantCulture);


    /// <summary>Creates a transcript seeded with <paramref name="seed"/>, wired to this file's AES-256-ECB and SHA-256 delegates.</summary>
    private static LongfellowTranscript NewTranscript(byte[] seed) =>
        new(seed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Creates the production-16 subfield additive FFT used to derive <c>of_scalar</c> values and drive the prove/verify gate.</summary>
    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>Computes the one-shot SHA-256 digest of <paramref name="input"/> into <paramref name="output"/>; <paramref name="hashFunction"/> is unused since this file only ever selects SHA-256.</summary>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        SHA256.HashData(input, output);
    }


    /// <summary>Computes the two-to-one SHA-256 compression of <paramref name="left"/> concatenated with <paramref name="right"/> into <paramref name="output"/>.</summary>
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[left.Length + right.Length];
        left.CopyTo(combined);
        right.CopyTo(combined[left.Length..]);
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>Encrypts one AES-256 block in ECB mode (no padding) with <paramref name="key"/>, the transcript's block cipher.</summary>
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    /// <summary>Loads a fixture's <c>key=value</c> tokens from every non-empty line into a case-sensitive lookup, skipping any token without an <c>=</c>.</summary>
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
