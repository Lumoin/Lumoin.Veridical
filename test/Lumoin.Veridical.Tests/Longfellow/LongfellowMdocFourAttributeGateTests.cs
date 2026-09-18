using Lumoin.Veridical.Core;
using Lumoin.Veridical.Longfellow;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Longfellow;

/// <summary>
/// The four-attribute breadth gate: <see cref="LongfellowMdoc.Verify"/> parameterized by
/// <see cref="LongfellowMdocZkSpec.Version7FourAttributes"/> ACCEPTS the reference implementation's real
/// four-attribute envelope (kZkSpecs[3] over the Sprind-Funke example credential, disclosing family_name,
/// birth_date, height and issue_date) — the four-attribute dual of the crown gate, driven through the public
/// facade so the spec registry row is exercised end to end. Tamper duals flip an envelope byte and a
/// public-template byte and confirm the verdict is no longer accepted.
/// </summary>
/// <remarks>
/// The anchor (<c>mdoc-zk-anchor-4attr-output.txt</c>) carries the envelope, the public-input templates
/// and the session transcript; the circuit bundle is the imported kZkSpecs[3] raw stream. The
/// signature template arrives little-endian in the fixture and is reversed to the canonical big-endian form
/// the statement carries; the facade frames it back into the Montgomery wire domain internally.
/// </remarks>
[TestClass]
internal sealed class LongfellowMdocFourAttributeGateTests
{
    /// <summary>
    /// The path, relative to the test project, of the gzip-compressed reference four-attribute
    /// raw circuit bytes.
    /// </summary>
    private const string RawGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-raw-4attr.gz";

    /// <summary>
    /// The path, relative to the test project, of the gzip-compressed four-attribute
    /// hash-witness column.
    /// </summary>
    private const string WitnessGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-hash-witness-4attr.gz";

    /// <summary>
    /// The path, relative to the test project, of the four-attribute anchor carrying the
    /// envelope, the public-input templates and the session transcript.
    /// </summary>
    private const string AnchorRelativePath = "TestMaterial/Longfellow/mdoc-zk-anchor-4attr-output.txt";

    /// <summary>
    /// The path, relative to the test project, of the four-attribute anchor carrying the raw and
    /// hash-witness circuit digests.
    /// </summary>
    private const string CircuitAnchorRelativePath = "TestMaterial/Longfellow/mdoc-circuit-anchor-4attr-output.txt";

    /// <summary>
    /// One canonical field element per 32-byte big-endian slot in the signature template.
    /// </summary>
    private const int ScalarSize = 32;

    /// <summary>
    /// A byte offset well inside the hash ZkProof region of the envelope, past the 96-byte MAC
    /// prefix; flipping the byte there must break the hash-circuit verify without touching the
    /// MAC prefix or the signature region.
    /// </summary>
    private const int EnvelopeTamperOffset = 5000;

    /// <summary>
    /// A byte offset inside the attribute-bit region of the hash template (element 100);
    /// flipping the byte there changes the public statement and must break the spliced-template
    /// verify.
    /// </summary>
    private const int TemplateTamperOffset = 100 * LongfellowMdocStatement.HashTemplateElementBytes;

    /// <summary>
    /// The decompressed reference four-attribute circuit-definition bytes (~115 MB), decompressed
    /// once and shared across the tests in this class.
    /// </summary>
    private static byte[] RawCircuitBytes { get; } = DecompressGzip(ReadFixture(RawGzipRelativePath));

    /// <summary>
    /// The four-attribute anchor's key/value pairs, keyed by field name.
    /// </summary>
    private static Dictionary<string, string> AnchorFixture { get; } = LoadFixture(AnchorRelativePath);

    /// <summary>
    /// The four-attribute circuit anchor's key/value pairs, keyed by field name.
    /// </summary>
    private static Dictionary<string, string> CircuitAnchorFixture { get; } = LoadFixture(CircuitAnchorRelativePath);


    /// <summary>
    /// Verifies that hashing the decompressed four-attribute raw circuit bytes reproduces the
    /// digest recorded in the circuit anchor.
    /// </summary>
    [TestMethod]
    public void TheCommittedFourAttributeRawStreamReproducesTheAnchorDigest()
    {
        string computed = Convert.ToHexStringLower(SHA256.HashData(RawCircuitBytes));

        Assert.AreEqual(CircuitAnchorFixture["raw_rawsha"], computed, "SHA-256 of the decompressed four-attribute raw circuit bytes must equal the reference's raw digest.");
    }


    /// <summary>
    /// Verifies that hashing the decompressed four-attribute hash-witness column reproduces the
    /// digest recorded in the circuit anchor.
    /// </summary>
    [TestMethod]
    public void TheCommittedFourAttributeWitnessColumnReproducesTheAnchorDigest()
    {
        byte[] witnessColumn = DecompressGzip(ReadFixture(WitnessGzipRelativePath));

        string computed = Convert.ToHexStringLower(SHA256.HashData(witnessColumn));
        Assert.AreEqual(CircuitAnchorFixture["hash_witness_rawsha"], computed, "SHA-256 of the four-attribute witness column must equal the reference's anchor column digest.");
    }


    /// <summary>
    /// Verifies that <see cref="LongfellowMdoc.Verify"/> accepts the reference four-attribute
    /// envelope built from the anchor's components, and that flipping a byte in either the
    /// envelope or the public hash template flips the verdict to rejected.
    /// </summary>
    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void TheFacadeAcceptsTheReferenceFourAttributeEnvelopeAndRejectsTampers()
    {
        //On the order of tens of seconds to a minute, hardware-dependent: three verifies over the imported
        //~115 MB four-attribute raw bundle (the facade re-parses the circuits per call). The default-suite
        //pin tests cover the fixture identity and the spec registry row cheaply.
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        LongfellowMdocZkSpec spec = LongfellowMdocZkSpec.Version7FourAttributes;
        LongfellowMdocCircuitSource circuits = LongfellowMdocCircuitSource.FromRawBytes(RawCircuitBytes);

        byte[] hashTemplate = Convert.FromHexString(AnchorFixture["hash_template"]);
        Assert.HasCount(spec.HashTemplateElementCount * LongfellowMdocStatement.HashTemplateElementBytes, hashTemplate, "The hash template is 3297 * 16 element bytes.");

        byte[] signatureTemplateWire = Convert.FromHexString(AnchorFixture["sig_template"]);
        Assert.HasCount(LongfellowMdocStatement.SignatureTemplateElementCount * ScalarSize, signatureTemplateWire, "The signature template is 4 * 32 element bytes.");
        byte[] signatureTemplateCanonical = ReverseElements(signatureTemplateWire);

        LongfellowMdocStatement statement = LongfellowMdocStatement.FromComponents(spec, hashTemplate, signatureTemplateCanonical);

        byte[] envelope = Convert.FromHexString(AnchorFixture["envelope"]);
        byte[] transcriptSeed = Convert.FromHexString(AnchorFixture["transcript"]);

        using LongfellowMdocProof proof = LongfellowMdocProof.FromCanonical(envelope, pool);
        LongfellowMdocVerdict verdict = LongfellowMdoc.Verify(proof, statement, circuits, transcriptSeed, pool);

        Assert.AreEqual(LongfellowMdocVerdict.Accepted, verdict, "The facade must accept the reference four-attribute envelope.");

        //The envelope tamper dual: a flipped byte inside the hash ZkProof region must no longer be accepted.
        using IMemoryOwner<byte> tamperedOwner = pool.Rent(envelope.Length);
        Span<byte> tamperedEnvelope = tamperedOwner.Memory.Span[..envelope.Length];
        envelope.CopyTo(tamperedEnvelope);
        tamperedEnvelope[LongfellowMdocProof.MacRegionBytes + EnvelopeTamperOffset] ^= 0x01;

        using LongfellowMdocProof tamperedProof = LongfellowMdocProof.FromCanonical(tamperedEnvelope, pool);
        LongfellowMdocVerdict tamperedVerdict = LongfellowMdoc.Verify(tamperedProof, statement, circuits, transcriptSeed, pool);

        //The flip lands inside the hash ZkProof's fixed-length sumcheck segment, so the specific expected
        //verdict is a hash-circuit rejection — not merely "not accepted" — matching the crown-gate pins.
        Assert.AreEqual(LongfellowMdocVerdict.HashRejected, tamperedVerdict, "A flipped envelope byte must fail the hash-circuit verify.");

        //The statement tamper dual: a flipped attribute bit in the public hash template must no longer verify
        //against the genuine envelope.
        hashTemplate[TemplateTamperOffset] ^= 0x01;
        LongfellowMdocStatement tamperedStatement = LongfellowMdocStatement.FromComponents(spec, hashTemplate, signatureTemplateCanonical);
        LongfellowMdocVerdict tamperedStatementVerdict = LongfellowMdoc.Verify(proof, tamperedStatement, circuits, transcriptSeed, pool);

        //The tampered element sits in the hash template, so the hash side rejects the spliced public inputs.
        Assert.AreEqual(LongfellowMdocVerdict.HashRejected, tamperedStatementVerdict, "A flipped public-template byte must fail the hash-circuit verify.");
    }


    /// <summary>
    /// Reverses each 32-byte element of a little-endian wire template into the canonical
    /// big-endian form the statement carries.
    /// </summary>
    /// <param name="littleEndianTemplate">The little-endian wire template to reverse.</param>
    /// <returns>The template with each element's bytes reversed to big-endian.</returns>
    private static byte[] ReverseElements(byte[] littleEndianTemplate)
    {
        byte[] canonical = new byte[littleEndianTemplate.Length];
        for(int element = 0; element < littleEndianTemplate.Length / ScalarSize; element++)
        {
            for(int i = 0; i < ScalarSize; i++)
            {
                canonical[(element * ScalarSize) + i] = littleEndianTemplate[(element * ScalarSize) + ScalarSize - 1 - i];
            }
        }

        return canonical;
    }


    /// <summary>
    /// Reads a fixture file's raw bytes from its path relative to the test project.
    /// </summary>
    /// <param name="relativePath">The fixture file's path, relative to the test project.</param>
    /// <returns>The fixture file's raw bytes.</returns>
    private static byte[] ReadFixture(string relativePath) => File.ReadAllBytes($"../../../{relativePath}");


    /// <summary>
    /// Decompresses a gzip-compressed byte array.
    /// </summary>
    /// <param name="gzip">The gzip-compressed bytes.</param>
    /// <returns>The decompressed bytes.</returns>
    private static byte[] DecompressGzip(byte[] gzip)
    {
        using var input = new MemoryStream(gzip);
        using var gzipStream = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzipStream.CopyTo(output);

        return output.ToArray();
    }


    /// <summary>
    /// Loads a fixture's newline-delimited <c>key=value</c> pairs into a dictionary keyed by name.
    /// </summary>
    /// <param name="relativePath">The fixture file's path, relative to the test project.</param>
    /// <returns>The fixture's entries, keyed by name.</returns>
    private static Dictionary<string, string> LoadFixture(string relativePath)
    {
        string path = $"../../../{relativePath}";
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach(string line in File.ReadAllLines(path))
        {
            int separator = line.IndexOf('=', StringComparison.Ordinal);
            if(separator < 0)
            {
                continue;
            }

            map[line[..separator]] = line[(separator + 1)..];
        }

        return map;
    }
}
