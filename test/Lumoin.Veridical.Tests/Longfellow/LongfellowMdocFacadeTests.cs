using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Longfellow;
using Lumoin.Veridical.Tests.Mdoc;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Numerics;
using System.Text;

namespace Lumoin.Veridical.Tests.Longfellow;

/// <summary>
/// The public dual-field mdoc FACADE gate: <see cref="LongfellowMdoc.Prove"/> over the real credential
/// (mdoc-00) produces a proof <see cref="LongfellowMdoc.Verify"/> ACCEPTS — the single full round-trip
/// through the curated surface, with the test playing the caller that fills the witness/statement/circuit
/// seams. The witness columns, common values, MAC keys and public-input templates are assembled the same way
/// the lower-level driver gate assembles them (the reconciled mdoc fillers and the device-authentication
/// hash from the anchor fixture); the facade owns the circuit parsing, the field bundles, the
/// canonical-to-Montgomery signature lift, the shared transcript and the proof envelope.
/// </summary>
/// <remarks>
/// The signature column and template are supplied CANONICAL — the facade lifts the column and frames the
/// template into the Montgomery wire domain internally — so the caller never touches the working-domain
/// detail. A tamper dual flips one envelope byte and confirms the verdict is no longer accepted, proving the
/// proof is actually checked.
/// </remarks>
[TestClass]
internal sealed class LongfellowMdocFacadeTests
{
    private const string RawGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-raw.gz";
    private const string AnchorRelativePath = "TestMaterial/Longfellow/mdoc-zk-anchor-output.txt";
    private const string CredentialRelativePath = "TestMaterial/Mdoc/mdoc-00.cbor";

    private const string AgeOver18Namespace = "org.iso.18013.5.1";
    private const string AgeOver18Element = "age_over_18";

    private const int ScalarSize = Scalar.SizeBytes;

    //The first signature template element index whose canonical big-endian bytes the anchor fixture pins is
    //the device-authentication hash e2 (one, pkX, pkY, e2 — index 3).
    private const int DeviceHashTemplateIndex = 3;

    //A byte well inside the hash ZkProof region of the envelope, past the 96-byte MAC prefix; flipping it must
    //break the hash-circuit verify without touching the MAC prefix or the signature region.
    private const int TamperOffset = 5000;

    private static readonly byte[] Now = Encoding.ASCII.GetBytes("2024-01-30T09:00:00Z");

    //A fixed session seed; the facade's prove and verify each build a fresh transcript from it.
    private static readonly byte[] SessionSeed = Encoding.ASCII.GetBytes("lumoin-veridical-longfellow-facade-roundtrip");

    private static readonly ScalarAddDelegate GfAdd = Gf2k128Backend.GetAdd();
    private static readonly ScalarSubtractDelegate GfSubtract = Gf2k128Backend.GetSubtract();
    private static readonly ScalarMultiplyDelegate GfMultiply = Gf2k128Backend.GetMultiply();
    private static readonly ScalarInvertDelegate GfInvert = Gf2k128Backend.GetInvert();

    //The decompressed reference circuit-definition bytes (~99 MB); decompress once and share.
    private static byte[] RawCircuitBytes { get; } = DecompressGzip(ReadFixture(RawGzipRelativePath));

    private static Dictionary<string, string> AnchorFixture { get; } = LoadFixture(AnchorRelativePath);


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void TheFacadeProvesARealCredentialItThenVerifies()
    {
        //On the order of a few minutes, hardware-dependent: a full dual-field prove commits and proves the
        //genuine ~85k-wire hash circuit and the P-256 signature circuit through the Ligero-over-the-whole-R1CS
        //path, with a second verify for the tamper dual.
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        byte[] credential = ReadFixture(CredentialRelativePath);
        LongfellowMdocCircuitSource circuits = LongfellowMdocCircuitSource.FromRawBytes(RawCircuitBytes);

        //The caller assembles the two field witness columns, the common values and the shared MAC keys.
        byte[] hashColumn = BuildHashColumn(credential, pool);

        MdocDisclosure issuer = MdocDisclosure.Extract(credential, AgeOver18Namespace, AgeOver18Element);
        MdocDeviceSignature device = MdocDeviceSignature.Extract(credential, DeviceHash());
        byte[] signatureColumn = new MdocSignatureWitnessFiller().FillForDriver(issuer, device);
        byte[] commonValues = MdocSignatureWitnessFiller.CommonValues(issuer, device);
        byte[] apKeys = MdocSignatureWitnessFiller.ApKeyBytes();

        LongfellowMdocWitness witness = LongfellowMdocWitness.FromComponents(hashColumn, signatureColumn, commonValues, apKeys);

        //The public statement: the hash template is the column prefix in GF wire framing; the signature
        //template is the canonical [one, pkX, pkY, e2] prefix the facade frames into the Montgomery wire form.
        int hashTemplateBytes = LongfellowMdocStatement.HashTemplateElementCount * LongfellowMdocStatement.HashTemplateElementBytes;
        using IMemoryOwner<byte> hashTemplateOwner = pool.Rent(hashTemplateBytes);
        Memory<byte> hashTemplate = hashTemplateOwner.Memory[..hashTemplateBytes];
        BuildHashTemplate(hashColumn, hashTemplate.Span);

        ReadOnlyMemory<byte> signatureTemplate = new ReadOnlyMemory<byte>(signatureColumn, 0, LongfellowMdocStatement.SignatureTemplateElementCount * ScalarSize);
        LongfellowMdocStatement statement = LongfellowMdocStatement.FromComponents(hashTemplate, signatureTemplate);

        using LongfellowMdocProof proof = LongfellowMdoc.Prove(witness, circuits, SessionSeed, pool);
        LongfellowMdocVerdict verdict = LongfellowMdoc.Verify(proof, statement, circuits, SessionSeed, pool);

        Assert.AreEqual(LongfellowMdocVerdict.Accepted, verdict, "The facade must accept its own prove over the real credential.");

        //The tamper dual: a flipped byte well inside the hash ZkProof region must no longer be accepted.
        ReadOnlySpan<byte> envelope = proof.AsReadOnlySpan();
        using IMemoryOwner<byte> tamperedOwner = pool.Rent(envelope.Length);
        Span<byte> tampered = tamperedOwner.Memory.Span[..envelope.Length];
        envelope.CopyTo(tampered);
        tampered[LongfellowMdocProof.MacRegionBytes + TamperOffset] ^= 0x01;

        using LongfellowMdocProof tamperedProof = LongfellowMdocProof.FromCanonical(tampered, pool);
        LongfellowMdocVerdict tamperedVerdict = LongfellowMdoc.Verify(tamperedProof, statement, circuits, SessionSeed, pool);

        Assert.AreNotEqual(LongfellowMdocVerdict.Accepted, tamperedVerdict, "A flipped envelope byte must break verification.");
    }


    //The hash witness column from the reconciled filler: the shared chosen ap keys filled at [85112,85118),
    //the public mac/av region [945,952) left zero (the prover patches it post-commit).
    private static byte[] BuildHashColumn(byte[] credential, BaseMemoryPool pool)
    {
        using Lch14AdditiveFft fft = new(Lch14Subfield.Production16, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, pool);
        var filler = new MdocHashWitnessFiller(fft, GfAdd);

        return filler.Fill(credential, MdocRequestedAttribute.AgeOver18, Now);
    }


    //The hash public-input template: the first 945 column elements as 16 little-endian wire bytes each (the
    //low 16 big-endian bytes reversed), mirroring the driver gate's HashTemplate.
    private static void BuildHashTemplate(byte[] hashColumn, Span<byte> template)
    {
        int elementBytes = LongfellowMdocStatement.HashTemplateElementBytes;
        for(int i = 0; i < LongfellowMdocStatement.HashTemplateElementCount; i++)
        {
            ReadOnlySpan<byte> element = hashColumn.AsSpan(i * ScalarSize, ScalarSize);
            Span<byte> wire = template.Slice(i * elementBytes, elementBytes);
            for(int b = 0; b < elementBytes; b++)
            {
                wire[b] = element[ScalarSize - 1 - b];
            }
        }
    }


    //e2: the anchor fixture's sig_template element 3 reversed from little-endian to canonical big-endian (the
    //device-authentication transcript hash the reference's CBOR walk captured), mirroring the driver gate.
    private static BigInteger DeviceHash()
    {
        byte[] sigTemplate = Convert.FromHexString(AnchorFixture["sig_template"]);
        ReadOnlySpan<byte> littleEndian = sigTemplate.AsSpan(DeviceHashTemplateIndex * ScalarSize, ScalarSize);
        Span<byte> canonical = stackalloc byte[ScalarSize];
        for(int i = 0; i < ScalarSize; i++)
        {
            canonical[i] = littleEndian[ScalarSize - 1 - i];
        }

        return new BigInteger(canonical, isUnsigned: true, isBigEndian: true);
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
