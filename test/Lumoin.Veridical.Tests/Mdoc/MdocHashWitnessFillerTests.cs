using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.IO;
using System.IO.Compression;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// The mdoc WITNESS FILLER (conformance step C.11): the C# port of google/longfellow-zk's GF(2^128)
/// hash-circuit witness filler (<c>fill_witness</c> + <c>MdocHashWitness::fill_witness</c>), gated against
/// the reference's own dumped column for the first test credential (<c>mdoc_tests[0]</c>) disclosing
/// <c>age_over_18</c>. The reference dump is <c>mdoc-circuit-hash-witness.gz</c> in TestMaterial/Longfellow
/// (85118 GF(2^128) elements, each 16 little-endian <c>to_bytes_field</c> bytes), produced by the C.10
/// harness.
/// </summary>
/// <remarks>
/// <para>
/// The column decomposes into the region map documented on <see cref="MdocHashWitnessFiller"/>. Every
/// region except the MAC randomness reproduces byte-for-byte from the credential alone; the gates check
/// each region in isolation so a future divergence is localizable.
/// </para>
/// <para>
/// The thirteen MAC-randomness slots are NOT reproducible: the reference's harness draws the six per-element
/// MAC keys (<c>state.ap</c>) and, via the post-commit transcript, the av key from a
/// <c>SecureRandomEngine</c>, so they differ every run. The full-column gate therefore splices those slots
/// from the dump; <see cref="TheMacAlgebraReproducesFromTheDumpedKeys"/> verifies the MAC computation itself
/// (the <c>(av + ap)·m</c> relation) against the dumped keys and macs, which is the portable part. The
/// dual-field commit that produces the real av is the C.12 envelope's job.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocHashWitnessFillerTests
{
    private const string CredentialRelativePath = "TestMaterial/Mdoc/mdoc-00.cbor";
    private const string WitnessGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-hash-witness.gz";

    private const int ScalarSize = 32;
    private const int ElementBytes = 16;
    private const int InputCount = 85118;

    //The deterministic-region boundaries (element indices) the region map documents.
    private const int OneWireEnd = 1;
    private const int AttributeEnd = 785;
    private const int NowEnd = 945;
    private const int MacPublicStart = 945;
    private const int MacPublicEnd = 952;
    private const int MacMessagesEnd = 1720;
    private const int HashWitnessEnd = 85112;
    private const int MacKeysStart = 85112;

    private static readonly byte[] Now = System.Text.Encoding.ASCII.GetBytes("2024-01-30T09:00:00Z");

    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    private static byte[] ReferenceColumn { get; } = DecompressGzip(ReadFixture(WitnessGzipRelativePath));

    private static byte[] Credential { get; } = ReadFixture(CredentialRelativePath);


    [TestMethod]
    public void TheDeterministicRegionsReproduceTheReferenceColumnByteForByte()
    {
        byte[] produced = Produce();

        Assert.HasCount(InputCount * ElementBytes, ReferenceColumn, "The reference column is ninputs little-endian elements.");
        Assert.AreEqual(InputCount, produced.Length / ScalarSize, "The filler must produce exactly ninputs elements.");

        AssertRegionMatches(produced, 0, OneWireEnd, "constant-one wire");
        AssertRegionMatches(produced, OneWireEnd, AttributeEnd, "attribute encoding");
        AssertRegionMatches(produced, AttributeEnd, NowEnd, "now timestamp");
        AssertRegionMatches(produced, MacPublicEnd, MacMessagesEnd, "MAC message bit strings");
        AssertRegionMatches(produced, MacMessagesEnd, HashWitnessEnd, "SHA and CBOR/attribute witnesses");
    }


    [TestMethod]
    public void TheFullColumnMatchesAfterSplicingTheMacRandomness()
    {
        byte[] produced = Produce();

        //Splice the thirteen non-deterministic MAC slots from the reference dump: the seven public mac/av
        //slots and the six private ap keys.
        SpliceReferenceElements(produced, MacPublicStart, MacPublicEnd);
        SpliceReferenceElements(produced, MacKeysStart, InputCount);

        for(int i = 0; i < InputCount; i++)
        {
            ReadOnlySpan<byte> producedElement = ToLittleEndian(produced.AsSpan(i * ScalarSize, ScalarSize));
            ReadOnlySpan<byte> referenceElement = ReferenceColumn.AsSpan(i * ElementBytes, ElementBytes);
            Assert.IsTrue(producedElement.SequenceEqual(referenceElement), $"Element {i} must match the reference (after MAC splicing).");
        }
    }


    [TestMethod]
    public void TheMacRandomnessSlotsAreTheOnlyDivergence()
    {
        byte[] produced = Produce();

        int divergences = 0;
        for(int i = 0; i < InputCount; i++)
        {
            ReadOnlySpan<byte> producedElement = ToLittleEndian(produced.AsSpan(i * ScalarSize, ScalarSize));
            ReadOnlySpan<byte> referenceElement = ReferenceColumn.AsSpan(i * ElementBytes, ElementBytes);
            if(!producedElement.SequenceEqual(referenceElement))
            {
                bool isMacSlot = (i >= MacPublicStart && i < MacPublicEnd) || (i >= MacKeysStart && i < InputCount);
                Assert.IsTrue(isMacSlot, $"Element {i} diverges but is not a MAC-randomness slot.");
                divergences++;
            }
        }

        Assert.AreEqual(13, divergences, "Exactly the seven MAC/av slots and the six ap keys may diverge.");
    }


    [TestMethod]
    public void TheMacAlgebraReproducesFromTheDumpedKeys()
    {
        byte[] produced = Produce();

        //The three MAC messages (e, dpkx, dpky) are reproduced in [952, 1720) as bit strings; recover them
        //as 32-byte canonical values from the filler state instead. The dumped ap keys are the six private
        //slots; the dumped macs/av are the seven public slots. Verify mac[i] = (av + ap)·m per half.
        MdocMacComputation.AssertMatchesDump(ReferenceColumn, MacPublicStart, MacKeysStart, Credential, MdocRequestedAttribute.AgeOver18);
    }


    [TestMethod]
    public void AFlippedCredentialByteChangesTheColumnInTheShaRegion()
    {
        byte[] baseline = Produce();

        //Flip one bit in the disclosed elementValue byte (the 0xf5 age_over_18 value at offset 248 in the
        //credential). It lives in the IssuerSignedItem, so the attribute's two-block SHA witness and the
        //128-byte attribute-bytes witness change — both in the SHA/CBOR region [1720, 85112).
        byte[] tampered = (byte[])Credential.Clone();
        int valueOffset = Credential.AsSpan().IndexOf(System.Text.Encoding.ASCII.GetBytes("elementValue")) + 12;
        tampered[valueOffset] ^= 0x01;

        byte[] produced = ProduceFrom(tampered, MdocRequestedAttribute.AgeOver18);

        Assert.IsFalse(produced.AsSpan().SequenceEqual(baseline), "A flipped credential byte must change the column.");

        //The first divergence lands in the SHA region (the preimage bytes / block witnesses), the bound
        //hash of the credential. The public attribute encoding (a verifier input) is unchanged.
        int firstDivergence = FirstDivergingElement(produced, baseline);
        Assert.IsTrue(firstDivergence >= MacMessagesEnd && firstDivergence < HashWitnessEnd, $"The first divergence (element {firstDivergence}) must be in the SHA/CBOR-witness region.");
    }


    [TestMethod]
    public void AFlippedAttributeValueChangesThePublicAttributeRegion()
    {
        byte[] baseline = Produce();

        //Disclose the same identifier with the opposite boolean value (0xf4 = false). The public attribute
        //encoding binds the claimed value, so the column the verifier checks against differs from the
        //genuine credential's — the proof would bind a statement the credential does not support.
        var notOver18 = new MdocRequestedAttribute(MdocRequestedAttribute.AgeOver18.NamespaceId, MdocRequestedAttribute.AgeOver18.Id, [0xf4]);
        byte[] produced = ProduceFrom(Credential, notOver18);

        Assert.IsFalse(produced.AsSpan().SequenceEqual(baseline), "A flipped attribute value must change the column.");

        int firstDivergence = FirstDivergingElement(produced, baseline);
        Assert.IsTrue(firstDivergence >= OneWireEnd && firstDivergence < AttributeEnd, $"The first divergence (element {firstDivergence}) must be in the public attribute-encoding region.");

        //The flipped value no longer matches the genuine credential's reference column (the public statement
        //diverges from the dump), so a verifier bound to the genuine column would reject the claim.
        ReadOnlySpan<byte> producedValue = ToLittleEndian(produced.AsSpan(firstDivergence * ScalarSize, ScalarSize));
        ReadOnlySpan<byte> referenceValue = ReferenceColumn.AsSpan(firstDivergence * ElementBytes, ElementBytes);
        Assert.IsFalse(producedValue.SequenceEqual(referenceValue), "The flipped attribute's public encoding must differ from the genuine reference column.");
    }


    private static int FirstDivergingElement(byte[] produced, byte[] baseline)
    {
        for(int i = 0; i < InputCount; i++)
        {
            if(!produced.AsSpan(i * ScalarSize, ScalarSize).SequenceEqual(baseline.AsSpan(i * ScalarSize, ScalarSize)))
            {
                return i;
            }
        }

        return -1;
    }


    private static byte[] Produce() => ProduceFrom(Credential, MdocRequestedAttribute.AgeOver18);


    private static byte[] ProduceFrom(byte[] credential, MdocRequestedAttribute attribute)
    {
        using var fft = new Lch14AdditiveFft(Lch14Subfield.Production16, Add, Gf2k128Backend.GetSubtract(), Gf2k128Backend.GetMultiply(), Gf2k128Backend.GetInvert(), CurveParameterSet.None, BaseMemoryPool.Shared);
        var filler = new MdocHashWitnessFiller(fft, Add);

        byte[] column = filler.Fill(credential, attribute, Now);
        Assert.AreEqual(InputCount, filler.Count, "The filler element count must equal ninputs.");

        return column;
    }


    private static void AssertRegionMatches(byte[] produced, int startElement, int endElement, string regionName)
    {
        for(int i = startElement; i < endElement; i++)
        {
            ReadOnlySpan<byte> producedElement = ToLittleEndian(produced.AsSpan(i * ScalarSize, ScalarSize));
            ReadOnlySpan<byte> referenceElement = ReferenceColumn.AsSpan(i * ElementBytes, ElementBytes);
            Assert.IsTrue(producedElement.SequenceEqual(referenceElement), $"Element {i} in the {regionName} region must match the reference.");
        }
    }


    private static void SpliceReferenceElements(byte[] produced, int startElement, int endElement)
    {
        for(int i = startElement; i < endElement; i++)
        {
            ReadOnlySpan<byte> referenceLittleEndian = ReferenceColumn.AsSpan(i * ElementBytes, ElementBytes);
            Span<byte> destination = produced.AsSpan(i * ScalarSize, ScalarSize);
            destination.Clear();
            for(int b = 0; b < ElementBytes; b++)
            {
                destination[ScalarSize - 1 - b] = referenceLittleEndian[b];
            }
        }
    }


    private static byte[] ToLittleEndian(ReadOnlySpan<byte> canonical)
    {
        byte[] littleEndian = new byte[ElementBytes];
        for(int i = 0; i < ElementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }

        return littleEndian;
    }


    //Static initializers feed the fixtures, so the reads stay synchronous (they cannot await).
    private static byte[] ReadFixture(string relativePath) => File.ReadAllBytes($"../../../{relativePath}");


    private static byte[] DecompressGzip(byte[] gzip)
    {
        using var input = new MemoryStream(gzip);
        using var gzipStream = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzipStream.CopyTo(output);

        return output.ToArray();
    }
}
