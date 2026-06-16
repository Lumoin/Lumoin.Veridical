using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// Validates the in-circuit disclosure inputs extracted from a real ISO 18013-5 credential
/// (<see cref="MdocDisclosure"/>) out of circuit: that SHA-256 of the tagged IssuerSignedItem
/// sits at the reported offset in the signed COSE Sig_structure, and that the contiguous
/// disclosure pattern (the element identifier immediately followed by its value) sits at the
/// reported offset in the item. Establishing the offsets here is the ground truth the in-circuit
/// <c>AssertVerifiesMdocAttribute</c> proof relies on.
/// </summary>
[TestClass]
internal sealed class RealCredentialDisclosureTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task ExtractsAgeOver18DisclosureInputsFromARealCredential()
    {
        byte[] credential = await File.ReadAllBytesAsync("../../../TestMaterial/Mdoc/mdoc-00.cbor", TestContext.CancellationToken).ConfigureAwait(false);
        MdocDisclosure disclosure = MdocDisclosure.Extract(credential, "org.iso.18013.5.1", "age_over_18");

        //SHA-256 of the tagged item sits in the signed structure at the reported offset.
        byte[] digest = SHA256.HashData(disclosure.IssuerSignedItem);
        bool digestAtOffset = disclosure.SignedStructure.AsSpan().Slice(disclosure.ItemDigestOffset, digest.Length).SequenceEqual(digest);
        Assert.IsTrue(digestAtOffset, "SHA-256 of the item must sit at the reported offset in the signed structure.");

        //The disclosure pattern sits in the item at the reported offset.
        bool patternAtOffset = disclosure.IssuerSignedItem.AsSpan().Slice(disclosure.AttributeOffset, disclosure.Attribute.Length).SequenceEqual(disclosure.Attribute);
        Assert.IsTrue(patternAtOffset, "The disclosure pattern must sit at the reported offset in the item.");

        //The pattern names age_over_18 and ends with its value, CBOR true.
        bool namesAge = disclosure.Attribute.AsSpan().IndexOf("age_over_18"u8) >= 0;
        Assert.IsTrue(namesAge, "The disclosure must name age_over_18.");
        Assert.AreEqual((byte)0xF5, disclosure.Attribute[^1], "The disclosed value must be CBOR true.");

        //The signature is the 64-byte ES256 r‖s.
        Assert.HasCount(32, disclosure.SignatureR);
        Assert.HasCount(32, disclosure.SignatureS);
    }
}
