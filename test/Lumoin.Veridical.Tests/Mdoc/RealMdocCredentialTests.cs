using System;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// Sources the genuine ISO/IEC 18013-5 (and EU AV) mdoc credentials — real DeviceResponse vectors
/// from the google/longfellow-zk reference (Apache-2.0), <c>lib/circuits/mdoc/mdoc_examples.h</c>
/// <c>mdoc_tests[]</c> — into the test material and reads them via a path relative to the test
/// binary. They are the real-world ground truth the in-circuit ECDSA / SHA-256 / CBOR mdoc gadgets
/// are aimed at; verifying an issuer signature and feeding a credential to
/// <c>AssertVerifiesMdocAttribute</c> is the next step (it needs a COSE/CBOR parse to extract the
/// issuerAuth, MSO and item offsets). Provenance and per-entry metadata are recorded in the sidecar
/// <c>index.tsv</c>.
/// </summary>
[TestClass]
internal sealed class RealMdocCredentialTests
{
    //The sourced credentials are mdoc-00.cbor .. mdoc-25.cbor.
    private const int CredentialCount = 26;

    //Issuer DS public key for mdoc-00 (Google TEST IACA mDL, the age_over_18 mDL), used by the
    //on-curve check; the full set of per-entry keys is recorded in index.tsv.
    private const string IssuerPublicKeyX = "2c80c10bf70f63bddcc41ea20d76a22ecba2a97fa8811bf19d572433b12c0c1f";
    private const string IssuerPublicKeyY = "3f994c043be7e17dd08387281bac0c37a529361b3cb36a0fac38d41ac066f903";


    public TestContext TestContext { get; set; } = null!;


    private static Task<byte[]> Credential(int index, CancellationToken cancellationToken) =>
        File.ReadAllBytesAsync($"../../../TestMaterial/Mdoc/mdoc-{index.ToString("D2", CultureInfo.InvariantCulture)}.cbor", cancellationToken);


    [TestMethod]
    public async Task AllSourcedCredentialsAreWellFormedDeviceResponses()
    {
        for(int index = 0; index < CredentialCount; index++)
        {
            byte[] credential = await Credential(index, TestContext.CancellationToken).ConfigureAwait(false);

            //Every entry is a complete CBOR DeviceResponse map (a3{version, documents, status}).
            Assert.IsGreaterThan(64, credential.Length, "Each credential must be a non-trivial CBOR document.");
            Assert.AreEqual((byte)0xA3, credential[0], "Each DeviceResponse is a CBOR map of three entries.");

            //The COSE_Sign1 issuerAuth (the issuer signature) must be present in every credential.
            bool hasIssuerAuth = credential.AsSpan().IndexOf("issuerAuth"u8) >= 0;
            Assert.IsTrue(hasIssuerAuth, "The COSE_Sign1 issuerAuth must be present.");
        }
    }


    [TestMethod]
    public async Task TheIso18013MdlEntryDisclosesAgeOver18()
    {
        byte[] credential = await Credential(0, TestContext.CancellationToken).ConfigureAwait(false);

        //Structural markers of a real ISO 18013-5 device response and the disclosed attribute.
        bool hasDocType = credential.AsSpan().IndexOf("org.iso.18013.5.1.mDL"u8) >= 0;
        Assert.IsTrue(hasDocType, "The mDL doctype must be present.");

        bool hasAttribute = credential.AsSpan().IndexOf("age_over_18"u8) >= 0;
        Assert.IsTrue(hasAttribute, "The age_over_18 attribute id must be present.");

        //In the IssuerSignedItem the elementValue immediately follows its key and is CBOR true.
        int elementValue = credential.AsSpan().IndexOf("elementValue"u8);
        bool hasElementValue = elementValue >= 0;
        Assert.IsTrue(hasElementValue, "The IssuerSignedItem elementValue must be present.");
        Assert.AreEqual((byte)0xF5, credential[elementValue + "elementValue".Length], "The disclosed value must be CBOR true.");
    }


    [TestMethod]
    public void IssuerPublicKeyLiesOnTheP256Curve()
    {
        //The sourced issuer key satisfies y² = x³ − 3x + b over the P-256 base field, confirming
        //the metadata is a genuine P-256 public key rather than arbitrary bytes.
        BigInteger p = Hex("0ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
        BigInteger a = p - 3;
        BigInteger b = Hex("05ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
        BigInteger x = Hex("0" + IssuerPublicKeyX);
        BigInteger y = Hex("0" + IssuerPublicKeyY);

        BigInteger left = Mod(y * y, p);
        BigInteger right = Mod((x * x * x) + (a * x) + b, p);
        Assert.AreEqual(left, right, "The sourced issuer public key must lie on the P-256 curve.");
    }


    private static BigInteger Hex(string value) =>
        BigInteger.Parse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);


    private static BigInteger Mod(BigInteger value, BigInteger modulus) =>
        ((value % modulus) + modulus) % modulus;
}
