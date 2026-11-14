using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// Verifies the issuer's COSE_Sign1 signature on genuine ISO 18013-5 mdoc credentials out of
/// circuit: parse the DeviceResponse with the minimal CBOR reader, extract the issuer DS
/// certificate from the x5chain, reconstruct the COSE <c>Sig_structure</c>, and check the ECDSA
/// signature with the certificate's public key, proving the parse and signed-bytes reconstruction
/// can consume a real credential's issuer signature end-to-end (the ground truth the in-circuit
/// <c>AssertVerifiesMdocAttribute</c> is aimed at) before that same statement is proven in zero
/// knowledge.
/// </summary>
[TestClass]
internal sealed class RealCredentialCoseTests
{
    /// <summary>The ambient MSTest context, used here for its cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The issuer's COSE_Sign1 signature over a genuine mdoc credential verifies against the
    /// x5chain issuer DS certificate's public key.
    /// </summary>
    [TestMethod]
    public async Task GenuineCredentialIssuerSignatureVerifiesOutOfCircuit()
    {
        byte[] credential = await File.ReadAllBytesAsync("../../../TestMaterial/Mdoc/mdoc-00.cbor", TestContext.CancellationToken).ConfigureAwait(false);
        CoseSign1 issuerAuth = CoseSign1.Extract(credential);

        //The signature is ES256 (r‖s, 64 bytes), and the signed bytes are the COSE Sig_structure.
        Assert.HasCount(64, issuerAuth.Signature, "An ES256 COSE_Sign1 signature is r‖s, 64 bytes.");

        byte[] issuerX = new byte[PlatformP256Key.ComponentSize];
        byte[] issuerY = new byte[PlatformP256Key.ComponentSize];
        Assert.IsTrue(TestPlatformCrypto.ReadCertificatePublicKey(issuerAuth.IssuerCertificate, issuerX, issuerY), "The issuer DS certificate must carry a P-256 public key.");

        byte[] signedStructure = issuerAuth.SignatureStructure();
        bool verified = TestPlatformCrypto.VerifyP256(issuerX, issuerY, signedStructure, issuerAuth.Signature);
        Assert.IsTrue(verified, "The genuine issuer COSE_Sign1 signature over the MSO must verify with the x5chain key.");
    }


    /// <summary>
    /// The issuer's COSE_Sign1 signature verifies, against its own embedded issuer DS
    /// certificate, for every sourced credential.
    /// </summary>
    [TestMethod]
    public async Task EverySourcedCredentialIssuerSignatureVerifiesOutOfCircuit()
    {
        //The parse + Sig_structure reconstruction generalises across the whole sourced set
        //(ISO mDL, EU AV and the other doctypes), each verified against its own embedded
        //issuer DS certificate.
        var failures = new List<string>();
        for(int index = 0; index < 26; index++)
        {
            string name = "mdoc-" + index.ToString("D2", CultureInfo.InvariantCulture) + ".cbor";
            string outcome = await VerifyOne(name, TestContext.CancellationToken).ConfigureAwait(false);
            if(outcome.Length > 0)
            {
                failures.Add(outcome);
            }
        }

        Assert.IsEmpty(failures, "Every sourced credential must verify against its embedded issuer certificate: " + string.Join("; ", failures));
    }


    /// <summary>
    /// Verifies one sourced credential, <paramref name="name"/>, against its own embedded issuer
    /// certificate; returns an empty string on success or a diagnostic message on failure.
    /// </summary>
    private static async Task<string> VerifyOne(string name, CancellationToken cancellationToken)
    {
        try
        {
            byte[] credential = await File.ReadAllBytesAsync($"../../../TestMaterial/Mdoc/{name}", cancellationToken).ConfigureAwait(false);
            CoseSign1 issuerAuth = CoseSign1.Extract(credential);

            byte[] issuerX = new byte[PlatformP256Key.ComponentSize];
            byte[] issuerY = new byte[PlatformP256Key.ComponentSize];
            if(!TestPlatformCrypto.ReadCertificatePublicKey(issuerAuth.IssuerCertificate, issuerX, issuerY))
            {
                return $"{name}: the issuer certificate carries no P-256 public key";
            }

            bool verified = TestPlatformCrypto.VerifyP256(issuerX, issuerY, issuerAuth.SignatureStructure(), issuerAuth.Signature);

            return verified ? string.Empty : $"{name}: the issuer signature did not verify";
        }
        catch(FormatException exception)
        {
            return $"{name}: parse failure — {exception.Message}";
        }
        catch(CryptographicException exception)
        {
            return $"{name}: certificate/crypto failure — {exception.Message}";
        }
    }
}
