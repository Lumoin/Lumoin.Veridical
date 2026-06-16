using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// Verifies the issuer's COSE_Sign1 signature on genuine ISO 18013-5 mdoc credentials out of
/// circuit: parse the DeviceResponse with the minimal CBOR reader, extract the issuer DS
/// certificate from the x5chain, reconstruct the COSE <c>Sig_structure</c>, and check the ECDSA
/// signature with the certificate's public key. This is rung 2 — it proves we can consume a
/// real credential's issuer signature end-to-end (the ground truth the in-circuit
/// <c>AssertVerifiesMdocAttribute</c> is aimed at), establishing the parse + signed-bytes
/// reconstruction before that same statement is proven in zero knowledge.
/// </summary>
[TestClass]
internal sealed class RealCredentialCoseTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task GenuineCredentialIssuerSignatureVerifiesOutOfCircuit()
    {
        byte[] credential = await File.ReadAllBytesAsync("../../../TestMaterial/Mdoc/mdoc-00.cbor", TestContext.CancellationToken).ConfigureAwait(false);
        CoseSign1 issuerAuth = CoseSign1.Extract(credential);

        //The signature is ES256 (r‖s, 64 bytes), and the signed bytes are the COSE Sig_structure.
        Assert.HasCount(64, issuerAuth.Signature, "An ES256 COSE_Sign1 signature is r‖s, 64 bytes.");

        using X509Certificate2 issuerCertificate = X509CertificateLoader.LoadCertificate(issuerAuth.IssuerCertificate);
        using ECDsa? issuerKey = issuerCertificate.GetECDsaPublicKey();
        Assert.IsNotNull(issuerKey, "The issuer DS certificate must carry an EC public key.");

        byte[] signedStructure = issuerAuth.SignatureStructure();
        bool verified = issuerKey.VerifyData(signedStructure, issuerAuth.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        Assert.IsTrue(verified, "The genuine issuer COSE_Sign1 signature over the MSO must verify with the x5chain key.");
    }


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


    //Verifies one sourced credential; returns an empty string on success or a diagnostic on
    //failure.
    private static async Task<string> VerifyOne(string name, CancellationToken cancellationToken)
    {
        try
        {
            byte[] credential = await File.ReadAllBytesAsync($"../../../TestMaterial/Mdoc/{name}", cancellationToken).ConfigureAwait(false);
            CoseSign1 issuerAuth = CoseSign1.Extract(credential);

            using X509Certificate2 issuerCertificate = X509CertificateLoader.LoadCertificate(issuerAuth.IssuerCertificate);
            using ECDsa? issuerKey = issuerCertificate.GetECDsaPublicKey();
            if(issuerKey is null)
            {
                return $"{name}: the issuer certificate carries no EC public key";
            }

            bool verified = issuerKey.VerifyData(issuerAuth.SignatureStructure(), issuerAuth.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

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
