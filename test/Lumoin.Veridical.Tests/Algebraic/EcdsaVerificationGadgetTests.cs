using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Ligero.Gadgets;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Mdoc;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The production in-circuit ECDSA-P256 verifier (<see cref="EcdsaVerificationGadgetExtensions"/>)
/// assembled over the P-256 base field Fp256: a named public signature (r, s) verifying
/// under a public key Q for a message hash e, via the Longfellow Alg.4 identity
/// e·G + r·Q − s·R = O with the nonce point R witnessed and r = R.x mod n. The
/// constraint logic is checked at full 256-bit width with the prover-independent
/// <see cref="LigeroConstraintEvaluator"/> (an honest signature satisfies; every
/// tamper does not); the slow end-to-end prove/verify smoke lives separately.
/// </summary>
[TestClass]
internal sealed class EcdsaVerificationGadgetTests
{
    public TestContext TestContext { get; set; } = null!;

    private const int ScalarSize = Scalar.SizeBytes;

    private const int InverseRate = 4;
    private const int OpenedColumns = 4;
    private const int Block = 64;

    private static readonly BigInteger P = EcdsaNonceRecovery.P;
    private static readonly BigInteger A = EcdsaNonceRecovery.A;
    private static readonly BigInteger B = P256BigIntegerG1Reference.CurveB;
    private static readonly BigInteger N = EcdsaNonceRecovery.N;

    private static readonly BigInteger Gx = EcdsaNonceRecovery.Gx;
    private static readonly BigInteger Gy = EcdsaNonceRecovery.Gy;
    private static readonly (BigInteger X, BigInteger Y) G = EcdsaNonceRecovery.G;

    private static readonly byte[] CurveABytes = Bytes(A);
    private static readonly byte[] CurveBBytes = Bytes(B);

    //Fixed test scalars, all < n (the leading nibble keeps them below n = 0xFFFF…).
    private static readonly BigInteger D = Hex("5b1e9f2c4a7d8e3f0a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7081");
    private static readonly BigInteger K = Hex("1234567890abcdeffedcba9876543210112233445566778899aabbccddeeff00");
    private static readonly BigInteger E = Hex("0a1b2c3d4e5f60718293a4b5c6d7e8f9000102030405060708090a0b0c0d0e0f");

    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private static readonly byte[] Domain = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.ecdsa-p256.v1");
    private static readonly byte[] RandomnessSeed = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.ecdsa-p256.rng.v1");
    private static readonly FiatShamirHashDelegate Hash = Blake3FiatShamirBackend.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = Blake3FiatShamirBackend.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;

    //An 8-bit difference covers any realistic age − threshold gap (0..255).
    private const int AgeDifferenceBits = 8;
    private const int AgeThreshold = 18;


    [TestMethod]
    public void VerifiesARealSignatureInCircuit()
    {
        (BigInteger qx, BigInteger qy, BigInteger rx, BigInteger ry, BigInteger r, BigInteger s) = Sign(D, K, E);

        //Gate: the synthetic signature satisfies the Alg.4 identity at the oracle level.
        Assert.IsNull(
            OracleAdd(OracleAdd(OracleScalarMultiply(E, G), OracleScalarMultiply(r, (qx, qy))), OracleScalarMultiply(N - s, (rx, ry))),
            "The synthetic signature must satisfy e·G + r·Q − s·R = O (oracle gate).");

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, Public(qx, qy, E, r, s), new EcdsaWitness(Bytes(rx), Bytes(ry)));

        Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), "A valid ECDSA signature must verify in-circuit.");
    }


    [TestMethod]
    public void RejectsATamperedSignatureS()
    {
        (BigInteger qx, BigInteger qy, BigInteger rx, BigInteger ry, BigInteger r, BigInteger s) = Sign(D, K, E);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, Public(qx, qy, E, r, ((s + 1) % N)), new EcdsaWitness(Bytes(rx), Bytes(ry)));

        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), "A tampered s breaks the identity and must not verify.");
    }


    [TestMethod]
    public void RejectsAWrongPublicKey()
    {
        (BigInteger qx, BigInteger qy, BigInteger rx, BigInteger ry, BigInteger r, BigInteger s) = Sign(D, K, E);

        //A different, on-curve public key (for private key d + 1) with the same signature.
        (BigInteger wrongQx, BigInteger wrongQy) = ScalarMultiply(D + 1, G);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, Public(wrongQx, wrongQy, E, r, s), new EcdsaWitness(Bytes(rx), Bytes(ry)));

        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), "A signature must not verify under a different public key.");
    }


    [TestMethod]
    public void RejectsAWrongNoncePoint()
    {
        (BigInteger qx, BigInteger qy, BigInteger _, BigInteger _, BigInteger r, BigInteger s) = Sign(D, K, E);

        //Witness a different on-curve nonce point R' = (k + 1)·G: its x no longer
        //reduces to r (the r = R.x mod n binding fails) and the identity no longer
        //vanishes.
        (BigInteger wrongRx, BigInteger wrongRy) = ScalarMultiply(K + 1, G);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, Public(qx, qy, E, r, s), new EcdsaWitness(Bytes(wrongRx), Bytes(wrongRy)));

        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), "A nonce point whose x ≠ r mod n must not verify.");
    }


    [TestMethod]
    public void RejectsAnOffCurveNoncePoint()
    {
        (BigInteger qx, BigInteger qy, BigInteger rx, BigInteger ry, BigInteger r, BigInteger s) = Sign(D, K, E);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, Public(qx, qy, E, r, s), new EcdsaWitness(Bytes(rx), Bytes((ry + 1) % P)));

        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), "An off-curve nonce point must not verify.");
    }


    [TestMethod]
    public void VerifiesGenuineDotNetEcdsaSignaturesInCircuit()
    {
        //The credibility step: signatures from .NET's own ECDSA (an independent,
        //standards-compliant implementation) verify in our ZK circuit. The verifier
        //never sees the nonce k — it recovers the nonce point R = (e/s)·G + (r/s)·Q from
        //the public (Q, e, r, s) alone, exactly as a real prover would. Several fresh
        //keys/messages give breadth (including the occasional R.x ≥ n branch); checked
        //fast with the constraint evaluator.
        foreach(ReadOnlyMemory<byte> message in new[]
        {
            (ReadOnlyMemory<byte>)"over-18 age assertion"u8.ToArray(),
            "a different signed credential"u8.ToArray(),
            "veridical longfellow mdoc"u8.ToArray(),
            "third-party ECDSA P-256"u8.ToArray(),
        })
        {
            using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] signature = ecdsa.SignData(message.Span, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            Assert.IsTrue(
                ecdsa.VerifyData(message.Span, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
                ".NET must accept its own signature (gate).");

            ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
            BigInteger qx = ToInteger(parameters.Q.X);
            BigInteger qy = ToInteger(parameters.Q.Y);
            BigInteger r = ToInteger(signature.AsSpan(0, ScalarSize));
            BigInteger s = ToInteger(signature.AsSpan(ScalarSize, ScalarSize));
            BigInteger e = ModN(ToInteger(SHA256.HashData(message.Span)));
            (BigInteger rx, BigInteger ry) = RecoverNoncePoint(qx, qy, e, r, s);

            var (builder, gadget) = NewGadget();
            builder.AssertVerifies(gadget, Public(qx, qy, e, r, s), new EcdsaWitness(Bytes(rx), Bytes(ry)));
            Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), "A genuine .NET ECDSA signature must verify in our ZK circuit.");

            var (tampered, tamperedGadget) = NewGadget();
            tampered.AssertVerifies(tamperedGadget, Public(qx, qy, e, r, ModN(s + 1)), new EcdsaWitness(Bytes(rx), Bytes(ry)));
            Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(tampered), "A tampered s on a genuine signature must not verify.");
        }
    }


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void ProvesAndVerifiesAGenuineDotNetEcdsaSignature()
    {
        //The same genuine .NET signature, proved and verified end-to-end in zero
        //knowledge through the real Ligero prover. On the order of a few minutes,
        //hardware-dependent; the fast evaluator gates cover the logic, so this gate adds
        //the end-to-end proving.
        byte[] message = "Veridical proves a real ECDSA signature in zero knowledge."u8.ToArray();
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] signature = ecdsa.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        Assert.IsTrue(
            ecdsa.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            ".NET must accept its own signature (gate).");

        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        BigInteger qx = ToInteger(parameters.Q.X);
        BigInteger qy = ToInteger(parameters.Q.Y);
        BigInteger r = ToInteger(signature.AsSpan(0, ScalarSize));
        BigInteger s = ToInteger(signature.AsSpan(ScalarSize, ScalarSize));
        BigInteger e = ModN(ToInteger(SHA256.HashData(message)));
        (BigInteger rx, BigInteger ry) = RecoverNoncePoint(qx, qy, e, r, s);

        EcdsaPublicInputs pub = Public(qx, qy, e, r, s);
        byte[] seed = EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(pub, Domain, Hash, WellKnownHashAlgorithms.Blake3);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, pub, new EcdsaWitness(Bytes(rx), Bytes(ry)));

        using LigeroProof proof = Prove(builder, seed);
        Assert.IsTrue(Verify(builder, proof, seed), "A genuine .NET ECDSA signature must prove and verify in zero knowledge.");
    }


    [TestMethod]
    public void VerifiesSignatureAndAgeThresholdTogetherInCircuit()
    {
        //The Longfellow credential-proof shape: one Fp256 Ligero proof attesting BOTH a
        //valid issuer ECDSA signature (verified in-circuit) AND a private age ≥ 18.
        (BigInteger qx, BigInteger qy, BigInteger rx, BigInteger ry, BigInteger r, BigInteger s) = Sign(D, K, E);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, Public(qx, qy, E, r, s), new EcdsaWitness(Bytes(rx), Bytes(ry)));
        builder.AddAtLeast(builder.AddWire(Bytes(34)), Bytes(AgeThreshold), AgeDifferenceBits);

        Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), "A valid signature together with age 34 ≥ 18 must verify in-circuit.");
    }


    [TestMethod]
    public void RejectsAgeBelowThresholdAlongsideAValidSignature()
    {
        //A genuinely valid signature does not rescue a sub-threshold age: the age
        //predicate is part of the same proof and fails independently.
        (BigInteger qx, BigInteger qy, BigInteger rx, BigInteger ry, BigInteger r, BigInteger s) = Sign(D, K, E);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, Public(qx, qy, E, r, s), new EcdsaWitness(Bytes(rx), Bytes(ry)));
        builder.AddAtLeast(builder.AddWire(Bytes(16)), Bytes(AgeThreshold), AgeDifferenceBits);

        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), "A valid signature must not make age 16 ≥ 18 provable.");
    }


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void SignatureAndAgeThresholdProveAndVerifyEndToEnd()
    {
        //The headline: one Ligero proof attests, in zero knowledge, that the holder has
        //a valid issuer ECDSA signature AND an age ≥ 18 — the signature now verified IN
        //circuit (vs out of circuit in the BLS-Spartan age e2e). Proved and verified
        //end-to-end through the real prover, with the seed bound to the public statement.
        //Scope: the age is a witness not yet cryptographically tied to the signed
        //message; binding it needs in-circuit SHA-256 + CBOR (the GF(2^128) half), so
        //this proves "valid signature AND age ≥ 18", not yet "the signed credential's
        //age ≥ 18". On the order of a few minutes, hardware-dependent; the fast
        //evaluator gates above cover the logic.
        (BigInteger qx, BigInteger qy, BigInteger rx, BigInteger ry, BigInteger r, BigInteger s) = Sign(D, K, E);
        EcdsaPublicInputs pub = Public(qx, qy, E, r, s);
        byte[] seed = EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(pub, Domain, Hash, WellKnownHashAlgorithms.Blake3);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, pub, new EcdsaWitness(Bytes(rx), Bytes(ry)));
        builder.AddAtLeast(builder.AddWire(Bytes(34)), Bytes(AgeThreshold), AgeDifferenceBits);

        using LigeroProof proof = Prove(builder, seed);
        Assert.IsTrue(Verify(builder, proof, seed), "An honest signature-plus-age credential proof must verify end-to-end.");
    }


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void FullWidthSignatureProvesAndVerifiesEndToEnd()
    {
        //The full gate: a real signature proved and verified end-to-end through the
        //actual Ligero prover/verifier at 256-bit width, with the transcript seed bound
        //to the public statement. Slow (the O(n²) barycentric encoder over the full MSM
        //and bindings — on the order of a few minutes, hardware-dependent); it confirms
        //the gadget's constraints are provable, not merely satisfiable, and that the
        //statement-bound seed makes the proof non-transferable. The fast evaluator gates
        //cover the logic.
        (BigInteger qx, BigInteger qy, BigInteger rx, BigInteger ry, BigInteger r, BigInteger s) = Sign(D, K, E);
        EcdsaPublicInputs pub = Public(qx, qy, E, r, s);
        var wit = new EcdsaWitness(Bytes(rx), Bytes(ry));

        byte[] seed = EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(pub, Domain, Hash, WellKnownHashAlgorithms.Blake3);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, pub, wit);

        using LigeroProof proof = Prove(builder, seed);
        Assert.IsTrue(Verify(builder, proof, seed), "An honest full-width ECDSA proof must verify.");

        //Statement binding: the same proof is rejected under a different statement's
        //seed (here the seed for a tampered s).
        byte[] otherSeed = EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(Public(qx, qy, E, r, (s + 1) % N), Domain, Hash, WellKnownHashAlgorithms.Blake3);
        Assert.IsFalse(Verify(builder, proof, otherSeed), "A proof must be rejected under a different statement's seed.");

        //Tampering an opened column breaks the proof.
        proof.OpenedColumnMutable(0)[0] ^= 0x01;
        Assert.IsFalse(Verify(builder, proof, seed), "A tampered full-width ECDSA proof must be rejected.");
    }


    [TestMethod]
    public void VerifiesAHashedMessageSignatureInCircuit()
    {
        //The full binding: a genuine .NET ECDSA signature verifies in-circuit with the
        //message hash e = SHA-256(message) computed INSIDE the proof, so the proof attests
        //the signed bytes — not a supplied e. .NET signs SHA-256(message); the circuit hashes
        //the witnessed message and feeds the 256-bit digest as the e·G scalar (D·G = e·G).
        byte[] message = "mdoc: age_over_18 = true"u8.ToArray();
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] signature = ecdsa.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        Assert.IsTrue(
            ecdsa.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            ".NET must accept its own signature (gate).");

        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        BigInteger qx = ToInteger(parameters.Q.X);
        BigInteger qy = ToInteger(parameters.Q.Y);
        BigInteger r = ToInteger(signature.AsSpan(0, ScalarSize));
        BigInteger s = ToInteger(signature.AsSpan(ScalarSize, ScalarSize));
        BigInteger e = ToInteger(SHA256.HashData(message));
        (BigInteger rx, BigInteger ry) = RecoverNoncePoint(qx, qy, e, r, s);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifiesHashedMessage(gadget, 
            new EcdsaHashedPublicInputs(Bytes(qx), Bytes(qy), Bytes(r), Bytes(s)),
            new EcdsaHashedWitness(message, Bytes(rx), Bytes(ry)));
        Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), "A signature must verify in-circuit for e = SHA-256(the witnessed message).");

        //Tampering the message changes the in-circuit hash, so the identity no longer vanishes.
        byte[] tampered = (byte[])message.Clone();
        tampered[0] ^= 0x01;
        var (tamperedBuilder, tamperedGadget) = NewGadget();
        tamperedBuilder.AssertVerifiesHashedMessage(tamperedGadget, 
            new EcdsaHashedPublicInputs(Bytes(qx), Bytes(qy), Bytes(r), Bytes(s)),
            new EcdsaHashedWitness(tampered, Bytes(rx), Bytes(ry)));
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(tamperedBuilder), "A tampered message must not verify against the original signature.");
    }


    [TestMethod]
    public void VerifiesADisclosedAttributeInASignedMessage()
    {
        //The full mdoc-shaped statement in one proof: a genuine .NET signature over a private
        //message verifies for e = SHA-256(message) AND the message contains the public attribute
        //(CBOR for age_over_18 = true) at a witnessed offset — message private, attribute public.
        byte[] attribute = CborTestEncoding.BooleanAttribute("age_over_18", true);
        //Arbitrary surrounding credential bytes; only the attribute and the hash matter here.
        byte[] prefix = [0xA1, 0x6C, .. "doc:mdl-1.0"u8.ToArray()];
        byte[] suffix = [CborTestEncoding.False];
        byte[] message = [.. prefix, .. attribute, .. suffix];
        int offset = prefix.Length;

        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] signature = ecdsa.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        Assert.IsTrue(
            ecdsa.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            ".NET must accept its own signature (gate).");

        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        BigInteger qx = ToInteger(parameters.Q.X);
        BigInteger qy = ToInteger(parameters.Q.Y);
        BigInteger r = ToInteger(signature.AsSpan(0, ScalarSize));
        BigInteger s = ToInteger(signature.AsSpan(ScalarSize, ScalarSize));
        BigInteger e = ToInteger(SHA256.HashData(message));
        (BigInteger rx, BigInteger ry) = RecoverNoncePoint(qx, qy, e, r, s);

        var publicInputs = new EcdsaHashedPublicInputs(Bytes(qx), Bytes(qy), Bytes(r), Bytes(s));
        var witness = new EcdsaHashedWitness(message, Bytes(rx), Bytes(ry));

        //Honest: the signature verifies and the attribute is disclosed from the signed bytes.
        var (builder, gadget) = NewGadget();
        builder.AssertVerifiesDisclosedAttribute(gadget, publicInputs, witness, attribute, offset);
        Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), "A signed message containing the attribute must verify and disclose it.");

        //An attribute that is not in the signed message must not be disclosable, even though the
        //signature itself is valid.
        byte[] absent = CborTestEncoding.BooleanAttribute("age_over_21", true);
        var (absentBuilder, absentGadget) = NewGadget();
        absentBuilder.AssertVerifiesDisclosedAttribute(absentGadget, publicInputs, witness, absent, offset);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(absentBuilder), "An absent attribute must not be disclosable even with a valid signature.");
    }


    [TestMethod]
    public void VerifiesATwoLevelMdocAttribute()
    {
        //The full ISO-18013-5 shape in one proof: the issuer signs an MSO; the MSO holds
        //SHA-256(IssuerSignedItem); the item holds the attribute. All three levels are bound -
        //signature → MSO digest → item digest → attribute - with the MSO and item private.
        byte[] attribute = CborTestEncoding.BooleanAttribute("age_over_18", true);
        byte[] itemPrefix = [0xA4, 0x6C, .. "elementValue"u8.ToArray()];   //arbitrary item lead-in.
        byte[] item = [.. itemPrefix, .. attribute, 0xFF];
        int attributeOffset = itemPrefix.Length;

        byte[] itemDigest = SHA256.HashData(item);
        byte[] msoPrefix = [0xA1, 0x6C, .. "valueDigests"u8.ToArray()];     //arbitrary MSO lead-in.
        byte[] mso = [.. msoPrefix, .. itemDigest, 0xFF];
        int itemDigestOffset = msoPrefix.Length;

        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] signature = ecdsa.SignData(mso, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        Assert.IsTrue(
            ecdsa.VerifyData(mso, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            ".NET must accept its own signature (gate).");

        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        BigInteger qx = ToInteger(parameters.Q.X);
        BigInteger qy = ToInteger(parameters.Q.Y);
        BigInteger r = ToInteger(signature.AsSpan(0, ScalarSize));
        BigInteger s = ToInteger(signature.AsSpan(ScalarSize, ScalarSize));
        BigInteger e = ToInteger(SHA256.HashData(mso));
        (BigInteger rx, BigInteger ry) = RecoverNoncePoint(qx, qy, e, r, s);

        var publicInputs = new EcdsaHashedPublicInputs(Bytes(qx), Bytes(qy), Bytes(r), Bytes(s));
        var witness = new EcdsaMdocWitness(mso, item, Bytes(rx), Bytes(ry));

        var (builder, gadget) = NewGadget();
        builder.AssertVerifiesMdocAttribute(gadget, publicInputs, witness, attribute, itemDigestOffset, attributeOffset);
        Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), "A signed MSO whose item holds the attribute must verify and disclose it.");

        //The item does not hold age_over_21, so it must not be disclosable even though the
        //signature, the MSO digest, and the item digest all check out.
        byte[] absent = CborTestEncoding.BooleanAttribute("age_over_21", true);
        var (absentBuilder, absentGadget) = NewGadget();
        absentBuilder.AssertVerifiesMdocAttribute(absentGadget, publicInputs, witness, absent, itemDigestOffset, attributeOffset);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(absentBuilder), "An attribute not in the signed item must not be disclosable.");
    }


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public async Task ProvesAgeOver18FromARealCredentialInCircuit()
    {
        //The headline rung: a GENUINE Google-Wallet-style ISO 18013-5 credential's age_over_18
        //disclosure, proven in-circuit over its real bytes. The issuer signed e = SHA-256(the COSE
        //Sig_structure); that signed structure carries the MSO, which holds SHA-256(IssuerSignedItem);
        //the item names age_over_18 = true. All three levels are bound by one constraint system, with
        //the nonce point R recovered from the real signature. (IsSatisfied gate — the circuit is large,
        //~700-byte in-circuit SHA-256; provability end-to-end is shown on the smaller synthetic mdoc.)
        byte[] credential = await File.ReadAllBytesAsync("../../../TestMaterial/Mdoc/mdoc-00.cbor", TestContext.CancellationToken).ConfigureAwait(false);
        MdocDisclosure disclosure = MdocDisclosure.Extract(credential, "org.iso.18013.5.1", "age_over_18");

        BigInteger qx = ToInteger(disclosure.IssuerKeyX);
        BigInteger qy = ToInteger(disclosure.IssuerKeyY);
        BigInteger r = ToInteger(disclosure.SignatureR);
        BigInteger s = ToInteger(disclosure.SignatureS);
        BigInteger e = ToInteger(SHA256.HashData(disclosure.SignedStructure));
        (BigInteger rx, BigInteger ry) = RecoverNoncePoint(qx, qy, e, r, s);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifiesMdocAttribute(
            gadget,
            new EcdsaHashedPublicInputs(Bytes(qx), Bytes(qy), Bytes(r), Bytes(s)),
            new EcdsaMdocWitness(disclosure.SignedStructure, disclosure.IssuerSignedItem, Bytes(rx), Bytes(ry)),
            disclosure.Attribute, disclosure.ItemDigestOffset, disclosure.AttributeOffset);

        Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), "A real credential's age_over_18 disclosure must verify in-circuit.");
    }


    [TestMethod]
    [Ignore("Documents the end-to-end target. The real-credential circuit is ~100k+ constraints (a "
        + "~700-byte in-circuit SHA-256), and the Ligero encoder is super-linear at that scale — a single "
        + "prove ran 6.6h without finishing, even on the Montgomery backend. Un-ignore once the FFT/NTT "
        + "encoder lands; the IsSatisfied gate ProvesAgeOver18FromARealCredentialInCircuit is today's result.")]
    public async Task ProvesAndVerifiesAgeOver18FromARealCredentialEndToEnd()
    {
        //The end-to-end target: a genuine ISO 18013-5 credential's age_over_18 disclosure proved AND
        //verified in zero knowledge through the real Ligero prover over the production Montgomery Fp256
        //backend. Ignored: the circuit is real-credential scale (~700-byte in-circuit SHA-256 over the
        //COSE Sig_structure, the item hash, and the three-scalar MSM ⇒ ~100k+ constraints), and the
        //encoder is super-linear there — a single prove ran 6.6h without finishing. The FFT/NTT encoder
        //is the gate. The seed is bound to the public statement.
        byte[] credential = await File.ReadAllBytesAsync("../../../TestMaterial/Mdoc/mdoc-00.cbor", TestContext.CancellationToken).ConfigureAwait(false);
        MdocDisclosure disclosure = MdocDisclosure.Extract(credential, "org.iso.18013.5.1", "age_over_18");

        BigInteger qx = ToInteger(disclosure.IssuerKeyX);
        BigInteger qy = ToInteger(disclosure.IssuerKeyY);
        BigInteger r = ToInteger(disclosure.SignatureR);
        BigInteger s = ToInteger(disclosure.SignatureS);
        BigInteger e = ToInteger(SHA256.HashData(disclosure.SignedStructure));
        (BigInteger rx, BigInteger ry) = RecoverNoncePoint(qx, qy, e, r, s);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifiesMdocAttribute(
            gadget,
            new EcdsaHashedPublicInputs(Bytes(qx), Bytes(qy), Bytes(r), Bytes(s)),
            new EcdsaMdocWitness(disclosure.SignedStructure, disclosure.IssuerSignedItem, Bytes(rx), Bytes(ry)),
            disclosure.Attribute, disclosure.ItemDigestOffset, disclosure.AttributeOffset);

        byte[] seed = EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(
            Public(qx, qy, e, r, s), Domain, Hash, WellKnownHashAlgorithms.Blake3);

        using LigeroProof proof = ProveMontgomery(builder, seed);
        Assert.IsTrue(VerifyMontgomery(builder, proof, seed), "A real credential's age_over_18 disclosure must prove and verify end-to-end in zero knowledge.");
    }


    private static (BigInteger Qx, BigInteger Qy, BigInteger Rx, BigInteger Ry, BigInteger R, BigInteger S) Sign(BigInteger d, BigInteger k, BigInteger e)
    {
        (BigInteger qx, BigInteger qy) = ScalarMultiply(d, G);
        (BigInteger rx, BigInteger ry) = ScalarMultiply(k, G);
        BigInteger r = ModN(rx);
        BigInteger s = ModN(ModInvN(k) * (e + (r * d)));

        return (qx, qy, rx, ry, r, s);
    }


    private static EcdsaPublicInputs Public(BigInteger qx, BigInteger qy, BigInteger e, BigInteger r, BigInteger s) =>
        new(Bytes(qx), Bytes(qy), Bytes(e), Bytes(r), Bytes(s));


    //The nonce point a verifier reconstructs from the public signature alone.
    private static (BigInteger X, BigInteger Y) RecoverNoncePoint(BigInteger qx, BigInteger qy, BigInteger e, BigInteger r, BigInteger s) =>
        EcdsaNonceRecovery.RecoverNoncePoint(qx, qy, e, r, s);


    private static BigInteger ToInteger(ReadOnlySpan<byte> bytes) => EcdsaNonceRecovery.ToInteger(bytes);


    private readonly List<LigeroConstraintSystemBuilder> builders = [];


    [TestCleanup]
    public void DisposeBuilders()
    {
        foreach(LigeroConstraintSystemBuilder builder in builders)
        {
            builder.Dispose();
        }
    }


    private (LigeroConstraintSystemBuilder Builder, EcdsaCurve Gadget) NewGadget()
    {
        var builder = new LigeroConstraintSystemBuilder(
            P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
            P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
            CurveParameterSet.None, InverseRate, OpenedColumns, Block, BaseMemoryPool.Shared);
        builders.Add(builder);
        var gadget = new EcdsaCurve(WeierstrassCurve.Create(builder, CurveABytes, CurveBBytes), Bytes(Gx), Bytes(Gy), Bytes(N));

        return (builder, gadget);
    }


    private static BigInteger ModN(BigInteger v) => EcdsaNonceRecovery.ModN(v);

    private static BigInteger ModInvN(BigInteger v) => EcdsaNonceRecovery.ModInvN(v);

    private static (BigInteger X, BigInteger Y) ScalarMultiply(BigInteger scalar, (BigInteger X, BigInteger Y) point) =>
        EcdsaNonceRecovery.ScalarMultiply(scalar, point);

    private static (BigInteger X, BigInteger Y)? OracleAdd((BigInteger X, BigInteger Y)? a, (BigInteger X, BigInteger Y)? b) =>
        EcdsaNonceRecovery.OracleAdd(a, b);

    private static (BigInteger X, BigInteger Y)? OracleScalarMultiply(BigInteger scalar, (BigInteger X, BigInteger Y) point) =>
        EcdsaNonceRecovery.OracleScalarMultiply(scalar, point);

    private static BigInteger Hex(string value) => EcdsaNonceRecovery.Hex(value);

    private static byte[] Bytes(BigInteger value) => EcdsaNonceRecovery.Bytes(value);


    private static LigeroProof Prove(LigeroConstraintSystemBuilder builder, byte[] seed) => LigeroProver.Prove(
        builder.BuildParameters(), builder.WitnessBytes(), builder.LinearConstraintCount, builder.LinearConstraints(),
        builder.TargetBytes(), builder.QuadraticConstraints(), seed,
        new DeterministicFp256Random(RandomnessSeed).AsDelegate(),
        P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
        P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
        Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
        CurveParameterSet.None, BaseMemoryPool.Shared);


    private static bool Verify(LigeroConstraintSystemBuilder builder, LigeroProof proof, byte[] seed) => LigeroVerifier.Verify(
        builder.BuildParameters(), proof, builder.LinearConstraintCount, builder.LinearConstraints(),
        builder.TargetBytes(), builder.QuadraticConstraints(), seed,
        P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
        P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
        Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
        CurveParameterSet.None, BaseMemoryPool.Shared);


    //The same prove/verify over the production Montgomery Fp256 backend (the validated faster
    //encoder path) — byte-identical to the reference, used for the large real-credential circuit.
    private static LigeroProof ProveMontgomery(LigeroConstraintSystemBuilder builder, byte[] seed) => LigeroProver.Prove(
        builder.BuildParameters(), builder.WitnessBytes(), builder.LinearConstraintCount, builder.LinearConstraints(),
        builder.TargetBytes(), builder.QuadraticConstraints(), seed,
        new DeterministicFp256Random(RandomnessSeed).AsDelegate(),
        P256BaseFieldMontgomeryBackend.GetAdd(), P256BaseFieldMontgomeryBackend.GetSubtract(), P256BaseFieldMontgomeryBackend.GetMultiply(),
        P256BaseFieldMontgomeryBackend.GetInvert(), P256BaseFieldMontgomeryBackend.GetReduce(),
        Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
        CurveParameterSet.None, BaseMemoryPool.Shared);


    private static bool VerifyMontgomery(LigeroConstraintSystemBuilder builder, LigeroProof proof, byte[] seed) => LigeroVerifier.Verify(
        builder.BuildParameters(), proof, builder.LinearConstraintCount, builder.LinearConstraints(),
        builder.TargetBytes(), builder.QuadraticConstraints(), seed,
        P256BaseFieldMontgomeryBackend.GetAdd(), P256BaseFieldMontgomeryBackend.GetSubtract(), P256BaseFieldMontgomeryBackend.GetMultiply(),
        P256BaseFieldMontgomeryBackend.GetInvert(), P256BaseFieldMontgomeryBackend.GetReduce(),
        Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
        CurveParameterSet.None, BaseMemoryPool.Shared);


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    //A reproducible Fp256 randomness source: BLAKE3-XOF of seed‖counter reduced
    //modulo the base-field prime.
    private sealed class DeterministicFp256Random
    {
        private readonly byte[] seed;
        private int counter;

        public DeterministicFp256Random(ReadOnlySpan<byte> seed) => this.seed = seed.ToArray();

        public ScalarRandomDelegate AsDelegate() => Fill;

        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[seed.Length + sizeof(int)];
            seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[seed.Length..], counter);
            counter++;

            Span<byte> wide = stackalloc byte[64];
            Blake3.Hash(input, wide);
            BigInteger reduced = new BigInteger(wide, isUnsigned: true, isBigEndian: true) % P;
            destination.Clear();
            reduced.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true);
            if(written < destination.Length)
            {
                int shift = destination.Length - written;
                destination[..written].CopyTo(destination[shift..]);
                destination[..shift].Clear();
            }

            return inboundTag;
        }
    }
}
