using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Ligero.Gadgets;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Mdoc;
using System;
using System.Buffers;
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
    /// <summary>The test context used to read the run's cancellation token for the real-credential async tests.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The canonical scalar width in bytes.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The Ligero inverse rate the gadget's constraint system is built at.</summary>
    private const int InverseRate = 4;

    /// <summary>The number of opened Ligero columns the gadget's constraint system is built at.</summary>
    private const int OpenedColumns = 4;

    /// <summary>The Ligero block size the gadget's constraint system is built at.</summary>
    private const int Block = 64;

    /// <summary>The P-256 base-field modulus.</summary>
    private static BigInteger P { get; } = EcdsaNonceRecovery.P;

    /// <summary>The P-256 short-Weierstrass curve coefficient <c>a</c>.</summary>
    private static BigInteger A { get; } = EcdsaNonceRecovery.A;

    /// <summary>The P-256 short-Weierstrass curve coefficient <c>b</c>.</summary>
    private static BigInteger B { get; } = P256BigIntegerG1Reference.CurveB;

    /// <summary>The P-256 group order.</summary>
    private static BigInteger N { get; } = EcdsaNonceRecovery.N;

    /// <summary>The P-256 generator's x coordinate.</summary>
    private static BigInteger Gx { get; } = EcdsaNonceRecovery.Gx;

    /// <summary>The P-256 generator's y coordinate.</summary>
    private static BigInteger Gy { get; } = EcdsaNonceRecovery.Gy;

    /// <summary>The P-256 generator point.</summary>
    private static (BigInteger X, BigInteger Y) G { get; } = EcdsaNonceRecovery.G;

    /// <summary>The canonical big-endian encoding of <see cref="A"/>.</summary>
    private static byte[] CurveABytes { get; } = Bytes(A);

    /// <summary>The canonical big-endian encoding of <see cref="B"/>.</summary>
    private static byte[] CurveBBytes { get; } = Bytes(B);

    /// <summary>A fixed test private-key scalar, below n (the leading nibble keeps it below n = 0xFFFF…).</summary>
    private static BigInteger D { get; } = Hex("5b1e9f2c4a7d8e3f0a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7081");

    /// <summary>A fixed test nonce scalar, below n (the leading nibble keeps it below n = 0xFFFF…).</summary>
    private static BigInteger K { get; } = Hex("1234567890abcdeffedcba9876543210112233445566778899aabbccddeeff00");

    /// <summary>A fixed test message-hash scalar, below n (the leading nibble keeps it below n = 0xFFFF…).</summary>
    private static BigInteger E { get; } = Hex("0a1b2c3d4e5f60718293a4b5c6d7e8f9000102030405060708090a0b0c0d0e0f");

    /// <summary>The wired Merkle digest size: BLAKE3's 32 bytes.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The Fiat-Shamir domain label the transcript seed is derived under.</summary>
    private static byte[] Domain { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.ecdsa-p256.v1");

    /// <summary>The deterministic prover-randomness seed shared by every proof in this suite.</summary>
    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.ecdsa-p256.rng.v1");

    /// <summary>The transcript's fixed-output BLAKE3 hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = Blake3FiatShamirBackend.GetHash();

    /// <summary>The transcript's BLAKE3 XOF backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = Blake3FiatShamirBackend.GetSqueeze();

    /// <summary>The two-to-one Merkle compression over BLAKE3.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>An 8-bit difference covers any realistic age − threshold gap (0..255).</summary>
    private const int AgeDifferenceBits = 8;

    /// <summary>The age-at-least threshold the age-predicate tests assert against.</summary>
    private const int AgeThreshold = 18;


    /// <summary>Pins that a synthetic ECDSA signature satisfying the Alg.4 identity at the oracle level also verifies in-circuit.</summary>
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


    /// <summary>Pins that incrementing s by one breaks the identity and must not verify.</summary>
    [TestMethod]
    public void RejectsATamperedSignatureS()
    {
        (BigInteger qx, BigInteger qy, BigInteger rx, BigInteger ry, BigInteger r, BigInteger s) = Sign(D, K, E);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, Public(qx, qy, E, r, ((s + 1) % N)), new EcdsaWitness(Bytes(rx), Bytes(ry)));

        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), "A tampered s breaks the identity and must not verify.");
    }


    /// <summary>Pins that a signature does not verify under a different, on-curve public key.</summary>
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


    /// <summary>Pins that witnessing a different on-curve nonce point, whose x does not reduce to r, must not verify.</summary>
    [TestMethod]
    public void RejectsAWrongNoncePoint()
    {
        (BigInteger qx, BigInteger qy, BigInteger _, BigInteger _, BigInteger r, BigInteger s) = Sign(D, K, E);

        //Witness a different on-curve nonce point R' = (k + 1)·G: its x does not
        //reduce to r (the r = R.x mod n binding fails) and the identity does not
        //vanish.
        (BigInteger wrongRx, BigInteger wrongRy) = ScalarMultiply(K + 1, G);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, Public(qx, qy, E, r, s), new EcdsaWitness(Bytes(wrongRx), Bytes(wrongRy)));

        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), "A nonce point whose x ≠ r mod n must not verify.");
    }


    /// <summary>Pins that an off-curve nonce point must not verify.</summary>
    [TestMethod]
    public void RejectsAnOffCurveNoncePoint()
    {
        (BigInteger qx, BigInteger qy, BigInteger rx, BigInteger ry, BigInteger r, BigInteger s) = Sign(D, K, E);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, Public(qx, qy, E, r, s), new EcdsaWitness(Bytes(rx), Bytes((ry + 1) % P)));

        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), "An off-curve nonce point must not verify.");
    }


    /// <summary>Pins that genuine .NET ECDSA signatures over several fresh keys and messages verify in-circuit after recovering the nonce point from the public signature alone, and that tampering s on each breaks verification.</summary>
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


    /// <summary>Proves and verifies a genuine signature using a caller-owned transcript seed.</summary>
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
        using BaseMemoryPool transcriptPool = new();
        using IMemoryOwner<byte> seedOwner = transcriptPool.Rent(ScalarSize);
        Span<byte> seed = seedOwner.Memory.Span[..ScalarSize];
        EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(pub, Domain, Hash, WellKnownHashAlgorithms.Blake3, transcriptPool, seed);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, pub, new EcdsaWitness(Bytes(rx), Bytes(ry)));

        using LigeroProof proof = Prove(builder, seed);
        Assert.IsTrue(Verify(builder, proof, seed), "A genuine .NET ECDSA signature must prove and verify in zero knowledge.");
    }


    /// <summary>Pins that one proof can attest both a valid issuer ECDSA signature and a private age at or above the threshold.</summary>
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


    /// <summary>Pins that a genuinely valid signature does not rescue a sub-threshold age: the age predicate fails independently within the same proof.</summary>
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


    /// <summary>Proves the signature and age threshold with a statement-bound transcript.</summary>
    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void SignatureAndAgeThresholdProveAndVerifyEndToEnd()
    {
        //The headline: one Ligero proof attests, in zero knowledge, that the holder has
        //a valid issuer ECDSA signature AND an age ≥ 18 — the signature verified IN
        //circuit (vs out of circuit in the BLS-Spartan age e2e). Proved and verified
        //end-to-end through the real prover, with the seed bound to the public statement.
        //Scope: the age is a witness not yet cryptographically tied to the signed
        //message; binding it needs in-circuit SHA-256 + CBOR (the GF(2^128) half), so
        //this proves "valid signature AND age ≥ 18", not yet "the signed credential's
        //age ≥ 18". On the order of a few minutes, hardware-dependent; the fast
        //evaluator gates above cover the logic.
        (BigInteger qx, BigInteger qy, BigInteger rx, BigInteger ry, BigInteger r, BigInteger s) = Sign(D, K, E);
        EcdsaPublicInputs pub = Public(qx, qy, E, r, s);
        using BaseMemoryPool transcriptPool = new();
        using IMemoryOwner<byte> seedOwner = transcriptPool.Rent(ScalarSize);
        Span<byte> seed = seedOwner.Memory.Span[..ScalarSize];
        EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(pub, Domain, Hash, WellKnownHashAlgorithms.Blake3, transcriptPool, seed);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, pub, new EcdsaWitness(Bytes(rx), Bytes(ry)));
        builder.AddAtLeast(builder.AddWire(Bytes(34)), Bytes(AgeThreshold), AgeDifferenceBits);

        using LigeroProof proof = Prove(builder, seed);
        Assert.IsTrue(Verify(builder, proof, seed), "An honest signature-plus-age credential proof must verify end-to-end.");
    }


    /// <summary>Checks full-width signature proofs, statement binding and tamper rejection.</summary>
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

        using BaseMemoryPool transcriptPool = new();
        using IMemoryOwner<byte> seedOwner = transcriptPool.Rent(ScalarSize);
        Span<byte> seed = seedOwner.Memory.Span[..ScalarSize];
        EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(pub, Domain, Hash, WellKnownHashAlgorithms.Blake3, transcriptPool, seed);

        var (builder, gadget) = NewGadget();
        builder.AssertVerifies(gadget, pub, wit);

        using LigeroProof proof = Prove(builder, seed);
        Assert.IsTrue(Verify(builder, proof, seed), "An honest full-width ECDSA proof must verify.");

        //Statement binding: the same proof is rejected under a different statement's
        //seed (here the seed for a tampered s).
        using IMemoryOwner<byte> otherSeedOwner = transcriptPool.Rent(ScalarSize);
        Span<byte> otherSeed = otherSeedOwner.Memory.Span[..ScalarSize];
        EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(Public(qx, qy, E, r, (s + 1) % N), Domain, Hash, WellKnownHashAlgorithms.Blake3, transcriptPool, otherSeed);
        Assert.IsFalse(Verify(builder, proof, otherSeed), "A proof must be rejected under a different statement's seed.");

        //Tampering an opened column breaks the proof.
        proof.OpenedColumnMutable(0)[0] ^= 0x01;
        Assert.IsFalse(Verify(builder, proof, seed), "A tampered full-width ECDSA proof must be rejected.");
    }


    /// <summary>Pins that a genuine .NET ECDSA signature verifies in-circuit with the message hash computed inside the proof from the witnessed message, and that tampering the message breaks verification.</summary>
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

        //Tampering the message changes the in-circuit hash, so the identity does not vanish.
        byte[] tampered = (byte[])message.Clone();
        tampered[0] ^= 0x01;
        var (tamperedBuilder, tamperedGadget) = NewGadget();
        tamperedBuilder.AssertVerifiesHashedMessage(tamperedGadget, 
            new EcdsaHashedPublicInputs(Bytes(qx), Bytes(qy), Bytes(r), Bytes(s)),
            new EcdsaHashedWitness(tampered, Bytes(rx), Bytes(ry)));
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(tamperedBuilder), "A tampered message must not verify against the original signature.");
    }


    /// <summary>Pins that a genuine signature over a private message verifies together with disclosure of a public attribute at a witnessed offset within that message, and that an attribute absent from the message cannot be disclosed even under an otherwise-valid signature.</summary>
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


    /// <summary>Pins the full ISO 18013-5 three-level binding — signature over the MSO, MSO digest over the item, item holding the attribute — in one proof, and that an attribute absent from the item cannot be disclosed even when every other level checks out.</summary>
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


    /// <summary>Pins that a genuine ISO 18013-5 credential's age_over_18 disclosure verifies in-circuit over its real bytes, with the nonce point recovered from the real signature.</summary>
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


    /// <summary>
    /// A generous hang guard for the full real-credential prove+verify: the FFT row extender removes the
    /// encoder's super-linear wall, and the measured run is ~37 minutes on a desktop-class machine — the
    /// remaining prover stages walk a ~100k-constraint circuit. Two hours guards a slower runner without
    /// asserting elapsed time; the prove is synchronous and does not observe the cooperative token, so the
    /// guard is sized above the measured run rather than relied on to interrupt it.
    /// </summary>
    private const int EndToEndHangGuardMilliseconds = 7_200_000;


    /// <summary>Proves the real credential disclosure using a statement-bound transcript.</summary>
    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    [Timeout(EndToEndHangGuardMilliseconds, CooperativeCancellation = true)]
    public async Task ProvesAndVerifiesAgeOver18FromARealCredentialEndToEnd()
    {
        //The end-to-end target: a genuine ISO 18013-5 credential's age_over_18 disclosure proved AND
        //verified through the real Ligero prover over the production Montgomery Fp256 backend with the
        //FFT convolution row extender. The circuit is real-credential scale (a ~700-byte in-circuit
        //SHA-256 over the COSE Sig_structure, the item hash, and the three-scalar MSM ⇒ ~100k+
        //constraints); the barycentric encoder was super-linear there — a single prove ran 6.6 hours
        //without finishing — and the extender's convolution produces the byte-identical codeword in
        //linearithmic time. The seed is bound to the public statement.
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

        using BaseMemoryPool transcriptPool = new();
        using IMemoryOwner<byte> seedOwner = transcriptPool.Rent(ScalarSize);
        Span<byte> seed = seedOwner.Memory.Span[..ScalarSize];
        EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(
            Public(qx, qy, e, r, s), Domain, Hash, WellKnownHashAlgorithms.Blake3, transcriptPool, seed);

        using LigeroProof proof = ProveMontgomery(builder, seed);
        Assert.IsTrue(VerifyMontgomery(builder, proof, seed), "A real credential's age_over_18 disclosure must prove and verify end-to-end in zero knowledge.");
    }


    /// <summary>Produces a valid ECDSA signature (r, s) and the corresponding public key and nonce point for the given private key, nonce and message hash.</summary>
    private static (BigInteger Qx, BigInteger Qy, BigInteger Rx, BigInteger Ry, BigInteger R, BigInteger S) Sign(BigInteger d, BigInteger k, BigInteger e)
    {
        (BigInteger qx, BigInteger qy) = ScalarMultiply(d, G);
        (BigInteger rx, BigInteger ry) = ScalarMultiply(k, G);
        BigInteger r = ModN(rx);
        BigInteger s = ModN(ModInvN(k) * (e + (r * d)));

        return (qx, qy, rx, ry, r, s);
    }


    /// <summary>Builds the gadget's public-input bundle from the signature components.</summary>
    private static EcdsaPublicInputs Public(BigInteger qx, BigInteger qy, BigInteger e, BigInteger r, BigInteger s) =>
        new(Bytes(qx), Bytes(qy), Bytes(e), Bytes(r), Bytes(s));


    /// <summary>The nonce point a verifier reconstructs from the public signature alone.</summary>
    private static (BigInteger X, BigInteger Y) RecoverNoncePoint(BigInteger qx, BigInteger qy, BigInteger e, BigInteger r, BigInteger s) =>
        EcdsaNonceRecovery.RecoverNoncePoint(qx, qy, e, r, s);


    /// <summary>Interprets canonical big-endian bytes as an unsigned integer.</summary>
    private static BigInteger ToInteger(ReadOnlySpan<byte> bytes) => EcdsaNonceRecovery.ToInteger(bytes);


    /// <summary>Every constraint builder this test created, disposed together at cleanup.</summary>
    private List<LigeroConstraintSystemBuilder> Builders { get; } = [];


    /// <summary>Disposes every constraint builder this test created.</summary>
    [TestCleanup]
    public void DisposeBuilders()
    {
        foreach(LigeroConstraintSystemBuilder builder in Builders)
        {
            builder.Dispose();
        }
    }


    /// <summary>Builds a fresh constraint builder and the ECDSA curve gadget over it, tracking the builder for cleanup.</summary>
    private (LigeroConstraintSystemBuilder Builder, EcdsaCurve Gadget) NewGadget()
    {
        var builder = new LigeroConstraintSystemBuilder(
            P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
            P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
            CurveParameterSet.None, InverseRate, OpenedColumns, Block, BaseMemoryPool.Shared);
        Builders.Add(builder);
        var gadget = new EcdsaCurve(WeierstrassCurve.Create(builder, CurveABytes, CurveBBytes), Bytes(Gx), Bytes(Gy), Bytes(N));

        return (builder, gadget);
    }


    /// <summary>Reduces a value modulo the P-256 group order.</summary>
    private static BigInteger ModN(BigInteger v) => EcdsaNonceRecovery.ModN(v);

    /// <summary>Inverts a value modulo the P-256 group order.</summary>
    private static BigInteger ModInvN(BigInteger v) => EcdsaNonceRecovery.ModInvN(v);

    /// <summary>Multiplies a P-256 point by a scalar over BigInteger arithmetic.</summary>
    private static (BigInteger X, BigInteger Y) ScalarMultiply(BigInteger scalar, (BigInteger X, BigInteger Y) point) =>
        EcdsaNonceRecovery.ScalarMultiply(scalar, point);

    /// <summary>Adds two P-256 points (or the point at infinity) over BigInteger arithmetic, the out-of-circuit oracle the in-circuit gadget is checked against.</summary>
    private static (BigInteger X, BigInteger Y)? OracleAdd((BigInteger X, BigInteger Y)? a, (BigInteger X, BigInteger Y)? b) =>
        EcdsaNonceRecovery.OracleAdd(a, b);

    /// <summary>Multiplies a P-256 point by a scalar, returning the point at infinity for a zero scalar, over BigInteger arithmetic.</summary>
    private static (BigInteger X, BigInteger Y)? OracleScalarMultiply(BigInteger scalar, (BigInteger X, BigInteger Y) point) =>
        EcdsaNonceRecovery.OracleScalarMultiply(scalar, point);

    /// <summary>Parses a hex string into an unsigned big-endian integer.</summary>
    private static BigInteger Hex(string value) => EcdsaNonceRecovery.Hex(value);

    /// <summary>Converts a value to its canonical big-endian scalar encoding.</summary>
    private static byte[] Bytes(BigInteger value) => EcdsaNonceRecovery.Bytes(value);


    /// <summary>Proves with pooled snapshots that remain owned until the prover returns.</summary>
    /// <param name="builder">The live constraint builder.</param>
    /// <param name="seed">The transcript seed borrowed for this call.</param>
    private static LigeroProof Prove(LigeroConstraintSystemBuilder builder, ReadOnlySpan<byte> seed)
    {
        using IMemoryOwner<byte>? witnessOwner = builder.WitnessBytes();
        using IMemoryOwner<byte>? targetsOwner = builder.TargetBytes();

        return LigeroProver.Prove(
            builder.BuildParameters(), (witnessOwner?.Memory ?? Memory<byte>.Empty).Span, builder.LinearConstraintCount, builder.LinearConstraints(),
            (targetsOwner?.Memory ?? Memory<byte>.Empty).Span, builder.QuadraticConstraints(), seed,
            new DeterministicFp256Random(RandomnessSeed).AsDelegate(),
            P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
            P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
            Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
            CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    /// <summary>Verifies with a pooled target snapshot owned until verification returns.</summary>
    /// <param name="builder">The live constraint builder.</param>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="seed">The transcript seed borrowed for this call.</param>
    private static bool Verify(LigeroConstraintSystemBuilder builder, LigeroProof proof, ReadOnlySpan<byte> seed)
    {
        using IMemoryOwner<byte>? targetsOwner = builder.TargetBytes();

        return LigeroVerifier.Verify(
            builder.BuildParameters(), proof, builder.LinearConstraintCount, builder.LinearConstraints(),
            (targetsOwner?.Memory ?? Memory<byte>.Empty).Span, builder.QuadraticConstraints(), seed,
            P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
            P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
            Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
            CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Proves through the production Montgomery Fp256 backend with the FFT convolution row extender
    /// installed, owning the witness and target snapshots. Byte-identical to the reference path — the
    /// extender computes the same integer-node extension, gated byte-for-byte by
    /// <c>Fp256LigeroRowExtenderTests</c> — and is the path this large real-credential circuit needs:
    /// its O(n²) barycentric encoder alone runs on the order of 6.6 hours over a circuit this size.
    /// </summary>
    /// <param name="builder">The live constraint builder.</param>
    /// <param name="seed">The transcript seed borrowed for this call.</param>
    private static LigeroProof ProveMontgomery(LigeroConstraintSystemBuilder builder, ReadOnlySpan<byte> seed)
    {
        Span<byte> root = stackalloc byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnity(root);
        using BaseMemoryPool fftPool = new();
        using var fft = new Fp256RealFft(
            root, LongfellowFp256Encoding.OmegaOrder,
            P256BaseFieldMontgomeryBackend.GetAdd(), P256BaseFieldMontgomeryBackend.GetSubtract(),
            P256BaseFieldMontgomeryBackend.GetMultiply(), P256BaseFieldMontgomeryBackend.GetInvert(),
            WriteCanonicalUInt, CurveParameterSet.None, fftPool);
        using var extenders = new Fp256LigeroRowExtenders(
            fft,
            P256BaseFieldMontgomeryBackend.GetAdd(), P256BaseFieldMontgomeryBackend.GetSubtract(),
            P256BaseFieldMontgomeryBackend.GetMultiply(), P256BaseFieldMontgomeryBackend.GetInvert(),
            WriteCanonicalUInt, CurveParameterSet.None, BaseMemoryPool.Shared);

        using IMemoryOwner<byte>? witnessOwner = builder.WitnessBytes();
        using IMemoryOwner<byte>? targetsOwner = builder.TargetBytes();

        return LigeroProver.Prove(
            builder.BuildParameters(), (witnessOwner?.Memory ?? Memory<byte>.Empty).Span, builder.LinearConstraintCount, builder.LinearConstraints(),
            (targetsOwner?.Memory ?? Memory<byte>.Empty).Span, builder.QuadraticConstraints(), seed,
            new DeterministicFp256Random(RandomnessSeed).AsDelegate(),
            P256BaseFieldMontgomeryBackend.GetAdd(), P256BaseFieldMontgomeryBackend.GetSubtract(), P256BaseFieldMontgomeryBackend.GetMultiply(),
            P256BaseFieldMontgomeryBackend.GetInvert(), P256BaseFieldMontgomeryBackend.GetReduce(),
            Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
            CurveParameterSet.None, BaseMemoryPool.Shared,
            rowExtenderFactory: extenders.Create);
    }


    /// <summary>Writes a 32-bit value as a zero-padded canonical big-endian scalar.</summary>
    private static void WriteCanonicalUInt(uint value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[(ScalarSize - sizeof(uint))..], value);
    }


    /// <summary>Verifies with a pooled target snapshot owned until verification returns.</summary>
    /// <param name="builder">The live constraint builder.</param>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="seed">The transcript seed borrowed for this call.</param>
    private static bool VerifyMontgomery(LigeroConstraintSystemBuilder builder, LigeroProof proof, ReadOnlySpan<byte> seed)
    {
        using IMemoryOwner<byte>? targetsOwner = builder.TargetBytes();

        return LigeroVerifier.Verify(
            builder.BuildParameters(), proof, builder.LinearConstraintCount, builder.LinearConstraints(),
            (targetsOwner?.Memory ?? Memory<byte>.Empty).Span, builder.QuadraticConstraints(), seed,
            P256BaseFieldMontgomeryBackend.GetAdd(), P256BaseFieldMontgomeryBackend.GetSubtract(), P256BaseFieldMontgomeryBackend.GetMultiply(),
            P256BaseFieldMontgomeryBackend.GetInvert(), P256BaseFieldMontgomeryBackend.GetReduce(),
            Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
            CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    /// <summary>The two-to-one compression: BLAKE3 over the concatenated children.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>A reproducible Fp256 randomness source: BLAKE3-XOF of seed‖counter reduced modulo the base-field prime.</summary>
    private sealed class DeterministicFp256Random
    {
        /// <summary>The fixed seed this source's every draw is derived from.</summary>
        private byte[] Seed { get; }

        /// <summary>The number of scalars drawn so far, mixed into each draw's pre-image.</summary>
        private int counter;

        /// <summary>Copies the seed for this source's lifetime.</summary>
        public DeterministicFp256Random(ReadOnlySpan<byte> seed) => this.Seed = seed.ToArray();

        /// <summary>Returns this source's fill delegate.</summary>
        public ScalarRandomDelegate AsDelegate() => Fill;

        /// <summary>Draws the next reproducible scalar: BLAKE3-XOF of seed‖counter reduced modulo the base-field prime, then advances the counter.</summary>
        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[Seed.Length + sizeof(int)];
            Seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[Seed.Length..], counter);
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
