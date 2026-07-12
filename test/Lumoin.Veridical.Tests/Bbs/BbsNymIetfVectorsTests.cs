using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Bbs.IetfVectors.Pseudonym;
using Lumoin.Veridical.Tests.Bbs.IetfVectors.Pseudonym.Sha256;
using Lumoin.Veridical.Tests.Bbs.IetfVectors.Pseudonym.Shake256;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Byte-equality tests against the per-verifier-pseudonym Appendix
/// vectors for both ciphersuites: the generator-derivation vectors, the
/// CommitWithNym vectors (KAT ladder Level 2), the BlindSignWithNym
/// vectors with their printed B and domain traces (Level 3), and the
/// full ProofGenWithNym / ProofVerifyWithNym pipeline including the
/// pseudonym bytes (Level 4), plus the recovered-scalar provenance
/// consistency (<c>prover_nym + signer_nym_entropy mod r == nym_secret</c>
/// and the pseudonym recomputation from <c>nym_secret</c>).
/// </summary>
/// <remarks>
/// <para>
/// Load-bearing correctness gate for the pseudonym Interface: any
/// divergence here means the implementation differs from any other
/// conformant implementation of
/// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c>.
/// </para>
/// <para>
/// Every vector in this family carries a single prover_nym scalar, so
/// the nym-vector length bound into <c>combined_header</c> is 1
/// throughout — derived in these tests from the prover_nyms vector
/// length, exactly as the operations derive it. The proof vectors'
/// <c>SignerMessageCount</c> field transcribes the draft's printed
/// <c>L</c> trace, which is the SIGNER-known message count the
/// verifier receives as an explicit input.
/// </para>
/// </remarks>
[TestClass]
internal sealed class BbsNymIetfVectorsTests
{
    private sealed record SuiteWiring(
        BbsCiphersuite PseudonymCiphersuite,
        ExpandMessageDelegate ExpandMessage,
        ScalarHashToScalarDelegate HashToScalar,
        G1HashToCurveDelegate G1HashToCurve);


    //Hash-delegate selection routes through the base hash suite: the
    //pseudonym interface value shares its expand_message/hash_to_scalar/
    //hash_to_curve flavor with the core suite it builds on.
    private static SuiteWiring CreateWiring(BbsCiphersuite pseudonymCiphersuite)
    {
        bool isSha256 = pseudonymCiphersuite.BaseHashSuite == BbsCiphersuite.Bls12Curve381Sha256;

        return new SuiteWiring(
            pseudonymCiphersuite,
            isSha256 ? TestSetup.Sha256.ExpandMessage : TestSetup.Shake256.ExpandMessage,
            isSha256 ? TestSetup.Sha256.HashToScalar : TestSetup.Shake256.HashToScalar,
            isSha256 ? TestSetup.Sha256.G1HashToCurve : TestSetup.Shake256.G1HashToCurve);
    }


    private static readonly SuiteWiring Sha256Wiring = CreateWiring(BbsCiphersuite.Bls12Curve381Sha256Pseudonym);
    private static readonly SuiteWiring Shake256Wiring = CreateWiring(BbsCiphersuite.Bls12Curve381Shake256Pseudonym);


    public static IEnumerable<object[]> Sha256CommitVectorsData =>
        Sha256NymCommitVectors.All.Select(v => new object[] { v });

    public static IEnumerable<object[]> Shake256CommitVectorsData =>
        Shake256NymCommitVectors.All.Select(v => new object[] { v });

    public static IEnumerable<object[]> Sha256SignatureVectorsData =>
        Sha256NymSignatureVectors.All.Select(v => new object[] { v });

    public static IEnumerable<object[]> Shake256SignatureVectorsData =>
        Shake256NymSignatureVectors.All.Select(v => new object[] { v });

    public static IEnumerable<object[]> Sha256ProofVectorsData =>
        Sha256NymProofVectors.All.Select(v => new object[] { v });

    public static IEnumerable<object[]> Shake256ProofVectorsData =>
        Shake256NymProofVectors.All.Select(v => new object[] { v });


    [TestMethod]
    public void GeneratorsVector_SignerFamily_Bls12Curve381Sha256() =>
        RunGeneratorsVector(
            Sha256NymGeneratorsVectors.Vector001,
            WellKnownBbsCiphersuites.Bls12Curve381Sha256Pseudonym,
            Sha256Wiring);


    [TestMethod]
    public void GeneratorsVector_BlindFamily_Bls12Curve381Sha256() =>
        RunGeneratorsVector(
            Sha256NymGeneratorsVectors.Vector002,
            BbsBlindAlgorithm.GetBlindGeneratorApiId(WellKnownBbsCiphersuites.Bls12Curve381Sha256Pseudonym),
            Sha256Wiring);


    [TestMethod]
    public void GeneratorsVector_SignerFamily_Bls12Curve381Shake256() =>
        RunGeneratorsVector(
            Shake256NymGeneratorsVectors.Vector001,
            WellKnownBbsCiphersuites.Bls12Curve381Shake256Pseudonym,
            Shake256Wiring);


    [TestMethod]
    public void GeneratorsVector_BlindFamily_Bls12Curve381Shake256() =>
        RunGeneratorsVector(
            Shake256NymGeneratorsVectors.Vector002,
            BbsBlindAlgorithm.GetBlindGeneratorApiId(WellKnownBbsCiphersuites.Bls12Curve381Shake256Pseudonym),
            Shake256Wiring);


    [TestMethod]
    [DynamicData(nameof(Sha256CommitVectorsData))]
    public void CommitVector_Bls12Curve381Sha256(NymCommitVector vector) =>
        RunCommitVector(vector, Sha256Wiring);


    [TestMethod]
    [DynamicData(nameof(Shake256CommitVectorsData))]
    public void CommitVector_Bls12Curve381Shake256(NymCommitVector vector) =>
        RunCommitVector(vector, Shake256Wiring);


    [TestMethod]
    [DynamicData(nameof(Sha256SignatureVectorsData))]
    public void SignatureVector_Bls12Curve381Sha256(NymSignatureVector vector) =>
        RunSignatureVector(vector, Sha256Wiring);


    [TestMethod]
    [DynamicData(nameof(Shake256SignatureVectorsData))]
    public void SignatureVector_Bls12Curve381Shake256(NymSignatureVector vector) =>
        RunSignatureVector(vector, Shake256Wiring);


    [TestMethod]
    [DynamicData(nameof(Sha256ProofVectorsData))]
    public void ProofVector_Bls12Curve381Sha256(NymProofVector vector) =>
        RunProofVector(vector, Sha256NymSignatureVectors.Vector004, Sha256Wiring);


    [TestMethod]
    [DynamicData(nameof(Shake256ProofVectorsData))]
    public void ProofVector_Bls12Curve381Shake256(NymProofVector vector) =>
        RunProofVector(vector, Shake256NymSignatureVectors.Vector004, Shake256Wiring);


    [TestMethod]
    [DynamicData(nameof(Sha256ProofVectorsData))]
    public void RecoveredScalarProvenance_Bls12Curve381Sha256(NymProofVector vector) =>
        RunRecoveredScalarProvenance(vector, Sha256Wiring);


    [TestMethod]
    [DynamicData(nameof(Shake256ProofVectorsData))]
    public void RecoveredScalarProvenance_Bls12Curve381Shake256(NymProofVector vector) =>
        RunRecoveredScalarProvenance(vector, Shake256Wiring);


    private static void RunGeneratorsVector(NymGeneratorsVector vector, string expectedApiId, SuiteWiring wiring)
    {
        //The vector pins the api_id octets the generator family derives
        //under; the compile-time constant composition must reproduce them.
        Assert.AreEqual(vector.ApiId, Convert.ToHexStringLower(Encoding.UTF8.GetBytes(expectedApiId)),
            $"api_id octet mismatch for '{vector.Id}'.");

        //P1 is a ciphersuite constant independent of the interface: the
        //pseudonym interface value must dispatch to the same bytes the
        //vector prints.
        using(G1Point p1 = BbsP1Generator.GetForCiphersuite(wiring.PseudonymCiphersuite, TestSetup.Pool))
        {
            Assert.AreEqual(vector.P1, Convert.ToHexStringLower(p1.AsReadOnlySpan()),
                $"P1 mismatch for '{vector.Id}'.");
        }

        int generatorCount = 1 + vector.MessageGenerators.Count;
        ImmutableArray<G1Point> generators = BbsAlgorithm.CreateGenerators(
            generatorCount,
            expectedApiId,
            wiring.ExpandMessage,
            wiring.G1HashToCurve,
            TestSetup.Pool);
        try
        {
            Assert.AreEqual(vector.Q1, Convert.ToHexStringLower(generators[0].AsReadOnlySpan()),
                $"First generator (Q) mismatch for '{vector.Id}'.");
            for(int i = 0; i < vector.MessageGenerators.Count; i++)
            {
                Assert.AreEqual(vector.MessageGenerators[i], Convert.ToHexStringLower(generators[1 + i].AsReadOnlySpan()),
                    $"Message generator #{i + 1} mismatch for '{vector.Id}'.");
            }
        }
        finally
        {
            foreach(G1Point generator in generators)
            {
                generator.Dispose();
            }
        }
    }


    private static void RunCommitVector(NymCommitVector vector, SuiteWiring wiring)
    {
        BbsMessage[] committedMessages = DecodeMessages(vector.CommittedMessages);
        byte[] seed = Convert.FromHexString(vector.MockedScalarSeed);
        byte[] expectedCommitmentWithProof = Convert.FromHexString(vector.CommitmentWithProof);

        //One m~ per committed message plus one for the prover_nym slot;
        //plus secret_prover_blind and s~.
        int committedScalarCount = committedMessages.Length + 1;
        int mockedScalarCount = committedScalarCount + 2;

        //The fixture mock DST is composed on the CORE interface api_id, not
        //the pseudonym one; the vector pins the exact octets.
        BbsCiphersuite baseSuite = wiring.PseudonymCiphersuite.BaseHashSuite;
        Assert.AreEqual(
            vector.MockedScalarDst,
            Convert.ToHexStringLower(Encoding.UTF8.GetBytes(baseSuite.Identifier + WellKnownBbsDomainSeparationTags.CommitMockRandomScalarsDstSuffix)),
            $"Mocked-scalar DST mismatch for '{vector.Id}'.");

        //The mocked stream itself must reproduce the printed trace scalars in
        //the CoreCommit draw order: secret_prover_blind, s~, m~_1..m~_{M+N}.
        ScalarRandomDelegate traceSource = BbsDeterministicScalars.FromSeed(
            seed,
            baseSuite,
            WellKnownBbsDomainSeparationTags.CommitMockRandomScalarsDstSuffix,
            mockedScalarCount,
            wiring.ExpandMessage,
            TestSetup.ScalarReduce);
        Assert.HasCount(committedScalarCount, vector.MTildes,
            $"m~ trace count mismatch for '{vector.Id}' (§{vector.DraftSection}).");
        string[] expectedTrace = new string[mockedScalarCount];
        expectedTrace[0] = vector.ProverBlind;
        expectedTrace[1] = vector.STilde;
        for(int i = 0; i < committedScalarCount; i++)
        {
            expectedTrace[2 + i] = vector.MTildes[i];
        }
        for(int i = 0; i < mockedScalarCount; i++)
        {
            using Scalar traced = Scalar.FromRandom(traceSource, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
            Assert.AreEqual(expectedTrace[i], Convert.ToHexStringLower(traced.AsReadOnlySpan()),
                $"Mocked-scalar trace #{i} mismatch for '{vector.Id}' (§{vector.DraftSection}).");
        }

        //CommitWithNym byte reproduction: a fresh mocked source drives the
        //commit; the prover_nym enters as a caller-held scalar, never from
        //the mocked stream.
        ScalarRandomDelegate deterministicRng = BbsDeterministicScalars.FromSeed(
            seed,
            baseSuite,
            WellKnownBbsDomainSeparationTags.CommitMockRandomScalarsDstSuffix,
            mockedScalarCount,
            wiring.ExpandMessage,
            TestSetup.ScalarReduce);

        using Scalar proverNym = Scalar.FromCanonical(Convert.FromHexString(vector.ProverNym), CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        (BbsCommitmentWithProof commitmentWithProof, Scalar secretProverBlind) = BbsCommitmentWithProof.CommitWithNym(
            committedMessages,
            new[] { proverNym },
            wiring.PseudonymCiphersuite,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarMultiply,
            deterministicRng,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.Pool);
        using(commitmentWithProof)
        using(secretProverBlind)
        {
            Assert.IsTrue(commitmentWithProof.AsReadOnlySpan().SequenceEqual(expectedCommitmentWithProof),
                $"CommitWithNym byte-equality failed for '{vector.Id}' (§{vector.DraftSection}).\n  expected: {vector.CommitmentWithProof}\n  got:      {Convert.ToHexStringLower(commitmentWithProof.AsReadOnlySpan())}");
            Assert.AreEqual(vector.ProverBlind, Convert.ToHexStringLower(secretProverBlind.AsReadOnlySpan()),
                $"secret_prover_blind mismatch for '{vector.Id}' (§{vector.DraftSection}).");
        }

        //deserialize_and_validate_commit acceptance over the published octets
        //under the pseudonym interface api_id.
        using BbsCommitmentWithProof decoded = BbsCommitmentWithProof.FromCanonical(
            expectedCommitmentWithProof,
            wiring.PseudonymCiphersuite,
            TestSetup.Pool);
        Assert.IsTrue(
            decoded.Verify(
                wiring.ExpandMessage,
                wiring.HashToScalar,
                TestSetup.ScalarNegate,
                TestSetup.G1MultiScalarMultiply,
                wiring.G1HashToCurve,
                TestSetup.G1IsOnCurve,
                TestSetup.G1IsInPrimeOrderSubgroup,
                TestSetup.Pool),
            $"CoreCommitVerify must accept the published commitment for '{vector.Id}' (§{vector.DraftSection}).");
    }


    private static void RunSignatureVector(NymSignatureVector vector, SuiteWiring wiring)
    {
        BbsCiphersuite baseSuite = wiring.PseudonymCiphersuite.BaseHashSuite;
        string apiId = wiring.PseudonymCiphersuite.Identifier;

        BbsMessage[] messages = DecodeMessages(vector.Messages);
        BbsMessage[] committedMessages = DecodeMessages(vector.CommittedMessages);
        byte[] headerBytes = Convert.FromHexString(vector.Header);
        byte[] commitmentBytes = Convert.FromHexString(vector.CommitmentWithProof);
        byte[] expectedSignature = Convert.FromHexString(vector.Signature);

        using BbsSecretKey secretKey = BbsSecretKey.FromCanonical(Convert.FromHexString(vector.SignerSecretKey), baseSuite, TestSetup.Pool);
        using BbsPublicKey publicKey = BbsPublicKey.FromCanonical(Convert.FromHexString(vector.SignerPublicKey), baseSuite, TestSetup.Pool);
        using Scalar signerNymEntropy = Scalar.FromCanonical(Convert.FromHexString(vector.SignerNymEntropy), CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        using Scalar proverNym = Scalar.FromCanonical(Convert.FromHexString(vector.ProverNym), CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        using Scalar secretProverBlind = Scalar.FromCanonical(Convert.FromHexString(vector.ProverBlind), CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        using BbsCommitmentWithProof commitmentWithProof = BbsCommitmentWithProof.FromCanonical(commitmentBytes, wiring.PseudonymCiphersuite, TestSetup.Pool);

        //Every vector in this family carries a single prover_nym.
        const int lengthNymVector = 1;

        //Trace assertions: recompute domain and B through the same internal
        //primitives the operation composes, pinning exactly where any
        //divergence sits before the end-to-end byte comparison runs.
        int signerMessageCount = messages.Length;
        int committedScalarCount = commitmentWithProof.CommittedMessageCount;
        ImmutableArray<G1Point> generators = BbsAlgorithm.CreateGenerators(signerMessageCount + 1, apiId, wiring.ExpandMessage, wiring.G1HashToCurve, TestSetup.Pool);
        ImmutableArray<G1Point> blindGenerators = BbsAlgorithm.CreateGenerators(
            committedScalarCount + 1,
            BbsBlindAlgorithm.GetBlindGeneratorApiId(apiId),
            wiring.ExpandMessage,
            wiring.G1HashToCurve,
            TestSetup.Pool);
        ImmutableArray<Scalar> messageScalars = BbsAlgorithm.MessagesToScalars(messages, apiId, wiring.HashToScalar, TestSetup.Pool);
        try
        {
            (IMemoryOwner<byte> combinedHeaderOwner, int combinedHeaderLength) = BbsPseudonymAlgorithm.ComputeCombinedHeader(headerBytes, lengthNymVector, TestSetup.Pool);
            using IMemoryOwner<byte> combinedHeader = combinedHeaderOwner;

            G1Point[] domainHPoints = new G1Point[signerMessageCount + committedScalarCount + 1];
            for(int i = 0; i < signerMessageCount; i++)
            {
                domainHPoints[i] = generators[1 + i];
            }
            for(int i = 0; i < blindGenerators.Length; i++)
            {
                domainHPoints[signerMessageCount + i] = blindGenerators[i];
            }
            using Scalar domain = BbsAlgorithm.CalculateDomain(publicKey, generators[0], domainHPoints, combinedHeader.Memory[..combinedHeaderLength], apiId, wiring.HashToScalar, TestSetup.Pool);
            Assert.AreEqual(vector.TraceDomain, Convert.ToHexStringLower(domain.AsReadOnlySpan()),
                $"domain trace mismatch for '{vector.Id}' (§{vector.DraftSection}).");

            //B = P1 + Q_1 * domain + sum H_i * msg_i + commitment + J_last * entropy.
            using G1Point p1 = BbsP1Generator.GetForCiphersuite(baseSuite, TestSetup.Pool);
            using G1Point bWithoutCommitment = BbsAlgorithm.ComputeMessageCommitment(p1, generators[0], domain, generators.AsSpan()[1..], messageScalars.AsSpan(), TestSetup.G1Add, TestSetup.G1MultiScalarMultiply, TestSetup.Pool);
            using G1Point commitmentPoint = G1Point.FromCanonical(commitmentWithProof.GetCBytes(), CurveParameterSet.Bls12Curve381, TestSetup.Pool);
            using G1Point bWithCommitment = bWithoutCommitment.Add(commitmentPoint, TestSetup.G1Add, TestSetup.Pool);
            using G1Point entropyTerm = blindGenerators[^1].ScalarMultiply(signerNymEntropy, TestSetup.G1ScalarMultiply, TestSetup.Pool);
            using G1Point b = bWithCommitment.Add(entropyTerm, TestSetup.G1Add, TestSetup.Pool);
            Assert.AreEqual(vector.TraceB, Convert.ToHexStringLower(b.AsReadOnlySpan()),
                $"B trace mismatch for '{vector.Id}' (§{vector.DraftSection}).");
        }
        finally
        {
            foreach(Scalar scalar in messageScalars)
            {
                scalar.Dispose();
            }
            foreach(G1Point generator in generators)
            {
                generator.Dispose();
            }
            foreach(G1Point generator in blindGenerators)
            {
                generator.Dispose();
            }
        }

        //BlindSignWithNym byte reproduction.
        using BbsBlindSignature actualSignature = secretKey.BlindSignWithNym(
            publicKey,
            commitmentWithProof,
            lengthNymVector,
            signerNymEntropy,
            new BbsHeader(headerBytes),
            messages,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarNegate,
            TestSetup.ScalarInvert,
            TestSetup.G1Add,
            TestSetup.G1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.Pool);
        Assert.IsTrue(actualSignature.AsReadOnlySpan().SequenceEqual(expectedSignature),
            $"BlindSignWithNym byte-equality failed for '{vector.Id}' (§{vector.DraftSection}).\n  expected: {vector.Signature}\n  got:      {Convert.ToHexStringLower(actualSignature.AsReadOnlySpan())}");

        //VerifyFinalizeWithNym acceptance over the published octets, returning
        //the finalized nym_secrets.
        using BbsBlindSignature signatureToVerify = BbsBlindSignature.FromCanonical(expectedSignature, wiring.PseudonymCiphersuite, TestSetup.Pool);
        Scalar[]? nymSecrets = signatureToVerify.VerifyFinalizeWithNym(
            publicKey,
            new BbsHeader(headerBytes),
            messages,
            committedMessages,
            new[] { proverNym },
            signerNymEntropy,
            secretProverBlind,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.G1Add,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.G2Add,
            TestSetup.G2ScalarMultiply,
            TestSetup.G2IsOnCurve,
            TestSetup.G2IsInPrimeOrderSubgroup,
            TestSetup.Pairing,
            TestSetup.Pool);
        Assert.IsNotNull(nymSecrets,
            $"VerifyFinalizeWithNym must accept the published signature for '{vector.Id}' (§{vector.DraftSection}).");
        try
        {
            Assert.HasCount(lengthNymVector, nymSecrets,
                $"nym_secrets count mismatch for '{vector.Id}' (§{vector.DraftSection}).");
            Assert.AreEqual(vector.NymSecret, Convert.ToHexStringLower(nymSecrets[0].AsReadOnlySpan()),
                $"nym_secret mismatch for '{vector.Id}' (§{vector.DraftSection}).");
        }
        finally
        {
            foreach(Scalar nymSecret in nymSecrets)
            {
                nymSecret.Dispose();
            }
        }
    }


    private static void RunProofVector(NymProofVector vector, NymSignatureVector signingChain, SuiteWiring wiring)
    {
        BbsCiphersuite baseSuite = wiring.PseudonymCiphersuite.BaseHashSuite;

        //Every proof vector chains from the suite's §12.x.4.4 signature (all
        //signer and committed messages present); the undisclosed message
        //contents come from that chain, since the proof vector prints only
        //the disclosed subset.
        Assert.AreEqual(signingChain.Signature, vector.Signature,
            $"Proof vector '{vector.Id}' does not chain from the expected signature vector.");
        BbsMessage[] messages = DecodeMessages(signingChain.Messages);
        BbsMessage[] committedMessages = DecodeMessages(signingChain.CommittedMessages);

        byte[] headerBytes = Convert.FromHexString(vector.Header);
        byte[] presentationHeaderBytes = Convert.FromHexString(vector.PresentationHeader);
        byte[] contextId = Convert.FromHexString(vector.ContextId);
        byte[] seed = Convert.FromHexString(vector.MockedScalarSeed);
        byte[] expectedProof = Convert.FromHexString(vector.Proof);
        int[] disclosedIndices = vector.DisclosedMessageIndexes.ToArray();
        int[] disclosedCommittedIndices = vector.DisclosedCommittedMessageIndexes.ToArray();

        using BbsPublicKey publicKey = BbsPublicKey.FromCanonical(Convert.FromHexString(vector.SignerPublicKey), baseSuite, TestSetup.Pool);
        using BbsBlindSignature signature = BbsBlindSignature.FromCanonical(Convert.FromHexString(vector.Signature), wiring.PseudonymCiphersuite, TestSetup.Pool);
        using Scalar nymSecret = Scalar.FromCanonical(Convert.FromHexString(vector.NymSecret), CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        using Scalar secretProverBlind = Scalar.FromCanonical(Convert.FromHexString(vector.ProverBlind), CurveParameterSet.Bls12Curve381, TestSetup.Pool);

        const int lengthNymVector = 1;

        //Domain trace: recomputed through the same internal primitives the
        //proof operations compose — combined generator list (H_1..H_L, Q_2,
        //J_1..J_{M'+N}) under the length-suffixed combined_header — pinning
        //exactly where any divergence sits before the end-to-end byte
        //comparison runs.
        string apiId = wiring.PseudonymCiphersuite.Identifier;
        ImmutableArray<G1Point> generators = BbsAlgorithm.CreateGenerators(messages.Length + 1, apiId, wiring.ExpandMessage, wiring.G1HashToCurve, TestSetup.Pool);
        ImmutableArray<G1Point> blindGenerators = BbsAlgorithm.CreateGenerators(
            committedMessages.Length + lengthNymVector + 1,
            BbsBlindAlgorithm.GetBlindGeneratorApiId(apiId),
            wiring.ExpandMessage,
            wiring.G1HashToCurve,
            TestSetup.Pool);
        try
        {
            (IMemoryOwner<byte> combinedHeaderOwner, int combinedHeaderLength) = BbsPseudonymAlgorithm.ComputeCombinedHeader(headerBytes, lengthNymVector, TestSetup.Pool);
            using IMemoryOwner<byte> combinedHeader = combinedHeaderOwner;

            G1Point[] domainHPoints = new G1Point[messages.Length + blindGenerators.Length];
            for(int i = 0; i < messages.Length; i++)
            {
                domainHPoints[i] = generators[1 + i];
            }
            for(int i = 0; i < blindGenerators.Length; i++)
            {
                domainHPoints[messages.Length + i] = blindGenerators[i];
            }
            using Scalar domain = BbsAlgorithm.CalculateDomain(publicKey, generators[0], domainHPoints, combinedHeader.Memory[..combinedHeaderLength], apiId, wiring.HashToScalar, TestSetup.Pool);
            Assert.AreEqual(vector.TraceDomain, Convert.ToHexStringLower(domain.AsReadOnlySpan()),
                $"domain trace mismatch for '{vector.Id}' (§{vector.DraftSection}).");
        }
        finally
        {
            foreach(G1Point generator in generators)
            {
                generator.Dispose();
            }
            foreach(G1Point generator in blindGenerators)
            {
                generator.Dispose();
            }
        }

        //Full combined vector: L signer messages + secret_prover_blind +
        //committed messages + nym_secrets.
        int totalMessageCount = messages.Length + 1 + committedMessages.Length + lengthNymVector;
        int undisclosedCount = totalMessageCount - disclosedIndices.Length - disclosedCommittedIndices.Length;
        int randomScalarCount = 5 + undisclosedCount;

        //The fixture mock DST is composed on the CORE interface api_id.
        Assert.AreEqual(
            vector.MockedScalarDst,
            Convert.ToHexStringLower(Encoding.UTF8.GetBytes(baseSuite.Identifier + WellKnownBbsDomainSeparationTags.ProofMockRandomScalarsDstSuffix)),
            $"Mocked-scalar DST mismatch for '{vector.Id}'.");

        //The mocked stream must reproduce the printed traces at the draw
        //positions the draft prints: r_1, r_2 lead; the m~ block trails
        //(e~, r1~, r3~ print as "undefined" in the draft and are skipped).
        Assert.HasCount(undisclosedCount, vector.TraceMTildeScalars,
            $"m~ trace count mismatch for '{vector.Id}' (§{vector.DraftSection}).");
        ScalarRandomDelegate traceSource = BbsDeterministicScalars.FromSeed(
            seed,
            baseSuite,
            WellKnownBbsDomainSeparationTags.ProofMockRandomScalarsDstSuffix,
            randomScalarCount,
            wiring.ExpandMessage,
            TestSetup.ScalarReduce);
        for(int i = 0; i < randomScalarCount; i++)
        {
            using Scalar traced = Scalar.FromRandom(traceSource, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
            string? expectedTraceValue = i switch
            {
                0 => vector.TraceR1,
                1 => vector.TraceR2,
                >= 5 => vector.TraceMTildeScalars[i - 5],
                _ => null,
            };
            if(expectedTraceValue is not null)
            {
                Assert.AreEqual(expectedTraceValue, Convert.ToHexStringLower(traced.AsReadOnlySpan()),
                    $"Mocked-scalar trace #{i} mismatch for '{vector.Id}' (§{vector.DraftSection}).");
            }
        }

        //ProofGenWithNym byte reproduction, including the pseudonym octets.
        ScalarRandomDelegate deterministicRng = BbsDeterministicScalars.FromSeed(
            seed,
            baseSuite,
            WellKnownBbsDomainSeparationTags.ProofMockRandomScalarsDstSuffix,
            randomScalarCount,
            wiring.ExpandMessage,
            TestSetup.ScalarReduce);

        (BbsPseudonymProof actualProof, BbsPseudonym actualPseudonym) = signature.ProofGenWithNym(
            publicKey,
            new BbsHeader(headerBytes),
            new BbsPresentationHeader(presentationHeaderBytes),
            new[] { nymSecret },
            contextId,
            messages,
            committedMessages,
            disclosedIndices,
            disclosedCommittedIndices,
            secretProverBlind,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarSubtract,
            TestSetup.ScalarMultiply,
            TestSetup.ScalarNegate,
            TestSetup.ScalarInvert,
            deterministicRng,
            TestSetup.G1Add,
            TestSetup.G1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.Pool);
        using(actualProof)
        using(actualPseudonym)
        {
            Assert.AreEqual(vector.Pseudonym, Convert.ToHexStringLower(actualPseudonym.AsReadOnlySpan()),
                $"Pseudonym byte-equality failed for '{vector.Id}' (§{vector.DraftSection}).");
            Assert.AreEqual(vector.TraceChallenge, Convert.ToHexStringLower(actualProof.GetChallengeBytes()),
                $"challenge trace mismatch for '{vector.Id}' (§{vector.DraftSection}).");
            Assert.IsTrue(actualProof.AsReadOnlySpan().SequenceEqual(expectedProof),
                $"ProofGenWithNym byte-equality failed for '{vector.Id}' (§{vector.DraftSection}).\n  expected: {vector.Proof}\n  got:      {Convert.ToHexStringLower(actualProof.AsReadOnlySpan())}");
        }

        //ProofVerifyWithNym acceptance over the published octets. The
        //vector's SignerMessageCount field transcribes the draft's printed L
        //trace — the signer-known message count the verifier receives.
        int signerMessageCount = vector.SignerMessageCount;
        Assert.AreEqual(messages.Length, signerMessageCount,
            $"The printed L trace must equal the signing chain's message count for '{vector.Id}'.");
        BbsMessage[] disclosedMessages = DecodeMessages(vector.DisclosedMessages);
        BbsMessage[] disclosedCommittedMessages = DecodeMessages(vector.DisclosedCommittedMessages);
        using BbsPseudonymProof proofToVerify = BbsPseudonymProof.FromCanonical(expectedProof, wiring.PseudonymCiphersuite, TestSetup.Pool);
        using BbsPseudonym pseudonymToVerify = BbsPseudonym.FromCanonical(Convert.FromHexString(vector.Pseudonym), wiring.PseudonymCiphersuite, TestSetup.Pool);
        Assert.IsTrue(
            publicKey.ProofVerifyWithNym(
                proofToVerify,
                pseudonymToVerify,
                new BbsHeader(headerBytes),
                new BbsPresentationHeader(presentationHeaderBytes),
                contextId,
                lengthNymVector,
                signerMessageCount,
                disclosedMessages,
                disclosedCommittedMessages,
                disclosedIndices,
                disclosedCommittedIndices,
                wiring.ExpandMessage,
                wiring.HashToScalar,
                TestSetup.ScalarAdd,
                TestSetup.ScalarMultiply,
                TestSetup.ScalarNegate,
                TestSetup.G1Add,
                TestSetup.G1MultiScalarMultiply,
                wiring.G1HashToCurve,
                TestSetup.G1IsOnCurve,
                TestSetup.G1IsInPrimeOrderSubgroup,
                TestSetup.G2Add,
                TestSetup.G2ScalarMultiply,
                TestSetup.G2IsOnCurve,
                TestSetup.G2IsInPrimeOrderSubgroup,
                TestSetup.Pairing,
                TestSetup.Pool),
            $"ProofVerifyWithNym must accept the published proof for '{vector.Id}' (§{vector.DraftSection}).");
    }


    private static void RunRecoveredScalarProvenance(NymProofVector vector, SuiteWiring wiring)
    {
        //Three-way consistency of the recovered scalars (the draft prints
        //prover_nym and nym_secret as "undefined"; see the vector records'
        //provenance docs): the entropy fold reproduces nym_secret, and
        //nym_secret reproduces the printed pseudonym bytes under the printed
        //context_id.
        using Scalar proverNym = Scalar.FromCanonical(Convert.FromHexString(vector.ProverNym), CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        using Scalar signerNymEntropy = Scalar.FromCanonical(Convert.FromHexString(vector.SignerNymEntropy), CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        using Scalar computedNymSecret = proverNym.Add(signerNymEntropy, TestSetup.ScalarAdd, TestSetup.Pool);
        Assert.AreEqual(vector.NymSecret, Convert.ToHexStringLower(computedNymSecret.AsReadOnlySpan()),
            $"prover_nym + signer_nym_entropy mod r must equal nym_secret for '{vector.Id}' (§{vector.DraftSection}).");

        byte[] contextId = Convert.FromHexString(vector.ContextId);
        using G1Point pseudonymPoint = BbsPseudonymAlgorithm.ComputePseudonymPoint(
            new[] { computedNymSecret },
            contextId,
            wiring.PseudonymCiphersuite.Identifier,
            wiring.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.G1ScalarMultiply,
            TestSetup.Pool);
        Assert.AreEqual(vector.Pseudonym, Convert.ToHexStringLower(pseudonymPoint.AsReadOnlySpan()),
            $"Pseudonym recomputed from nym_secret must match the printed bytes for '{vector.Id}' (§{vector.DraftSection}).");
    }


    private static BbsMessage[] DecodeMessages(IReadOnlyList<string> hexMessages) =>
        hexMessages
            .Select(m => new BbsMessage(m.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(m)))
            .ToArray();
}
