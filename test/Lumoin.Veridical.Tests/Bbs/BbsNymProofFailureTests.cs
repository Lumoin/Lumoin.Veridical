using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Text;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Rejection gates for the per-verifier-pseudonym proof pipeline per
/// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c>: the
/// Sybil-resistance length binding at proof verification, byte tampering
/// at every named proof-component offset, pseudonym substitution
/// (identity, BP1, and a valid-but-wrong subgroup point), context
/// binding, the structural impossibility of disclosing a nym secret or
/// the blinding slot, the sigma-protocol degeneracy checks of Sections
/// 7.3.1/7.3.2, and Interface-tag separation between the two pseudonym
/// suites.
/// </summary>
[TestClass]
internal sealed class BbsNymProofFailureTests
{
    private static readonly byte[] KeyMaterial = MakeBytes(64, 0x61);
    private static readonly byte[] KeyInfo = "nym-proof-failure-key-info"u8.ToArray();
    private static readonly byte[] Header = "nym-proof-failure-header"u8.ToArray();
    private static readonly byte[] PresentationHeader = "nym-proof-failure-presentation"u8.ToArray();
    private static readonly byte[] ContextId = "nym-proof-failure-context"u8.ToArray();
    private static readonly byte[] OtherContextId = "nym-proof-failure-other-context"u8.ToArray();

    //With one committed message the committed index space ends at 0, so
    //index 1 is exactly the (structurally undisclosable) nym slot.
    private static readonly int[] NymTailCommittedIndex = [1];

    //Pre-calculated wrong-subgroup probe shared with
    //BbsSubgroupValidationTests: the BLS12-381 G1 point with x = 0 is on
    //the curve but outside the r-order subgroup.
    private static readonly byte[] WrongSubgroupG1Compressed = Convert.FromHexString(
        "a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");


    private sealed record SuiteWiring(
        BbsCiphersuite PseudonymCiphersuite,
        ExpandMessageDelegate ExpandMessage,
        ScalarHashToScalarDelegate HashToScalar,
        G1HashToCurveDelegate G1HashToCurve);


    //Hash-delegate selection routes through the base hash suite shared by
    //the core and pseudonym interface values.
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


    private sealed record IssuanceChain(
        BbsKeyPair Pair,
        BbsMessage[] Messages,
        BbsMessage[] CommittedMessages,
        Scalar[] NymSecrets,
        Scalar SecretProverBlind,
        BbsBlindSignature Signature) : IDisposable
    {
        public void Dispose()
        {
            Signature.Dispose();
            SecretProverBlind.Dispose();
            foreach(Scalar nymSecret in NymSecrets)
            {
                nymSecret.Dispose();
            }
            Pair.Dispose();
        }
    }


    [TestMethod]
    public void ProofVerifyRejectsWrongLengthNymVector()
    {
        //The Sybil-resistance binding at presentation time: the verifier
        //folds the declared N into the domain and slices the last N response
        //scalars into the pseudonym announcement, so any N other than the
        //one the signer certified fails the challenge comparison.
        SuiteWiring wiring = Sha256Wiring;
        using IssuanceChain chain = CreateIssuance(wiring, signerMessageCount: 2, committedMessageCount: 1, nymCount: 2);
        int[] disclosedIndices = [0];
        int[] disclosedCommittedIndices = [0];

        (BbsPseudonymProof proof, BbsPseudonym pseudonym) = GenerateProof(wiring, chain, ContextId, disclosedIndices, disclosedCommittedIndices);
        using(proof)
        using(pseudonym)
        {
            Assert.IsTrue(VerifyProof(wiring, chain, proof, pseudonym, ContextId, lengthNymVector: 2, disclosedIndices, disclosedCommittedIndices),
                "The certified nym-vector length must verify (guards the negative assertions below).");
            Assert.IsFalse(VerifyProof(wiring, chain, proof, pseudonym, ContextId, lengthNymVector: 1, disclosedIndices, disclosedCommittedIndices),
                "A declared nym-vector length below the certified one must fail proof verification.");
            Assert.IsFalse(VerifyProof(wiring, chain, proof, pseudonym, ContextId, lengthNymVector: 3, disclosedIndices, disclosedCommittedIndices),
                "A declared nym-vector length above the certified one must fail proof verification.");
        }
    }


    [TestMethod]
    public void ProofVerifyRejectsTamperingAtEveryComponentOffset()
    {
        SuiteWiring wiring = Sha256Wiring;
        using IssuanceChain chain = CreateIssuance(wiring, signerMessageCount: 2, committedMessageCount: 1, nymCount: 1);
        int[] disclosedIndices = [0];
        int[] disclosedCommittedIndices = [];

        (BbsPseudonymProof proof, BbsPseudonym pseudonym) = GenerateProof(wiring, chain, ContextId, disclosedIndices, disclosedCommittedIndices);
        using(proof)
        using(pseudonym)
        {
            Assert.IsTrue(VerifyProof(wiring, chain, proof, pseudonym, ContextId, lengthNymVector: 1, disclosedIndices, disclosedCommittedIndices),
                "The untampered proof must verify (guards the tamper loop below).");

            byte[] proofBytes = proof.AsReadOnlySpan().ToArray();
            int undisclosedCount = proof.UndisclosedMessageCount;

            //One probe inside every named component of the wire layout:
            //the point bodies past their compression-flag byte, and the last
            //byte of every scalar slot (including the LAST m^, which carries
            //the nym secret's response and feeds the announcement Uv).
            (string Name, int Offset)[] tamperTargets =
            [
                ("Abar", BbsProof.ABarOffset + 1),
                ("Bbar", BbsProof.BBarOffset + 1),
                ("D", BbsProof.DOffset + 1),
                ("e^", BbsProof.EHatOffset + BbsProof.ScalarSizeBytes - 1),
                ("r1^", BbsProof.R1HatOffset + BbsProof.ScalarSizeBytes - 1),
                ("r3^", BbsProof.R3HatOffset + BbsProof.ScalarSizeBytes - 1),
                ("m^ first", BbsProof.CommitmentsOffset + BbsProof.ScalarSizeBytes - 1),
                ("m^ last (nym response)", BbsProof.CommitmentsOffset + BbsProof.ScalarSizeBytes * undisclosedCount - 1),
                ("challenge", BbsProof.CommitmentsOffset + BbsProof.ScalarSizeBytes * (undisclosedCount + 1) - 1),
            ];

            foreach((string name, int offset) in tamperTargets)
            {
                byte[] tampered = (byte[])proofBytes.Clone();
                tampered[offset] ^= 0x01;

                //A flipped scalar byte may leave the canonical range and be
                //refused at intake; that rejection and a false verification
                //are the same defense, so both count.
                bool rejected;
                try
                {
                    using BbsPseudonymProof tamperedProof = BbsPseudonymProof.FromCanonical(tampered, wiring.PseudonymCiphersuite, TestSetup.Pool);
                    rejected = !VerifyProof(wiring, chain, tamperedProof, pseudonym, ContextId, lengthNymVector: 1, disclosedIndices, disclosedCommittedIndices);
                }
                catch(ArgumentException)
                {
                    rejected = true;
                }

                Assert.IsTrue(rejected, $"Tampering the '{name}' component at byte offset {offset} must be rejected.");
            }
        }
    }


    [TestMethod]
    public void ProofVerifyRejectsSubstitutedPseudonym()
    {
        SuiteWiring wiring = Sha256Wiring;
        using IssuanceChain chain = CreateIssuance(wiring, signerMessageCount: 1, committedMessageCount: 0, nymCount: 1);
        int[] disclosedIndices = [];
        int[] disclosedCommittedIndices = [];

        (BbsPseudonymProof proof, BbsPseudonym pseudonym) = GenerateProof(wiring, chain, ContextId, disclosedIndices, disclosedCommittedIndices);
        using(proof)
        using(pseudonym)
        {
            Assert.IsTrue(VerifyProof(wiring, chain, proof, pseudonym, ContextId, lengthNymVector: 1, disclosedIndices, disclosedCommittedIndices),
                "The genuine pseudonym must verify (guards the negative assertions below).");

            //The two named forbidden encodings are refused before any
            //verification can even start (nym -03 Section 3.3).
            Assert.ThrowsExactly<ArgumentException>(() =>
                _ = BbsPseudonym.FromCanonical(WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bls12Curve381), wiring.PseudonymCiphersuite, TestSetup.Pool));
            Assert.ThrowsExactly<ArgumentException>(() =>
                _ = BbsPseudonym.FromCanonical(WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.Bls12Curve381), wiring.PseudonymCiphersuite, TestSetup.Pool));

            //A perfectly valid subgroup point that simply is not this
            //prover's pseudonym for this context: the same secrets evaluated
            //under a different context_id.
            using G1Point otherPoint = BbsPseudonymAlgorithm.ComputePseudonymPoint(
                chain.NymSecrets,
                OtherContextId,
                wiring.PseudonymCiphersuite.Identifier,
                wiring.HashToScalar,
                TestSetup.ScalarAdd,
                TestSetup.ScalarMultiply,
                wiring.G1HashToCurve,
                TestSetup.G1ScalarMultiply,
                TestSetup.Pool);
            using BbsPseudonym otherPseudonym = BbsPseudonym.FromCanonical(otherPoint.AsReadOnlySpan(), wiring.PseudonymCiphersuite, TestSetup.Pool);

            Assert.IsFalse(VerifyProof(wiring, chain, proof, otherPseudonym, ContextId, lengthNymVector: 1, disclosedIndices, disclosedCommittedIndices),
                "A valid subgroup point other than the bound pseudonym must fail proof verification.");
        }
    }


    [TestMethod]
    public void ProofVerifyRejectsWrongSubgroupPseudonym()
    {
        //BbsPseudonym intake refuses only the identity/BP1 encodings, so an
        //on-curve point outside the r-order subgroup reaches the verify
        //surface — the subgroup delegate there is the gate that stops a
        //small-subgroup pseudonym substitution.
        SuiteWiring wiring = Sha256Wiring;
        using IssuanceChain chain = CreateIssuance(wiring, signerMessageCount: 1, committedMessageCount: 0, nymCount: 1);

        (BbsPseudonymProof proof, BbsPseudonym pseudonym) = GenerateProof(wiring, chain, ContextId, disclosedIndices: [], disclosedCommittedIndices: []);
        using(proof)
        using(pseudonym)
        {
            using BbsPseudonym wrongSubgroupPseudonym = BbsPseudonym.FromCanonical(WrongSubgroupG1Compressed, wiring.PseudonymCiphersuite, TestSetup.Pool);

            bool pseudonymSubgroupChecked = false;
            G1IsInPrimeOrderSubgroupDelegate recordingSubgroup = (point, curve) =>
            {
                if(point.SequenceEqual(WrongSubgroupG1Compressed))
                {
                    pseudonymSubgroupChecked = true;
                }

                return TestSetup.G1IsInPrimeOrderSubgroup(point, curve);
            };

            bool verified = chain.Pair.PublicKey.ProofVerifyWithNym(
                proof,
                wrongSubgroupPseudonym,
                new BbsHeader(Header),
                new BbsPresentationHeader(PresentationHeader),
                ContextId,
                lengthNymVector: 1,
                signerMessageCount: chain.Messages.Length,
                disclosedMessages: Array.Empty<BbsMessage>(),
                disclosedCommittedMessages: Array.Empty<BbsMessage>(),
                disclosedIndices: Array.Empty<int>(),
                disclosedCommittedIndices: Array.Empty<int>(),
                wiring.ExpandMessage,
                wiring.HashToScalar,
                TestSetup.ScalarAdd,
                TestSetup.ScalarMultiply,
                TestSetup.ScalarNegate,
                TestSetup.G1Add,
                TestSetup.G1MultiScalarMultiply,
                wiring.G1HashToCurve,
                TestSetup.G1IsOnCurve,
                recordingSubgroup,
                TestSetup.G2Add,
                TestSetup.G2ScalarMultiply,
                TestSetup.G2IsOnCurve,
                TestSetup.G2IsInPrimeOrderSubgroup,
                TestSetup.Pairing,
                TestSetup.Pool);

            Assert.IsFalse(verified,
                "A pseudonym outside the prime-order subgroup must fail proof verification even though it lies on the curve.");
            Assert.IsTrue(pseudonymSubgroupChecked,
                "Verification must consult the G1 subgroup delegate for the pseudonym point.");
        }
    }


    [TestMethod]
    public void ProofVerifyRejectsWrongContextId()
    {
        //context_id enters three ways — the pseudonym base point OP, the
        //polynomial evaluation point z, and the challenge tail — so a proof
        //presented against a different context must fail even with the
        //matching pseudonym octets.
        SuiteWiring wiring = Sha256Wiring;
        using IssuanceChain chain = CreateIssuance(wiring, signerMessageCount: 1, committedMessageCount: 0, nymCount: 1);
        int[] disclosedIndices = [];
        int[] disclosedCommittedIndices = [];

        (BbsPseudonymProof proof, BbsPseudonym pseudonym) = GenerateProof(wiring, chain, ContextId, disclosedIndices, disclosedCommittedIndices);
        using(proof)
        using(pseudonym)
        {
            Assert.IsFalse(VerifyProof(wiring, chain, proof, pseudonym, OtherContextId, lengthNymVector: 1, disclosedIndices, disclosedCommittedIndices),
                "A proof bound to one context_id must fail verification under another.");
        }
    }


    [TestMethod]
    public void ProofGenRefusesDisclosingNymSecretOrBlindSlot()
    {
        //Neither index space can address the secret_prover_blind slot or the
        //nym tail: the signer space ends at L - 1 and the committed space at
        //M - 1, so the smallest out-of-range index in each space is exactly
        //the first structurally undisclosable slot.
        SuiteWiring wiring = Sha256Wiring;
        using IssuanceChain chain = CreateIssuance(wiring, signerMessageCount: 1, committedMessageCount: 1, nymCount: 1);

        ArgumentException signerSpace = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = GenerateProof(wiring, chain, ContextId, disclosedIndices: [1], disclosedCommittedIndices: []));
        Assert.Contains("disclosedIndices", signerSpace.Message, StringComparison.Ordinal);

        ArgumentException committedSpace = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = GenerateProof(wiring, chain, ContextId, disclosedIndices: [], disclosedCommittedIndices: [1]));
        Assert.Contains("disclosedCommittedIndices", committedSpace.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void ProofVerifyRejectsDisclosedIndexIntoTheNymTail()
    {
        //Verifier side of the same structural rule: with the committed count
        //recovered from the proof length, a disclosed committed index equal
        //to it would address the nym slot and must be refused.
        SuiteWiring wiring = Sha256Wiring;
        using IssuanceChain chain = CreateIssuance(wiring, signerMessageCount: 1, committedMessageCount: 1, nymCount: 1);
        int[] disclosedIndices = [];
        int[] disclosedCommittedIndices = [0];

        (BbsPseudonymProof proof, BbsPseudonym pseudonym) = GenerateProof(wiring, chain, ContextId, disclosedIndices, disclosedCommittedIndices);
        using(proof)
        using(pseudonym)
        {
            //The rejection is structural: the early index gate must refuse
            //the nym-tail index before any algebra, so the pairing delegate
            //must never be consulted.
            bool pairingInvoked = false;
            PairingDelegate recordingPairing = (p, q, result, curve) =>
            {
                pairingInvoked = true;
                TestSetup.Pairing(p, q, result, curve);
            };

            bool verified = chain.Pair.PublicKey.ProofVerifyWithNym(
                proof,
                pseudonym,
                new BbsHeader(Header),
                new BbsPresentationHeader(PresentationHeader),
                ContextId,
                lengthNymVector: 1,
                signerMessageCount: chain.Messages.Length,
                disclosedMessages: Array.Empty<BbsMessage>(),
                disclosedCommittedMessages: new[] { chain.CommittedMessages[0] },
                disclosedIndices: Array.Empty<int>(),
                disclosedCommittedIndices: NymTailCommittedIndex,
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
                recordingPairing,
                TestSetup.Pool);

            Assert.IsFalse(verified, "A disclosed committed index addressing the nym slot must fail proof verification.");
            Assert.IsFalse(pairingInvoked, "The nym-tail index must be refused by the index gate before any pairing runs.");
        }
    }


    [TestMethod]
    public void ProofDoesNotVerifyUnderTheOtherPseudonymSuite()
    {
        //Interface-tag separation between the two pseudonym suites: the
        //verify surface refuses containers whose tags do not match the
        //key's pseudonym Interface before touching any cryptography.
        SuiteWiring wiring = Sha256Wiring;
        using IssuanceChain chain = CreateIssuance(wiring, signerMessageCount: 1, committedMessageCount: 0, nymCount: 1);
        int[] disclosedIndices = [];
        int[] disclosedCommittedIndices = [];

        (BbsPseudonymProof proof, BbsPseudonym pseudonym) = GenerateProof(wiring, chain, ContextId, disclosedIndices, disclosedCommittedIndices);
        using(proof)
        using(pseudonym)
        {
            using BbsPseudonymProof retaggedProof = BbsPseudonymProof.FromCanonical(
                proof.AsReadOnlySpan(),
                BbsCiphersuite.Bls12Curve381Shake256Pseudonym,
                TestSetup.Pool);

            Assert.IsFalse(VerifyProof(wiring, chain, retaggedProof, pseudonym, ContextId, lengthNymVector: 1, disclosedIndices, disclosedCommittedIndices),
                "A proof tagged with the other pseudonym suite must be refused against this key.");
        }
    }


    [TestMethod]
    public void PseudonymProofInitRejectsDegeneratePolynomials()
    {
        //Section 7.3.1 step 9: with two coefficients (-z, 1) the nym
        //polynomial evaluates to -z + 1 * z = 0, collapsing the pseudonym
        //(or the announcement Ut, when the degenerate pair sits in the
        //random scalars) to the identity.
        SuiteWiring wiring = Sha256Wiring;
        string apiId = wiring.PseudonymCiphersuite.Identifier;

        using Scalar z = BbsPseudonymAlgorithm.ComputeEvaluationPoint(ContextId, apiId, wiring.HashToScalar, TestSetup.Pool);
        using Scalar minusZ = z.Negate(TestSetup.ScalarNegate, TestSetup.Pool);
        using Scalar one = MakeOneScalar();

        Scalar[] degenerate = [minusZ, one];
        Scalar[] benign = [one, one];

        (G1Point Pseudonym, G1Point Ut)? secretsDegenerate = BbsPseudonymAlgorithm.PseudonymProofInit(
            degenerate, benign, ContextId, apiId,
            wiring.HashToScalar, TestSetup.ScalarAdd, TestSetup.ScalarMultiply, wiring.G1HashToCurve, TestSetup.G1ScalarMultiply, TestSetup.Pool);
        Assert.IsNull(secretsDegenerate, "PseudonymProofInit must reject nym secrets whose polynomial evaluates to zero.");

        (G1Point Pseudonym, G1Point Ut)? randomsDegenerate = BbsPseudonymAlgorithm.PseudonymProofInit(
            benign, degenerate, ContextId, apiId,
            wiring.HashToScalar, TestSetup.ScalarAdd, TestSetup.ScalarMultiply, wiring.G1HashToCurve, TestSetup.G1ScalarMultiply, TestSetup.Pool);
        Assert.IsNull(randomsDegenerate, "PseudonymProofInit must reject random scalars whose polynomial evaluates to zero.");

        (G1Point Pseudonym, G1Point Ut)? wellFormed = BbsPseudonymAlgorithm.PseudonymProofInit(
            benign, benign, ContextId, apiId,
            wiring.HashToScalar, TestSetup.ScalarAdd, TestSetup.ScalarMultiply, wiring.G1HashToCurve, TestSetup.G1ScalarMultiply, TestSetup.Pool);
        Assert.IsNotNull(wellFormed, "Non-degenerate inputs must produce a pseudonym and announcement (guards the null assertions above).");
        wellFormed.Value.Pseudonym.Dispose();
        wellFormed.Value.Ut.Dispose();
    }


    [TestMethod]
    public void PseudonymProofVerifyInitRejectsDegenerateAnnouncement()
    {
        //Section 7.3.2 step 7: responses satisfying OP * poly(m^) ==
        //pseudonym * challenge exactly collapse Uv to the identity — with a
        //single nym secret s, m^ = s * c does so for pseudonym = OP * s.
        SuiteWiring wiring = Sha256Wiring;
        string apiId = wiring.PseudonymCiphersuite.Identifier;

        using G1Point originPoint = BbsPseudonymAlgorithm.ComputeOriginPoint(ContextId, apiId, wiring.G1HashToCurve, TestSetup.Pool);
        using Scalar nymSecret = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        using Scalar challenge = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        using G1Point pseudonym = originPoint.ScalarMultiply(nymSecret, TestSetup.G1ScalarMultiply, TestSetup.Pool);
        using Scalar degenerateResponse = nymSecret.Multiply(challenge, TestSetup.ScalarMultiply, TestSetup.Pool);

        G1Point? uv = BbsPseudonymAlgorithm.PseudonymProofVerifyInit(
            pseudonym, [degenerateResponse], challenge, ContextId, apiId,
            wiring.HashToScalar, TestSetup.ScalarAdd, TestSetup.ScalarMultiply, TestSetup.ScalarNegate,
            wiring.G1HashToCurve, TestSetup.G1MultiScalarMultiply, TestSetup.Pool);
        Assert.IsNull(uv, "PseudonymProofVerifyInit must reject responses that collapse Uv to the identity.");

        using Scalar unrelatedResponse = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        G1Point? nonDegenerate = BbsPseudonymAlgorithm.PseudonymProofVerifyInit(
            pseudonym, [unrelatedResponse], challenge, ContextId, apiId,
            wiring.HashToScalar, TestSetup.ScalarAdd, TestSetup.ScalarMultiply, TestSetup.ScalarNegate,
            wiring.G1HashToCurve, TestSetup.G1MultiScalarMultiply, TestSetup.Pool);
        Assert.IsNotNull(nonDegenerate, "An unrelated response must recompute a non-identity Uv (guards the null assertion above).");
        nonDegenerate.Dispose();
    }


    private static IssuanceChain CreateIssuance(SuiteWiring wiring, int signerMessageCount, int committedMessageCount, int nymCount)
    {
        BbsKeyPair pair = wiring.PseudonymCiphersuite.BaseHashSuite.Generate(
            KeyMaterial,
            KeyInfo,
            wiring.HashToScalar,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pool);
        BbsMessage[] messages = MakeMessages("issuer", signerMessageCount);
        BbsMessage[] committedMessages = MakeMessages("committed", committedMessageCount);

        Scalar[] proverNyms = new Scalar[nymCount];
        for(int i = 0; i < nymCount; i++)
        {
            proverNyms[i] = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        }
        using Scalar signerNymEntropy = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        try
        {
            (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = BbsCommitmentWithProof.CommitWithNym(
                committedMessages,
                proverNyms,
                wiring.PseudonymCiphersuite,
                wiring.ExpandMessage,
                wiring.HashToScalar,
                TestSetup.ScalarAdd,
                TestSetup.ScalarMultiply,
                TestSetup.ScalarRandom,
                TestSetup.G1MultiScalarMultiply,
                wiring.G1HashToCurve,
                TestSetup.Pool);
            using(commitment)
            {
                BbsBlindSignature signature = pair.SecretKey.BlindSignWithNym(
                    pair.PublicKey,
                    commitment,
                    nymCount,
                    signerNymEntropy,
                    new BbsHeader(Header),
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

                Scalar[]? nymSecrets = signature.VerifyFinalizeWithNym(
                    pair.PublicKey,
                    new BbsHeader(Header),
                    messages,
                    committedMessages,
                    proverNyms,
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
                Assert.IsNotNull(nymSecrets, "Issuance-chain finalization must succeed before any negative test can run.");

                return new IssuanceChain(pair, messages, committedMessages, nymSecrets, secretProverBlind, signature);
            }
        }
        finally
        {
            foreach(Scalar proverNym in proverNyms)
            {
                proverNym.Dispose();
            }
        }
    }


    private static (BbsPseudonymProof Proof, BbsPseudonym Pseudonym) GenerateProof(
        SuiteWiring wiring,
        IssuanceChain chain,
        byte[] contextId,
        int[] disclosedIndices,
        int[] disclosedCommittedIndices) =>
        chain.Signature.ProofGenWithNym(
            chain.Pair.PublicKey,
            new BbsHeader(Header),
            new BbsPresentationHeader(PresentationHeader),
            chain.NymSecrets,
            contextId,
            chain.Messages,
            chain.CommittedMessages,
            disclosedIndices,
            disclosedCommittedIndices,
            chain.SecretProverBlind,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarSubtract,
            TestSetup.ScalarMultiply,
            TestSetup.ScalarNegate,
            TestSetup.ScalarInvert,
            TestSetup.ScalarRandom,
            TestSetup.G1Add,
            TestSetup.G1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.Pool);


    private static bool VerifyProof(
        SuiteWiring wiring,
        IssuanceChain chain,
        BbsPseudonymProof proof,
        BbsPseudonym pseudonym,
        byte[] contextId,
        int lengthNymVector,
        int[] disclosedIndices,
        int[] disclosedCommittedIndices)
    {
        BbsMessage[] disclosedMessages = new BbsMessage[disclosedIndices.Length];
        for(int i = 0; i < disclosedIndices.Length; i++)
        {
            disclosedMessages[i] = chain.Messages[disclosedIndices[i]];
        }
        BbsMessage[] disclosedCommittedMessages = new BbsMessage[disclosedCommittedIndices.Length];
        for(int i = 0; i < disclosedCommittedIndices.Length; i++)
        {
            disclosedCommittedMessages[i] = chain.CommittedMessages[disclosedCommittedIndices[i]];
        }

        return chain.Pair.PublicKey.ProofVerifyWithNym(
            proof,
            pseudonym,
            new BbsHeader(Header),
            new BbsPresentationHeader(PresentationHeader),
            contextId,
            lengthNymVector,
            chain.Messages.Length,
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
            TestSetup.Pool);
    }


    private static Scalar MakeOneScalar()
    {
        byte[] oneBytes = new byte[Scalar.SizeBytes];
        oneBytes[^1] = 1;

        return Scalar.FromCanonical(oneBytes, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
    }


    private static BbsMessage[] MakeMessages(string prefix, int count)
    {
        BbsMessage[] messages = new BbsMessage[count];
        for(int i = 0; i < count; i++)
        {
            messages[i] = new BbsMessage(Encoding.UTF8.GetBytes($"{prefix}-message-{i}"));
        }

        return messages;
    }


    private static byte[] MakeBytes(int length, byte start)
    {
        byte[] result = new byte[length];
        for(int i = 0; i < length; i++)
        {
            result[i] = (byte)(start + i);
        }

        return result;
    }
}
