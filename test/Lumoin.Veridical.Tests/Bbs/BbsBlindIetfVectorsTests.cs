using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Bbs.IetfVectors.Blind;
using Lumoin.Veridical.Tests.Bbs.IetfVectors.Blind.Sha256;
using Lumoin.Veridical.Tests.Bbs.IetfVectors.Blind.Shake256;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Byte-equality tests against the blind-BBS Appendix vectors for both
/// ciphersuites: the generator-derivation vectors (KAT ladder Level 0)
/// and the commitment vectors (Level 1, CoreCommit byte reproduction
/// via the IETF mocked RNG plus CoreCommitVerify acceptance and
/// per-offset tamper rejection).
/// </summary>
/// <remarks>
/// Load-bearing correctness gate for the Blind BBS Interface: any
/// divergence here means the implementation differs from any other
/// conformant implementation of
/// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> (the vectors carry
/// over unchanged from the -02 Appendix; see
/// <see cref="BlindDraftRevision.CommitmentVectorSourceRevision"/>).
/// </remarks>
[TestClass]
internal sealed class BbsBlindIetfVectorsTests
{
    private sealed record SuiteWiring(
        BbsCiphersuite BlindCiphersuite,
        ExpandMessageDelegate ExpandMessage,
        ScalarHashToScalarDelegate HashToScalar,
        G1HashToCurveDelegate G1HashToCurve);


    //Hash-delegate selection routes through the base hash suite: the blind
    //interface value shares its expand_message/hash_to_scalar/hash_to_curve
    //flavor with the core suite it builds on.
    private static SuiteWiring CreateWiring(BbsCiphersuite blindCiphersuite)
    {
        bool isSha256 = blindCiphersuite.BaseHashSuite == BbsCiphersuite.Bls12Curve381Sha256;

        return new SuiteWiring(
            blindCiphersuite,
            isSha256 ? TestSetup.Sha256.ExpandMessage : TestSetup.Shake256.ExpandMessage,
            isSha256 ? TestSetup.Sha256.HashToScalar : TestSetup.Shake256.HashToScalar,
            isSha256 ? TestSetup.Sha256.G1HashToCurve : TestSetup.Shake256.G1HashToCurve);
    }


    private static readonly SuiteWiring Sha256Wiring = CreateWiring(BbsCiphersuite.Bls12Curve381Sha256Blind);
    private static readonly SuiteWiring Shake256Wiring = CreateWiring(BbsCiphersuite.Bls12Curve381Shake256Blind);


    public static IEnumerable<object[]> Sha256CommitmentVectorsData =>
        Sha256BlindCommitmentVectors.All.Select(v => new object[] { v });

    public static IEnumerable<object[]> Shake256CommitmentVectorsData =>
        Shake256BlindCommitmentVectors.All.Select(v => new object[] { v });


    [TestMethod]
    public void GeneratorsVector_SignerFamily_Bls12Curve381Sha256() =>
        RunGeneratorsVector(
            Sha256BlindGeneratorsVectors.Vector001,
            WellKnownBbsCiphersuites.Bls12Curve381Sha256Blind,
            Sha256Wiring);


    [TestMethod]
    public void GeneratorsVector_BlindFamily_Bls12Curve381Sha256() =>
        RunGeneratorsVector(
            Sha256BlindGeneratorsVectors.Vector002,
            BbsBlindAlgorithm.GetBlindGeneratorApiId(WellKnownBbsCiphersuites.Bls12Curve381Sha256Blind),
            Sha256Wiring);


    [TestMethod]
    public void GeneratorsVector_SignerFamily_Bls12Curve381Shake256() =>
        RunGeneratorsVector(
            Shake256BlindGeneratorsVectors.Vector001,
            WellKnownBbsCiphersuites.Bls12Curve381Shake256Blind,
            Shake256Wiring);


    [TestMethod]
    public void GeneratorsVector_BlindFamily_Bls12Curve381Shake256() =>
        RunGeneratorsVector(
            Shake256BlindGeneratorsVectors.Vector002,
            BbsBlindAlgorithm.GetBlindGeneratorApiId(WellKnownBbsCiphersuites.Bls12Curve381Shake256Blind),
            Shake256Wiring);


    [TestMethod]
    [DynamicData(nameof(Sha256CommitmentVectorsData))]
    public void CommitmentVector_Bls12Curve381Sha256(BlindCommitmentVector vector) =>
        RunCommitmentVector(vector, Sha256Wiring);


    [TestMethod]
    [DynamicData(nameof(Shake256CommitmentVectorsData))]
    public void CommitmentVector_Bls12Curve381Shake256(BlindCommitmentVector vector) =>
        RunCommitmentVector(vector, Shake256Wiring);


    [TestMethod]
    [DynamicData(nameof(Sha256CommitmentVectorsData))]
    public void CommitmentVectorTamperRejects_Bls12Curve381Sha256(BlindCommitmentVector vector) =>
        RunCommitmentTamperVector(vector, Sha256Wiring);


    [TestMethod]
    [DynamicData(nameof(Shake256CommitmentVectorsData))]
    public void CommitmentVectorTamperRejects_Bls12Curve381Shake256(BlindCommitmentVector vector) =>
        RunCommitmentTamperVector(vector, Shake256Wiring);


    private static void RunGeneratorsVector(BlindGeneratorsVector vector, string expectedApiId, SuiteWiring wiring)
    {
        //The vector pins the api_id octets the generator family derives
        //under; the compile-time constant composition must reproduce them.
        Assert.AreEqual(vector.ApiId, Convert.ToHexStringLower(Encoding.UTF8.GetBytes(expectedApiId)),
            $"api_id octet mismatch for '{vector.Id}'.");

        //P1 is a ciphersuite constant independent of the interface: the
        //blind interface value must dispatch to the same bytes the vector
        //prints.
        using(G1Point p1 = BbsP1Generator.GetForCiphersuite(wiring.BlindCiphersuite, TestSetup.Pool))
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


    private static void RunCommitmentVector(BlindCommitmentVector vector, SuiteWiring wiring)
    {
        BbsMessage[] committedMessages = DecodeMessages(vector.CommittedMessages);
        byte[] seed = Convert.FromHexString(vector.MockedScalarSeed);
        byte[] expectedCommitmentWithProof = Convert.FromHexString(vector.CommitmentWithProof);
        int mockedScalarCount = committedMessages.Length + 2;

        //The fixture mock DST is composed on the CORE interface api_id, not
        //the blind one; the vector pins the exact octets.
        BbsCiphersuite baseSuite = wiring.BlindCiphersuite.BaseHashSuite;
        Assert.AreEqual(
            vector.MockedScalarDst,
            Convert.ToHexStringLower(Encoding.UTF8.GetBytes(baseSuite.Identifier + WellKnownBbsDomainSeparationTags.CommitMockRandomScalarsDstSuffix)),
            $"Mocked-scalar DST mismatch for '{vector.Id}'.");

        //The mocked stream itself must reproduce the printed trace scalars in
        //the CoreCommit draw order: secret_prover_blind, s~, m~_1..m~_M.
        ScalarRandomDelegate traceSource = BbsDeterministicScalars.FromSeed(
            seed,
            baseSuite,
            WellKnownBbsDomainSeparationTags.CommitMockRandomScalarsDstSuffix,
            mockedScalarCount,
            wiring.ExpandMessage,
            TestSetup.ScalarReduce);
        string[] expectedTrace = new string[mockedScalarCount];
        expectedTrace[0] = vector.ProverBlind;
        expectedTrace[1] = vector.STilde;
        for(int i = 0; i < committedMessages.Length; i++)
        {
            expectedTrace[2 + i] = vector.MTildes[i];
        }
        for(int i = 0; i < mockedScalarCount; i++)
        {
            using Scalar traced = Scalar.FromRandom(traceSource, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
            Assert.AreEqual(expectedTrace[i], Convert.ToHexStringLower(traced.AsReadOnlySpan()),
                $"Mocked-scalar trace #{i} mismatch for '{vector.Id}' (§{vector.DraftSection}).");
        }

        //CoreCommit byte reproduction: a fresh mocked source drives Commit.
        ScalarRandomDelegate deterministicRng = BbsDeterministicScalars.FromSeed(
            seed,
            baseSuite,
            WellKnownBbsDomainSeparationTags.CommitMockRandomScalarsDstSuffix,
            mockedScalarCount,
            wiring.ExpandMessage,
            TestSetup.ScalarReduce);

        (BbsCommitmentWithProof commitmentWithProof, Scalar secretProverBlind) = BbsCommitmentWithProof.Commit(
            committedMessages,
            wiring.BlindCiphersuite,
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
                $"Commit byte-equality failed for '{vector.Id}' (§{vector.DraftSection}).\n  expected: {vector.CommitmentWithProof}\n  got:      {Convert.ToHexStringLower(commitmentWithProof.AsReadOnlySpan())}");
            Assert.AreEqual(vector.ProverBlind, Convert.ToHexStringLower(secretProverBlind.AsReadOnlySpan()),
                $"secret_prover_blind mismatch for '{vector.Id}' (§{vector.DraftSection}).");
        }

        //CoreCommitVerify acceptance over the published octets.
        using BbsCommitmentWithProof decoded = BbsCommitmentWithProof.FromCanonical(
            expectedCommitmentWithProof,
            wiring.BlindCiphersuite,
            TestSetup.Pool);
        Assert.IsTrue(VerifyCommitment(decoded, wiring),
            $"CoreCommitVerify must accept the published commitment for '{vector.Id}' (§{vector.DraftSection}).");
    }


    private static void RunCommitmentTamperVector(BlindCommitmentVector vector, SuiteWiring wiring)
    {
        byte[] commitmentBytes = Convert.FromHexString(vector.CommitmentWithProof);
        int committedMessageCount = vector.CommittedMessages.Count;
        int challengeOffset = BbsCommitmentWithProof.MessageHatsOffset
            + BbsCommitmentWithProof.ScalarSizeBytes * committedMessageCount;

        //One tampered byte inside each named component: the commitment point
        //C, the response s^, the first m^ response (when present), and the
        //challenge. Tampering the final byte of each region keeps every
        //scalar canonical so rejection happens at Schnorr verification (or,
        //for C, at point-geometry validation), never at container intake.
        List<int> tamperOffsets =
        [
            BbsCommitmentWithProof.COffset + BbsCommitmentWithProof.CSizeBytes - 1,
            BbsCommitmentWithProof.SHatOffset + BbsCommitmentWithProof.ScalarSizeBytes - 1,
            challengeOffset + BbsCommitmentWithProof.ScalarSizeBytes - 1,
        ];
        if(committedMessageCount > 0)
        {
            tamperOffsets.Add(BbsCommitmentWithProof.MessageHatsOffset + BbsCommitmentWithProof.ScalarSizeBytes - 1);
        }

        foreach(int offset in tamperOffsets)
        {
            byte[] tamperedBytes = (byte[])commitmentBytes.Clone();
            tamperedBytes[offset] ^= 0x01;

            using BbsCommitmentWithProof tampered = BbsCommitmentWithProof.FromCanonical(
                tamperedBytes,
                wiring.BlindCiphersuite,
                TestSetup.Pool);
            Assert.IsFalse(VerifyCommitment(tampered, wiring),
                $"A commitment tampered at byte offset {offset} must fail verification ('{vector.Id}', §{vector.DraftSection}).");
        }
    }


    private static bool VerifyCommitment(BbsCommitmentWithProof commitmentWithProof, SuiteWiring wiring) =>
        commitmentWithProof.Verify(
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.ScalarNegate,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.Pool);


    private static BbsMessage[] DecodeMessages(IReadOnlyList<string> hexMessages) =>
        hexMessages
            .Select(m => new BbsMessage(m.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(m)))
            .ToArray();
}
