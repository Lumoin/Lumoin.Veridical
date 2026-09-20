using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Self-consistency and adversarial gates for the blind BBS proof
/// pipeline per <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Sections
/// 4.2.3/4.2.4 (BlindProofGen/BlindProofVerify) and 4.3.4/4.3.5
/// (CoreProofGen/CoreProofVerify with committed disclosure). The -03
/// framed proof wire surface has NO published test vectors (draft
/// Section 10), so these suites are the gate: roundtrips across the
/// three-way DISCLOSE/HIDE/COMMIT map matrix for both ciphersuites,
/// tampering of every framed component, cross-interface separation, and
/// disclosed-set substitution. The disclosure-index and generator-vector
/// interpretation choices these tests pin are re-KATed when the regenerated official
/// fixtures land.
/// </summary>
[TestClass]
internal sealed class BbsBlindProofGenVerifyTests
{
    /// <summary>The fixed 64-byte key-generation seed shared by every test in this suite.</summary>
    private static byte[] KeyMaterial { get; } = MakeBytes(64, 0x51);

    /// <summary>The fixed key-generation info octet string shared by every test in this suite.</summary>
    private static byte[] KeyInfo { get; } = "blind-proof-key-info"u8.ToArray();

    /// <summary>The fixed signature header shared by every test in this suite.</summary>
    private static byte[] Header { get; } = "blind-proof-header"u8.ToArray();

    /// <summary>The fixed presentation header shared by every test in this suite.</summary>
    private static byte[] PresentationHeaderBytes { get; } = "blind-proof-presentation"u8.ToArray();

    /// <summary>A single-element disclosed-index array selecting index 0, used by the core-interface comparison tests.</summary>
    private static int[] FirstIndexOnly { get; } = [0];


    /// <summary>The per-ciphersuite delegate bundle a wiring binds together: the base (non-blind) and blind ciphersuite identities, and the message-expansion, hash-to-scalar and G1 hash-to-curve backends the base ciphersuite's hash variant selects.</summary>
    private sealed record SuiteWiring(
        BbsCiphersuite Ciphersuite,
        BbsCiphersuite BlindCiphersuite,
        ExpandMessageDelegate ExpandMessage,
        ScalarHashToScalarDelegate HashToScalar,
        G1HashToCurveDelegate G1HashToCurve);


    /// <summary>Builds the delegate bundle for one blind ciphersuite, selecting the SHA-256 or SHAKE-256 backends according to <paramref name="blindCiphersuite"/>'s base hash suite.</summary>
    private static SuiteWiring CreateWiring(BbsCiphersuite blindCiphersuite)
    {
        BbsCiphersuite baseSuite = blindCiphersuite.BaseHashSuite;
        bool isSha256 = baseSuite == BbsCiphersuite.Bls12Curve381Sha256;

        return new SuiteWiring(
            baseSuite,
            blindCiphersuite,
            isSha256 ? TestSetup.Sha256.ExpandMessage : TestSetup.Shake256.ExpandMessage,
            isSha256 ? TestSetup.Sha256.HashToScalar : TestSetup.Shake256.HashToScalar,
            isSha256 ? TestSetup.Sha256.G1HashToCurve : TestSetup.Shake256.G1HashToCurve);
    }


    /// <summary>The cached wiring for the BLS12-381/SHA-256 blind ciphersuite.</summary>
    private static SuiteWiring Sha256Wiring { get; } = CreateWiring(BbsCiphersuite.Bls12Curve381Sha256Blind);

    /// <summary>The cached wiring for the BLS12-381/SHAKE-256 blind ciphersuite.</summary>
    private static SuiteWiring Shake256Wiring { get; } = CreateWiring(BbsCiphersuite.Bls12Curve381Shake256Blind);


    /// <summary>Everything a single issuance produces that the prover needs to present and the test needs to dispose.</summary>
    private sealed class Issuance(
        BbsKeyPair keyPair,
        BbsMessage[] signerMessages,
        BbsMessage[] committedMessages,
        BbsCommitmentWithProof? commitment,
        Scalar? secretProverBlind,
        BbsBlindSignature signature): IDisposable
    {
        /// <summary>The issuer key pair the signature was produced under.</summary>
        public BbsKeyPair KeyPair { get; } = keyPair;

        /// <summary>The issuer-known messages the blind signature covers.</summary>
        public BbsMessage[] SignerMessages { get; } = signerMessages;

        /// <summary>The prover-committed messages bound into the commitment, if one was made.</summary>
        public BbsMessage[] CommittedMessages { get; } = committedMessages;

        /// <summary>The prover's commitment-with-proof, or <see langword="null"/> when this issuance used no commitment.</summary>
        public BbsCommitmentWithProof? Commitment { get; } = commitment;

        /// <summary>The prover's blinding scalar for the commitment, or <see langword="null"/> when this issuance used no commitment.</summary>
        public Scalar? SecretProverBlind { get; } = secretProverBlind;

        /// <summary>The resulting blind signature.</summary>
        public BbsBlindSignature Signature { get; } = signature;

        /// <summary>Disposes the signature, blind, commitment and key pair, in that order.</summary>
        public void Dispose()
        {
            Signature.Dispose();
            SecretProverBlind?.Dispose();
            Commitment?.Dispose();
            KeyPair.Dispose();
        }
    }


    /// <summary>Pins that BlindProofGen/BlindProofVerify round-trips successfully when every signer and committed message is disclosed, for both the SHA-256 and SHAKE-256 ciphersuites.</summary>
    [TestMethod]
    public void AllDiscloseRoundtripSucceedsForBothSuites()
    {
        RunRoundtrip(Sha256Wiring, signerMessageCount: 3, committedMessageCount: 2,
            AllOf(BbsMessageDisclosure.Disclose, 3), AllOf(BbsMessageDisclosure.Disclose, 2));
        RunRoundtrip(Shake256Wiring, signerMessageCount: 3, committedMessageCount: 2,
            AllOf(BbsMessageDisclosure.Disclose, 3), AllOf(BbsMessageDisclosure.Disclose, 2));
    }


    /// <summary>Pins that the round trip succeeds when every signer and committed message is hidden, for both ciphersuites.</summary>
    [TestMethod]
    public void AllHideRoundtripSucceedsForBothSuites()
    {
        RunRoundtrip(Sha256Wiring, signerMessageCount: 3, committedMessageCount: 2,
            AllOf(BbsMessageDisclosure.Hide, 3), AllOf(BbsMessageDisclosure.Hide, 2));
        RunRoundtrip(Shake256Wiring, signerMessageCount: 3, committedMessageCount: 2,
            AllOf(BbsMessageDisclosure.Hide, 3), AllOf(BbsMessageDisclosure.Hide, 2));
    }


    /// <summary>Pins that the round trip succeeds for a disclosure map mixing DISCLOSE and HIDE entries across both signer and committed messages, with no COMMIT entries (N = 0), for both ciphersuites.</summary>
    [TestMethod]
    public void MixedDiscloseHideRoundtripSucceedsForBothSuites()
    {
        //N = 0: the basic blind presentation without committed disclosure.
        BbsMessageDisclosure[] signerMap = [BbsMessageDisclosure.Disclose, BbsMessageDisclosure.Hide, BbsMessageDisclosure.Disclose];
        BbsMessageDisclosure[] committedMap = [BbsMessageDisclosure.Hide, BbsMessageDisclosure.Disclose];

        RunRoundtrip(Sha256Wiring, signerMessageCount: 3, committedMessageCount: 2, signerMap, committedMap);
        RunRoundtrip(Shake256Wiring, signerMessageCount: 3, committedMessageCount: 2, signerMap, committedMap);
    }


    /// <summary>Pins that the round trip succeeds, and the framed proof carries the expected number of committed disclosures, across disclosure maps with one, two and three COMMIT entries spanning both issuer-known and prover-committed messages.</summary>
    [TestMethod]
    public void CommittedDisclosureRoundtripsSucceedAcrossCommitCounts()
    {
        //1..3 COMMIT entries spanning both issuer-known and prover-committed
        //messages, mixed with DISCLOSE and HIDE around them.
        BbsMessageDisclosure[][] signerMaps =
        [
            [BbsMessageDisclosure.Disclose, BbsMessageDisclosure.Commit, BbsMessageDisclosure.Hide],
            [BbsMessageDisclosure.Disclose, BbsMessageDisclosure.Commit, BbsMessageDisclosure.Hide],
            [BbsMessageDisclosure.Commit, BbsMessageDisclosure.Hide, BbsMessageDisclosure.Commit],
        ];
        BbsMessageDisclosure[][] committedMaps =
        [
            [BbsMessageDisclosure.Hide, BbsMessageDisclosure.Disclose, BbsMessageDisclosure.Hide],
            [BbsMessageDisclosure.Commit, BbsMessageDisclosure.Disclose, BbsMessageDisclosure.Hide],
            [BbsMessageDisclosure.Hide, BbsMessageDisclosure.Commit, BbsMessageDisclosure.Disclose],
        ];
        int[] expectedCommitCounts = [1, 2, 3];

        for(int i = 0; i < signerMaps.Length; i++)
        {
            RunRoundtrip(Sha256Wiring, signerMessageCount: 3, committedMessageCount: 3, signerMaps[i], committedMaps[i], expectedCommitCounts[i]);
            RunRoundtrip(Shake256Wiring, signerMessageCount: 3, committedMessageCount: 3, signerMaps[i], committedMaps[i], expectedCommitCounts[i]);
        }
    }


    /// <summary>Pins that the round trip succeeds when every message is prover-committed (L = 0) and one committed message is disclosed.</summary>
    [TestMethod]
    public void RoundtripWithNoSignerMessagesSucceeds()
    {
        //L = 0: every message is prover-committed; one is committed-disclosed.
        BbsMessageDisclosure[] committedMap = [BbsMessageDisclosure.Disclose, BbsMessageDisclosure.Commit];

        RunRoundtrip(Sha256Wiring, signerMessageCount: 0, committedMessageCount: 2, [], committedMap, expectedCommitCount: 1);
        RunRoundtrip(Shake256Wiring, signerMessageCount: 0, committedMessageCount: 2, [], committedMap, expectedCommitCount: 1);
    }


    /// <summary>Pins that the round trip succeeds with no prover-committed messages (M = 0), both with a blind-only commitment and with the commitment-free default where secret_prover_blind is the specification's zero.</summary>
    [TestMethod]
    public void RoundtripWithNoCommittedMessagesSucceeds()
    {
        //M = 0 with a blind-only commitment, and the commitment-free default
        //where secret_prover_blind is the spec's zero.
        BbsMessageDisclosure[] signerMap = [BbsMessageDisclosure.Disclose, BbsMessageDisclosure.Commit];

        RunRoundtrip(Sha256Wiring, signerMessageCount: 2, committedMessageCount: 0, signerMap, [], expectedCommitCount: 1);
        RunRoundtrip(Shake256Wiring, signerMessageCount: 2, committedMessageCount: 0, signerMap, [], expectedCommitCount: 1);
        RunRoundtrip(Sha256Wiring, signerMessageCount: 2, committedMessageCount: 0, signerMap, [], expectedCommitCount: 1, useCommitment: false);
    }


    /// <summary>Pins that add_zkp_info produces exactly one commitment opening per COMMIT entry, that each opening's commitment matches the corresponding commitment point framed in the proof, and that the opening's randomness never appears in the proof's serialized bytes.</summary>
    [TestMethod]
    public void OpeningsMatchTheFramedCommitmentsAndAreNeverSerialized()
    {
        SuiteWiring wiring = Sha256Wiring;
        using Issuance issuance = Issue(wiring, signerMessageCount: 2, committedMessageCount: 2);
        BbsMessageDisclosure[] signerMap = [BbsMessageDisclosure.Disclose, BbsMessageDisclosure.Commit];
        BbsMessageDisclosure[] committedMap = [BbsMessageDisclosure.Commit, BbsMessageDisclosure.Hide];

        (BbsBlindProof proof, BbsBlindProofCommitmentOpenings openings) = GenerateProof(wiring, issuance, signerMap, committedMap);
        using(proof)
        using(openings)
        {
            Assert.AreEqual(2, openings.Count, "add_zkp_info must carry one opening per COMMIT entry.");
            for(int i = 0; i < openings.Count; i++)
            {
                Assert.IsTrue(
                    openings.GetCommitment(i).AsReadOnlySpan().SequenceEqual(proof.GetCommittedDisclosurePointBytes(i)),
                    $"Opening #{i} must hold the same commitment the framed proof carries.");
            }

            //The randomness never appears in the wire bytes: the framed proof
            //carries C_i and s^_i = s~_i + c * s_i, not s_i itself.
            ReadOnlySpan<byte> proofBytes = proof.AsReadOnlySpan();
            for(int i = 0; i < openings.Count; i++)
            {
                Assert.IsLessThan(0, proofBytes.IndexOf(openings.GetRandomness(i).AsReadOnlySpan()),
                    $"The commitment randomness s_{i} must not appear anywhere in the serialized proof.");
            }
        }
    }


    /// <summary>Pins that flipping a single bit anywhere in the framed proof — every count field, core-proof point and scalar, disclosed index, and committed-disclosure commitment, response scalar and index — causes verification to fail or the proof to be rejected at intake.</summary>
    [TestMethod]
    public void TamperingAnyFramedComponentFailsVerification()
    {
        SuiteWiring wiring = Sha256Wiring;
        using Issuance issuance = Issue(wiring, signerMessageCount: 2, committedMessageCount: 1);
        BbsMessageDisclosure[] signerMap = [BbsMessageDisclosure.Disclose, BbsMessageDisclosure.Hide];
        BbsMessageDisclosure[] committedMap = [BbsMessageDisclosure.Commit];

        (BbsBlindProof proof, BbsBlindProofCommitmentOpenings openings) = GenerateProof(wiring, issuance, signerMap, committedMap);
        using(proof)
        using(openings)
        {
            BbsMessage[] disclosedMessages = [issuance.SignerMessages[0]];
            Assert.IsTrue(VerifyProof(wiring, issuance.KeyPair.PublicKey, proof, issuance.SignerMessages.Length, disclosedMessages),
                "The untampered proof must verify (guards every negative assertion below).");

            byte[] pristine = proof.AsReadOnlySpan().ToArray();
            int coreProofSizeBytes = BbsProof.ComputeSizeBytes(proof.UndisclosedMessageCount);

            //One tamper offset inside every framed component: the four count
            //fields, each core-proof point and scalar, each disclosed index,
            //each committed-disclosure commitment, response scalar and index.
            var tamperOffsets = new List<(string Name, int Offset)>
            {
                ("bbs_proof_len", BbsBlindProof.BbsProofLengthOffset + 7),
                ("core Abar", BbsBlindProof.CoreProofOffset + BbsProof.ABarOffset + 1),
                ("core Bbar", BbsBlindProof.CoreProofOffset + BbsProof.BBarOffset + 1),
                ("core D", BbsBlindProof.CoreProofOffset + BbsProof.DOffset + 1),
                ("core e^", BbsBlindProof.CoreProofOffset + BbsProof.EHatOffset + 31),
                ("core r1^", BbsBlindProof.CoreProofOffset + BbsProof.R1HatOffset + 31),
                ("core r3^", BbsBlindProof.CoreProofOffset + BbsProof.R3HatOffset + 31),
            };
            for(int i = 0; i < proof.UndisclosedMessageCount + 1; i++)
            {
                string name = i < proof.UndisclosedMessageCount ? $"core m^_{i}" : "core challenge";
                tamperOffsets.Add((name, BbsBlindProof.CoreProofOffset + BbsProof.CommitmentsOffset + BbsProof.ScalarSizeBytes * i + 31));
            }

            int cursor = BbsBlindProof.CoreProofOffset + coreProofSizeBytes;
            tamperOffsets.Add(("disclosed_indexes_len", cursor + 7));
            cursor += BbsBlindProof.Int64FieldSizeBytes;
            for(int i = 0; i < proof.DisclosedIndexCount; i++)
            {
                tamperOffsets.Add(($"disclosed index #{i}", cursor + 7));
                cursor += BbsBlindProof.Int64FieldSizeBytes;
            }

            tamperOffsets.Add(("commits_proof_len", cursor + 7));
            cursor += BbsBlindProof.Int64FieldSizeBytes;
            for(int i = 0; i < proof.CommittedDisclosureCount; i++)
            {
                tamperOffsets.Add(($"C_{i}", cursor + 1));
                cursor += BbsBlindProof.CommittedDisclosurePointSizeBytes;
            }
            for(int i = 0; i < proof.CommittedDisclosureCount; i++)
            {
                tamperOffsets.Add(($"s^_{i}", cursor + 31));
                cursor += BbsBlindProof.CommittedDisclosureScalarSizeBytes;
            }

            tamperOffsets.Add(("commits_indexes_len", cursor + 7));
            cursor += BbsBlindProof.Int64FieldSizeBytes;
            for(int i = 0; i < proof.CommittedDisclosureCount; i++)
            {
                tamperOffsets.Add(($"commit index #{i}", cursor + 7));
                cursor += BbsBlindProof.Int64FieldSizeBytes;
            }

            Assert.AreEqual(pristine.Length, cursor, "The tamper sweep's cursor arithmetic must cover the exact frame.");

            foreach((string name, int offset) in tamperOffsets)
            {
                byte[] tampered = (byte[])pristine.Clone();
                tampered[offset] ^= 0x01;

                AssertTamperedProofIsRejected(wiring, issuance, tampered, disclosedMessages, name);
            }
        }
    }


    /// <summary>Pins that a proof fails verification when presented with a substituted disclosed-message value, and when presented with the message from a different (undisclosed) position, even though the genuine disclosed set still verifies.</summary>
    [TestMethod]
    public void ProofGeneratedUnderOneDisclosureMapFailsAgainstADifferentDisclosedSet()
    {
        SuiteWiring wiring = Sha256Wiring;
        using Issuance issuance = Issue(wiring, signerMessageCount: 2, committedMessageCount: 1);
        BbsMessageDisclosure[] signerMap = [BbsMessageDisclosure.Disclose, BbsMessageDisclosure.Hide];
        BbsMessageDisclosure[] committedMap = [BbsMessageDisclosure.Hide];

        (BbsBlindProof proof, BbsBlindProofCommitmentOpenings openings) = GenerateProof(wiring, issuance, signerMap, committedMap);
        using(proof)
        using(openings)
        {
            Assert.IsTrue(VerifyProof(wiring, issuance.KeyPair.PublicKey, proof, issuance.SignerMessages.Length, [issuance.SignerMessages[0]]),
                "The genuine disclosed set must verify (guards the negative assertions below).");

            Assert.IsFalse(VerifyProof(wiring, issuance.KeyPair.PublicKey, proof, issuance.SignerMessages.Length, [new BbsMessage("substituted-message"u8.ToArray())]),
                "A different disclosed message value must fail the challenge recomputation.");
            Assert.IsFalse(VerifyProof(wiring, issuance.KeyPair.PublicKey, proof, issuance.SignerMessages.Length, [issuance.SignerMessages[1]]),
                "The message from a different (undisclosed) position must not verify in the disclosed slot.");
        }
    }


    /// <summary>Pins that transplanting a structurally valid committed-disclosure commitment from a second, independently generated proof into a first proof's frame fails verification, because the swapped commitment does not match the first proof's shared challenge.</summary>
    [TestMethod]
    public void CommitmentSwappedBetweenTwoValidProofsFailsVerification()
    {
        SuiteWiring wiring = Sha256Wiring;
        using Issuance issuance = Issue(wiring, signerMessageCount: 2, committedMessageCount: 1);
        BbsMessageDisclosure[] signerMap = [BbsMessageDisclosure.Disclose, BbsMessageDisclosure.Hide];
        BbsMessageDisclosure[] committedMap = [BbsMessageDisclosure.Commit];

        //Two proofs over the same issuance: the second draws fresh randomness,
        //so its C_1 is a different, individually valid commitment to the same
        //message.
        (BbsBlindProof firstProof, BbsBlindProofCommitmentOpenings firstOpenings) = GenerateProof(wiring, issuance, signerMap, committedMap);
        using(firstProof)
        using(firstOpenings)
        {
            (BbsBlindProof secondProof, BbsBlindProofCommitmentOpenings secondOpenings) = GenerateProof(wiring, issuance, signerMap, committedMap);
            using(secondProof)
            using(secondOpenings)
            {
                BbsMessage[] disclosedMessages = [issuance.SignerMessages[0]];
                Assert.IsTrue(VerifyProof(wiring, issuance.KeyPair.PublicKey, firstProof, issuance.SignerMessages.Length, disclosedMessages),
                    "The first proof must verify before the swap (guards the negative assertion).");

                byte[] crossed = firstProof.AsReadOnlySpan().ToArray();
                int commitmentOffset = BbsBlindProof.CoreProofOffset
                    + BbsProof.ComputeSizeBytes(firstProof.UndisclosedMessageCount)
                    + BbsBlindProof.Int64FieldSizeBytes + firstProof.DisclosedIndexCount * BbsBlindProof.Int64FieldSizeBytes
                    + BbsBlindProof.Int64FieldSizeBytes;
                secondProof.GetCommittedDisclosurePointBytes(0).CopyTo(
                    crossed.AsSpan(commitmentOffset, BbsBlindProof.CommittedDisclosurePointSizeBytes));

                using BbsBlindProof crossedProof = BbsBlindProof.FromCanonical(crossed, wiring.BlindCiphersuite, TestSetup.Pool);
                Assert.IsFalse(VerifyProof(wiring, issuance.KeyPair.PublicKey, crossedProof, issuance.SignerMessages.Length, disclosedMessages),
                    "A structurally valid commitment transplanted from another proof must fail the shared challenge.");
            }
        }
    }


    /// <summary>Pins that a core-interface proof re-framed as a blind proof fails verification, because the blind api_id changes the generators, the domain and the challenge DST, and the appended committed-disclosure block changes the challenge input shape, even for the N = 0 case whose challenge block is an all-zero placeholder.</summary>
    [TestMethod]
    public void CoreInterfaceProofWrappedInTheBlindFrameFailsVerification()
    {
        //Interface separation: even with N = 0 (whose challenge block is
        //eight zero octets rather than nothing) and identical points, a
        //core-interface proof re-framed as a blind proof must fail — the
        //blind api_id changes the generators, the domain, and the challenge
        //DST, and the appended N-block changes the challenge input shape.
        SuiteWiring wiring = Sha256Wiring;
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] messages = MakeMessages("separation", 2);

        using BbsSignature coreSignature = pair.SecretKey.Sign(
            pair.PublicKey,
            new BbsHeader(Header),
            messages,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarInvert,
            TestSetup.G1Add,
            TestSetup.G1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.Pool);
        using BbsProof coreProof = coreSignature.GenerateProof(
            pair.PublicKey,
            new BbsHeader(Header),
            new BbsPresentationHeader(PresentationHeaderBytes),
            messages,
            FirstIndexOnly,
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

        //Frame the core proof bytes as a blind proof disclosing index 0 with
        //no committed disclosures.
        byte[] coreProofBytes = coreProof.AsReadOnlySpan().ToArray();
        int framedLength = BbsBlindProof.ComputeSizeBytes(coreProof.UndisclosedMessageCount, disclosedIndexCount: 1, committedDisclosureCount: 0);
        byte[] framed = new byte[framedLength];
        Span<byte> frameCursor = framed;
        BinaryPrimitives.WriteInt64BigEndian(frameCursor, coreProofBytes.Length);
        frameCursor = frameCursor[BbsBlindProof.Int64FieldSizeBytes..];
        coreProofBytes.CopyTo(frameCursor);
        frameCursor = frameCursor[coreProofBytes.Length..];
        BinaryPrimitives.WriteInt64BigEndian(frameCursor, 1);
        frameCursor = frameCursor[BbsBlindProof.Int64FieldSizeBytes..];
        BinaryPrimitives.WriteInt64BigEndian(frameCursor, 0);

        using BbsBlindProof reframed = BbsBlindProof.FromCanonical(framed, wiring.BlindCiphersuite, TestSetup.Pool);
        //The core proof was over 2 messages (no blind slot); presenting it as
        //a blind proof over (1 issuer message, blind slot, 0 committed)
        //aligns the slot arithmetic while every challenge input differs.
        Assert.IsFalse(VerifyProof(wiring, pair.PublicKey, reframed, issuerMessageCount: 1, [messages[0]]),
            "A core-interface proof must not verify when re-framed under the blind interface.");
    }


    /// <summary>Pins that the core-layout byte region carried inside a blind proof fails verification when reinterpreted directly as a core-interface proof.</summary>
    [TestMethod]
    public void BlindProofCoreRegionDoesNotVerifyUnderTheCoreInterface()
    {
        SuiteWiring wiring = Sha256Wiring;
        using Issuance issuance = Issue(wiring, signerMessageCount: 2, committedMessageCount: 0, useCommitment: false);
        BbsMessageDisclosure[] signerMap = [BbsMessageDisclosure.Disclose, BbsMessageDisclosure.Hide];

        (BbsBlindProof proof, BbsBlindProofCommitmentOpenings openings) = GenerateProof(wiring, issuance, signerMap, []);
        using(proof)
        using(openings)
        {
            using BbsProof reinterpreted = BbsProof.FromCanonical(proof.GetCoreProofBytes(), wiring.Ciphersuite, TestSetup.Pool);

            bool verified = issuance.KeyPair.PublicKey.VerifyProof(
                reinterpreted,
                new BbsHeader(Header),
                new BbsPresentationHeader(PresentationHeaderBytes),
                new BbsMessage[] { issuance.SignerMessages[0] },
                FirstIndexOnly,
                wiring.ExpandMessage,
                wiring.HashToScalar,
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

            Assert.IsFalse(verified, "The core-layout region of a blind proof must not verify under the core interface.");
        }
    }


    /// <summary>Pins that a different presentation header fails the challenge recomputation, even though the genuine header still verifies.</summary>
    [TestMethod]
    public void WrongPresentationHeaderFailsVerification()
    {
        SuiteWiring wiring = Sha256Wiring;
        using Issuance issuance = Issue(wiring, signerMessageCount: 2, committedMessageCount: 1);
        BbsMessageDisclosure[] signerMap = [BbsMessageDisclosure.Disclose, BbsMessageDisclosure.Hide];
        BbsMessageDisclosure[] committedMap = [BbsMessageDisclosure.Commit];

        (BbsBlindProof proof, BbsBlindProofCommitmentOpenings openings) = GenerateProof(wiring, issuance, signerMap, committedMap);
        using(proof)
        using(openings)
        {
            BbsMessage[] disclosedMessages = [issuance.SignerMessages[0]];
            Assert.IsTrue(VerifyProof(wiring, issuance.KeyPair.PublicKey, proof, issuance.SignerMessages.Length, disclosedMessages),
                "The genuine presentation header must verify (guards the negative assertion).");
            Assert.IsFalse(VerifyProof(wiring, issuance.KeyPair.PublicKey, proof, issuance.SignerMessages.Length, disclosedMessages,
                presentationHeader: "wrong-presentation"u8.ToArray()),
                "A different presentation header must fail the challenge recomputation.");
        }
    }


    /// <summary>Pins that an issuer-message count one too high or one too low fails verification, because it shifts where the committed-generator family's leading point sits in the combined generator vector.</summary>
    [TestMethod]
    public void WrongIssuerMessageCountFailsVerification()
    {
        SuiteWiring wiring = Sha256Wiring;
        using Issuance issuance = Issue(wiring, signerMessageCount: 2, committedMessageCount: 1);
        BbsMessageDisclosure[] signerMap = [BbsMessageDisclosure.Disclose, BbsMessageDisclosure.Hide];
        BbsMessageDisclosure[] committedMap = [BbsMessageDisclosure.Hide];

        (BbsBlindProof proof, BbsBlindProofCommitmentOpenings openings) = GenerateProof(wiring, issuance, signerMap, committedMap);
        using(proof)
        using(openings)
        {
            BbsMessage[] disclosedMessages = [issuance.SignerMessages[0]];

            //A shifted issuer count moves the Q_2 slot, changing the
            //generator split the domain and the pairing equation are built
            //over.
            Assert.IsFalse(VerifyProof(wiring, issuance.KeyPair.PublicKey, proof, issuance.SignerMessages.Length + 1, disclosedMessages),
                "An issuer-message count one too high must fail.");
            Assert.IsFalse(VerifyProof(wiring, issuance.KeyPair.PublicKey, proof, issuance.SignerMessages.Length - 1, disclosedMessages),
                "An issuer-message count one too low must fail.");
        }
    }


    /// <summary>Asserts that verifying the tampered bytes under the blind interface either is rejected at proof intake (a caught <see cref="ArgumentException"/>, an equally acceptable outcome) or fails verification.</summary>
    private static void AssertTamperedProofIsRejected(
        SuiteWiring wiring,
        Issuance issuance,
        byte[] tamperedBytes,
        BbsMessage[] disclosedMessages,
        string componentName)
    {
        BbsBlindProof tamperedProof;
        try
        {
            tamperedProof = BbsBlindProof.FromCanonical(tamperedBytes, wiring.BlindCiphersuite, TestSetup.Pool);
        }
        catch(ArgumentException)
        {
            //Frame-arithmetic tampering (count fields, non-canonical scalars)
            //is rejected at intake — an equally acceptable outcome.
            return;
        }

        using(tamperedProof)
        {
            Assert.IsFalse(
                VerifyProof(wiring, issuance.KeyPair.PublicKey, tamperedProof, issuance.SignerMessages.Length, disclosedMessages),
                $"Tampering the {componentName} component must make verification return false.");
        }
    }


    /// <summary>Issues a blind signature, generates a blind proof over the given signer and committed disclosure maps, and asserts that BlindProofVerify accepts it — optionally checking the framed committed-disclosure count and opening count against an expected value.</summary>
    private static void RunRoundtrip(
        SuiteWiring wiring,
        int signerMessageCount,
        int committedMessageCount,
        BbsMessageDisclosure[] signerMap,
        BbsMessageDisclosure[] committedMap,
        int expectedCommitCount = -1,
        bool useCommitment = true)
    {
        using Issuance issuance = Issue(wiring, signerMessageCount, committedMessageCount, useCommitment);

        (BbsBlindProof proof, BbsBlindProofCommitmentOpenings openings) = GenerateProof(wiring, issuance, signerMap, committedMap);
        using(proof)
        using(openings)
        {
            if(expectedCommitCount >= 0)
            {
                Assert.AreEqual(expectedCommitCount, proof.CommittedDisclosureCount,
                    "The framed proof must carry one committed disclosure per COMMIT entry.");
                Assert.AreEqual(expectedCommitCount, openings.Count,
                    "add_zkp_info must carry one opening per COMMIT entry.");
            }

            BbsMessage[] disclosedMessages = CollectDisclosedMessages(issuance, signerMap, committedMap);
            Assert.IsTrue(VerifyProof(wiring, issuance.KeyPair.PublicKey, proof, signerMessageCount, disclosedMessages),
                $"BlindProofGen → BlindProofVerify must roundtrip for L={signerMessageCount}, M={committedMessageCount}, commitment={useCommitment} under '{wiring.BlindCiphersuite.Identifier}'.");
        }
    }


    /// <summary>Disclosed messages in frame order: signer disclosures first, then committed ones — matching the ascending combined index space.</summary>
    private static BbsMessage[] CollectDisclosedMessages(Issuance issuance, BbsMessageDisclosure[] signerMap, BbsMessageDisclosure[] committedMap)
    {
        var disclosed = new List<BbsMessage>();
        for(int i = 0; i < signerMap.Length; i++)
        {
            if(signerMap[i] == BbsMessageDisclosure.Disclose)
            {
                disclosed.Add(issuance.SignerMessages[i]);
            }
        }
        for(int i = 0; i < committedMap.Length; i++)
        {
            if(committedMap[i] == BbsMessageDisclosure.Disclose)
            {
                disclosed.Add(issuance.CommittedMessages[i]);
            }
        }

        return [.. disclosed];
    }


    /// <summary>Generates a key pair, builds the signer and committed messages, optionally commits to the committed messages, and blind-signs the signer messages, returning everything the proof-generation step and the test's cleanup need.</summary>
    private static Issuance Issue(SuiteWiring wiring, int signerMessageCount, int committedMessageCount, bool useCommitment = true)
    {
        BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] signerMessages = MakeMessages("issuer", signerMessageCount);
        BbsMessage[] committedMessages = MakeMessages("committed", committedMessageCount);

        BbsCommitmentWithProof? commitment = null;
        Scalar? secretProverBlind = null;
        if(useCommitment)
        {
            (commitment, secretProverBlind) = BbsCommitmentWithProof.Commit(
                committedMessages,
                wiring.BlindCiphersuite,
                wiring.ExpandMessage,
                wiring.HashToScalar,
                TestSetup.ScalarAdd,
                TestSetup.ScalarMultiply,
                TestSetup.ScalarRandom,
                TestSetup.G1MultiScalarMultiply,
                wiring.G1HashToCurve,
                TestSetup.Pool);
        }

        BbsBlindSignature signature = pair.SecretKey.BlindSign(
            pair.PublicKey,
            commitment,
            new BbsHeader(Header),
            signerMessages,
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

        return new Issuance(pair, signerMessages, committedMessages, commitment, secretProverBlind, signature);
    }


    /// <summary>Runs BlindProofGen over the issuance's signature for the given signer and committed disclosure maps.</summary>
    private static (BbsBlindProof Proof, BbsBlindProofCommitmentOpenings Openings) GenerateProof(
        SuiteWiring wiring,
        Issuance issuance,
        BbsMessageDisclosure[] signerMap,
        BbsMessageDisclosure[] committedMap) =>
        issuance.Signature.BlindProofGen(
            issuance.KeyPair.PublicKey,
            new BbsHeader(Header),
            new BbsPresentationHeader(PresentationHeaderBytes),
            issuance.SignerMessages,
            issuance.CommittedMessages,
            signerMap,
            committedMap,
            issuance.SecretProverBlind,
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


    /// <summary>Runs BlindProofVerify against the given public key, issuer-message count and disclosed messages, using the presentation header supplied or, absent one, the suite's fixed header.</summary>
    private static bool VerifyProof(
        SuiteWiring wiring,
        BbsPublicKey publicKey,
        BbsBlindProof proof,
        int issuerMessageCount,
        BbsMessage[] disclosedMessages,
        byte[]? presentationHeader = null) =>
        proof.BlindProofVerify(
            publicKey,
            new BbsHeader(Header),
            new BbsPresentationHeader(presentationHeader ?? PresentationHeaderBytes),
            issuerMessageCount,
            disclosedMessages,
            wiring.ExpandMessage,
            wiring.HashToScalar,
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


    /// <summary>Generates a key pair from the fixed key material and info under the wiring's base ciphersuite.</summary>
    private static BbsKeyPair MakeKeyPair(SuiteWiring wiring) =>
        wiring.Ciphersuite.Generate(
            KeyMaterial,
            KeyInfo,
            wiring.HashToScalar,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pool);


    /// <summary>Builds a disclosure map of the given length whose every entry is the same disclosure kind.</summary>
    private static BbsMessageDisclosure[] AllOf(BbsMessageDisclosure disclosure, int count) =>
        [.. Enumerable.Repeat(disclosure, count)];


    /// <summary>Builds a sequence of distinct UTF-8 messages numbered from zero under the given prefix.</summary>
    private static BbsMessage[] MakeMessages(string prefix, int count)
    {
        BbsMessage[] messages = new BbsMessage[count];
        for(int i = 0; i < count; i++)
        {
            messages[i] = new BbsMessage(Encoding.UTF8.GetBytes($"{prefix}-message-{i}"));
        }

        return messages;
    }


    /// <summary>Builds a deterministic byte sequence of the given length, each byte one more than the last starting from <paramref name="start"/> and wrapping modulo 256.</summary>
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
