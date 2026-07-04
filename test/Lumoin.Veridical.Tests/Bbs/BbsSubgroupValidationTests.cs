using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Deserialization-validation tests for the BBS+ verification surfaces
/// per IETF draft-irtf-cfrg-bbs-signatures-10: <c>octets_to_signature</c>
/// (Section 4.2.4.3) and <c>octets_to_proof</c> (Section 4.2.4.5) reject
/// G1 points that are off-curve, the identity, or outside the prime-order
/// subgroup; <c>octets_to_pubkey</c> (Section 4.2.4.6) does the same for
/// the G2 public key. Both BLS12-381 groups have non-trivial cofactors,
/// so on-curve membership alone does not imply subgroup membership.
/// </summary>
[TestClass]
internal sealed class BbsSubgroupValidationTests
{
    //Pre-calculated wrong-subgroup probe: the BLS12-381 G1 point with x = 0
    //(y^2 = 4, roots +-2) is on the curve but outside the r-order subgroup:
    //[r]P != O while [h1 * r]P == O for the G1 cofactor h1. ZCash-convention
    //encoding: compression flag 0x80 plus y-parity flag 0x20 because the
    //encoded root y = p - 2 is the lexicographically larger one; the x bytes
    //are all zero. Re-derive by walking x upward from 0 and taking the first
    //x whose curve RHS is a quadratic residue and whose point fails [r]P == O.
    private static readonly byte[] WrongSubgroupG1Compressed = Convert.FromHexString(
        "a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    //Pre-calculated wrong-subgroup probe for G2: the point with x = (2, 0) on
    //the twist y^2 = x^3 + 4(1 + u) over Fp2 is on the curve but outside the
    //r-order subgroup: [r]P != O while [h2 * r]P == O for the G2 cofactor h2.
    //ZCash-convention encoding: x.c1 (all zero) carries the flags in byte 0 -
    //compression 0x80 plus y-parity 0x20 because y.c1 is the lexicographically
    //larger root component - followed by x.c0 = 2. Re-derive by walking
    //x = (n, 0) upward from n = 0 with the same first-hit rule as G1.
    private static readonly byte[] WrongSubgroupG2Compressed = Convert.FromHexString(
        "a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002");

    //Pre-calculated off-curve probes: x = 1 on the G1 side (1 + 4 = 5 is a
    //quadratic non-residue mod p) and x = (0, 0) on the G2 side (4(1 + u) is a
    //non-residue in Fp2), each encoded with only the compression flag set.
    //octets_to_point fails for both, so on-curve validation must reject them.
    //Re-derive by walking x upward from 0 and taking the first x whose curve
    //RHS is a quadratic non-residue.
    private static readonly byte[] OffCurveG1Compressed = Convert.FromHexString(
        "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001");

    private static readonly byte[] OffCurveG2Compressed = Convert.FromHexString(
        "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    private static readonly byte[] Header = "subgroup-validation-header"u8.ToArray();
    private static readonly byte[] PresentationHeader = "subgroup-validation-ph"u8.ToArray();
    private static readonly BbsMessage[] Messages = [new BbsMessage("first"u8.ToArray()), new BbsMessage("second"u8.ToArray())];
    private static readonly int[] DisclosedIndices = [0];
    private static readonly BbsMessage[] DisclosedMessages = [Messages[0]];

    //Arbitrary distinct key-material seeds, mirroring the sibling failure tests.
    private const byte KeySeed = 0x30;
    private const int KeyMaterialSizeBytes = 64;


    private sealed record SuiteWiring(
        BbsCiphersuite Ciphersuite,
        ExpandMessageDelegate ExpandMessage,
        ScalarHashToScalarDelegate HashToScalar,
        G1HashToCurveDelegate G1HashToCurve);

    private static readonly SuiteWiring Sha256Wiring = new(
        BbsCiphersuite.Bls12Curve381Sha256,
        TestSetup.Sha256.ExpandMessage,
        TestSetup.Sha256.HashToScalar,
        TestSetup.Sha256.G1HashToCurve);

    private static readonly SuiteWiring Shake256Wiring = new(
        BbsCiphersuite.Bls12Curve381Shake256,
        TestSetup.Shake256.ExpandMessage,
        TestSetup.Shake256.HashToScalar,
        TestSetup.Shake256.G1HashToCurve);


    [TestMethod]
    public void WrongSubgroupProbesAreOnCurveButOutsideSubgroup()
    {
        //Pins the literals themselves: both probes must decode onto their
        //curves yet fail the prime-order-subgroup check, otherwise every
        //rejection test below would pass for the wrong reason.
        Assert.IsTrue(TestSetup.G1IsOnCurve(WrongSubgroupG1Compressed, CurveParameterSet.Bls12Curve381), "The G1 probe must lie on the curve.");
        Assert.IsFalse(TestSetup.G1IsInPrimeOrderSubgroup(WrongSubgroupG1Compressed, CurveParameterSet.Bls12Curve381), "The G1 probe must lie outside the prime-order subgroup.");
        Assert.IsTrue(TestSetup.G2IsOnCurve(WrongSubgroupG2Compressed, CurveParameterSet.Bls12Curve381), "The G2 probe must lie on the curve.");
        Assert.IsFalse(TestSetup.G2IsInPrimeOrderSubgroup(WrongSubgroupG2Compressed, CurveParameterSet.Bls12Curve381), "The G2 probe must lie outside the prime-order subgroup.");
        Assert.IsFalse(TestSetup.G1IsOnCurve(OffCurveG1Compressed, CurveParameterSet.Bls12Curve381), "The off-curve G1 probe must fail the on-curve check.");
        Assert.IsFalse(TestSetup.G2IsOnCurve(OffCurveG2Compressed, CurveParameterSet.Bls12Curve381), "The off-curve G2 probe must fail the on-curve check.");
    }


    [TestMethod]
    public void VerifyRejectsWrongSubgroupSignaturePointOnSha256()
    {
        VerifyRejectsWrongSubgroupSignaturePointCore(Sha256Wiring);
    }


    [TestMethod]
    public void VerifyRejectsWrongSubgroupSignaturePointOnShake256()
    {
        VerifyRejectsWrongSubgroupSignaturePointCore(Shake256Wiring);
    }


    private static void VerifyRejectsWrongSubgroupSignaturePointCore(SuiteWiring wiring)
    {
        using BbsKeyPair pair = MakeKeyPair(wiring);
        using BbsSignature signature = SignMessages(pair, wiring);
        using BbsSignature tampered = SpliceSignaturePoint(signature, WrongSubgroupG1Compressed, wiring.Ciphersuite);

        bool subgroupChecked = false;
        bool pairingCalled = false;
        G1IsInPrimeOrderSubgroupDelegate recordingSubgroup = (point, curve) =>
        {
            subgroupChecked = true;

            return TestSetup.G1IsInPrimeOrderSubgroup(point, curve);
        };
        PairingDelegate recordingPairing = (g1, g2, result, curve) =>
        {
            pairingCalled = true;
            TestSetup.Pairing(g1, g2, result, curve);
        };

        bool verified = VerifySignature(pair.PublicKey, tampered, wiring, g1SubgroupOverride: recordingSubgroup, pairingOverride: recordingPairing);

        Assert.IsFalse(verified, "Verify must reject a signature whose A lies outside the prime-order subgroup.");
        Assert.IsTrue(subgroupChecked, "Verify must consult the G1 subgroup delegate for the signature point A.");
        Assert.IsFalse(pairingCalled, "Rejection must happen at deserialization validation, before any pairing.");
    }


    [TestMethod]
    public void VerifyRejectsIdentitySignaturePoint()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);
        using BbsSignature tampered = SpliceSignaturePoint(signature, WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bls12Curve381), Sha256Wiring.Ciphersuite);

        bool pairingCalled = false;
        PairingDelegate recordingPairing = (g1, g2, result, curve) =>
        {
            pairingCalled = true;
            TestSetup.Pairing(g1, g2, result, curve);
        };

        bool verified = VerifySignature(pair.PublicKey, tampered, Sha256Wiring, pairingOverride: recordingPairing);

        Assert.IsFalse(verified, "Verify must reject a signature whose A is the identity (octets_to_signature step 6).");
        Assert.IsFalse(pairingCalled, "Rejection must happen at deserialization validation, before any pairing.");
    }


    [TestMethod]
    public void VerifyRejectsNonCanonicalInfinitySignaturePoint()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);

        foreach(byte[] probe in NonCanonicalInfinityProbes(WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bls12Curve381)))
        {
            using BbsSignature tampered = SpliceSignaturePoint(signature, probe, Sha256Wiring.Ciphersuite);

            bool pairingCalled = false;
            PairingDelegate recordingPairing = (g1, g2, result, curve) =>
            {
                pairingCalled = true;
                TestSetup.Pairing(g1, g2, result, curve);
            };

            Assert.IsFalse(
                VerifySignature(pair.PublicKey, tampered, Sha256Wiring, pairingOverride: recordingPairing),
                "Verify must reject a non-canonical infinity encoding of A rather than alias it onto the identity.");
            Assert.IsFalse(pairingCalled, "Rejection must happen at deserialization validation, before any pairing; an aliased identity would instead reach the pairing.");
        }
    }


    [TestMethod]
    public void VerifyRejectsOffCurveSignaturePoint()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);
        using BbsSignature tampered = SpliceSignaturePoint(signature, OffCurveG1Compressed, Sha256Wiring.Ciphersuite);

        bool pairingCalled = false;
        PairingDelegate recordingPairing = (g1, g2, result, curve) =>
        {
            pairingCalled = true;
            TestSetup.Pairing(g1, g2, result, curve);
        };

        Assert.IsFalse(
            VerifySignature(pair.PublicKey, tampered, Sha256Wiring, pairingOverride: recordingPairing),
            "Verify must reject a signature whose A does not decode onto the curve (octets_to_signature step 5).");
        Assert.IsFalse(pairingCalled, "Rejection must happen at deserialization validation, before any pairing.");
    }


    [TestMethod]
    public void VerifyRejectsWrongSubgroupPublicKeyOnSha256()
    {
        VerifyRejectsWrongSubgroupPublicKeyCore(Sha256Wiring);
    }


    [TestMethod]
    public void VerifyRejectsWrongSubgroupPublicKeyOnShake256()
    {
        VerifyRejectsWrongSubgroupPublicKeyCore(Shake256Wiring);
    }


    private static void VerifyRejectsWrongSubgroupPublicKeyCore(SuiteWiring wiring)
    {
        using BbsKeyPair pair = MakeKeyPair(wiring);
        using BbsSignature signature = SignMessages(pair, wiring);
        using BbsPublicKey wrongSubgroupKey = BbsPublicKey.FromCanonical(WrongSubgroupG2Compressed, wiring.Ciphersuite, TestSetup.Pool);

        bool subgroupChecked = false;
        bool pairingCalled = false;
        G2IsInPrimeOrderSubgroupDelegate recordingSubgroup = (point, curve) =>
        {
            subgroupChecked = true;

            return TestSetup.G2IsInPrimeOrderSubgroup(point, curve);
        };
        PairingDelegate recordingPairing = (g1, g2, result, curve) =>
        {
            pairingCalled = true;
            TestSetup.Pairing(g1, g2, result, curve);
        };

        bool verified = VerifySignature(wrongSubgroupKey, signature, wiring, g2SubgroupOverride: recordingSubgroup, pairingOverride: recordingPairing);

        Assert.IsFalse(verified, "Verify must reject a public key W outside the prime-order subgroup (octets_to_pubkey step 3).");
        Assert.IsTrue(subgroupChecked, "Verify must consult the G2 subgroup delegate for the public key W.");
        Assert.IsFalse(pairingCalled, "Rejection must happen at deserialization validation, before any pairing.");
    }


    [TestMethod]
    public void VerifyRejectsIdentityPublicKey()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);
        using BbsPublicKey identityKey = BbsPublicKey.FromCanonical(WellKnownCurves.GetG2IdentityCompressed(CurveParameterSet.Bls12Curve381), Sha256Wiring.Ciphersuite, TestSetup.Pool);

        bool pairingCalled = false;
        PairingDelegate recordingPairing = (g1, g2, result, curve) =>
        {
            pairingCalled = true;
            TestSetup.Pairing(g1, g2, result, curve);
        };

        bool verified = VerifySignature(identityKey, signature, Sha256Wiring, pairingOverride: recordingPairing);

        Assert.IsFalse(verified, "Verify must reject the identity public key (octets_to_pubkey step 4).");
        Assert.IsFalse(pairingCalled, "Rejection must happen at deserialization validation, before any pairing.");
    }


    [TestMethod]
    public void VerifyRejectsNonCanonicalInfinityPublicKey()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);

        foreach(byte[] probe in NonCanonicalInfinityProbes(WellKnownCurves.GetG2IdentityCompressed(CurveParameterSet.Bls12Curve381)))
        {
            using BbsPublicKey nonCanonicalKey = BbsPublicKey.FromCanonical(probe, Sha256Wiring.Ciphersuite, TestSetup.Pool);

            bool pairingCalled = false;
            PairingDelegate recordingPairing = (g1, g2, result, curve) =>
            {
                pairingCalled = true;
                TestSetup.Pairing(g1, g2, result, curve);
            };

            Assert.IsFalse(
                VerifySignature(nonCanonicalKey, signature, Sha256Wiring, pairingOverride: recordingPairing),
                "Verify must reject a non-canonical infinity encoding of W rather than alias it onto the identity.");
            Assert.IsFalse(pairingCalled, "Rejection must happen at deserialization validation, before any pairing; an aliased identity would instead reach the pairing.");
        }
    }


    [TestMethod]
    public void VerifyRejectsOffCurvePublicKey()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);
        using BbsPublicKey offCurveKey = BbsPublicKey.FromCanonical(OffCurveG2Compressed, Sha256Wiring.Ciphersuite, TestSetup.Pool);

        bool pairingCalled = false;
        PairingDelegate recordingPairing = (g1, g2, result, curve) =>
        {
            pairingCalled = true;
            TestSetup.Pairing(g1, g2, result, curve);
        };

        Assert.IsFalse(
            VerifySignature(offCurveKey, signature, Sha256Wiring, pairingOverride: recordingPairing),
            "Verify must reject a public key W that does not decode onto the curve (octets_to_pubkey step 2).");
        Assert.IsFalse(pairingCalled, "Rejection must happen at deserialization validation, before any pairing.");
    }


    //On the VerifyProof surface a pairing-not-called pin cannot discriminate the
    //validation block from the challenge re-derivation gate: a spliced proof point
    //changes the challenge input, so the challenge compare also returns false
    //before any pairing. The discriminating observable is the T1/Bv/T2 MSMs —
    //deserialization validation rejects before the first MSM, while the challenge
    //gate only fires after all three. The wrong-subgroup tests additionally pin
    //that the subgroup delegate itself observed and rejected the point, which a
    //deleted validation block could never produce (a real malicious prover
    //computes the challenge over its own tampered points, so only the validation
    //block stops that attack).
    [TestMethod]
    public void VerifyProofRejectsWrongSubgroupProofPoints()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);
        using BbsProof proof = GenerateProof(signature, pair, Sha256Wiring);

        int[] proofPointOffsets = [BbsProof.ABarOffset, BbsProof.BBarOffset, BbsProof.DOffset];
        foreach(int offset in proofPointOffsets)
        {
            using BbsProof tampered = SpliceProofPoint(proof, offset, WrongSubgroupG1Compressed, Sha256Wiring.Ciphersuite);

            bool subgroupRejected = false;
            bool msmCalled = false;
            G1IsInPrimeOrderSubgroupDelegate recordingSubgroup = (point, curve) =>
            {
                bool isMember = TestSetup.G1IsInPrimeOrderSubgroup(point, curve);
                subgroupRejected |= !isMember;

                return isMember;
            };
            G1MultiScalarMultiplyDelegate recordingMsm = (points, scalars, count, result, curve) =>
            {
                msmCalled = true;
                TestSetup.G1MultiScalarMultiply(points, scalars, count, result, curve);
            };

            bool verified = VerifyProof(pair.PublicKey, tampered, Sha256Wiring, g1SubgroupOverride: recordingSubgroup, msmOverride: recordingMsm);

            Assert.IsFalse(verified, $"VerifyProof must reject a proof point at offset {offset} outside the prime-order subgroup.");
            Assert.IsTrue(subgroupRejected, $"The G1 subgroup delegate must observe and reject the tampered point at offset {offset}.");
            Assert.IsFalse(msmCalled, $"Rejection of the proof point at offset {offset} must happen at deserialization validation, before any MSM.");
        }
    }


    [TestMethod]
    public void VerifyProofRejectsWrongSubgroupAbarOnShake256()
    {
        using BbsKeyPair pair = MakeKeyPair(Shake256Wiring);
        using BbsSignature signature = SignMessages(pair, Shake256Wiring);
        using BbsProof proof = GenerateProof(signature, pair, Shake256Wiring);
        using BbsProof tampered = SpliceProofPoint(proof, BbsProof.ABarOffset, WrongSubgroupG1Compressed, Shake256Wiring.Ciphersuite);

        bool subgroupRejected = false;
        bool msmCalled = false;
        G1IsInPrimeOrderSubgroupDelegate recordingSubgroup = (point, curve) =>
        {
            bool isMember = TestSetup.G1IsInPrimeOrderSubgroup(point, curve);
            subgroupRejected |= !isMember;

            return isMember;
        };
        G1MultiScalarMultiplyDelegate recordingMsm = (points, scalars, count, result, curve) =>
        {
            msmCalled = true;
            TestSetup.G1MultiScalarMultiply(points, scalars, count, result, curve);
        };

        Assert.IsFalse(
            VerifyProof(pair.PublicKey, tampered, Shake256Wiring, g1SubgroupOverride: recordingSubgroup, msmOverride: recordingMsm),
            "VerifyProof must reject an Abar outside the prime-order subgroup on the SHAKE-256 ciphersuite.");
        Assert.IsTrue(subgroupRejected, "The G1 subgroup delegate must observe and reject the tampered Abar.");
        Assert.IsFalse(msmCalled, "Rejection must happen at deserialization validation, before any MSM.");
    }


    [TestMethod]
    public void VerifyProofRejectsIdentityProofPoints()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);
        using BbsProof proof = GenerateProof(signature, pair, Sha256Wiring);

        int[] proofPointOffsets = [BbsProof.ABarOffset, BbsProof.BBarOffset, BbsProof.DOffset];
        foreach(int offset in proofPointOffsets)
        {
            using BbsProof tampered = SpliceProofPoint(proof, offset, WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bls12Curve381), Sha256Wiring.Ciphersuite);

            bool msmCalled = false;
            G1MultiScalarMultiplyDelegate recordingMsm = (points, scalars, count, result, curve) =>
            {
                msmCalled = true;
                TestSetup.G1MultiScalarMultiply(points, scalars, count, result, curve);
            };

            Assert.IsFalse(
                VerifyProof(pair.PublicKey, tampered, Sha256Wiring, msmOverride: recordingMsm),
                $"VerifyProof must reject an identity proof point at offset {offset} (octets_to_proof step 7).");
            Assert.IsFalse(msmCalled, $"Rejection of the identity point at offset {offset} must happen at deserialization validation, before any MSM.");
        }
    }


    [TestMethod]
    public void VerifyProofRejectsOffCurveAbar()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);
        using BbsProof proof = GenerateProof(signature, pair, Sha256Wiring);
        using BbsProof tampered = SpliceProofPoint(proof, BbsProof.ABarOffset, OffCurveG1Compressed, Sha256Wiring.Ciphersuite);

        bool msmCalled = false;
        G1MultiScalarMultiplyDelegate recordingMsm = (points, scalars, count, result, curve) =>
        {
            msmCalled = true;
            TestSetup.G1MultiScalarMultiply(points, scalars, count, result, curve);
        };

        Assert.IsFalse(
            VerifyProof(pair.PublicKey, tampered, Sha256Wiring, msmOverride: recordingMsm),
            "VerifyProof must reject an Abar that does not decode onto the curve (octets_to_proof step 7).");
        Assert.IsFalse(msmCalled, "Rejection must happen at deserialization validation, before any MSM.");
    }


    [TestMethod]
    public void VerifyProofRejectsNonCanonicalInfinityAbar()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);
        using BbsProof proof = GenerateProof(signature, pair, Sha256Wiring);

        foreach(byte[] probe in NonCanonicalInfinityProbes(WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bls12Curve381)))
        {
            using BbsProof tampered = SpliceProofPoint(proof, BbsProof.ABarOffset, probe, Sha256Wiring.Ciphersuite);

            bool msmCalled = false;
            G1MultiScalarMultiplyDelegate recordingMsm = (points, scalars, count, result, curve) =>
            {
                msmCalled = true;
                TestSetup.G1MultiScalarMultiply(points, scalars, count, result, curve);
            };

            Assert.IsFalse(
                VerifyProof(pair.PublicKey, tampered, Sha256Wiring, msmOverride: recordingMsm),
                "VerifyProof must reject a non-canonical infinity encoding of Abar rather than alias it onto the identity.");
            Assert.IsFalse(msmCalled, "Rejection must happen at deserialization validation, before any MSM; an aliased identity would instead reach the MSM.");
        }
    }


    [TestMethod]
    public void VerifyProofRejectsWrongSubgroupPublicKey()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);
        using BbsProof proof = GenerateProof(signature, pair, Sha256Wiring);
        using BbsPublicKey wrongSubgroupKey = BbsPublicKey.FromCanonical(WrongSubgroupG2Compressed, Sha256Wiring.Ciphersuite, TestSetup.Pool);

        bool subgroupRejected = false;
        bool msmCalled = false;
        G2IsInPrimeOrderSubgroupDelegate recordingSubgroup = (point, curve) =>
        {
            bool isMember = TestSetup.G2IsInPrimeOrderSubgroup(point, curve);
            subgroupRejected |= !isMember;

            return isMember;
        };
        G1MultiScalarMultiplyDelegate recordingMsm = (points, scalars, count, result, curve) =>
        {
            msmCalled = true;
            TestSetup.G1MultiScalarMultiply(points, scalars, count, result, curve);
        };

        Assert.IsFalse(
            VerifyProof(wrongSubgroupKey, proof, Sha256Wiring, g2SubgroupOverride: recordingSubgroup, msmOverride: recordingMsm),
            "VerifyProof must reject a public key W outside the prime-order subgroup (octets_to_pubkey step 3).");
        Assert.IsTrue(subgroupRejected, "The G2 subgroup delegate must observe and reject the tampered public key.");
        Assert.IsFalse(msmCalled, "Rejection must happen at deserialization validation, before any MSM.");
    }


    [TestMethod]
    public void VerifyProofRejectsIdentityPublicKey()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);
        using BbsProof proof = GenerateProof(signature, pair, Sha256Wiring);
        using BbsPublicKey identityKey = BbsPublicKey.FromCanonical(WellKnownCurves.GetG2IdentityCompressed(CurveParameterSet.Bls12Curve381), Sha256Wiring.Ciphersuite, TestSetup.Pool);

        bool msmCalled = false;
        G1MultiScalarMultiplyDelegate recordingMsm = (points, scalars, count, result, curve) =>
        {
            msmCalled = true;
            TestSetup.G1MultiScalarMultiply(points, scalars, count, result, curve);
        };

        Assert.IsFalse(
            VerifyProof(identityKey, proof, Sha256Wiring, msmOverride: recordingMsm),
            "VerifyProof must reject the identity public key (octets_to_pubkey step 4).");
        Assert.IsFalse(msmCalled, "Rejection must happen at deserialization validation, before any MSM.");
    }


    [TestMethod]
    public void GenerateProofThrowsOnWrongSubgroupSignaturePoint()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);
        using BbsSignature tampered = SpliceSignaturePoint(signature, WrongSubgroupG1Compressed, Sha256Wiring.Ciphersuite);

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => GenerateProof(tampered, pair, Sha256Wiring).Dispose());
        Assert.Contains("prime-order subgroup", ex.Message, "The exception must name the failed subgroup requirement.");
    }


    [TestMethod]
    public void GenerateProofThrowsOnIdentitySignaturePoint()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);
        using BbsSignature tampered = SpliceSignaturePoint(signature, WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bls12Curve381), Sha256Wiring.Ciphersuite);

        Assert.ThrowsExactly<ArgumentException>(() => GenerateProof(tampered, pair, Sha256Wiring).Dispose());
    }


    [TestMethod]
    public void GenerateProofThrowsOnOffCurveSignaturePoint()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);
        using BbsSignature tampered = SpliceSignaturePoint(signature, OffCurveG1Compressed, Sha256Wiring.Ciphersuite);

        //ThrowsExactly discriminates: without the validation an off-curve A only
        //surfaces later as an InvalidOperationException inside the backend.
        Assert.ThrowsExactly<ArgumentException>(() => GenerateProof(tampered, pair, Sha256Wiring).Dispose());
    }


    [TestMethod]
    public void GenerateProofThrowsOnNonCanonicalInfinitySignaturePoint()
    {
        using BbsKeyPair pair = MakeKeyPair(Sha256Wiring);
        using BbsSignature signature = SignMessages(pair, Sha256Wiring);

        foreach(byte[] probe in NonCanonicalInfinityProbes(WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bls12Curve381)))
        {
            using BbsSignature tampered = SpliceSignaturePoint(signature, probe, Sha256Wiring.Ciphersuite);

            //ThrowsExactly discriminates: an aliased identity would pass the
            //on-curve and subgroup checks and generate a proof without throwing.
            Assert.ThrowsExactly<ArgumentException>(() => GenerateProof(tampered, pair, Sha256Wiring).Dispose());
        }
    }


    private static BbsKeyPair MakeKeyPair(SuiteWiring wiring)
    {
        byte[] keyMaterial = new byte[KeyMaterialSizeBytes];
        for(int i = 0; i < keyMaterial.Length; i++)
        {
            keyMaterial[i] = (byte)(KeySeed + i);
        }

        return wiring.Ciphersuite.Generate(
            keyMaterial,
            "subgroup-validation-key-info"u8.ToArray(),
            wiring.HashToScalar,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pool);
    }


    private static BbsSignature SignMessages(BbsKeyPair pair, SuiteWiring wiring)
    {
        return pair.SecretKey.Sign(
            pair.PublicKey,
            new BbsHeader(Header),
            Messages,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarInvert,
            TestSetup.G1Add,
            TestSetup.G1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.Pool);
    }


    private static BbsProof GenerateProof(BbsSignature signature, BbsKeyPair pair, SuiteWiring wiring)
    {
        return signature.GenerateProof(
            pair.PublicKey,
            new BbsHeader(Header),
            new BbsPresentationHeader(PresentationHeader),
            Messages,
            DisclosedIndices,
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
    }


    private static bool VerifySignature(
        BbsPublicKey publicKey,
        BbsSignature signature,
        SuiteWiring wiring,
        G1IsInPrimeOrderSubgroupDelegate? g1SubgroupOverride = null,
        G2IsInPrimeOrderSubgroupDelegate? g2SubgroupOverride = null,
        PairingDelegate? pairingOverride = null)
    {
        return publicKey.Verify(
            signature,
            new BbsHeader(Header),
            Messages,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.G1Add,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            g1SubgroupOverride ?? TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.G2Add,
            TestSetup.G2ScalarMultiply,
            TestSetup.G2IsOnCurve,
            g2SubgroupOverride ?? TestSetup.G2IsInPrimeOrderSubgroup,
            pairingOverride ?? TestSetup.Pairing,
            TestSetup.Pool);
    }


    private static bool VerifyProof(
        BbsPublicKey publicKey,
        BbsProof proof,
        SuiteWiring wiring,
        G1IsInPrimeOrderSubgroupDelegate? g1SubgroupOverride = null,
        G2IsInPrimeOrderSubgroupDelegate? g2SubgroupOverride = null,
        G1MultiScalarMultiplyDelegate? msmOverride = null,
        PairingDelegate? pairingOverride = null)
    {
        return publicKey.VerifyProof(
            proof,
            new BbsHeader(Header),
            new BbsPresentationHeader(PresentationHeader),
            DisclosedMessages,
            DisclosedIndices,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.G1Add,
            msmOverride ?? TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            g1SubgroupOverride ?? TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.G2Add,
            TestSetup.G2ScalarMultiply,
            TestSetup.G2IsOnCurve,
            g2SubgroupOverride ?? TestSetup.G2IsInPrimeOrderSubgroup,
            pairingOverride ?? TestSetup.Pairing,
            TestSetup.Pool);
    }


    private static BbsSignature SpliceSignaturePoint(BbsSignature signature, ReadOnlySpan<byte> pointBytes, BbsCiphersuite ciphersuite)
    {
        byte[] tampered = signature.AsReadOnlySpan().ToArray();
        pointBytes.CopyTo(tampered.AsSpan(BbsSignature.AOffset, BbsSignature.ASizeBytes));

        return BbsSignature.FromCanonical(tampered, ciphersuite, TestSetup.Pool);
    }


    private static BbsProof SpliceProofPoint(BbsProof proof, int offset, ReadOnlySpan<byte> pointBytes, BbsCiphersuite ciphersuite)
    {
        byte[] tampered = proof.AsReadOnlySpan().ToArray();
        pointBytes.CopyTo(tampered.AsSpan(offset, BbsProof.ABarSizeBytes));

        return BbsProof.FromCanonical(tampered, ciphersuite, TestSetup.Pool);
    }


    private static byte[][] NonCanonicalInfinityProbes(ReadOnlySpan<byte> canonicalIdentity)
    {
        //Two non-canonical variants of the identity encoding: the y-parity
        //flag additionally set, and a non-zero trailing byte. Both must be
        //rejected at decode rather than aliased onto the identity, otherwise
        //they would bypass a byte-compare identity check while decoding to
        //the identity point.
        byte[] extraFlag = canonicalIdentity.ToArray();
        extraFlag[0] |= 0x20;

        byte[] trailingGarbage = canonicalIdentity.ToArray();
        trailingGarbage[^1] = 0x01;

        return [extraFlag, trailingGarbage];
    }
}
