using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Tamper-rejection tests for BBS+ <c>VerifyProof</c>. Single-bit
/// flips in any structural slot of the proof bytes must cause
/// Verify to return false rather than accept the modified proof.
/// </summary>
[TestClass]
internal sealed class BbsProofFailureTests
{
    [TestMethod]
    public void TamperedABarBitFlipRejected()
    {
        TamperBitAndExpectRejection(byteIndex: BbsProof.ABarOffset + 5, bitMask: 0x01);
    }


    [TestMethod]
    public void TamperedBBarBitFlipRejected()
    {
        TamperBitAndExpectRejection(byteIndex: BbsProof.BBarOffset + 5, bitMask: 0x01);
    }


    [TestMethod]
    [DataRow(BbsProof.EHatOffset)]
    [DataRow(BbsProof.R1HatOffset)]
    [DataRow(BbsProof.R3HatOffset)]
    public void TamperedScalarBitFlipRejected(int scalarByteOffset)
    {
        //Flip a low bit in the middle of each fixed scalar slot.
        TamperBitAndExpectRejection(byteIndex: scalarByteOffset + 10, bitMask: 0x01);
    }


    [TestMethod]
    public void TamperedChallengeBitFlipRejected()
    {
        //Generate the proof first to learn its length, then compute
        //the challenge offset, then re-generate and tamper at that
        //offset.
        using BbsKeyPair pair = BbsProofGenerateVerifyTests.MakeKeyPair();
        BbsMessage[] messages = BbsProofGenerateVerifyTests.BuildMessages(3);
        int[] disclosedIndices = [0];

        using BbsProof originalProof = BbsProofGenerateVerifyTests.GenerateProof(pair, messages, disclosedIndices);
        int challengeOffset = BbsProof.CommitmentsOffset
            + Scalar.SizeBytes * originalProof.UndisclosedMessageCount;

        TamperBitAndExpectRejection(byteIndex: challengeOffset + 10, bitMask: 0x01);
    }


    [TestMethod]
    public void MalformedCanonicalBytesReturnsFalse()
    {
        //Corrupt the high byte of the Abar slot so the G1 compression
        //flag is invalid. VerifyProof must return false rather than
        //throw on the FromCanonical decode failure.
        using BbsKeyPair pair = BbsProofGenerateVerifyTests.MakeKeyPair();
        BbsMessage[] messages = BbsProofGenerateVerifyTests.BuildMessages(3);
        int[] disclosedIndices = [0];
        BbsMessage[] disclosedMessages = BbsProofGenerateVerifyTests.SelectDisclosed(messages, disclosedIndices);

        using BbsProof proof = BbsProofGenerateVerifyTests.GenerateProof(pair, messages, disclosedIndices);

        byte[] tamperedBytes = proof.AsReadOnlySpan().ToArray();
        //Clear the compression flag (top bit). The decoder rejects
        //G1 encodings without the compression bit set.
        tamperedBytes[BbsProof.ABarOffset] &= 0x7F;

        using BbsProof tamperedProof = BbsProof.FromCanonical(tamperedBytes, BbsCiphersuite.Bls12Curve381Sha256, TestSetup.Pool);

        bool verified = BbsProofGenerateVerifyTests.VerifyProof(
            pair.PublicKey,
            tamperedProof,
            disclosedMessages,
            disclosedIndices);

        Assert.IsFalse(verified, "VerifyProof must return false on a malformed proof rather than throw.");
    }


    private static void TamperBitAndExpectRejection(int byteIndex, byte bitMask)
    {
        using BbsKeyPair pair = BbsProofGenerateVerifyTests.MakeKeyPair();
        BbsMessage[] messages = BbsProofGenerateVerifyTests.BuildMessages(3);
        int[] disclosedIndices = [0];
        BbsMessage[] disclosedMessages = BbsProofGenerateVerifyTests.SelectDisclosed(messages, disclosedIndices);

        using BbsProof proof = BbsProofGenerateVerifyTests.GenerateProof(pair, messages, disclosedIndices);

        byte[] tamperedBytes = proof.AsReadOnlySpan().ToArray();
        tamperedBytes[byteIndex] ^= bitMask;

        using BbsProof tamperedProof = BbsProof.FromCanonical(tamperedBytes, BbsCiphersuite.Bls12Curve381Sha256, TestSetup.Pool);

        bool verified = BbsProofGenerateVerifyTests.VerifyProof(
            pair.PublicKey,
            tamperedProof,
            disclosedMessages,
            disclosedIndices);

        Assert.IsFalse(verified, $"VerifyProof must reject a proof with a flipped bit at byte {byteIndex} (mask 0x{bitMask:X2}).");
    }
}