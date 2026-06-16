using Lumoin.Veridical.Bbs;
using System;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Semantic-correctness tests for BBS+ <c>VerifyProof</c> disclosure
/// handling. A proof generated for one (disclosed-messages,
/// disclosed-indices) pair must NOT verify when handed to the
/// verifier under a different pair.
/// </summary>
[TestClass]
internal sealed class BbsProofDisclosureTests
{
    [TestMethod]
    public void VerifyProofWithWrongDisclosedMessageReturnsFalse()
    {
        //Prover discloses message at index 1; verifier supplies a
        //different message claiming the same index. Verify must fail.
        using BbsKeyPair pair = BbsProofGenerateVerifyTests.MakeKeyPair();
        BbsMessage[] messages = BbsProofGenerateVerifyTests.BuildMessages(4);
        int[] disclosedIndices = [1];
        BbsMessage tampered = new(BbsProofGenerateVerifyTests.MakeBytes(16, 0xFF));

        using BbsProof proof = BbsProofGenerateVerifyTests.GenerateProof(pair, messages, disclosedIndices);

        bool verified = BbsProofGenerateVerifyTests.VerifyProof(
            pair.PublicKey,
            proof,
            new[] { tampered },
            disclosedIndices);

        Assert.IsFalse(verified, "VerifyProof must reject a tampered disclosed message.");
    }


    [TestMethod]
    public void VerifyProofWithWrongDisclosedIndicesReturnsFalse()
    {
        //Prover discloses messages [0, 2] of a 4-message vector;
        //verifier supplies the same messages but claims indices [0, 1].
        //Verify must fail because the challenge re-derivation will
        //hash a different (R, idx, msg, ...) tuple than the prover
        //hashed when committing.
        using BbsKeyPair pair = BbsProofGenerateVerifyTests.MakeKeyPair();
        BbsMessage[] messages = BbsProofGenerateVerifyTests.BuildMessages(4);
        int[] disclosedIndices = [0, 2];

        using BbsProof proof = BbsProofGenerateVerifyTests.GenerateProof(pair, messages, disclosedIndices);

        BbsMessage[] disclosedMessages = BbsProofGenerateVerifyTests.SelectDisclosed(messages, disclosedIndices);
        int[] wrongIndices = [0, 1];

        bool verified = BbsProofGenerateVerifyTests.VerifyProof(
            pair.PublicKey,
            proof,
            disclosedMessages,
            wrongIndices);

        Assert.IsFalse(verified, "VerifyProof must reject mismatched disclosed indices.");
    }


    [TestMethod]
    public void VerifyProofWithInconsistentDisclosureLengthReturnsFalse()
    {
        //Supplied disclosedMessages.Length != disclosedIndices.Length.
        //Verify must return false (not throw).
        using BbsKeyPair pair = BbsProofGenerateVerifyTests.MakeKeyPair();
        BbsMessage[] messages = BbsProofGenerateVerifyTests.BuildMessages(4);
        int[] disclosedIndices = [0, 2];

        using BbsProof proof = BbsProofGenerateVerifyTests.GenerateProof(pair, messages, disclosedIndices);

        BbsMessage[] disclosedMessages = BbsProofGenerateVerifyTests.SelectDisclosed(messages, disclosedIndices);

        bool verified = BbsProofGenerateVerifyTests.VerifyProof(
            pair.PublicKey,
            proof,
            new[] { disclosedMessages[0] }, //only 1 message
            disclosedIndices);              //but 2 indices claimed

        Assert.IsFalse(verified, "VerifyProof must reject inconsistent disclosure-length inputs.");
    }
}