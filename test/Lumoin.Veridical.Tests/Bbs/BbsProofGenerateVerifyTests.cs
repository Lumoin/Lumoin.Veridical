using CsCheck;
using Lumoin.Veridical.Bbs;
using System;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Roundtrip property tests for BBS+ <c>GenerateProof</c> and
/// <c>VerifyProof</c>. Verify-after-Generate must always hold; two
/// generates with different randomness must produce distinct
/// byte-different proofs that both verify.
/// </summary>
[TestClass]
internal sealed class BbsProofGenerateVerifyTests
{
    private static readonly byte[] KeyMaterial = MakeBytes(64, 0x40);
    private static readonly byte[] KeyInfo = "proof-roundtrip-key-info"u8.ToArray();
    private static readonly byte[] Header = "proof-roundtrip-header"u8.ToArray();
    private static readonly byte[] PresentationHeader = "proof-roundtrip-ph"u8.ToArray();


    [TestMethod]
    public void ProofRoundtripFullDisclosure()
    {
        Gen.Int[2, 5]
            .Sample(messageCount =>
            {
                using BbsKeyPair pair = MakeKeyPair();
                BbsMessage[] messages = BuildMessages(messageCount);
                int[] disclosedIndices = BuildIndices(messageCount, includeAll: true);
                BbsMessage[] disclosed = SelectDisclosed(messages, disclosedIndices);

                using BbsProof proof = GenerateProof(pair, messages, disclosedIndices);
                return VerifyProof(pair.PublicKey, proof, disclosed, disclosedIndices);
            }, iter: 2);
    }


    [TestMethod]
    public void ProofRoundtripNoDisclosure()
    {
        Gen.Int[2, 5]
            .Sample(messageCount =>
            {
                using BbsKeyPair pair = MakeKeyPair();
                BbsMessage[] messages = BuildMessages(messageCount);
                int[] disclosedIndices = Array.Empty<int>();
                BbsMessage[] disclosed = Array.Empty<BbsMessage>();

                using BbsProof proof = GenerateProof(pair, messages, disclosedIndices);
                return VerifyProof(pair.PublicKey, proof, disclosed, disclosedIndices);
            }, iter: 2);
    }


    [TestMethod]
    public void ProofRoundtripPartialDisclosure()
    {
        //Disclose roughly half: indices 0, 2, 4 of a 5-message vector.
        using BbsKeyPair pair = MakeKeyPair();
        BbsMessage[] messages = BuildMessages(5);
        int[] disclosedIndices = [0, 2, 4];
        BbsMessage[] disclosed = SelectDisclosed(messages, disclosedIndices);

        using BbsProof proof = GenerateProof(pair, messages, disclosedIndices);
        Assert.IsTrue(
            VerifyProof(pair.PublicKey, proof, disclosed, disclosedIndices),
            "Partial-disclosure proof roundtrip must verify.");
    }


    [TestMethod]
    public void ProofGenerationProducesDistinctProofsWithDifferentRandomness()
    {
        //Two GenerateProof calls with identical inputs but different
        //random scalars must produce byte-different proofs that both
        //verify. This is the unlinkability foundation: a verifier
        //holding two proofs cannot tell whether they came from the
        //same signature.
        using BbsKeyPair pair = MakeKeyPair();
        BbsMessage[] messages = BuildMessages(3);
        int[] disclosedIndices = [1];
        BbsMessage[] disclosed = SelectDisclosed(messages, disclosedIndices);

        using BbsProof first = GenerateProof(pair, messages, disclosedIndices);
        using BbsProof second = GenerateProof(pair, messages, disclosedIndices);

        Assert.IsFalse(
            first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()),
            "Two GenerateProof calls under the OS random scalar source must produce byte-different proofs.");

        Assert.IsTrue(
            VerifyProof(pair.PublicKey, first, disclosed, disclosedIndices),
            "First proof must verify.");
        Assert.IsTrue(
            VerifyProof(pair.PublicKey, second, disclosed, disclosedIndices),
            "Second proof must verify.");
    }


    internal static BbsKeyPair MakeKeyPair()
    {
        return BbsCiphersuite.Bls12Curve381Sha256.Generate(
            KeyMaterial,
            KeyInfo,
            TestSetup.Sha256.HashToScalar,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pool);
    }


    internal static BbsSignature SignMessages(BbsKeyPair pair, BbsMessage[] messages)
    {
        return pair.SecretKey.Sign(
            pair.PublicKey,
            new BbsHeader(Header),
            messages,
            TestSetup.Sha256.ExpandMessage,
            TestSetup.Sha256.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarInvert,
            TestSetup.G1Add,
            TestSetup.G1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            TestSetup.Sha256.G1HashToCurve,
            TestSetup.Pool);
    }


    internal static BbsProof GenerateProof(BbsKeyPair pair, BbsMessage[] messages, int[] disclosedIndices)
    {
        using BbsSignature signature = SignMessages(pair, messages);
        return signature.GenerateProof(
            pair.PublicKey,
            new BbsHeader(Header),
            new BbsPresentationHeader(PresentationHeader),
            messages,
            disclosedIndices,
            TestSetup.Sha256.ExpandMessage,
            TestSetup.Sha256.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarSubtract,
            TestSetup.ScalarMultiply,
            TestSetup.ScalarNegate,
            TestSetup.ScalarInvert,
            TestSetup.ScalarRandom,
            TestSetup.G1Add,
            TestSetup.G1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            TestSetup.Sha256.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.Pool);
    }


    internal static bool VerifyProof(BbsPublicKey publicKey, BbsProof proof, BbsMessage[] disclosedMessages, int[] disclosedIndices)
    {
        return publicKey.VerifyProof(
            proof,
            new BbsHeader(Header),
            new BbsPresentationHeader(PresentationHeader),
            disclosedMessages,
            disclosedIndices,
            TestSetup.Sha256.ExpandMessage,
            TestSetup.Sha256.HashToScalar,
            TestSetup.G1Add,
            TestSetup.G1MultiScalarMultiply,
            TestSetup.Sha256.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.G2Add,
            TestSetup.G2ScalarMultiply,
            TestSetup.G2IsOnCurve,
            TestSetup.G2IsInPrimeOrderSubgroup,
            TestSetup.Pairing,
            TestSetup.Pool);
    }


    internal static BbsMessage[] BuildMessages(int count)
    {
        BbsMessage[] messages = new BbsMessage[count];
        for(int i = 0; i < count; i++)
        {
            messages[i] = new BbsMessage(MakeBytes(16 + i, (byte)(0x50 + i)));
        }

        return messages;
    }


    internal static int[] BuildIndices(int count, bool includeAll)
    {
        if(!includeAll)
        {
            return Array.Empty<int>();
        }
        int[] result = new int[count];
        for(int i = 0; i < count; i++)
        {
            result[i] = i;
        }

        return result;
    }


    internal static BbsMessage[] SelectDisclosed(BbsMessage[] messages, int[] disclosedIndices)
    {
        BbsMessage[] result = new BbsMessage[disclosedIndices.Length];
        for(int i = 0; i < disclosedIndices.Length; i++)
        {
            result[i] = messages[disclosedIndices[i]];
        }

        return result;
    }


    internal static byte[] MakeBytes(int length, byte start)
    {
        byte[] result = new byte[length];
        for(int i = 0; i < length; i++)
        {
            result[i] = (byte)(start + i);
        }

        return result;
    }
}