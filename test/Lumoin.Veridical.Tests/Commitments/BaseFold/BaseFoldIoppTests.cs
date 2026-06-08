using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// Tests for the BaseFold IOPP (AB.3): the standalone interactive-oracle proof
/// of proximity that a Merkle-committed codeword is close to a codeword of the
/// random foldable code. Positive tests confirm an honestly-encoded codeword
/// verifies; negative tests confirm a word far from the code is rejected (the
/// base-codeword check), and that tampering the commitment, any fold root, or
/// any authentication path breaks verification. The real BLS12-381 scalar
/// arithmetic and the production BLAKE3 hash are wired throughout.
/// </summary>
[TestClass]
internal sealed class BaseFoldIoppTests
{
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate Invert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly ScalarHashToScalarDelegate HashToScalar = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;

    private const int ScalarSize = 32;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    //A modest query count keeps the property and tamper tests fast; correctness
    //of the protocol does not depend on the soundness-driven repetition count,
    //which the WellKnownBaseFoldIoppParameters derivation tests cover separately.
    private const int TestQueryCount = 16;

    private const int IterationCount = 20;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    public void HonestCodewordVerifies(int layerCount)
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(layerCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        int codewordElements = parameters.CodewordLength;
        using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
        Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
        EncodeSmallMessage(code, parameters, codeword, pool);

        bool verified = ProveThenVerify(code, codeword, TestQueryCount, pool);

        Assert.IsTrue(verified, $"An honestly-encoded codeword must verify for d = {layerCount}.");
    }


    [TestMethod]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    public void RandomWordFarFromCodeIsRejected(int layerCount)
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(layerCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        int codewordElements = parameters.CodewordLength;
        using IMemoryOwner<byte> wordOwner = pool.Rent(codewordElements * ScalarSize);
        Span<byte> word = wordOwner.Memory.Span[..(codewordElements * ScalarSize)];

        //A pseudo-random word: distinct canonical scalars that, with
        //overwhelming probability, do not fold to a valid base (repetition)
        //codeword, so the verifier's final base-codeword check rejects it.
        FillPseudoRandomScalars(word, codewordElements);

        bool verified = ProveThenVerify(code, word, TestQueryCount, pool);

        Assert.IsFalse(verified, $"A word far from the code must be rejected for d = {layerCount}.");
    }


    [TestMethod]
    public void TamperedCommitmentIsRejected()
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        const int LayerCount = 3;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(LayerCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        int codewordElements = parameters.CodewordLength;
        using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
        Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
        EncodeSmallMessage(code, parameters, codeword, pool);

        using FiatShamirTranscript proverTx = NewTranscript();
        using BaseFoldIoppProof proof = BaseFoldIoppProver.Prove(
            code, codeword, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

        //Build the true commitment, then flip a bit so it no longer matches.
        Span<byte> rootBytes = stackalloc byte[DigestSizeBytes];
        BuildCommitmentBytes(codeword, codewordElements, rootBytes);
        rootBytes[0] ^= 0x01;
        using MerkleRoot tamperedCommitment = MerkleRoot.FromBytes(rootBytes, pool);

        using FiatShamirTranscript verifierTx = NewTranscript();
        bool verified = BaseFoldIoppVerifier.Verify(
            code, tamperedCommitment, proof, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

        Assert.IsFalse(verified, "A tampered commitment must break verification.");
    }


    [TestMethod]
    public void TamperedFoldRootIsRejected()
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        const int LayerCount = 3;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(LayerCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        int codewordElements = parameters.CodewordLength;
        using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
        Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
        EncodeSmallMessage(code, parameters, codeword, pool);

        using FiatShamirTranscript proverTx = NewTranscript();
        using BaseFoldIoppProof proof = BaseFoldIoppProver.Prove(
            code, codeword, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

        //Flip a bit in the first fold root (root of π_{d-1}).
        proof.FoldRoots[0].AsSpan()[0] ^= 0x01;

        Span<byte> rootBytes = stackalloc byte[DigestSizeBytes];
        BuildCommitmentBytes(codeword, codewordElements, rootBytes);
        using MerkleRoot commitment = MerkleRoot.FromBytes(rootBytes, pool);

        using FiatShamirTranscript verifierTx = NewTranscript();
        bool verified = BaseFoldIoppVerifier.Verify(
            code, commitment, proof, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

        Assert.IsFalse(verified, "A tampered fold-layer root must break verification.");
    }


    [TestMethod]
    public void TamperedAuthenticationPathIsRejected()
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        const int LayerCount = 3;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(LayerCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        int codewordElements = parameters.CodewordLength;
        using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
        Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
        EncodeSmallMessage(code, parameters, codeword, pool);

        using FiatShamirTranscript proverTx = NewTranscript();
        using BaseFoldIoppProof proof = BaseFoldIoppProver.Prove(
            code, codeword, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

        //Flip a bit in the first query's top-layer first-path sibling.
        proof.Openings[0][0].FirstPath.AsSpan()[0] ^= 0x01;

        Span<byte> rootBytes = stackalloc byte[DigestSizeBytes];
        BuildCommitmentBytes(codeword, codewordElements, rootBytes);
        using MerkleRoot commitment = MerkleRoot.FromBytes(rootBytes, pool);

        using FiatShamirTranscript verifierTx = NewTranscript();
        bool verified = BaseFoldIoppVerifier.Verify(
            code, commitment, proof, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

        Assert.IsFalse(verified, "A tampered authentication path must break verification.");
    }


    [TestMethod]
    public void MismatchedQueryCountIsRejected()
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        const int LayerCount = 3;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(LayerCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        int codewordElements = parameters.CodewordLength;
        using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
        Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
        EncodeSmallMessage(code, parameters, codeword, pool);

        using FiatShamirTranscript proverTx = NewTranscript();
        using BaseFoldIoppProof proof = BaseFoldIoppProver.Prove(
            code, codeword, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

        Span<byte> rootBytes = stackalloc byte[DigestSizeBytes];
        BuildCommitmentBytes(codeword, codewordElements, rootBytes);
        using MerkleRoot commitment = MerkleRoot.FromBytes(rootBytes, pool);

        using FiatShamirTranscript verifierTx = NewTranscript();
        bool verified = BaseFoldIoppVerifier.Verify(
            code, commitment, proof, TestQueryCount + 1, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

        Assert.IsFalse(verified, "Verifying with a query count that differs from the proof's must be rejected.");
    }


    [TestMethod]
    public void RandomHonestCodewordsAlwaysVerify()
    {
        Gen.Int[1, 4]
            .SelectMany(layerCount =>
            {
                int messageElements = 1 << layerCount;
                return Gen.Select(Gen.Const(layerCount), Gen.Byte.Array[messageElements * ScalarSize]);
            })
            .Sample((layerCount, messageBytes) =>
            {
                SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
                FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(layerCount, Curve);
                using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

                int messageElements = parameters.MessageLength;
                using IMemoryOwner<byte> messageOwner = pool.Rent(messageElements * ScalarSize);
                Span<byte> message = messageOwner.Memory.Span[..(messageElements * ScalarSize)];
                for(int i = 0; i < messageElements; i++)
                {
                    Reduce(messageBytes.AsSpan(i * ScalarSize, ScalarSize), message.Slice(i * ScalarSize, ScalarSize), Curve);
                }

                int codewordElements = parameters.CodewordLength;
                using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
                Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
                code.Encode(message, codeword, Add, Subtract, Multiply, pool);

                return ProveThenVerify(code, codeword, TestQueryCount, pool);
            }, iter: IterationCount);
    }


    [TestMethod]
    public void QueryCountDerivationMatchesTheRegimeFormulas()
    {
        const double DeltaMin = WellKnownBaseFoldIoppParameters.ClassicalSecurityRelativeMinimumDistance;
        const int InverseRate = WellKnownFoldableCodeParameters.ClassicalSecurityInverseRate;
        const int Lambda = WellKnownBaseFoldIoppParameters.ClassicalSecurityLevelBits;

        //Capacity: δ = 1 - 1/8 = 0.875, ℓ = ⌈128/3⌉ = 43.
        Assert.AreEqual(
            43,
            WellKnownBaseFoldIoppParameters.ComputeQueryCount(Lambda, DeltaMin, InverseRate, BaseFoldSoundnessRegime.ConjecturedCapacity),
            "Conjectured-capacity 128-bit query count.");

        //Unique decoding: δ = 0.728/2 = 0.364, ℓ = ⌈128 / -log2(0.636)⌉ = 197.
        Assert.AreEqual(
            197,
            WellKnownBaseFoldIoppParameters.ComputeQueryCount(Lambda, DeltaMin, InverseRate, BaseFoldSoundnessRegime.UniqueDecoding),
            "Unique-decoding 128-bit query count.");

        //List decoding: δ = J(J(0.728)) ≈ 0.2778, ℓ = ⌈128 / -log2(0.7222)⌉ = 273.
        Assert.AreEqual(
            273,
            WellKnownBaseFoldIoppParameters.ComputeQueryCount(Lambda, DeltaMin, InverseRate, BaseFoldSoundnessRegime.ListDecodingJohnson),
            "List-decoding (double-Johnson) 128-bit query count.");

        //The default preset is the list-decoding count.
        Assert.AreEqual(
            273,
            WellKnownBaseFoldIoppParameters.ClassicalSecurityDefaultQueryCount,
            "The default query count is the paper-proven list-decoding count.");
    }


    [TestMethod]
    public void JohnsonRadiusMatchesItsDefinition()
    {
        //J(x) = 1 - sqrt(1 - x). J(0) = 0; J(1) = 1; J(0.75) = 0.5.
        Assert.AreEqual(0.0, WellKnownBaseFoldIoppParameters.JohnsonRadius(0.0), 1e-12);
        Assert.AreEqual(1.0, WellKnownBaseFoldIoppParameters.JohnsonRadius(1.0), 1e-12);
        Assert.AreEqual(0.5, WellKnownBaseFoldIoppParameters.JohnsonRadius(0.75), 1e-12);
    }


    //Runs the prover then the verifier on the same codeword with fresh,
    //identically-initialised transcripts, returning the verifier's verdict.
    private static bool ProveThenVerify(FoldableCode code, ReadOnlySpan<byte> codeword, int queryCount, SensitiveMemoryPool<byte> pool)
    {
        int codewordElements = code.Parameters.CodewordLength;

        using FiatShamirTranscript proverTx = NewTranscript();
        using BaseFoldIoppProof proof = BaseFoldIoppProver.Prove(
            code, codeword, queryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

        Span<byte> rootBytes = stackalloc byte[DigestSizeBytes];
        BuildCommitmentBytes(codeword, codewordElements, rootBytes);
        using MerkleRoot commitment = MerkleRoot.FromBytes(rootBytes, pool);

        using FiatShamirTranscript verifierTx = NewTranscript();
        return BaseFoldIoppVerifier.Verify(
            code, commitment, proof, queryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);
    }


    private static void BuildCommitmentBytes(ReadOnlySpan<byte> codeword, int codewordElements, Span<byte> rootBytes)
    {
        using MerkleTree tree = MerkleTree.Build(codeword, codewordElements, Merkle, SensitiveMemoryPool<byte>.Shared);
        tree.Root.AsReadOnlySpan().CopyTo(rootBytes);
    }


    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldIoppParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            SensitiveMemoryPool<byte>.Shared);
    }


    private static void EncodeSmallMessage(FoldableCode code, FoldableCodeParameters parameters, Span<byte> codeword, SensitiveMemoryPool<byte> pool)
    {
        int messageElements = parameters.MessageLength;
        using IMemoryOwner<byte> messageOwner = pool.Rent(messageElements * ScalarSize);
        Span<byte> message = messageOwner.Memory.Span[..(messageElements * ScalarSize)];
        for(int i = 0; i < messageElements; i++)
        {
            message.Slice(i * ScalarSize, ScalarSize).Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(message.Slice(i * ScalarSize, ScalarSize)[^4..], (2 * i) + 1);
        }

        code.Encode(message, codeword, Add, Subtract, Multiply, pool);
    }


    //Distinct, canonical, non-trivial scalars: a counter hashed through the
    //field-reduction backend so consecutive positions differ widely.
    private static void FillPseudoRandomScalars(Span<byte> word, int elements)
    {
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < elements; i++)
        {
            wide.Clear();
            //Spread a varying pattern across the full width so the reduced
            //scalar is large and the word lands far from any codeword.
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[..4], (7 * i) + 3);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (13 * i) + 5);
            Reduce(wide, word.Slice(i * ScalarSize, ScalarSize), Curve);
        }
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.BaseFold.AB3.Iopp.Test"u8;
}
