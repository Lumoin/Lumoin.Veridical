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
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// AB.6 soundness validation for the BaseFold IOPP: the checks the honest
/// round-trip and Merkle-tamper tests do not directly target.
/// <list type="bullet">
///   <item><description>A <em>malicious prover</em> that Merkle-commits an intermediate fold oracle which is NOT the honest fold. Its openings authenticate (valid Merkle paths against the committed root) and its transcript is self-consistent, so the only check that can catch it is the per-layer fold-consistency relation — this confirms that relation rejects, distinct from the Merkle-binding tampers AB.3 exercises.</description></item>
///   <item><description>An informational rejection sweep: random words far from the code are rejected (the IOPP's base-code and fold-consistency checks).</description></item>
/// </list>
/// </summary>
[TestClass]
internal sealed class BaseFoldIoppSoundnessTests
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
    private const int TestQueryCount = 16;
    private const int SweepIterations = 20;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void MaliciousProverWithInconsistentOracleIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int LayerCount = 3;
        //Tamper the layer-1 oracle: the fold-consistency check at level 2
        //(fold of the π_2 pair must equal the committed π_1 entry) then fails for
        //every queried position, since the committed π_1 is the honest fold plus
        //one in every coordinate.
        const int TamperLayer = 1;

        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(LayerCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        int codewordElements = parameters.CodewordLength;
        using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
        Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
        EncodeSmallMessage(code, parameters, codeword, pool);

        using MerkleRoot commitment = BuildCommitment(codeword, codewordElements, pool);

        //Sanity: an honest proof over the same codeword verifies, so a rejection
        //below is attributable to the injected inconsistency, not the harness.
        using(FiatShamirTranscript honestProverTx = NewTranscript())
        using(BaseFoldIoppProof honestProof = BaseFoldIoppProver.Prove(
            code, codeword, TestQueryCount, honestProverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool))
        using(FiatShamirTranscript honestVerifierTx = NewTranscript())
        {
            Assert.IsTrue(
                BaseFoldIoppVerifier.Verify(code, commitment, honestProof, TestQueryCount, honestVerifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool),
                "The honest control proof must verify.");
        }

        //The malicious proof: same transcript discipline, but the layer-1 oracle
        //is replaced with a non-fold before it is committed.
        using FiatShamirTranscript maliciousProverTx = NewTranscript();
        using BaseFoldIoppProof maliciousProof = ProveWithTamperedLayer(
            code, codeword, TestQueryCount, TamperLayer, maliciousProverTx, pool);

        using FiatShamirTranscript verifierTx = NewTranscript();
        bool verified = BaseFoldIoppVerifier.Verify(
            code, commitment, maliciousProof, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

        Assert.IsFalse(verified, "A proof whose committed intermediate oracle is not the honest fold must be rejected by the fold-consistency check.");
    }


    [TestMethod]
    public void RandomWordsFarFromCodeAreAlwaysRejected()
    {
        //Informational soundness sweep: words built from independent random
        //scalars are, with overwhelming probability, far from the code, so the
        //IOPP rejects every one. (A single case is covered by AB.3; this confirms
        //the behaviour across a sample.)
        Gen.Int[2, 4]
            .SelectMany(layerCount =>
            {
                int codewordElements = WellKnownFoldableCodeParameters.ClassicalSecurityInverseRate << layerCount;
                return Gen.Select(Gen.Const(layerCount), Gen.Byte.Array[codewordElements * ScalarSize]);
            })
            .Sample((layerCount, rawBytes) =>
            {
                BaseMemoryPool pool = BaseMemoryPool.Shared;
                FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(layerCount, Curve);
                using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

                int codewordElements = parameters.CodewordLength;
                using IMemoryOwner<byte> wordOwner = pool.Rent(codewordElements * ScalarSize);
                Span<byte> word = wordOwner.Memory.Span[..(codewordElements * ScalarSize)];
                for(int i = 0; i < codewordElements; i++)
                {
                    Reduce(rawBytes.AsSpan(i * ScalarSize, ScalarSize), word.Slice(i * ScalarSize, ScalarSize), Curve);
                }

                using MerkleRoot commitment = BuildCommitment(word, codewordElements, pool);
                using FiatShamirTranscript proverTx = NewTranscript();
                using BaseFoldIoppProof proof = BaseFoldIoppProver.Prove(
                    code, word, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

                using FiatShamirTranscript verifierTx = NewTranscript();
                //A random word is far from the code: rejection is the expected,
                //overwhelmingly-likely outcome.
                return !BaseFoldIoppVerifier.Verify(
                    code, commitment, proof, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);
            }, iter: SweepIterations);
    }


    //A dishonest IOPP prover: honest in every respect except that, after folding
    //into layer tamperLayer, it replaces that oracle with (honest fold + 1) in
    //every coordinate before committing it, then continues folding the tampered
    //oracle downward. The transcript stays self-consistent (the verifier replays
    //the tampered roots) and every Merkle opening authenticates, so only the
    //fold-consistency relation can catch the substitution.
    [SuppressMessage("Reliability", "CA2000", Justification = "Working codewords and trees are disposed in the finally block; the buffers the proof keeps are copied into the returned proof, which owns them.")]
    private static BaseFoldIoppProof ProveWithTamperedLayer(
        FoldableCode code,
        ReadOnlySpan<byte> inputCodeword,
        int queryCount,
        int tamperLayer,
        FiatShamirTranscript transcript,
        BaseMemoryPool pool)
    {
        FoldableCodeParameters parameters = code.Parameters;
        int d = parameters.LayerCount;
        int baseUnit = parameters.InverseRate * parameters.BaseDimension;

        var codewords = new IMemoryOwner<byte>?[d + 1];
        var trees = new MerkleTree?[d + 1];
        var disposables = new List<IDisposable>();

        Span<byte> fieldOne = stackalloc byte[ScalarSize];
        fieldOne.Clear();
        fieldOne[^1] = 0x01;

        try
        {
            int topLength = LayerLength(baseUnit, d);
            codewords[d] = RentCopy(inputCodeword, pool, disposables);
            trees[d] = BuildTree(codewords[d]!, topLength, pool, disposables);

            for(int level = d; level >= 1; level--)
            {
                transcript.AbsorbBaseFoldFoldRoot(trees[level]!.Root, Hash);
                using Scalar challenge = transcript.SqueezeBaseFoldFoldChallenge(Squeeze, Hash, Reduce, Curve, pool);

                int lowerLength = LayerLength(baseUnit, level - 1);
                codewords[level - 1] = pool.Rent(lowerLength * ScalarSize);
                disposables.Add(codewords[level - 1]!);
                Span<byte> lower = codewords[level - 1]!.Memory.Span[..(lowerLength * ScalarSize)];

                code.Fold(
                    codewords[level]!.Memory.Span[..(LayerLength(baseUnit, level) * ScalarSize)],
                    level, challenge.AsReadOnlySpan(), lower, Add, Subtract, Multiply, Invert);

                //Inject the inconsistency: bump every coordinate of the layer's
                //oracle so it is no longer the honest fold of the layer above.
                if(level - 1 == tamperLayer)
                {
                    for(int i = 0; i < lowerLength; i++)
                    {
                        Span<byte> entry = lower.Slice(i * ScalarSize, ScalarSize);
                        Add(entry, fieldOne, entry, Curve);
                    }
                }

                if(level - 1 >= 1)
                {
                    trees[level - 1] = BuildTree(codewords[level - 1]!, lowerLength, pool, disposables);
                }
            }

            int finalLength = LayerLength(baseUnit, 0) * ScalarSize;
            ReadOnlySpan<byte> finalOracleSpan = codewords[0]!.Memory.Span[..finalLength];
            transcript.AbsorbBaseFoldFinalOracle(finalOracleSpan, Hash);

            int queryDomainSize = LayerLength(baseUnit, d - 1);
            var openings = new BaseFoldQueryStep[queryCount][];
            for(int q = 0; q < queryCount; q++)
            {
                int j0 = transcript.SqueezeBaseFoldQueryIndex(queryDomainSize, Squeeze, Hash);
                openings[q] = BaseFoldQueryPhase.BuildOpening(trees, codewords, baseUnit, d, j0, pool);
            }

            MerkleRoot[] foldRoots = CopyFoldRoots(trees, d, pool);
            IMemoryOwner<byte> finalOracle = RentCopy(finalOracleSpan, pool, null);

            return new BaseFoldIoppProof(parameters, queryCount, foldRoots, finalOracle, finalLength, openings);
        }
        finally
        {
            for(int i = disposables.Count - 1; i >= 0; i--)
            {
                disposables[i].Dispose();
            }
        }
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Each copied root transfers ownership to the returned array, which the proof owns and disposes.")]
    private static MerkleRoot[] CopyFoldRoots(MerkleTree?[] trees, int d, BaseMemoryPool pool)
    {
        var foldRoots = new MerkleRoot[d - 1];
        for(int i = 0; i < d - 1; i++)
        {
            int level = d - 1 - i;
            foldRoots[i] = MerkleRoot.FromBytes(trees[level]!.Root.AsReadOnlySpan(), pool);
        }

        return foldRoots;
    }


    private static int LayerLength(int baseUnit, int level) => baseUnit << level;


    private static IMemoryOwner<byte> RentCopy(ReadOnlySpan<byte> source, BaseMemoryPool pool, List<IDisposable>? track)
    {
        IMemoryOwner<byte> owner = pool.Rent(source.Length);
        source.CopyTo(owner.Memory.Span[..source.Length]);
        track?.Add(owner);

        return owner;
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The tree is tracked in the disposables list and released in the finally block.")]
    private static MerkleTree BuildTree(IMemoryOwner<byte> codeword, int leafCount, BaseMemoryPool pool, List<IDisposable> disposables)
    {
        MerkleTree tree = MerkleTree.Build(codeword.Memory.Span[..(leafCount * ScalarSize)], leafCount, Merkle, pool);
        disposables.Add(tree);

        return tree;
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the returned root transfers to the caller's using declaration.")]
    private static MerkleRoot BuildCommitment(ReadOnlySpan<byte> codeword, int codewordElements, BaseMemoryPool pool)
    {
        using MerkleTree tree = MerkleTree.Build(codeword, codewordElements, Merkle, pool);
        return MerkleRoot.FromBytes(tree.Root.AsReadOnlySpan(), pool);
    }


    private static void EncodeSmallMessage(FoldableCode code, FoldableCodeParameters parameters, Span<byte> codeword, BaseMemoryPool pool)
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


    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldIoppParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.BaseFold.AB6.Soundness"u8;
}
