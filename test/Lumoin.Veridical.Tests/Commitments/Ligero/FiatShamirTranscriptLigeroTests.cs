using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;

namespace Lumoin.Veridical.Tests.Commitments.Ligero;

/// <summary>
/// Gates the Ligero Fiat-Shamir transcript helpers (LF.4b.3): the
/// challenge-scalar vector squeeze and the distinct opened-column-index
/// sampler. The properties checked are the ones soundness and prover/verifier
/// agreement rest on: a prover and a verifier replaying the identical absorb
/// schedule obtain identical challenges and indices; the indices are distinct
/// and in range over both power-of-two and non-power-of-two extension widths
/// (the sampler must not assume a maskable domain); sampling the whole domain
/// yields a permutation; the challenges bind to the absorbed root; and distinct
/// operation labels separate otherwise-identical squeezes.
/// </summary>
[TestClass]
internal sealed class FiatShamirTranscriptLigeroTests
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int RootSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    private static readonly FiatShamirHashDelegate Hash = Blake3FiatShamirBackend.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = Blake3FiatShamirBackend.GetSqueeze();
    private static readonly ScalarReduceDelegate Reduce = SmallPrimeFieldScalars.GetReduce();

    //A fixed public-input seed; the transcript binds every challenge to it.
    private static readonly byte[] Seed = [0x4C, 0x46, 0x34, 0x62, 0x33]; //"LF4b3"


    [TestMethod]
    public void ProverAndVerifierAgreeOnChallengesAndIndices()
    {
        const int ChallengeCount = 5;
        const int ExtensionWidth = 16;
        const int OpenedColumns = 4;

        Span<byte> proverChallenges = stackalloc byte[ChallengeCount * ScalarSize];
        Span<int> proverIndices = stackalloc int[OpenedColumns];
        Span<byte> verifierChallenges = stackalloc byte[ChallengeCount * ScalarSize];
        Span<int> verifierIndices = stackalloc int[OpenedColumns];

        RunSchedule(0x11, ChallengeCount, ExtensionWidth, OpenedColumns, proverChallenges, proverIndices);
        RunSchedule(0x11, ChallengeCount, ExtensionWidth, OpenedColumns, verifierChallenges, verifierIndices);

        Assert.IsTrue(proverChallenges.SequenceEqual(verifierChallenges), "Identical absorb schedules must yield identical challenge scalars.");
        Assert.IsTrue(proverIndices.SequenceEqual(verifierIndices), "Identical absorb schedules must yield identical opened-column indices.");
    }


    [TestMethod]
    [DataRow(16, 4, "power-of-two extension width")]
    [DataRow(12, 5, "non-power-of-two extension width")]
    public void OpenedColumnIndicesAreDistinctAndInRange(int extensionWidth, int openedColumns, string scenario)
    {
        Span<int> indices = stackalloc int[openedColumns];
        SampleIndices(0x22, extensionWidth, openedColumns, indices);

        for(int i = 0; i < indices.Length; i++)
        {
            Assert.IsGreaterThanOrEqualTo(0, indices[i], $"Index must be non-negative ({scenario}).");
            Assert.IsLessThan(extensionWidth, indices[i], $"Index must be below the extension width ({scenario}).");
            for(int j = i + 1; j < indices.Length; j++)
            {
                Assert.AreNotEqual(indices[i], indices[j], $"Opened-column indices must be distinct ({scenario}).");
            }
        }
    }


    [TestMethod]
    public void SamplingTheWholeDomainYieldsAPermutation()
    {
        //count == width forces the dedup loop to fill out every position, so the
        //draws must be exactly a permutation of [0, width).
        const int Width = 8;
        Span<int> indices = stackalloc int[Width];
        SampleIndices(0x33, Width, Width, indices);

        Span<bool> present = stackalloc bool[Width];
        foreach(int index in indices)
        {
            Assert.IsFalse(present[index], "Each position must appear exactly once.");
            present[index] = true;
        }

        foreach(bool seen in present)
        {
            Assert.IsTrue(seen, "Sampling the whole domain must cover every position.");
        }
    }


    [TestMethod]
    public void ChallengesAndIndicesBindToTheAbsorbedRoot()
    {
        const int ChallengeCount = 4;
        const int ExtensionWidth = 16;
        const int OpenedColumns = 4;

        Span<byte> challengesA = stackalloc byte[ChallengeCount * ScalarSize];
        Span<int> indicesA = stackalloc int[OpenedColumns];
        Span<byte> challengesB = stackalloc byte[ChallengeCount * ScalarSize];
        Span<int> indicesB = stackalloc int[OpenedColumns];

        RunSchedule(0x44, ChallengeCount, ExtensionWidth, OpenedColumns, challengesA, indicesA);
        RunSchedule(0x45, ChallengeCount, ExtensionWidth, OpenedColumns, challengesB, indicesB);

        Assert.IsFalse(challengesA.SequenceEqual(challengesB), "A different absorbed root must change the challenges.");
        Assert.IsFalse(indicesA.SequenceEqual(indicesB), "A different absorbed root must change the opened-column indices.");
    }


    [TestMethod]
    public void DistinctLabelsSeparateOtherwiseIdenticalSqueezes()
    {
        const int Count = 4;

        Span<byte> low = stackalloc byte[Count * ScalarSize];
        Span<byte> linear = stackalloc byte[Count * ScalarSize];

        using(FiatShamirTranscript transcript = NewTranscript())
        {
            transcript.SqueezeLigeroChallengeScalars(
                new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.LowDegreeChallenge), Count, low, Squeeze, Hash, Reduce, CurveParameterSet.None, BaseMemoryPool.Shared);
        }

        using(FiatShamirTranscript transcript = NewTranscript())
        {
            transcript.SqueezeLigeroChallengeScalars(
                new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.LinearChallenge), Count, linear, Squeeze, Hash, Reduce, CurveParameterSet.None, BaseMemoryPool.Shared);
        }

        Assert.IsFalse(low.SequenceEqual(linear), "The same squeeze under different operation labels must differ.");
    }


    //Runs the standalone challenge schedule against a fresh transcript: absorb
    //the root, squeeze the challenge scalars, then the opened-column indices.
    private static void RunSchedule(
        byte rootKey,
        int challengeCount,
        int extensionWidth,
        int openedColumns,
        Span<byte> challenges,
        Span<int> indices)
    {
        Span<byte> rootBytes = stackalloc byte[RootSizeBytes];
        FillRoot(rootKey, rootBytes);
        using MerkleRoot root = MerkleRoot.FromBytes(rootBytes, BaseMemoryPool.Shared);
        using FiatShamirTranscript transcript = NewTranscript();

        transcript.AbsorbLigeroTableauRoot(root, Hash);
        transcript.SqueezeLigeroChallengeScalars(
            new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.LowDegreeChallenge), challengeCount, challenges, Squeeze, Hash, Reduce, CurveParameterSet.None, BaseMemoryPool.Shared);
        transcript.SqueezeLigeroDistinctColumnIndices(extensionWidth, openedColumns, indices, Squeeze, Hash);
    }


    private static void SampleIndices(byte rootKey, int extensionWidth, int openedColumns, Span<int> indices)
    {
        Span<byte> rootBytes = stackalloc byte[RootSizeBytes];
        FillRoot(rootKey, rootBytes);
        using MerkleRoot root = MerkleRoot.FromBytes(rootBytes, BaseMemoryPool.Shared);
        using FiatShamirTranscript transcript = NewTranscript();

        transcript.AbsorbLigeroTableauRoot(root, Hash);
        transcript.SqueezeLigeroDistinctColumnIndices(extensionWidth, openedColumns, indices, Squeeze, Hash);
    }


    private static FiatShamirTranscript NewTranscript() =>
        FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownLigeroDomainLabels.LigeroV1),
            Seed,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);


    //Fills a distinct 32-byte root pattern keyed by a single byte.
    private static void FillRoot(byte key, Span<byte> root)
    {
        for(int i = 0; i < root.Length; i++)
        {
            root[i] = (byte)(key + i);
        }
    }
}
