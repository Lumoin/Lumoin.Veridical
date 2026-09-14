using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Tests.Commitments.Ligero;

/// <summary>
/// Gates the Ligero Fiat-Shamir transcript helpers: the
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

    /// <summary>The number of challenge scalars requested when the challenge destination is deliberately mis-sized.</summary>
    private const int MisSizedChallengeCount = 1;

    /// <summary>
    /// A challenge destination one scalar longer than <see cref="MisSizedChallengeCount"/> scalars occupy, so the
    /// length guard rejects it while every scalar the squeeze loop writes stays inside it.
    /// </summary>
    private const int OversizedChallengeDestinationBytes = (MisSizedChallengeCount + 1) * ScalarSize;

    /// <summary>The extension width sampled from when the index destination is deliberately mis-sized; it is wider than the requested count, so the count guard accepts it.</summary>
    private const int MisSizedIndexExtensionWidth = 4;

    /// <summary>The number of distinct indices requested when the index destination is deliberately mis-sized.</summary>
    private const int MisSizedIndexCount = 1;

    /// <summary>
    /// An index destination one slot longer than <see cref="MisSizedIndexCount"/>, so the length guard rejects it
    /// while every index write the sampler makes stays inside it.
    /// </summary>
    private const int OversizedIndexDestinationLength = MisSizedIndexCount + 1;

    /// <summary>The parameter name both destination-length guards report.</summary>
    private const string DestinationParameterName = "destination";

    /// <summary>
    /// An extension width that is not a power of two. Since 4 is congruent to 1 modulo 3, 2^64 = 4^32 leaves
    /// remainder one, so the acceptance limit is 2^64 - 1 and the all-ones 64-bit draw lies in the rejected
    /// biased tail.
    /// </summary>
    private const int BiasedTailExtensionWidth = 3;

    /// <summary>The number of indices requested from the saturated squeeze; one suffices because no draw is ever accepted.</summary>
    private const int SaturatedSqueezeIndexCount = 1;

    /// <summary>The leading words of the sampler's attempt-cap message; no argument guard produces this text.</summary>
    private const string AttemptCapMessageFragment = "Could not draw a fresh opened-column index";

    /// <summary>The parameter name the transcript null checks of both squeezes report.</summary>
    private const string TranscriptParameterName = "transcript";

    /// <summary>The parameter name the tableau-root null check reports.</summary>
    private const string RootParameterName = "root";

    /// <summary>The parameter name the reduce-backend null check of the challenge-scalar squeeze reports.</summary>
    private const string ReduceParameterName = "reduce";

    /// <summary>The parameter name the pool null check of the challenge-scalar squeeze reports.</summary>
    private const string PoolParameterName = "pool";

    /// <summary>The parameter name the count range checks of both squeezes report.</summary>
    private const string CountParameterName = "count";

    /// <summary>The parameter name the extension-width check of the index sampler reports.</summary>
    private const string ExtensionWidthParameterName = "extensionWidth";

    /// <summary>
    /// The number of scalars or indices requested alongside an empty destination. The destination-length checks
    /// accept it and neither squeeze loop runs, so no backend delegate is invoked and only an argument guard can
    /// refuse the call.
    /// </summary>
    private const int EmptyRequestCount = 0;

    /// <summary>A negative request count, which no destination length can match.</summary>
    private const int NegativeRequestCount = -1;

    /// <summary>The narrowest extension width the width guard accepts.</summary>
    private const int SingleColumnExtensionWidth = 1;

    /// <summary>An extension width the width guard refuses; with <see cref="EmptyRequestCount"/> the count checks still accept it.</summary>
    private const int ZeroExtensionWidth = 0;

    /// <summary>A count one above <see cref="SingleColumnExtensionWidth"/>, more distinct indices than that width holds.</summary>
    private const int ExcessIndexCount = SingleColumnExtensionWidth + 1;

    /// <summary>The number of indices requested from the counter-scheduled squeezes.</summary>
    private const int ScheduledSqueezeIndexCount = 1;

    /// <summary>The destination slot the sampler writes its first drawn index into.</summary>
    private const int FirstIndexSlot = 0;

    /// <summary>The sampler's per-index attempt cap: the number of squeezes it spends on one index before it throws.</summary>
    private const long AttemptCapPerIndex = 1024;

    /// <summary>The number of squeezes one accepted first draw takes, and the squeeze counter below which <see cref="InRangeOnlyOnFirstDrawSqueeze"/> yields an in-range draw.</summary>
    private const long FirstDrawSqueezeCount = 1;

    /// <summary>
    /// The byte the counter-scheduled squeezes fill an accepted draw with. The eight-byte draw 0x0101010101010101 lies
    /// far below the acceptance limit of every width.
    /// </summary>
    private const byte InRangeDrawByte = 0x01;

    /// <summary>
    /// The index the in-range draw maps to over <see cref="BiasedTailExtensionWidth"/> columns: the draw is the sum of
    /// 256^k for k in [0, 8), and 256 is congruent to 1 modulo 3, so it reduces to 8 modulo 3, which is two.
    /// </summary>
    private const int InRangeDrawIndex = 2;

    /// <summary>The width of the big-endian squeeze counter the transcript writes as the last field of every XOF input.</summary>
    private const int SqueezeCounterBytes = sizeof(long);

    private static FiatShamirHashDelegate Hash { get; } = Blake3FiatShamirBackend.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = Blake3FiatShamirBackend.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = SmallPrimeFieldScalars.GetReduce();

    //A fixed public-input seed; the transcript binds every challenge to it.
    private static byte[] Seed { get; } = "Lumoin.Veridical.Ligero.Transcript.Test"u8.ToArray();


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


    /// <summary>
    /// Pins that the Ligero challenge-scalar squeeze rejects a destination whose length is not the requested count
    /// times the scalar width with an <see cref="ArgumentException"/> that names <c>destination</c> and states both
    /// the required and the received byte length. The destination is one scalar too long rather than too short, so
    /// the length guard is the only check that can refuse it: every scalar the squeeze loop writes lands inside it.
    /// The transcript, the reduce backend and the pool are non-null and the count is not negative, so no sibling
    /// guard answers first, and the exact exception type excludes the <see cref="ArgumentNullException"/> and
    /// <see cref="ArgumentOutOfRangeException"/> those guards raise.
    /// </summary>
    [TestMethod]
    public void ChallengeScalarSqueezeRejectsAnOversizedDestination()
    {
        string expectedMessage = $"Destination must be {MisSizedChallengeCount * ScalarSize} bytes; received {OversizedChallengeDestinationBytes}.";

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => SqueezeChallengeScalarsIntoOversizedDestination(),
            "A challenge destination longer than the requested scalars must be rejected.");

        Assert.AreEqual(DestinationParameterName, exception.ParamName, "The rejection must name the destination parameter.");
        Assert.Contains(expectedMessage, exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Pins that the distinct opened-column-index sampler rejects a destination whose length differs from the
    /// requested count with an <see cref="ArgumentException"/> that names <c>destination</c> and states both the
    /// requested count and the received length. The destination is one slot too long rather than too short, so the
    /// length guard is the only check that can refuse it: every index the sampler writes lands inside it. The
    /// transcript is non-null, the width is positive and the count lies in <c>[0, extensionWidth]</c>, so no sibling
    /// guard answers first, and the exact exception type excludes the <see cref="ArgumentNullException"/> and
    /// <see cref="ArgumentOutOfRangeException"/> those guards raise.
    /// </summary>
    [TestMethod]
    public void DistinctColumnIndexSqueezeRejectsAnOversizedDestination()
    {
        string expectedMessage = $"Destination must hold {MisSizedIndexCount} indices; received {OversizedIndexDestinationLength}.";

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => SampleIndicesIntoOversizedDestination(),
            "An index destination longer than the requested count must be rejected.");

        Assert.AreEqual(DestinationParameterName, exception.ParamName, "The rejection must name the destination parameter.");
        Assert.Contains(expectedMessage, exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Pins that the distinct opened-column-index sampler re-squeezes every draw at or above the acceptance limit
    /// instead of reducing it into range, and throws <see cref="InvalidOperationException"/> once the per-index
    /// attempt cap is spent without an accepted draw. Over a width of three the acceptance limit is 2^64 - 1, so
    /// the all-ones draw the saturated squeeze yields on every attempt is always in the biased tail; reduced modulo
    /// the width it would be index zero, so a sampler that mapped a tail draw into range would return that index
    /// instead of throwing. The transcript is non-null, the width is positive, the count lies in
    /// <c>[0, extensionWidth]</c> and the destination holds exactly that count, so no argument guard answers first.
    /// </summary>
    [TestMethod]
    public void DistinctColumnIndexSqueezeThrowsWhenEveryDrawFallsInTheBiasedTail()
    {
        InvalidOperationException exception = Assert.ThrowsExactly<InvalidOperationException>(
            () => SampleIndicesFromSaturatedSqueeze(),
            "A squeeze whose every draw lies in the biased tail must exhaust the attempt cap and throw.");

        Assert.Contains(AttemptCapMessageFragment, exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Pins that the tableau-root absorb rejects a <see langword="null"/> root with an
    /// <see cref="ArgumentNullException"/> that reports the <c>root</c> parameter, instead of failing when the root's
    /// bytes are read for the absorb. The transcript is live and the hash delegate is non-null, so the root is the only
    /// null argument, and the exact exception type excludes the <see cref="NullReferenceException"/> that reading a
    /// missing root raises.
    /// </summary>
    [TestMethod]
    public void TableauRootAbsorbRejectsNullRoot()
    {
        using FiatShamirTranscript transcript = NewTranscript();

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => transcript.AbsorbLigeroTableauRoot(null!, Hash),
            "A null tableau root must be rejected as a null argument.");

        Assert.AreEqual(RootParameterName, exception.ParamName, "The rejection must name the root parameter.");
    }


    /// <summary>
    /// Pins that the tableau-root absorb checks the transcript before the root: when both are
    /// <see langword="null"/>, the <see cref="ArgumentNullException"/> reports the <c>transcript</c> parameter,
    /// because the transcript check comes first and the root check would otherwise answer with <c>root</c>. The hash
    /// delegate is non-null, so no other argument is missing.
    /// </summary>
    [TestMethod]
    public void TableauRootAbsorbChecksTheTranscriptBeforeTheRoot()
    {
        FiatShamirTranscript transcript = null!;

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => transcript.AbsorbLigeroTableauRoot(null!, Hash),
            "A null transcript and a null root must be rejected as a null argument.");

        Assert.AreEqual(TranscriptParameterName, exception.ParamName, "The transcript check must answer before the root check.");
    }


    /// <summary>
    /// Pins that the challenge-scalar squeeze rejects a <see langword="null"/> transcript with an
    /// <see cref="ArgumentNullException"/> that reports the <c>transcript</c> parameter even when no scalar is
    /// requested. The count is zero and the destination is empty, so the squeeze loop never reaches the transcript and
    /// only this check can refuse the call; the reduce backend and the pool are non-null.
    /// </summary>
    [TestMethod]
    public void ChallengeScalarSqueezeRejectsNullTranscript()
    {
        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => SqueezeNoChallengeScalars(null!, Reduce, BaseMemoryPool.Shared),
            "A null transcript must be rejected as a null argument.");

        Assert.AreEqual(TranscriptParameterName, exception.ParamName, "The rejection must name the transcript parameter.");
    }


    /// <summary>
    /// Pins that the challenge-scalar squeeze rejects a <see langword="null"/> reduce backend with an
    /// <see cref="ArgumentNullException"/> that reports the <c>reduce</c> parameter even when no scalar is requested.
    /// The count is zero and the destination is empty, so the squeeze loop never invokes the backend and only this
    /// check can refuse the call; the transcript is live and the pool is non-null.
    /// </summary>
    [TestMethod]
    public void ChallengeScalarSqueezeRejectsNullReduceDelegate()
    {
        using FiatShamirTranscript transcript = NewTranscript();

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => SqueezeNoChallengeScalars(transcript, null!, BaseMemoryPool.Shared),
            "A null reduce backend must be rejected as a null argument.");

        Assert.AreEqual(ReduceParameterName, exception.ParamName, "The rejection must name the reduce parameter.");
    }


    /// <summary>
    /// Pins that the challenge-scalar squeeze rejects a <see langword="null"/> pool with an
    /// <see cref="ArgumentNullException"/> that reports the <c>pool</c> parameter, instead of failing when the squeeze
    /// scratch is rented. The transcript is live and the reduce backend is non-null, so the pool is the only null
    /// argument, and the exact exception type excludes the <see cref="NullReferenceException"/> that renting from a
    /// missing pool raises.
    /// </summary>
    [TestMethod]
    public void ChallengeScalarSqueezeRejectsNullPool()
    {
        using FiatShamirTranscript transcript = NewTranscript();

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => SqueezeNoChallengeScalars(transcript, Reduce, null!),
            "A null pool must be rejected as a null argument.");

        Assert.AreEqual(PoolParameterName, exception.ParamName, "The rejection must name the pool parameter.");
    }


    /// <summary>
    /// Pins that the challenge-scalar squeeze rejects a negative count with an
    /// <see cref="ArgumentOutOfRangeException"/> that reports the <c>count</c> parameter and carries the refused value.
    /// The transcript, the reduce backend and the pool are non-null, so no null check answers. The count check runs
    /// before the destination-length check, which no destination can satisfy for a negative count and which would
    /// raise the base <see cref="ArgumentException"/> naming <c>destination</c>; the exact exception type and the
    /// parameter name exclude it.
    /// </summary>
    [TestMethod]
    public void ChallengeScalarSqueezeRejectsNegativeCount()
    {
        using FiatShamirTranscript transcript = NewTranscript();

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => transcript.SqueezeLigeroChallengeScalars(
                new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.LowDegreeChallenge), NegativeRequestCount, Span<byte>.Empty, Squeeze, Hash, Reduce, CurveParameterSet.None, BaseMemoryPool.Shared),
            "A negative challenge count must be rejected.");

        Assert.AreEqual(CountParameterName, exception.ParamName, "The rejection must name the count parameter.");
        Assert.AreEqual(NegativeRequestCount, exception.ActualValue, "The rejection must carry the negative count it refused.");
    }


    /// <summary>
    /// Pins that the distinct opened-column-index sampler rejects a <see langword="null"/> transcript with an
    /// <see cref="ArgumentNullException"/> that reports the <c>transcript</c> parameter even when no index is
    /// requested. The width is one, the count is zero and the destination is empty, so every range and length check
    /// accepts the call and the sampling loop never reaches the transcript.
    /// </summary>
    [TestMethod]
    public void DistinctColumnIndexSqueezeRejectsNullTranscript()
    {
        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => SampleIndicesIntoEmptyDestination(null!, SingleColumnExtensionWidth, EmptyRequestCount),
            "A null transcript must be rejected as a null argument.");

        Assert.AreEqual(TranscriptParameterName, exception.ParamName, "The rejection must name the transcript parameter.");
    }


    /// <summary>
    /// Pins that the distinct opened-column-index sampler rejects a zero extension width with an
    /// <see cref="ArgumentOutOfRangeException"/> that reports the <c>extensionWidth</c> parameter and carries the
    /// refused width, instead of reducing the acceptance limit modulo zero. The transcript is live and the count is zero
    /// with an empty destination, so the count and length checks accept the call and only the width check refuses it.
    /// </summary>
    [TestMethod]
    public void DistinctColumnIndexSqueezeRejectsZeroExtensionWidth()
    {
        using FiatShamirTranscript transcript = NewTranscript();

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => SampleIndicesIntoEmptyDestination(transcript, ZeroExtensionWidth, EmptyRequestCount),
            "A zero extension width must be rejected.");

        Assert.AreEqual(ExtensionWidthParameterName, exception.ParamName, "The rejection must name the extensionWidth parameter.");
        Assert.AreEqual(ZeroExtensionWidth, exception.ActualValue, "The rejection must carry the width it refused.");
    }


    /// <summary>
    /// Pins that the distinct opened-column-index sampler rejects a negative count with an
    /// <see cref="ArgumentOutOfRangeException"/> that reports the <c>count</c> parameter and carries the refused value.
    /// The transcript is live and the width is one; a count of minus one does not exceed that width, so the upper-bound
    /// check that reports the same parameter name stays silent, and only the non-negative check reports a negative
    /// actual value. The destination-length check, which no destination can satisfy for a negative count, would raise
    /// the base <see cref="ArgumentException"/> naming <c>destination</c>, which the exact type excludes.
    /// </summary>
    [TestMethod]
    public void DistinctColumnIndexSqueezeRejectsNegativeCount()
    {
        using FiatShamirTranscript transcript = NewTranscript();

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => SampleIndicesIntoEmptyDestination(transcript, SingleColumnExtensionWidth, NegativeRequestCount),
            "A negative index count must be rejected.");

        Assert.AreEqual(CountParameterName, exception.ParamName, "The rejection must name the count parameter.");
        Assert.AreEqual(NegativeRequestCount, exception.ActualValue, "The rejection must carry the negative count it refused.");
    }


    /// <summary>
    /// Pins that the distinct opened-column-index sampler rejects a count above the extension width with an
    /// <see cref="ArgumentOutOfRangeException"/> that reports the <c>count</c> parameter and carries the refused count,
    /// instead of searching for more distinct indices than the width holds until the attempt cap throws
    /// <see cref="InvalidOperationException"/>. Two indices are requested over a single column into a destination of
    /// exactly two slots; the transcript is live, the width is positive and the count is not negative, so only the
    /// upper-bound check refuses the call.
    /// </summary>
    [TestMethod]
    public void DistinctColumnIndexSqueezeRejectsCountAboveExtensionWidth()
    {
        using FiatShamirTranscript transcript = NewTranscript();

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => SampleExcessIndicesFromSingleColumn(transcript),
            "A count above the extension width must be rejected.");

        Assert.AreEqual(CountParameterName, exception.ParamName, "The rejection must name the count parameter.");
        Assert.AreEqual(ExcessIndexCount, exception.ActualValue, "The rejection must carry the count it refused.");
    }


    /// <summary>
    /// Pins that the distinct opened-column-index sampler stops once it has written the requested count: one index
    /// over a width of three takes exactly one squeeze when that squeeze's draw is accepted. The squeeze backend yields
    /// the in-range draw only at squeeze counter zero and the all-ones biased-tail draw at every later counter, so a
    /// sampler that did not advance past the slot it filled would keep squeezing, see only tail draws, and throw once
    /// the attempt cap is spent instead of returning index two after a single squeeze.
    /// </summary>
    [TestMethod]
    public void DistinctColumnIndexSqueezeStopsOnceTheRequestedCountIsFilled()
    {
        Span<int> destination = stackalloc int[ScheduledSqueezeIndexCount];
        using FiatShamirTranscript transcript = NewTranscript();

        transcript.SqueezeLigeroDistinctColumnIndices(BiasedTailExtensionWidth, ScheduledSqueezeIndexCount, destination, InRangeOnlyOnFirstDrawSqueeze, Hash);

        Assert.AreEqual(InRangeDrawIndex, destination[FirstIndexSlot], "The single accepted draw must be written as the requested index.");
        Assert.AreEqual(FirstDrawSqueezeCount, transcript.SqueezeCount, "Filling the requested count must end the sampling after the accepted draw.");
    }


    /// <summary>
    /// Pins that the distinct opened-column-index sampler spends exactly <see cref="AttemptCapPerIndex"/> squeezes on
    /// one index before it throws <see cref="InvalidOperationException"/>. The squeeze backend yields the all-ones
    /// biased-tail draw for squeeze counters below the cap and the in-range draw from the cap onwards, so the sampler
    /// must throw with the transcript's squeeze count at the cap. A sampler that allowed one attempt more, or whose
    /// attempt counter never reached the cap, would take the in-range draw at the counter equal to the cap and return
    /// index two instead of throwing.
    /// </summary>
    [TestMethod]
    public void DistinctColumnIndexSqueezeThrowsAfterExactlyTheAttemptCap()
    {
        using FiatShamirTranscript transcript = NewTranscript();

        InvalidOperationException exception = Assert.ThrowsExactly<InvalidOperationException>(
            () => SampleIndexFromCapExhaustingSqueeze(transcript),
            "Tail draws for every attempt up to the cap must exhaust the cap and throw.");

        Assert.Contains(AttemptCapMessageFragment, exception.Message, StringComparison.Ordinal);
        Assert.AreEqual(AttemptCapPerIndex, transcript.SqueezeCount, "The sampler must spend exactly the attempt cap in squeezes before it throws.");
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


    /// <summary>
    /// Squeezes <see cref="MisSizedChallengeCount"/> challenge scalars into a destination of
    /// <see cref="OversizedChallengeDestinationBytes"/> bytes. The destination is stack-allocated inside this helper
    /// because an assertion lambda cannot capture a stack span.
    /// </summary>
    private static void SqueezeChallengeScalarsIntoOversizedDestination()
    {
        Span<byte> destination = stackalloc byte[OversizedChallengeDestinationBytes];
        using FiatShamirTranscript transcript = NewTranscript();

        transcript.SqueezeLigeroChallengeScalars(
            new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.LowDegreeChallenge), MisSizedChallengeCount, destination, Squeeze, Hash, Reduce, CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Samples <see cref="MisSizedIndexCount"/> index over <see cref="MisSizedIndexExtensionWidth"/> columns into a
    /// destination of <see cref="OversizedIndexDestinationLength"/> slots. The destination is stack-allocated inside
    /// this helper because an assertion lambda cannot capture a stack span.
    /// </summary>
    private static void SampleIndicesIntoOversizedDestination()
    {
        Span<int> destination = stackalloc int[OversizedIndexDestinationLength];
        using FiatShamirTranscript transcript = NewTranscript();

        transcript.SqueezeLigeroDistinctColumnIndices(MisSizedIndexExtensionWidth, MisSizedIndexCount, destination, Squeeze, Hash);
    }


    /// <summary>
    /// Samples <see cref="SaturatedSqueezeIndexCount"/> index over <see cref="BiasedTailExtensionWidth"/> columns with
    /// <see cref="SaturatedSqueeze"/> as the squeeze backend and the BLAKE3 hash for the post-squeeze state update, so
    /// every draw lies in the biased tail. The destination is stack-allocated inside this helper because an assertion
    /// lambda cannot capture a stack span.
    /// </summary>
    private static void SampleIndicesFromSaturatedSqueeze()
    {
        Span<int> destination = stackalloc int[SaturatedSqueezeIndexCount];
        using FiatShamirTranscript transcript = NewTranscript();

        transcript.SqueezeLigeroDistinctColumnIndices(BiasedTailExtensionWidth, SaturatedSqueezeIndexCount, destination, SaturatedSqueeze, Hash);
    }


    /// <summary>
    /// A squeeze backend that writes <see cref="byte.MaxValue"/> into every output byte, so each eight-byte index
    /// draw reads as 2^64 - 1, the largest 64-bit value, whatever the transcript state.
    /// </summary>
    /// <param name="input">The squeeze input, which the saturated output does not depend on.</param>
    /// <param name="output">Receives the all-ones bytes.</param>
    /// <param name="hashFunction">The requested hash function name, which the saturated output does not depend on.</param>
    private static void SaturatedSqueeze(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        output.Fill(byte.MaxValue);
    }


    /// <summary>
    /// Squeezes <see cref="EmptyRequestCount"/> challenge scalars under the low-degree challenge label into an empty
    /// destination, so the squeeze loop never runs and only the argument guards can refuse the call.
    /// </summary>
    /// <param name="transcript">The transcript to squeeze from, or <see langword="null"/> to exercise its null check.</param>
    /// <param name="reduce">The scalar-reduce backend, or <see langword="null"/> to exercise its null check.</param>
    /// <param name="pool">The pool the squeeze scratch is rented from, or <see langword="null"/> to exercise its null check.</param>
    private static void SqueezeNoChallengeScalars(FiatShamirTranscript transcript, ScalarReduceDelegate reduce, BaseMemoryPool pool)
    {
        transcript.SqueezeLigeroChallengeScalars(
            new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.LowDegreeChallenge), EmptyRequestCount, Span<byte>.Empty, Squeeze, Hash, reduce, CurveParameterSet.None, pool);
    }


    /// <summary>
    /// Samples <paramref name="count"/> distinct indices over <paramref name="extensionWidth"/> columns into an empty
    /// destination with the BLAKE3 squeeze and hash backends.
    /// </summary>
    /// <param name="transcript">The transcript to squeeze from, or <see langword="null"/> to exercise its null check.</param>
    /// <param name="extensionWidth">The number of columns to sample from.</param>
    /// <param name="count">The number of distinct indices to request.</param>
    private static void SampleIndicesIntoEmptyDestination(FiatShamirTranscript transcript, int extensionWidth, int count)
    {
        transcript.SqueezeLigeroDistinctColumnIndices(extensionWidth, count, Span<int>.Empty, Squeeze, Hash);
    }


    /// <summary>
    /// Samples <see cref="ExcessIndexCount"/> distinct indices over <see cref="SingleColumnExtensionWidth"/> columns
    /// into a destination of exactly <see cref="ExcessIndexCount"/> slots with the BLAKE3 squeeze and hash backends. The
    /// destination is stack-allocated inside this helper because an assertion lambda cannot capture a stack span.
    /// </summary>
    /// <param name="transcript">The live transcript to squeeze from.</param>
    private static void SampleExcessIndicesFromSingleColumn(FiatShamirTranscript transcript)
    {
        Span<int> destination = stackalloc int[ExcessIndexCount];
        transcript.SqueezeLigeroDistinctColumnIndices(SingleColumnExtensionWidth, ExcessIndexCount, destination, Squeeze, Hash);
    }


    /// <summary>
    /// Samples <see cref="ScheduledSqueezeIndexCount"/> index over <see cref="BiasedTailExtensionWidth"/> columns with
    /// <see cref="InRangeOnlyAfterAttemptCapSqueeze"/> as the squeeze backend and the BLAKE3 hash for the post-squeeze
    /// state update. The destination is stack-allocated inside this helper because an assertion lambda cannot capture a
    /// stack span.
    /// </summary>
    /// <param name="transcript">A freshly initialised transcript, whose squeeze counter starts at zero.</param>
    private static void SampleIndexFromCapExhaustingSqueeze(FiatShamirTranscript transcript)
    {
        Span<int> destination = stackalloc int[ScheduledSqueezeIndexCount];
        transcript.SqueezeLigeroDistinctColumnIndices(BiasedTailExtensionWidth, ScheduledSqueezeIndexCount, destination, InRangeOnlyAfterAttemptCapSqueeze, Hash);
    }


    /// <summary>
    /// A squeeze backend that fills the output with <see cref="InRangeDrawByte"/> while the transcript's squeeze counter
    /// is below <see cref="FirstDrawSqueezeCount"/> and with <see cref="byte.MaxValue"/> afterwards. Over
    /// <see cref="BiasedTailExtensionWidth"/> columns only the first draw of a fresh transcript is accepted; every later
    /// draw lies in the biased tail.
    /// </summary>
    /// <param name="input">The XOF input, whose trailing <see cref="SqueezeCounterBytes"/> bytes are the big-endian squeeze counter.</param>
    /// <param name="output">Receives the scheduled draw bytes.</param>
    /// <param name="hashFunction">The requested hash function name, which the scheduled output does not depend on.</param>
    private static void InRangeOnlyOnFirstDrawSqueeze(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        long counter = BinaryPrimitives.ReadInt64BigEndian(input[^SqueezeCounterBytes..]);
        output.Fill(counter < FirstDrawSqueezeCount ? InRangeDrawByte : byte.MaxValue);
    }


    /// <summary>
    /// A squeeze backend that fills the output with <see cref="byte.MaxValue"/> while the transcript's squeeze counter is
    /// below <see cref="AttemptCapPerIndex"/> and with <see cref="InRangeDrawByte"/> from then on. Over
    /// <see cref="BiasedTailExtensionWidth"/> columns every draw of a fresh transcript up to the attempt cap lies in the
    /// biased tail, and the first draw past it is accepted.
    /// </summary>
    /// <param name="input">The XOF input, whose trailing <see cref="SqueezeCounterBytes"/> bytes are the big-endian squeeze counter.</param>
    /// <param name="output">Receives the scheduled draw bytes.</param>
    /// <param name="hashFunction">The requested hash function name, which the scheduled output does not depend on.</param>
    private static void InRangeOnlyAfterAttemptCapSqueeze(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        long counter = BinaryPrimitives.ReadInt64BigEndian(input[^SqueezeCounterBytes..]);
        output.Fill(counter < AttemptCapPerIndex ? byte.MaxValue : InRangeDrawByte);
    }
}
