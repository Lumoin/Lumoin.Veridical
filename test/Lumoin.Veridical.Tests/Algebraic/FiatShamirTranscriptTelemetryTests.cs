using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Operation accounting for <see cref="FiatShamirTranscript"/>: with counting enabled, initialising a transcript,
/// absorbing bytes into it and squeezing bytes from it each record one operation under their own
/// <see cref="CryptographicOperationKind"/>, and a squeeze also records the chained state update it performs.
/// </summary>
/// <remarks>
/// Counter aggregation is process-wide static state, so these tests run sequentially
/// (<see cref="DoNotParallelizeAttribute"/>) and turn both gates off and clear the counts before and after each test,
/// matching <c>CryptographicOperationCountersTests</c>.
/// </remarks>
[TestClass]
[DoNotParallelize]
internal sealed class FiatShamirTranscriptTelemetryTests
{
    /// <summary>The count one transcript operation adds to its own kind.</summary>
    private const long SingleOperationCount = 1;

    /// <summary>The count of a kind that no operation in the measured window records.</summary>
    private const long NoOperationCount = 0;

    /// <summary>The width of the squeeze destination, one full BLAKE3 output.</summary>
    private const int SqueezeByteCount = 32;

    /// <summary>The fixed-output BLAKE3 transcript hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The XOF-mode BLAKE3 transcript squeeze backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The protocol-identifying label the counted transcripts are initialised under.</summary>
    private static FiatShamirDomainLabel DomainLabel { get; } = new("veridical.test.telemetry.v1");

    /// <summary>The operation label the counted absorbs and squeezes are issued under.</summary>
    private static FiatShamirOperationLabel OperationLabel { get; } = new("test.telemetry.operation");


    /// <summary>Turns both counter gates off and clears the counts, so each test measures only the operations it enables counting for.</summary>
    [TestInitialize]
    public void Initialize()
    {
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;
        CryptographicOperationCounters.Reset();
    }


    /// <summary>Restores both counter gates to their off default and clears the counts, so later test classes start clean.</summary>
    [TestCleanup]
    public void Cleanup()
    {
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;
        CryptographicOperationCounters.Reset();
    }


    /// <summary>
    /// Pins that <see cref="FiatShamirTranscript.Initialise"/> records exactly one
    /// <see cref="CryptographicOperationKind.TranscriptInitialise"/> operation and nothing under the absorb, squeeze or
    /// state-update kinds: computing the initial state is accounted as initialisation, not as a state update.
    /// </summary>
    [TestMethod]
    public void InitialiseCountsOneTranscriptInitialise()
    {
        CryptographicOperationCounters.IsCountingEnabled = true;

        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(DomainLabel, ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        Assert.AreEqual(SingleOperationCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.TranscriptInitialise),
            "One initialisation must record one TranscriptInitialise operation.");
        Assert.AreEqual(NoOperationCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.TranscriptAbsorbBytes));
        Assert.AreEqual(NoOperationCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.TranscriptSqueezeBytes));
        Assert.AreEqual(NoOperationCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.TranscriptUpdateState));
    }


    /// <summary>
    /// Pins that <c>AbsorbBytes</c> records exactly one <see cref="CryptographicOperationKind.TranscriptAbsorbBytes"/>
    /// operation and nothing under <see cref="CryptographicOperationKind.TranscriptUpdateState"/>: an absorb replaces the
    /// state, but it is accounted under its own kind, distinct from the state update that follows a squeeze. Counting is
    /// enabled only after initialisation, so the measured window holds the absorb alone.
    /// </summary>
    [TestMethod]
    public void AbsorbBytesCountsOneTranscriptAbsorbBytes()
    {
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(DomainLabel, ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        CryptographicOperationCounters.IsCountingEnabled = true;
        transcript.AbsorbBytes(OperationLabel, "telemetry.absorbed"u8, Hash);

        Assert.AreEqual(SingleOperationCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.TranscriptAbsorbBytes),
            "One absorb must record one TranscriptAbsorbBytes operation.");
        Assert.AreEqual(NoOperationCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.TranscriptUpdateState),
            "An absorb must not be recorded as a squeeze's state update.");
        Assert.AreEqual(NoOperationCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.TranscriptSqueezeBytes));
        Assert.AreEqual(NoOperationCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.TranscriptInitialise));
    }


    /// <summary>
    /// Pins that <c>SqueezeBytes</c> records exactly one <see cref="CryptographicOperationKind.TranscriptSqueezeBytes"/>
    /// operation for the XOF output and exactly one <see cref="CryptographicOperationKind.TranscriptUpdateState"/>
    /// operation for the chained state-update hash, and nothing under the absorb kind. Counting is enabled only after
    /// initialisation, so the measured window holds the squeeze alone.
    /// </summary>
    [TestMethod]
    public void SqueezeBytesCountsOneSqueezeAndOneStateUpdate()
    {
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(DomainLabel, ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        Span<byte> challenge = stackalloc byte[SqueezeByteCount];

        CryptographicOperationCounters.IsCountingEnabled = true;
        transcript.SqueezeBytes(OperationLabel, challenge, Squeeze, Hash);

        Assert.AreEqual(SingleOperationCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.TranscriptSqueezeBytes),
            "One squeeze must record one TranscriptSqueezeBytes operation.");
        Assert.AreEqual(SingleOperationCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.TranscriptUpdateState),
            "One squeeze must record one TranscriptUpdateState operation for its chained state update.");
        Assert.AreEqual(NoOperationCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.TranscriptAbsorbBytes));
        Assert.AreEqual(NoOperationCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.TranscriptInitialise));
    }
}
