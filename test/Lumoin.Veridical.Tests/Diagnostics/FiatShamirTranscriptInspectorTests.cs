using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Diagnostics;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Diagnostics;

/// <summary>
/// Tests for the verbose <see cref="FiatShamirTranscriptInspector"/>.
/// Each test constructs a transcript and asserts the bundled report
/// reflects its observable state.
/// </summary>
[TestClass]
internal sealed class FiatShamirTranscriptInspectorTests
{
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();
    private static readonly FiatShamirDomainLabel DomainLabel = new("veridical.test.inspector.v1");


    [TestMethod]
    public void InspectingFreshTranscriptReportsZeroSqueezeCount()
    {
        ReadOnlySpan<byte> seed = stackalloc byte[8];
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, SensitiveMemoryPool<byte>.Shared);

        FiatShamirTranscriptReport report = FiatShamirTranscriptInspector.Inspect(transcript);

        Assert.AreEqual(DomainLabel, report.DomainLabel);
        Assert.AreEqual(WellKnownHashAlgorithms.Blake3, report.HashFunction);
        Assert.AreEqual(0L, report.SqueezeCount);
        Assert.AreEqual(FiatShamirTranscript.StateSizeBytes * 2, report.CurrentStateHex.Length, "32-byte state should render as 64 hex characters.");
        Assert.Contains("FiatShamirTranscript", report.TagSummary);
    }


    [TestMethod]
    public void InspectingTranscriptAfterSqueezeReflectsAdvancedCounterAndChangedState()
    {
        ReadOnlySpan<byte> seed = stackalloc byte[8];
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, SensitiveMemoryPool<byte>.Shared);

        FiatShamirTranscriptReport initial = FiatShamirTranscriptInspector.Inspect(transcript);

        using IMemoryOwner<byte> owner = SensitiveMemoryPool<byte>.Shared.Rent(32);
        Span<byte> output = owner.Memory.Span[..32];
        transcript.SqueezeBytes(new FiatShamirOperationLabel("challenge"), output, Squeeze, Hash);

        FiatShamirTranscriptReport afterSqueeze = FiatShamirTranscriptInspector.Inspect(transcript);

        Assert.AreEqual(1L, afterSqueeze.SqueezeCount);
        Assert.AreNotEqual(initial.CurrentStateHex, afterSqueeze.CurrentStateHex, "State must change after a squeeze due to the state-update step.");
    }


    [TestMethod]
    public void InspectThrowsOnNullTranscript()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => FiatShamirTranscriptInspector.Inspect(null!));
    }


    [TestMethod]
    public void InspectionExtensionsReturnExpectedValues()
    {
        ReadOnlySpan<byte> seed = stackalloc byte[8];
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, SensitiveMemoryPool<byte>.Shared);

        Assert.AreEqual(WellKnownHashAlgorithms.Blake3, transcript.HashFunctionName);
        Assert.AreEqual(64, transcript.CurrentStateHex.Length, "32-byte state should render as 64 hex characters.");
    }
}