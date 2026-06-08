using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using System;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// The wire-format <c>FromBytes</c> entry points of the Hyrax-shaped Spartan
/// proof containers (<see cref="SpartanProof.FromBytes"/> and
/// <see cref="MaskedSpartanProof.FromBytes"/>): a proof arriving over a wire or
/// from storage must be rejected when its length does not match the layout the
/// supplied dimensions dictate, exactly as the BaseFold-shaped siblings already
/// do. The happy path — committed fixture bytes rehydrated through
/// <c>FromBytes</c> and verified — is exercised by <see cref="SpartanFixtureTests"/>
/// and <see cref="MaskedSpartanFixtureTests"/>; the tampered-bytes path by the
/// failure suites. These tests pin the length contract itself.
/// </summary>
[TestClass]
internal sealed class SpartanProofSerializationTests
{
    //Small but representative dimensions: a 2-row witness commitment over
    //2 + 2 sumcheck rounds with 1-round IPA openings.
    private const int WitnessRowCount = 2;
    private const int OuterRoundCount = 2;
    private const int InnerRoundCount = 2;
    private const int IpaRoundCount = 1;
    private const int ErrorIpaRoundCount = 1;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void SpartanProofFromBytesRejectsWrongLength()
    {
        int expected = SpartanProof.GetBufferSizeBytes(
            WitnessRowCount, OuterRoundCount, InnerRoundCount, IpaRoundCount, ErrorIpaRoundCount, Curve);

        //One byte short and one byte long must both be rejected: the layout
        //carries no length prefixes, so the length is the framing contract.
        byte[] tooShort = new byte[expected - 1];
        byte[] tooLong = new byte[expected + 1];

        _ = Assert.ThrowsExactly<ArgumentException>(() => _ = SpartanProof.FromBytes(
            tooShort, WitnessRowCount, OuterRoundCount, InnerRoundCount, IpaRoundCount, ErrorIpaRoundCount,
            Curve, SensitiveMemoryPool<byte>.Shared));
        _ = Assert.ThrowsExactly<ArgumentException>(() => _ = SpartanProof.FromBytes(
            tooLong, WitnessRowCount, OuterRoundCount, InnerRoundCount, IpaRoundCount, ErrorIpaRoundCount,
            Curve, SensitiveMemoryPool<byte>.Shared));
    }


    [TestMethod]
    public void SpartanProofFromBytesRoundTripsExactLengthBytes()
    {
        int expected = SpartanProof.GetBufferSizeBytes(
            WitnessRowCount, OuterRoundCount, InnerRoundCount, IpaRoundCount, ErrorIpaRoundCount, Curve);

        //Content-agnostic framing check: FromBytes copies exact-length bytes
        //verbatim and the round-tripped span is byte-identical. Cryptographic
        //validity is the verifier's concern (the fixture suites), not framing's.
        byte[] bytes = new byte[expected];
        for(int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)(i * 31);
        }

        using SpartanProof proof = SpartanProof.FromBytes(
            bytes, WitnessRowCount, OuterRoundCount, InnerRoundCount, IpaRoundCount, ErrorIpaRoundCount,
            Curve, SensitiveMemoryPool<byte>.Shared);

        Assert.AreEqual(WitnessRowCount, proof.WitnessCommitmentRowCount);
        Assert.AreEqual(OuterRoundCount, proof.OuterRoundCount);
        Assert.AreEqual(InnerRoundCount, proof.InnerRoundCount);
        Assert.IsTrue(proof.AsReadOnlySpan().SequenceEqual(bytes), "The rehydrated proof must carry the wire bytes verbatim.");
    }


    [TestMethod]
    public void MaskedSpartanProofFromBytesRejectsWrongLength()
    {
        int expected = MaskedSpartanProof.GetBufferSizeBytes(
            WitnessRowCount, WitnessRowCount, WitnessRowCount,
            OuterRoundCount, InnerRoundCount,
            IpaRoundCount, IpaRoundCount, IpaRoundCount, ErrorIpaRoundCount, Curve);

        byte[] tooShort = new byte[expected - 1];
        byte[] tooLong = new byte[expected + 1];

        _ = Assert.ThrowsExactly<ArgumentException>(() => _ = MaskedSpartanProof.FromBytes(
            tooShort, WitnessRowCount, WitnessRowCount, WitnessRowCount,
            OuterRoundCount, InnerRoundCount,
            IpaRoundCount, IpaRoundCount, IpaRoundCount, ErrorIpaRoundCount,
            Curve, SensitiveMemoryPool<byte>.Shared));
        _ = Assert.ThrowsExactly<ArgumentException>(() => _ = MaskedSpartanProof.FromBytes(
            tooLong, WitnessRowCount, WitnessRowCount, WitnessRowCount,
            OuterRoundCount, InnerRoundCount,
            IpaRoundCount, IpaRoundCount, IpaRoundCount, ErrorIpaRoundCount,
            Curve, SensitiveMemoryPool<byte>.Shared));
    }


    [TestMethod]
    public void MaskedSpartanProofFromBytesRoundTripsExactLengthBytes()
    {
        int expected = MaskedSpartanProof.GetBufferSizeBytes(
            WitnessRowCount, WitnessRowCount, WitnessRowCount,
            OuterRoundCount, InnerRoundCount,
            IpaRoundCount, IpaRoundCount, IpaRoundCount, ErrorIpaRoundCount, Curve);

        byte[] bytes = new byte[expected];
        for(int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)(i * 37);
        }

        using MaskedSpartanProof proof = MaskedSpartanProof.FromBytes(
            bytes, WitnessRowCount, WitnessRowCount, WitnessRowCount,
            OuterRoundCount, InnerRoundCount,
            IpaRoundCount, IpaRoundCount, IpaRoundCount, ErrorIpaRoundCount,
            Curve, SensitiveMemoryPool<byte>.Shared);

        Assert.AreEqual(WitnessRowCount, proof.WitnessCommitmentRowCount);
        Assert.AreEqual(OuterRoundCount, proof.OuterRoundCount);
        Assert.AreEqual(InnerRoundCount, proof.InnerRoundCount);
        Assert.IsTrue(proof.AsReadOnlySpan().SequenceEqual(bytes), "The rehydrated proof must carry the wire bytes verbatim.");
    }
}
