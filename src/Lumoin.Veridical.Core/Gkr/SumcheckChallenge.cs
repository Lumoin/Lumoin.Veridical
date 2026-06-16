using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// Shared Fiat-Shamir and small-constant helpers for the sumcheck protocols: absorbing a round
/// polynomial and squeezing the next challenge, and encoding the field constants the round
/// machinery needs. Both <see cref="MultilinearSumcheck"/> and <see cref="ProductSumcheck"/> drive
/// the transcript identically so a verifier replays the prover's challenges.
/// </summary>
internal static class SumcheckChallenge
{
    public const int ScalarSize = Scalar.SizeBytes;

    //64-byte wide squeeze keeps the modular-reduction bias below 2^-256 (RFC 9380 L = 64), the
    //same width the Ligero challenge squeeze uses.
    private const int SqueezeWideBytes = 64;

    public static readonly FiatShamirOperationLabel RoundPolynomialLabel = new("veridical.gkr.sumcheck.round");
    public static readonly FiatShamirOperationLabel ChallengeLabel = new("veridical.gkr.sumcheck.challenge");


    //Absorbs the round polynomial bytes and squeezes the next challenge, reducing a wide squeeze
    //into a canonical field element via the supplied reduce delegate (so it works over any field,
    //including the P-256 base field under CurveParameterSet.None).
    public static void AbsorbAndSqueeze(
        FiatShamirTranscript transcript,
        ReadOnlySpan<byte> roundPolynomial,
        Span<byte> challenge,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve)
    {
        transcript.AbsorbBytes(RoundPolynomialLabel, roundPolynomial, hash);
        Squeeze(transcript, ChallengeLabel, challenge, squeeze, hash, reduce, curve);
    }


    //Squeezes one canonical field element under the given label (a wide squeeze reduced by the
    //supplied delegate). Used directly by protocols that absorb under their own labels first.
    public static void Squeeze(
        FiatShamirTranscript transcript,
        FiatShamirOperationLabel label,
        Span<byte> challenge,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve)
    {
        Span<byte> wide = stackalloc byte[SqueezeWideBytes];
        transcript.SqueezeBytes(label, wide, squeeze, hash);
        reduce(wide, challenge, curve);
    }


    public static void EncodeOne(Span<byte> destination)
    {
        destination.Clear();
        destination[ScalarSize - 1] = 1;
    }


    public static void EncodeConstant(uint value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[(ScalarSize - sizeof(uint))..], value);
    }
}
