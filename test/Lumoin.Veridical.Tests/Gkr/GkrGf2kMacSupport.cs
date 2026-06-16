using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Gkr;
using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The shared GF(2^128)-side machinery of the cross-field MAC: the one-layer MAC instance whose
/// coefficients embed the post-commit verifier key, the key squeeze, the out-of-circuit MAC
/// computation, and the bit packing conventions — bit <c>i</c> of a 128-bit half is bit <c>i</c>
/// of its big-endian 16 bytes and the coefficient of <c>x^i</c> in the field element, the same
/// convention on the GF and Fp sides of the binding.
/// </summary>
internal static class GkrGf2kMacSupport
{
    public const int ScalarSize = GkrGf2kTestSupport.ScalarSize;
    public const int HalfBits = 128;
    public const int HalfBytes = HalfBits / 8;
    public const int CopyCount = 2;

    //Per copy (one message half): the 128 message bits, then the prover's key share as one
    //native field element, padded to 256.
    public const int InputCount = 256;
    public const int KeyWire = 128;
    public const int OutputCount = 2;
    public const int WitnessBytes = CopyCount * InputCount * ScalarSize;
    public const int OutputBytes = CopyCount * OutputCount * ScalarSize;

    public static FiatShamirOperationLabel KeyLabel { get; } = new("veridical.gkr.mac.verifier.key");


    //One layer per half-copy: mac = Σ_i (a_v·α^i)·x_i² + Σ_i α^i·(a_p·x_i). The verifier key
    //and the basis powers are public constants shared by both copies — legal coefficients; the
    //key share is a committed wire, so its product with each message bit is a quadratic term.
    public static GkrCircuit BuildMacCircuit(ReadOnlySpan<byte> verifierKey)
    {
        Span<byte> alpha = stackalloc byte[ScalarSize];
        alpha[ScalarSize - 1] = 2;
        Span<byte> power = stackalloc byte[ScalarSize];
        power[ScalarSize - 1] = 1;
        Span<byte> keyed = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];

        var terms = new List<GkrLayerTerm>();
        for(int i = 0; i < HalfBits; i++)
        {
            GkrGf2kTestSupport.Multiply(verifierKey, power, keyed, CurveParameterSet.None);
            terms.Add(new GkrLayerTerm(0, i, i, keyed.ToArray()));
            terms.Add(new GkrLayerTerm(0, KeyWire, i, power.ToArray()));

            GkrGf2kTestSupport.Multiply(power, alpha, scratch, CurveParameterSet.None);
            scratch.CopyTo(power);
        }

        return new GkrCircuit([new GkrLayer([.. terms], OutputCount)], InputCount);
    }


    //mac_h = (a_p,h + a_v) · x_h with x_h packed from the bits — matching the reference
    //implementation's MACReference::compute.
    public static void ComputeMacs(ReadOnlySpan<byte> value, byte[][] keyShares, ReadOnlySpan<byte> verifierKey, Span<byte> macs)
    {
        Span<byte> half = stackalloc byte[ScalarSize];
        Span<byte> key = stackalloc byte[ScalarSize];
        for(int h = 0; h < CopyCount; h++)
        {
            HalfElement(value, h, half);
            GkrGf2kTestSupport.Add(keyShares[h], verifierKey, key, CurveParameterSet.None);
            GkrGf2kTestSupport.Multiply(key, half, macs.Slice(h * ScalarSize, ScalarSize), CurveParameterSet.None);
        }
    }


    //The field element of one 128-bit half of a 32-byte value: bytes h·16..h·16+15 big-endian.
    public static void HalfElement(ReadOnlySpan<byte> value, int half, Span<byte> element)
    {
        element.Clear();
        value.Slice(half * HalfBytes, HalfBytes).CopyTo(element[(ScalarSize - HalfBytes)..]);
    }


    //Bit i of the given half — the coefficient of x^i in the half's field element.
    public static int HalfBit(ReadOnlySpan<byte> value, int half, int bit)
    {
        ReadOnlySpan<byte> bytes = value.Slice(half * HalfBytes, HalfBytes);

        return (bytes[(HalfBytes - 1) - (bit >> 3)] >> (bit & 7)) & 1;
    }


    //Per copy: the half's 128 bits, the key share element.
    public static void PackGfWitness(Span<byte> witness, ReadOnlySpan<byte> value, byte[][] keyShares)
    {
        witness.Clear();
        for(int h = 0; h < CopyCount; h++)
        {
            Span<byte> copy = witness.Slice(h * InputCount * ScalarSize, InputCount * ScalarSize);
            for(int i = 0; i < HalfBits; i++)
            {
                copy[(i * ScalarSize) + ScalarSize - 1] = (byte)HalfBit(value, h, i);
            }

            keyShares[h].CopyTo(copy.Slice(KeyWire * ScalarSize, ScalarSize));
        }
    }


    //Bitness for the message bits of both copies; the key shares are arbitrary elements.
    public static LigeroQuadraticConstraint[] BuildGfBitness()
    {
        var quadratics = new List<LigeroQuadraticConstraint>();
        for(int h = 0; h < CopyCount; h++)
        {
            for(int i = 0; i < HalfBits; i++)
            {
                int index = (h * InputCount) + i;
                quadratics.Add(new LigeroQuadraticConstraint(index, index, index));
            }
        }

        return [.. quadratics];
    }


    public static void SqueezeVerifierKey(FiatShamirTranscript transcript, Span<byte> verifierKey)
    {
        Span<byte> wide = stackalloc byte[ScalarSize];
        transcript.SqueezeBytes(KeyLabel, wide, GkrGf2kTestSupport.Squeeze, GkrGf2kTestSupport.Hash);
        GkrGf2kTestSupport.Reduce(wide, verifierKey, CurveParameterSet.None);
    }
}
