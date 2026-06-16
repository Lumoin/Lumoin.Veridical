using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The four SHA-256 sigma functions through the committed GKR engine: Σ0 and Σ1 (three rotations
/// of a working variable) and σ0 and σ1 (two rotations and a logical shift of a message word),
/// each output bit the XOR of three taps of one 32-bit word. Rotations and shifts cost nothing —
/// they are rewiring in the term indices. The three-way XOR is degree three in the bits, so each
/// function takes two layers: the inner layer forms <c>w = u + v − 2·u·v = u ⊕ v</c> from the
/// first two taps, the output layer XORs in the third (positions the shift pushes past the word
/// edge lose the tap and pass <c>w</c> through). All four functions of the same committed word
/// prove as one circuit; eight words run as data-parallel copies; only the 128 output bits are
/// public. Gated bit-exact against the plain uint computation.
/// </summary>
[TestClass]
internal sealed class GkrShaSigmaFragmentTests
{
    private const int ScalarSize = GkrTestSupport.ScalarSize;
    private const int WordBits = 32;
    private const int CopyCount = 8;
    private const int FunctionCount = 4;

    //Per copy: the 32 bit wires of the word, the constant-one wire, padded to 64.
    private const int InputCount = 64;
    private const int InputOneWire = 32;

    //The inner layer: the four w = first ⊕ second words at function·32, the input word passed
    //through at 128 (the output layer needs the third taps), the one wire at 160, padded to 256.
    private const int InnerWidth = 256;
    private const int PassthroughBase = 128;
    private const int InnerOneWire = 160;

    private const int OutputCount = FunctionCount * WordBits;
    private const int InputBytes = CopyCount * InputCount * ScalarSize;
    private const int OutputBytes = CopyCount * OutputCount * ScalarSize;

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.sha.sigma.test");

    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.sha.sigma.rng.v1");

    private static byte[] One { get; } = GkrTestSupport.One;

    private static byte[] NegativeTwo { get; } = GkrTestSupport.NegativeTwo;

    //Σ0, Σ1, σ0, σ1: two rotation taps and a third tap that is a rotation for Σ and a logical
    //right shift for σ.
    private static (int First, int Second, int Third, bool ThirdIsShift)[] Taps { get; } =
    [
        (2, 13, 22, false),
        (6, 11, 25, false),
        (7, 18, 3, true),
        (17, 19, 10, true),
    ];

    private static uint[] Words { get; } =
    [
        0x6a09e667, 0x510e527f, 0x00000000, 0xffffffff, 0x80000000, 0x00000001, 0x428a2f98, 0x9abcdef0,
    ];


    [TestMethod]
    public void SigmaFunctionsEvaluateBitExactAcrossCopies()
    {
        GkrCircuit circuit = BuildSigmaCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..InputBytes];
        PackInputs(inputs);
        using GkrWireTables tables = circuit.EvaluateDataParallel(inputs, CopyCount, GkrTestSupport.Add, GkrTestSupport.Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);

        for(int c = 0; c < CopyCount; c++)
        {
            ReadOnlySpan<byte> copyOutputs = tables.Table(0).Span.Slice(c * OutputCount * ScalarSize, OutputCount * ScalarSize);
            for(int f = 0; f < FunctionCount; f++)
            {
                uint expected = Oracle(Words[c], Taps[f]);
                for(int bit = 0; bit < WordBits; bit++)
                {
                    int actual = copyOutputs[((((f * WordBits) + bit) * ScalarSize)) + ScalarSize - 1];
                    Assert.AreEqual((int)((expected >> bit) & 1), actual, $"Copy {c} function {f} bit {bit} must match the uint oracle.");
                }
            }
        }
    }


    [TestMethod]
    public void CommittedSigmaProofVerifiesWithoutTheWitnessBits()
    {
        GkrCircuit circuit = BuildSigmaCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..InputBytes];
        PackInputs(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..OutputBytes];
        GkrTestSupport.Outputs(circuit, inputs, CopyCount, outputs);

        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrCommittedProof proof = GkrTestSupport.Prove(circuit, inputs, CopyCount, RandomnessSeed, proverTranscript);

        using FiatShamirTranscript verifierTranscript = NewTranscript();
        bool verified = GkrTestSupport.Verify(circuit, outputs, CopyCount, proof, verifierTranscript);

        Assert.IsTrue(verified, "Eight committed copies of all four sigma functions must prove and verify with only the output bits public.");
    }


    [TestMethod]
    public void WrongSigmaOutputsAreRejected()
    {
        GkrCircuit circuit = BuildSigmaCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..InputBytes];
        PackInputs(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..OutputBytes];
        GkrTestSupport.Outputs(circuit, inputs, CopyCount, outputs);

        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrCommittedProof proof = GkrTestSupport.Prove(circuit, inputs, CopyCount, RandomnessSeed, proverTranscript);

        //Flip one output bit of one copy.
        outputs[ScalarSize - 1] ^= 0x01;

        using FiatShamirTranscript verifierTranscript = NewTranscript();
        bool verified = GkrTestSupport.Verify(circuit, outputs, CopyCount, proof, verifierTranscript);

        Assert.IsFalse(verified, "A flipped sigma output bit must be rejected.");
    }


    //Bit i of ROTR(x, r) is bit (i + r) mod 32 of x; bit i of x >> s is bit i + s when it exists.
    private static GkrCircuit BuildSigmaCircuit()
    {
        var inner = new List<GkrLayerTerm>();
        for(int f = 0; f < FunctionCount; f++)
        {
            for(int i = 0; i < WordBits; i++)
            {
                int output = (f * WordBits) + i;
                int u = (i + Taps[f].First) & (WordBits - 1);
                int v = (i + Taps[f].Second) & (WordBits - 1);
                inner.Add(new GkrLayerTerm(output, u, InputOneWire, One));
                inner.Add(new GkrLayerTerm(output, v, InputOneWire, One));
                inner.Add(new GkrLayerTerm(output, u, v, NegativeTwo));
            }
        }

        for(int i = 0; i < WordBits; i++)
        {
            inner.Add(new GkrLayerTerm(PassthroughBase + i, i, InputOneWire, One));
        }

        inner.Add(new GkrLayerTerm(InnerOneWire, InputOneWire, InputOneWire, One));

        var outer = new List<GkrLayerTerm>();
        for(int f = 0; f < FunctionCount; f++)
        {
            for(int i = 0; i < WordBits; i++)
            {
                int output = (f * WordBits) + i;
                int w = (f * WordBits) + i;
                int third = i + Taps[f].Third;
                if(Taps[f].ThirdIsShift && third >= WordBits)
                {
                    outer.Add(new GkrLayerTerm(output, w, InnerOneWire, One));
                    continue;
                }

                int z = PassthroughBase + (third & (WordBits - 1));
                outer.Add(new GkrLayerTerm(output, w, InnerOneWire, One));
                outer.Add(new GkrLayerTerm(output, z, InnerOneWire, One));
                outer.Add(new GkrLayerTerm(output, w, z, NegativeTwo));
            }
        }

        return new GkrCircuit([new GkrLayer([.. outer], OutputCount), new GkrLayer([.. inner], InnerWidth)], InputCount);
    }


    //Per copy: the bits of the word (least-significant first), the constant-one wire, zero padding.
    private static void PackInputs(Span<byte> inputs)
    {
        inputs.Clear();
        for(int c = 0; c < CopyCount; c++)
        {
            Span<byte> copy = inputs.Slice(c * InputCount * ScalarSize, InputCount * ScalarSize);
            for(int bit = 0; bit < WordBits; bit++)
            {
                copy[(bit * ScalarSize) + ScalarSize - 1] = (byte)((Words[c] >> bit) & 1);
            }

            copy[(InputOneWire * ScalarSize) + ScalarSize - 1] = 1;
        }
    }


    private static uint Oracle(uint word, (int First, int Second, int Third, bool ThirdIsShift) taps)
    {
        uint third = taps.ThirdIsShift ? word >> taps.Third : uint.RotateRight(word, taps.Third);

        return uint.RotateRight(word, taps.First) ^ uint.RotateRight(word, taps.Second) ^ third;
    }


    private static FiatShamirTranscript NewTranscript() =>
        GkrTestSupport.NewTranscript(Domain, "veridical.gkr.sha.sigma.seed"u8);
}
