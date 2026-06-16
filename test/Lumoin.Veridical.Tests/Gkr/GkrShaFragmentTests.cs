using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The SHA-256 bitwise word functions through the committed GKR engine. The choose function
/// <c>Ch(e, f, g) = (e ∧ f) ⊕ (¬e ∧ g)</c> is <c>e·f + g − e·g</c> per bit over a prime field —
/// one GKR layer of three terms per output bit. The majority function
/// <c>Maj(a, b, c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)</c> is degree three in the bits, so it takes two
/// layers via <c>Maj = a·b + c·(a ⊕ b)</c>: the inner layer forms the product and the XOR, the
/// output layer recombines. Eight independent word triples run as data-parallel copies with the
/// copy variable bound once, the bit wires committed (private), and only the 32 output bits
/// public. This is the translation pattern the full SHA-256 uses in Longfellow: round boundaries
/// are witnessed at the input layer, so the 64 round checks — each a shallow circuit like these —
/// become independent data-parallel copies. Gated bit-exact against the plain uint computation.
/// </summary>
[TestClass]
internal sealed class GkrShaFragmentTests
{
    private const int ScalarSize = GkrTestSupport.ScalarSize;
    private const int WordBits = 32;
    private const int CopyCount = 8;

    //Per copy: the 96 bit wires of the three words, then the constant-one wire, padded to 128.
    private const int InputCount = 128;
    private const int OneWire = 96;
    private const int InputBytes = CopyCount * InputCount * ScalarSize;
    private const int OutputBytes = CopyCount * WordBits * ScalarSize;

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.sha.ch.test");

    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.sha.ch.rng.v1");

    private static byte[] One { get; } = GkrTestSupport.One;

    private static byte[] NegativeOne { get; } = GkrTestSupport.NegativeOne;

    private static byte[] NegativeTwo { get; } = GkrTestSupport.NegativeTwo;

    //Eight word triples — real SHA-256 working-variable shapes.
    private static uint[][] Words { get; } =
    [
        [0x510e527f, 0x9b05688c, 0x1f83d9ab],
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372],
        [0xdeadbeef, 0xcafebabe, 0x01234567],
        [0xffffffff, 0x00000000, 0xaaaaaaaa],
        [0x00000000, 0xffffffff, 0x55555555],
        [0x428a2f98, 0x71374491, 0xb5c0fbcf],
        [0x80000000, 0x00000001, 0x7fffffff],
        [0x12345678, 0x9abcdef0, 0x0fedcba9],
    ];


    [TestMethod]
    public void ChooseFunctionEvaluatesBitExactAcrossCopies()
    {
        GkrCircuit circuit = BuildChooseCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..InputBytes];
        PackInputs(inputs);

        AssertWordOutputs(circuit, inputs, static words => (words[0] & words[1]) ^ (~words[0] & words[2]), "Ch");
    }


    [TestMethod]
    public void CommittedChooseProofVerifiesWithoutTheWitnessBits()
    {
        GkrCircuit circuit = BuildChooseCircuit();
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

        Assert.IsTrue(verified, "Eight committed Ch copies must prove and verify with only the output bits public.");
    }


    [TestMethod]
    public void WrongChooseOutputsAreRejected()
    {
        GkrCircuit circuit = BuildChooseCircuit();
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

        Assert.IsFalse(verified, "A flipped Ch output bit must be rejected.");
    }


    [TestMethod]
    public void MajorityFunctionEvaluatesBitExactAcrossCopies()
    {
        GkrCircuit circuit = BuildMajorityCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..InputBytes];
        PackInputs(inputs);

        AssertWordOutputs(circuit, inputs, static words => (words[0] & words[1]) ^ (words[0] & words[2]) ^ (words[1] & words[2]), "Maj");
    }


    [TestMethod]
    public void CommittedMajorityProofVerifiesWithoutTheWitnessBits()
    {
        GkrCircuit circuit = BuildMajorityCircuit();
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

        Assert.IsTrue(verified, "Eight committed two-layer Maj copies must prove and verify with only the output bits public.");
    }


    [TestMethod]
    public void WrongMajorityOutputsAreRejected()
    {
        GkrCircuit circuit = BuildMajorityCircuit();
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

        Assert.IsFalse(verified, "A flipped Maj output bit must be rejected.");
    }


    //One layer, three terms per output bit i: e_i·f_i + g_i·1 − e_i·g_i.
    private static GkrCircuit BuildChooseCircuit()
    {
        var terms = new GkrLayerTerm[3 * WordBits];
        for(int i = 0; i < WordBits; i++)
        {
            terms[3 * i] = new GkrLayerTerm(i, i, WordBits + i, One);
            terms[(3 * i) + 1] = new GkrLayerTerm(i, (2 * WordBits) + i, OneWire, One);
            terms[(3 * i) + 2] = new GkrLayerTerm(i, i, (2 * WordBits) + i, NegativeOne);
        }

        return new GkrCircuit([new GkrLayer(terms, WordBits)], InputCount);
    }


    //Two layers. The inner layer mirrors the input layout (so the one wire stays at the same
    //index): p_i = a_i·b_i at i, q_i = a_i + b_i − 2·a_i·b_i = a_i ⊕ b_i at 32 + i, the c bits and
    //the one wire passed through. The output layer recombines: Maj_i = p_i + c_i·q_i — when
    //a_i = b_i the XOR vanishes and the majority is a_i·b_i, otherwise the product vanishes and
    //the majority is c_i.
    private static GkrCircuit BuildMajorityCircuit()
    {
        var inner = new GkrLayerTerm[(5 * WordBits) + 1];
        for(int i = 0; i < WordBits; i++)
        {
            inner[5 * i] = new GkrLayerTerm(i, i, WordBits + i, One);
            inner[(5 * i) + 1] = new GkrLayerTerm(WordBits + i, i, OneWire, One);
            inner[(5 * i) + 2] = new GkrLayerTerm(WordBits + i, WordBits + i, OneWire, One);
            inner[(5 * i) + 3] = new GkrLayerTerm(WordBits + i, i, WordBits + i, NegativeTwo);
            inner[(5 * i) + 4] = new GkrLayerTerm((2 * WordBits) + i, (2 * WordBits) + i, OneWire, One);
        }

        inner[5 * WordBits] = new GkrLayerTerm(OneWire, OneWire, OneWire, One);

        var outer = new GkrLayerTerm[2 * WordBits];
        for(int i = 0; i < WordBits; i++)
        {
            outer[2 * i] = new GkrLayerTerm(i, i, OneWire, One);
            outer[(2 * i) + 1] = new GkrLayerTerm(i, (2 * WordBits) + i, WordBits + i, One);
        }

        return new GkrCircuit([new GkrLayer(outer, WordBits), new GkrLayer(inner, InputCount)], InputCount);
    }


    //Per copy: the bits of the three words (least-significant first), the constant-one wire,
    //zero padding.
    private static void PackInputs(Span<byte> inputs)
    {
        inputs.Clear();
        for(int c = 0; c < CopyCount; c++)
        {
            Span<byte> copy = inputs.Slice(c * InputCount * ScalarSize, InputCount * ScalarSize);
            for(int word = 0; word < 3; word++)
            {
                for(int bit = 0; bit < WordBits; bit++)
                {
                    copy[(((word * WordBits) + bit) * ScalarSize) + ScalarSize - 1] = (byte)((Words[c][word] >> bit) & 1);
                }
            }

            copy[(OneWire * ScalarSize) + ScalarSize - 1] = 1;
        }
    }


    private static void AssertWordOutputs(GkrCircuit circuit, ReadOnlySpan<byte> inputs, Func<uint[], uint> oracle, string name)
    {
        using GkrWireTables tables = circuit.EvaluateDataParallel(inputs, CopyCount, GkrTestSupport.Add, GkrTestSupport.Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);

        for(int c = 0; c < CopyCount; c++)
        {
            uint expected = oracle(Words[c]);
            ReadOnlySpan<byte> copyOutputs = tables.Table(0).Span.Slice(c * WordBits * ScalarSize, WordBits * ScalarSize);
            for(int bit = 0; bit < WordBits; bit++)
            {
                int actual = copyOutputs[(bit * ScalarSize) + ScalarSize - 1];
                Assert.AreEqual((int)((expected >> bit) & 1), actual, $"Copy {c} bit {bit} of {name} must match the uint oracle.");
            }
        }
    }


    private static FiatShamirTranscript NewTranscript() =>
        GkrTestSupport.NewTranscript(Domain, "veridical.gkr.sha.ch.seed"u8);
}
