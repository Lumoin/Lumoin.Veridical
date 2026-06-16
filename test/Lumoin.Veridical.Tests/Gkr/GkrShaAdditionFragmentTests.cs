using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// SHA-256 modular addition through the committed GKR engine: <c>s = a + b mod 2³²</c> checked
/// column by column over witnessed sum and carry bits — column i emits
/// <c>a_i + b_i + c_i − s_i − 2·c_{i+1}</c> as a public-must-be-zero output (the final carry is
/// witnessed and discarded, which is exactly the mod 2³² reduction). Every newly witnessed bit is
/// pinned by a bitness check <c>b·b − b</c>, also a public-must-be-zero output. Because all the
/// constraint outputs of an honest witness are zero, the constant-one wire must itself be pinned:
/// it passes through to a public output that must equal 1, otherwise committing zero there would
/// satisfy every linear term vacuously. The digit-two test shows the bitness outputs are
/// load-bearing: a witness encoding <c>s_0 = 2</c> satisfies every column equation of a different
/// (wrong) sum, and only the bitness check rejects it. One layer, eight additions as data-parallel
/// copies, operands and sum and carries all committed (private).
/// </summary>
[TestClass]
internal sealed class GkrShaAdditionFragmentTests
{
    private const int ScalarSize = GkrTestSupport.ScalarSize;
    private const int WordBits = 32;
    private const int CopyCount = 8;

    //Per copy: the bits of a, b, s, then the 32 carry bits (wire CarryBase + i carries out of
    //column i), the constant-one wire, padded to 256.
    private const int InputCount = 256;
    private const int SumBase = 2 * WordBits;
    private const int CarryBase = 3 * WordBits;
    private const int OneWire = 4 * WordBits;

    //Outputs: the 32 column checks, the 32 sum bitness checks, the 32 carry bitness checks (all
    //must be zero), the one-wire pass at OneOutput (must be 1), padded to 128.
    private const int OutputCount = 128;
    private const int SumBitnessBase = WordBits;
    private const int CarryBitnessBase = 2 * WordBits;
    private const int OneOutput = 3 * WordBits;
    private const int InputBytes = CopyCount * InputCount * ScalarSize;
    private const int OutputBytes = CopyCount * OutputCount * ScalarSize;

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.sha.add.test");

    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.sha.add.rng.v1");

    private static byte[] One { get; } = GkrTestSupport.One;

    private static byte[] NegativeOne { get; } = GkrTestSupport.NegativeOne;

    private static byte[] NegativeTwo { get; } = GkrTestSupport.NegativeTwo;

    //Eight operand pairs; index 2 is the all-ones pair the digit-two test rebuilds.
    private static uint[][] Pairs { get; } =
    [
        [0x6a09e667, 0x510e527f],
        [0xffffffff, 0x00000001],
        [0xffffffff, 0xffffffff],
        [0x00000000, 0x00000000],
        [0x80000000, 0x80000000],
        [0x12345678, 0x9abcdef0],
        [0x7fffffff, 0x00000001],
        [0xdeadbeef, 0x21524111],
    ];

    private const int CheatCopy = 2;


    [TestMethod]
    public void AdditionConstraintsEvaluateToZeroForAnHonestWitness()
    {
        GkrCircuit circuit = BuildAdditionCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..InputBytes];
        PackInputs(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..OutputBytes];
        GkrTestSupport.Outputs(circuit, inputs, CopyCount, outputs);
        using IMemoryOwner<byte> expectedOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> expected = expectedOwner.Memory.Span[..OutputBytes];
        ExpectedOutputs(expected);

        Assert.IsTrue(outputs.SequenceEqual(expected), "An honest witnessed-carry addition must zero every column and bitness output and pass the one wire through.");
    }


    [TestMethod]
    public void CommittedAdditionProofVerifiesWithoutTheWitness()
    {
        GkrCircuit circuit = BuildAdditionCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..InputBytes];
        PackInputs(inputs);
        using IMemoryOwner<byte> expectedOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> expected = expectedOwner.Memory.Span[..OutputBytes];
        ExpectedOutputs(expected);

        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrCommittedProof proof = GkrTestSupport.Prove(circuit, inputs, CopyCount, RandomnessSeed, proverTranscript);

        using FiatShamirTranscript verifierTranscript = NewTranscript();
        bool verified = GkrTestSupport.Verify(circuit, expected, CopyCount, proof, verifierTranscript);

        Assert.IsTrue(verified, "Eight committed witnessed-carry additions must prove and verify against the public zero outputs.");
    }


    [TestMethod]
    public void ADigitTwoSumWitnessIsRejectedByTheBitnessCheck()
    {
        //On the all-ones pair, column 0 is 1 + 1 + 0 = s_0 + 2·c_1 — the honest witness takes
        //s_0 = 0, c_1 = 1, the cheat takes s_0 = 2, c_1 = 0 and re-balances column 1, encoding a
        //sum that is not the mod-2³² result. Every column equation still holds.
        GkrCircuit circuit = BuildAdditionCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..InputBytes];
        PackInputs(inputs);
        SetWire(inputs, CheatCopy, SumBase, GkrTestSupport.Scalar(2));
        SetWire(inputs, CheatCopy, CarryBase, GkrTestSupport.Scalar(0));
        SetWire(inputs, CheatCopy, SumBase + 1, GkrTestSupport.Scalar(0));

        using IMemoryOwner<byte> cheatOutputsOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> cheatOutputs = cheatOutputsOwner.Memory.Span[..OutputBytes];
        GkrTestSupport.Outputs(circuit, inputs, CopyCount, cheatOutputs);
        ReadOnlySpan<byte> cheatCopy = cheatOutputs.Slice(CheatCopy * OutputCount * ScalarSize, OutputCount * ScalarSize);
        Assert.IsFalse(cheatCopy[..(WordBits * ScalarSize)].ContainsAnyExcept((byte)0), "Every column equation must still hold for the digit-two encoding — the columns alone do not pin the sum.");
        Assert.IsTrue(cheatCopy.Slice(SumBitnessBase * ScalarSize, ScalarSize).ContainsAnyExcept((byte)0), "The bitness check of s_0 must be the output that fires.");

        using IMemoryOwner<byte> expectedOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> expected = expectedOwner.Memory.Span[..OutputBytes];
        ExpectedOutputs(expected);

        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrCommittedProof proof = GkrTestSupport.Prove(circuit, inputs, CopyCount, RandomnessSeed, proverTranscript);

        using FiatShamirTranscript verifierTranscript = NewTranscript();
        bool verified = GkrTestSupport.Verify(circuit, expected, CopyCount, proof, verifierTranscript);

        Assert.IsFalse(verified, "A sum witness with a digit two must be rejected by the bitness outputs.");
    }


    [TestMethod]
    public void AFlippedCarryWitnessIsRejected()
    {
        GkrCircuit circuit = BuildAdditionCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..InputBytes];
        PackInputs(inputs);
        int wire = CarryBase + 7;
        byte current = inputs[(((CheatCopy * InputCount) + wire) * ScalarSize) + ScalarSize - 1];
        SetWire(inputs, CheatCopy, wire, GkrTestSupport.Scalar(1 - current));

        using IMemoryOwner<byte> expectedOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> expected = expectedOwner.Memory.Span[..OutputBytes];
        ExpectedOutputs(expected);

        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrCommittedProof proof = GkrTestSupport.Prove(circuit, inputs, CopyCount, RandomnessSeed, proverTranscript);

        using FiatShamirTranscript verifierTranscript = NewTranscript();
        bool verified = GkrTestSupport.Verify(circuit, expected, CopyCount, proof, verifierTranscript);

        Assert.IsFalse(verified, "A flipped carry bit must be rejected by the column checks.");
    }


    [TestMethod]
    public void AZeroedConstantOneWireIsRejected()
    {
        //With the one wire committed as zero every linear term vanishes, so all the constraint
        //outputs read zero no matter the witness — the public 1 at the pass-through output is
        //what makes that encoding unprovable.
        GkrCircuit circuit = BuildAdditionCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..InputBytes];
        PackInputs(inputs);
        SetWire(inputs, CheatCopy, OneWire, GkrTestSupport.Scalar(0));

        using IMemoryOwner<byte> expectedOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> expected = expectedOwner.Memory.Span[..OutputBytes];
        ExpectedOutputs(expected);

        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrCommittedProof proof = GkrTestSupport.Prove(circuit, inputs, CopyCount, RandomnessSeed, proverTranscript);

        using FiatShamirTranscript verifierTranscript = NewTranscript();
        bool verified = GkrTestSupport.Verify(circuit, expected, CopyCount, proof, verifierTranscript);

        Assert.IsFalse(verified, "A zeroed constant-one wire must be rejected by the pinned pass-through output.");
    }


    //One layer. Column i: a_i + b_i + c_i − s_i − 2·c_{i+1}, all linear through the one wire
    //(column 0 has no carry in). Bitness: s_i² − s_i and carry² − carry. The one wire passes
    //through to a public output.
    private static GkrCircuit BuildAdditionCircuit()
    {
        var terms = new List<GkrLayerTerm>();
        for(int i = 0; i < WordBits; i++)
        {
            terms.Add(new GkrLayerTerm(i, i, OneWire, One));
            terms.Add(new GkrLayerTerm(i, WordBits + i, OneWire, One));
            if(i > 0)
            {
                terms.Add(new GkrLayerTerm(i, CarryBase + i - 1, OneWire, One));
            }

            terms.Add(new GkrLayerTerm(i, SumBase + i, OneWire, NegativeOne));
            terms.Add(new GkrLayerTerm(i, CarryBase + i, OneWire, NegativeTwo));

            terms.Add(new GkrLayerTerm(SumBitnessBase + i, SumBase + i, SumBase + i, One));
            terms.Add(new GkrLayerTerm(SumBitnessBase + i, SumBase + i, OneWire, NegativeOne));

            terms.Add(new GkrLayerTerm(CarryBitnessBase + i, CarryBase + i, CarryBase + i, One));
            terms.Add(new GkrLayerTerm(CarryBitnessBase + i, CarryBase + i, OneWire, NegativeOne));
        }

        terms.Add(new GkrLayerTerm(OneOutput, OneWire, OneWire, One));

        return new GkrCircuit([new GkrLayer([.. terms], OutputCount)], InputCount);
    }


    //Per copy: the bits of a, b, the honest sum bits and carry bits of the schoolbook addition
    //(least-significant first), the constant-one wire, zero padding.
    private static void PackInputs(Span<byte> inputs)
    {
        inputs.Clear();
        for(int c = 0; c < CopyCount; c++)
        {
            Span<byte> copy = inputs.Slice(c * InputCount * ScalarSize, InputCount * ScalarSize);
            int carry = 0;
            for(int i = 0; i < WordBits; i++)
            {
                int a = (int)((Pairs[c][0] >> i) & 1);
                int b = (int)((Pairs[c][1] >> i) & 1);
                int column = a + b + carry;
                carry = column >> 1;
                copy[(i * ScalarSize) + ScalarSize - 1] = (byte)a;
                copy[((WordBits + i) * ScalarSize) + ScalarSize - 1] = (byte)b;
                copy[((SumBase + i) * ScalarSize) + ScalarSize - 1] = (byte)(column & 1);
                copy[((CarryBase + i) * ScalarSize) + ScalarSize - 1] = (byte)carry;
            }

            copy[(OneWire * ScalarSize) + ScalarSize - 1] = 1;
        }
    }


    //All constraint outputs zero, the one-wire pass-through 1, per copy.
    private static void ExpectedOutputs(Span<byte> outputs)
    {
        outputs.Clear();
        for(int c = 0; c < CopyCount; c++)
        {
            outputs[(((c * OutputCount) + OneOutput) * ScalarSize) + ScalarSize - 1] = 1;
        }
    }


    private static void SetWire(Span<byte> inputs, int copy, int wire, ReadOnlySpan<byte> value) =>
        value.CopyTo(inputs.Slice((((copy * InputCount) + wire) * ScalarSize), ScalarSize));


    private static FiatShamirTranscript NewTranscript() =>
        GkrTestSupport.NewTranscript(Domain, "veridical.gkr.sha.add.seed"u8);
}
