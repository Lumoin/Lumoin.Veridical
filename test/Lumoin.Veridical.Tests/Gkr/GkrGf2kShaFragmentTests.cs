using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The SHA-256 building blocks re-arithmetized for characteristic two, through the committed GKR
/// engine over <c>GF(2^128)</c>. Everything gets shallower than the Fp256 circuits:
/// <list type="bullet">
/// <item>Maj collapses to ONE layer — over the integers it is <c>ab + ac + bc − 2abc</c> (degree
/// three, two layers in Fp256); modulo two the last term vanishes, leaving three quadratic
/// terms.</item>
/// <item>Σ0/Σ1/σ0/σ1 collapse to LINEAR — XOR3 is field addition, one layer of square terms
/// (a committed bit passes as its own square), no XOR-pair intermediate layers.</item>
/// <item>The modular addition loses the radix-4 columns entirely: the full adder is
/// <c>s_i = a_i + b_i + c_i</c> — EXACT as field addition — and the carry is the majority
/// relation <c>c_{i+1} = a_i·b_i + a_i·c_i + b_i·c_i</c>, witnessed single-bit carries checked
/// as public-zero outputs. <c>c_0 = 0</c> is structural (no wire) and the final carry is simply
/// never used, which is precisely the mod-2³² truncation.</item>
/// </list>
/// Bitness of every witnessed bit rides as quadratic commitment constraints, as in the Fp256
/// circuits. Gated bit-exact against the plain uint computation; the adder's flipped-carry
/// attack is rejected by the walk (the carry check fires) and its digit-two sum by the
/// commitment's bitness rows.
/// </summary>
[TestClass]
internal sealed class GkrGf2kShaFragmentTests
{
    private const int ScalarSize = GkrGf2kTestSupport.ScalarSize;
    private const int WordBits = 32;
    private const int CopyCount = 8;

    //The Maj fragment: per copy the bits of a, b, c, zero-padded to 128.
    private const int MajorityInputCount = 128;
    private const int MajorityInputBytes = CopyCount * MajorityInputCount * ScalarSize;
    private const int MajorityOutputBytes = CopyCount * WordBits * ScalarSize;

    //The sigma fragment: per copy the 32 bits of one word; all four functions in one circuit.
    private const int SigmaInputCount = 32;
    private const int FunctionCount = 4;
    private const int SigmaOutputCount = FunctionCount * WordBits;
    private const int SigmaInputBytes = CopyCount * SigmaInputCount * ScalarSize;
    private const int SigmaOutputBytes = CopyCount * SigmaOutputCount * ScalarSize;

    //The adder fragment: per copy the bits of a, b, the witnessed sum s and the witnessed
    //carries c_1..c_31 (wire CarryWire + k holds c_{k+1}), zero-padded to 128.
    private const int AdderInputCount = 128;
    private const int AdderSumWire = 64;
    private const int AdderCarryWire = 96;
    private const int AdderCarryCount = WordBits - 1;
    private const int AdderOutputCount = 64;
    private const int AdderCarryCheckBase = WordBits;
    private const int AdderInputBytes = CopyCount * AdderInputCount * ScalarSize;
    private const int AdderOutputBytes = CopyCount * AdderOutputCount * ScalarSize;

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.gf2k.sha.test");

    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.gf2k.sha.rng.v1");

    private static byte[] One { get; } = GkrGf2kTestSupport.One;

    //Eight word triples — real SHA-256 working-variable shapes. The sigma fragment uses the
    //first word of each triple; the adder adds the first two.
    private static uint[][] Words { get; } =
    [
        [0x510e527f, 0x9b05688c, 0x1f83d9ab],
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372],
        [0xdeadbeef, 0xcafebabe, 0x01234567],
        [0xffffffff, 0x00000000, 0xaaaaaaaa],
        [0x00000000, 0xffffffff, 0x55555555],
        [0x428a2f98, 0x71374491, 0xb5c0fbcf],
        [0x80000000, 0x00000001, 0x7fffffff],
        [0xffffffff, 0xffffffff, 0x0fedcba9],
    ];

    //(first, second) rotation taps and a third tap that is a rotation for Σ and a shift for σ.
    private static (int First, int Second, int Third, bool ThirdIsShift)[] Taps { get; } =
    [
        (2, 13, 22, false),
        (6, 11, 25, false),
        (7, 18, 3, true),
        (17, 19, 10, true),
    ];


    [TestMethod]
    public void MajorityIsOneLayerOverTheBinaryField()
    {
        GkrCircuit circuit = BuildMajorityCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(MajorityInputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..MajorityInputBytes];
        PackMajorityInputs(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(MajorityOutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..MajorityOutputBytes];
        GkrGf2kTestSupport.Outputs(circuit, inputs, CopyCount, outputs);

        for(int c = 0; c < CopyCount; c++)
        {
            uint expected = (Words[c][0] & Words[c][1]) ^ (Words[c][0] & Words[c][2]) ^ (Words[c][1] & Words[c][2]);
            AssertWordBits(outputs.Slice(c * WordBits * ScalarSize, WordBits * ScalarSize), expected, $"Copy {c} of Maj");
        }
    }


    [TestMethod]
    public void CommittedMajorityVerifiesOverTheBinaryField()
    {
        GkrCircuit circuit = BuildMajorityCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(MajorityInputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..MajorityInputBytes];
        PackMajorityInputs(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(MajorityOutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..MajorityOutputBytes];
        GkrGf2kTestSupport.Outputs(circuit, inputs, CopyCount, outputs);

        using FiatShamirTranscript proverTranscript = NewTranscript(inputs);
        LigeroQuadraticConstraint[] bitness = BuildBitness(MajorityInputCount, 0, 3 * WordBits);
        using GkrCommittedProof proof = GkrGf2kTestSupport.Prove(circuit, inputs, CopyCount, RandomnessSeed, proverTranscript, bitness);

        using(FiatShamirTranscript verifierTranscript = NewTranscript(inputs))
        {
            Assert.IsTrue(
                GkrGf2kTestSupport.Verify(circuit, outputs, CopyCount, proof, verifierTranscript, bitness),
                "The committed one-layer Maj must verify over GF(2^128).");
        }

        outputs[ScalarSize - 1] ^= 0x01;
        using(FiatShamirTranscript verifierTranscript = NewTranscript(inputs))
        {
            Assert.IsFalse(
                GkrGf2kTestSupport.Verify(circuit, outputs, CopyCount, proof, verifierTranscript, bitness),
                "A flipped Maj output bit must be rejected.");
        }
    }


    [TestMethod]
    public void SigmaFunctionsAreLinearOverTheBinaryField()
    {
        GkrCircuit circuit = BuildSigmaCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(SigmaInputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..SigmaInputBytes];
        PackSigmaInputs(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(SigmaOutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..SigmaOutputBytes];
        GkrGf2kTestSupport.Outputs(circuit, inputs, CopyCount, outputs);

        for(int c = 0; c < CopyCount; c++)
        {
            for(int f = 0; f < FunctionCount; f++)
            {
                uint third = Taps[f].ThirdIsShift ? Words[c][0] >> Taps[f].Third : uint.RotateRight(Words[c][0], Taps[f].Third);
                uint expected = uint.RotateRight(Words[c][0], Taps[f].First) ^ uint.RotateRight(Words[c][0], Taps[f].Second) ^ third;
                AssertWordBits(outputs.Slice(((c * SigmaOutputCount) + (f * WordBits)) * ScalarSize, WordBits * ScalarSize), expected, $"Copy {c} function {f}");
            }
        }
    }


    [TestMethod]
    public void CommittedSigmaVerifiesOverTheBinaryField()
    {
        //This circuit's output layer (128) is wider than its input layer (32) — the shape that
        //exposed the verifier's scratch-sizing bug.
        GkrCircuit circuit = BuildSigmaCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(SigmaInputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..SigmaInputBytes];
        PackSigmaInputs(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(SigmaOutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..SigmaOutputBytes];
        GkrGf2kTestSupport.Outputs(circuit, inputs, CopyCount, outputs);

        using FiatShamirTranscript proverTranscript = NewTranscript(inputs);
        LigeroQuadraticConstraint[] bitness = BuildBitness(SigmaInputCount, 0, WordBits);
        using GkrCommittedProof proof = GkrGf2kTestSupport.Prove(circuit, inputs, CopyCount, RandomnessSeed, proverTranscript, bitness);

        using(FiatShamirTranscript verifierTranscript = NewTranscript(inputs))
        {
            Assert.IsTrue(
                GkrGf2kTestSupport.Verify(circuit, outputs, CopyCount, proof, verifierTranscript, bitness),
                "The committed single-layer sigma functions must verify over GF(2^128).");
        }

        outputs[ScalarSize - 1] ^= 0x01;
        using(FiatShamirTranscript verifierTranscript = NewTranscript(inputs))
        {
            Assert.IsFalse(
                GkrGf2kTestSupport.Verify(circuit, outputs, CopyCount, proof, verifierTranscript, bitness),
                "A flipped sigma output bit must be rejected.");
        }
    }


    [TestMethod]
    public void TheFullAdderClosesOverTheBinaryField()
    {
        GkrCircuit circuit = BuildAdderCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(AdderInputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..AdderInputBytes];
        PackAdderInputs(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(AdderOutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..AdderOutputBytes];
        GkrGf2kTestSupport.Outputs(circuit, inputs, CopyCount, outputs);

        Assert.IsFalse(outputs.ContainsAnyExcept((byte)0), "Every sum and carry check of an honest witnessed-carry addition must close to zero.");
    }


    [TestMethod]
    public void CommittedAdderVerifiesOverTheBinaryField()
    {
        GkrCircuit circuit = BuildAdderCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(AdderInputBytes);
        Memory<byte> inputs = inputsOwner.Memory[..AdderInputBytes];
        PackAdderInputs(inputs.Span);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(AdderOutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..AdderOutputBytes];
        GkrGf2kTestSupport.Outputs(circuit, inputs.Span, CopyCount, outputs);

        LigeroQuadraticConstraint[] bitness = BuildBitness(AdderInputCount, 0, AdderSumWire + WordBits + AdderCarryCount);
        using(FiatShamirTranscript proverTranscript = NewTranscript(inputs.Span))
        {
            using GkrCommittedProof proof = GkrGf2kTestSupport.Prove(circuit, inputs.Span, CopyCount, RandomnessSeed, proverTranscript, bitness);

            using(FiatShamirTranscript verifierTranscript = NewTranscript(inputs.Span))
            {
                Assert.IsTrue(
                    GkrGf2kTestSupport.Verify(circuit, outputs, CopyCount, proof, verifierTranscript, bitness),
                    "The committed witnessed-carry addition must verify over GF(2^128).");
            }

            //A flipped carry stays a bit (the bitness rows pass) but breaks its carry check —
            //the walk must reject the all-zero output claim.
            inputs.Span[(((AdderCarryWire + 7) * ScalarSize) + ScalarSize) - 1] ^= 0x01;
            using FiatShamirTranscript tamperedProverTranscript = NewTranscript(inputs.Span);
            using GkrCommittedProof tamperedProof = GkrGf2kTestSupport.Prove(circuit, inputs.Span, CopyCount, RandomnessSeed, tamperedProverTranscript, bitness);
            using(FiatShamirTranscript verifierTranscript = NewTranscript(inputs.Span))
            {
                Assert.IsFalse(
                    GkrGf2kTestSupport.Verify(circuit, outputs, CopyCount, tamperedProof, verifierTranscript, bitness),
                    "A flipped carry must fail its majority check against the zero outputs.");
            }
        }

        //A digit-two sum wire violates the commitment's bitness rows: unprovable.
        PackAdderInputs(inputs.Span);
        inputs.Span[((AdderSumWire * ScalarSize) + ScalarSize) - 1] = 2;
        using FiatShamirTranscript digitTwoTranscript = NewTranscript(inputs.Span);
        Assert.ThrowsExactly<InvalidOperationException>(
            () => GkrGf2kTestSupport.Prove(circuit, inputs.Span, CopyCount, RandomnessSeed, digitTwoTranscript, bitness).Dispose(),
            "A non-bit sum digit must violate the quadratic bitness constraints of the commitment.");
    }


    //Maj = a·b + a·c + b·c — over the integers the majority carries a −2abc term needing a
    //second layer; modulo two it vanishes.
    private static GkrCircuit BuildMajorityCircuit()
    {
        var terms = new List<GkrLayerTerm>();
        for(int i = 0; i < WordBits; i++)
        {
            terms.Add(new GkrLayerTerm(i, i, WordBits + i, One));
            terms.Add(new GkrLayerTerm(i, i, (2 * WordBits) + i, One));
            terms.Add(new GkrLayerTerm(i, WordBits + i, (2 * WordBits) + i, One));
        }

        return new GkrCircuit([new GkrLayer([.. terms], WordBits)], MajorityInputCount);
    }


    //All four sigma functions of one word in one single layer: each output bit is the field sum
    //of its two or three taps, every tap a committed bit passing as its own square.
    private static GkrCircuit BuildSigmaCircuit()
    {
        var terms = new List<GkrLayerTerm>();
        for(int f = 0; f < FunctionCount; f++)
        {
            for(int i = 0; i < WordBits; i++)
            {
                int output = (f * WordBits) + i;
                AddTap(terms, output, (i + Taps[f].First) & (WordBits - 1));
                AddTap(terms, output, (i + Taps[f].Second) & (WordBits - 1));
                if(Taps[f].ThirdIsShift)
                {
                    if(i + Taps[f].Third < WordBits)
                    {
                        AddTap(terms, output, i + Taps[f].Third);
                    }
                }
                else
                {
                    AddTap(terms, output, (i + Taps[f].Third) & (WordBits - 1));
                }
            }
        }

        return new GkrCircuit([new GkrLayer([.. terms], SigmaOutputCount)], SigmaInputCount);

        static void AddTap(List<GkrLayerTerm> terms, int output, int tap) =>
            terms.Add(new GkrLayerTerm(output, tap, tap, One));
    }


    //One layer of full-adder checks: sum check i is s_i + a_i + b_i + c_i (carry absent for
    //i = 0), carry check k is c_{k+1} + a_k·b_k + a_k·c_k + b_k·c_k (the c_k products absent
    //for k = 0) — all public-must-be-zero, addition and subtraction being the same map.
    private static GkrCircuit BuildAdderCircuit()
    {
        var terms = new List<GkrLayerTerm>();
        for(int i = 0; i < WordBits; i++)
        {
            terms.Add(new GkrLayerTerm(i, AdderSumWire + i, AdderSumWire + i, One));
            terms.Add(new GkrLayerTerm(i, i, i, One));
            terms.Add(new GkrLayerTerm(i, WordBits + i, WordBits + i, One));
            if(i > 0)
            {
                int carryIn = AdderCarryWire + i - 1;
                terms.Add(new GkrLayerTerm(i, carryIn, carryIn, One));
            }
        }

        for(int k = 0; k < AdderCarryCount; k++)
        {
            int output = AdderCarryCheckBase + k;
            int carryOut = AdderCarryWire + k;
            terms.Add(new GkrLayerTerm(output, carryOut, carryOut, One));
            terms.Add(new GkrLayerTerm(output, k, WordBits + k, One));
            if(k > 0)
            {
                int carryIn = AdderCarryWire + k - 1;
                terms.Add(new GkrLayerTerm(output, k, carryIn, One));
                terms.Add(new GkrLayerTerm(output, WordBits + k, carryIn, One));
            }
        }

        return new GkrCircuit([new GkrLayer([.. terms], AdderOutputCount)], AdderInputCount);
    }


    private static void PackMajorityInputs(Span<byte> inputs)
    {
        inputs.Clear();
        for(int c = 0; c < CopyCount; c++)
        {
            Span<byte> copy = inputs.Slice(c * MajorityInputCount * ScalarSize, MajorityInputCount * ScalarSize);
            for(int word = 0; word < 3; word++)
            {
                WriteWordBits(copy, word * WordBits, Words[c][word]);
            }
        }
    }


    private static void PackSigmaInputs(Span<byte> inputs)
    {
        inputs.Clear();
        for(int c = 0; c < CopyCount; c++)
        {
            WriteWordBits(inputs.Slice(c * SigmaInputCount * ScalarSize, SigmaInputCount * ScalarSize), 0, Words[c][0]);
        }
    }


    private static void PackAdderInputs(Span<byte> inputs)
    {
        inputs.Clear();
        for(int c = 0; c < CopyCount; c++)
        {
            Span<byte> copy = inputs.Slice(c * AdderInputCount * ScalarSize, AdderInputCount * ScalarSize);
            uint a = Words[c][0];
            uint b = Words[c][1];
            uint sum = a + b;
            WriteWordBits(copy, 0, a);
            WriteWordBits(copy, WordBits, b);
            WriteWordBits(copy, AdderSumWire, sum);

            int carry = 0;
            for(int k = 0; k < AdderCarryCount; k++)
            {
                int aBit = (int)((a >> k) & 1);
                int bBit = (int)((b >> k) & 1);
                carry = ((aBit & bBit) | (aBit & carry) | (bBit & carry)) & 1;
                copy[(((AdderCarryWire + k) * ScalarSize) + ScalarSize) - 1] = (byte)carry;
            }
        }
    }


    private static void WriteWordBits(Span<byte> copy, int wireBase, uint word)
    {
        for(int bit = 0; bit < WordBits; bit++)
        {
            copy[(((wireBase + bit) * ScalarSize) + ScalarSize) - 1] = (byte)((word >> bit) & 1);
        }
    }


    private static void AssertWordBits(ReadOnlySpan<byte> outputs, uint expected, string label)
    {
        for(int bit = 0; bit < WordBits; bit++)
        {
            int actual = outputs[(bit * ScalarSize) + ScalarSize - 1];
            Assert.AreEqual((int)((expected >> bit) & 1), actual, $"{label} bit {bit} must match the uint oracle.");
        }
    }


    //Bitness for the wires [firstWire, firstWire + count) of every copy.
    private static LigeroQuadraticConstraint[] BuildBitness(int inputCount, int firstWire, int count)
    {
        var quadratics = new List<LigeroQuadraticConstraint>();
        for(int c = 0; c < CopyCount; c++)
        {
            for(int wire = firstWire; wire < firstWire + count; wire++)
            {
                int index = (c * inputCount) + wire;
                quadratics.Add(new LigeroQuadraticConstraint(index, index, index));
            }
        }

        return [.. quadratics];
    }


    private static FiatShamirTranscript NewTranscript(ReadOnlySpan<byte> statement) =>
        GkrGf2kTestSupport.NewTranscript(Domain, "veridical.gkr.gf2k.sha.seed"u8, statement);
}
