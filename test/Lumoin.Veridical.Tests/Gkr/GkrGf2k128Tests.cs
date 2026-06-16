using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The data-parallel GKR engine over <c>GF(2^128)</c> — the binary field the deployed Longfellow
/// runs its hash side on. The engine is delegate-based and never names a field, but
/// characteristic two stresses what odd characteristic cannot: the integer evaluation points
/// <c>0..3</c> of the degree-3 round polynomials become the field elements
/// <c>{0, 1, x, x+1}</c> (distinct, so the Lagrange interpolation's denominators stay
/// invertible), the <c>eq</c> tables compute <c>1 − r</c> as <c>1 XOR r</c>, and the SHA choose
/// function re-arithmetizes as <c>Ch = e·f + g² + e·g</c> — over GF(2) the <c>−1</c>
/// coefficients of the Fp256 circuit ARE <c>1</c>, XOR is plain addition, and a bit passes as
/// its own square. Eight word triples prove as data-parallel copies through the full
/// (uncommitted) walk: copy rounds, hand sumchecks, tensor-point input checks, all over the
/// binary field. Gated bit-exact against the plain uint computation.
/// <para>
/// Running the engine over a structurally different field is a regression strategy in its own
/// right, beyond enabling the binary-field deployment: field-generic code can carry silent
/// field-specific assumptions (an integer constant where the field's element belongs, a
/// reliance on <c>2 ≠ 0</c>, arithmetic that holds only while nothing wraps), and tests over
/// a single field cannot expose them — such a bug is consistent there by construction. A
/// second field with different structure falsifies them wholesale, and characteristic two,
/// where <c>−1 = 1</c> and doubling annihilates, differs the most.
/// </para>
/// </summary>
[TestClass]
internal sealed class GkrGf2k128Tests
{
    private const int ScalarSize = 32;
    private const int WordBits = 32;
    private const int CopyCount = 8;

    //Per copy: the 96 bit wires of e, f, g, zero-padded to 128. No constant-one wire: every
    //linear use of a bit is its square, and over GF(2) the choose function needs no negation.
    private const int InputCount = 128;
    private const int InputBytes = CopyCount * InputCount * ScalarSize;
    private const int OutputBytes = CopyCount * WordBits * ScalarSize;

    private static ScalarAddDelegate Add { get; } = GkrGf2kTestSupport.Add;

    private static ScalarSubtractDelegate Subtract { get; } = GkrGf2kTestSupport.Subtract;

    private static ScalarMultiplyDelegate Multiply { get; } = GkrGf2kTestSupport.Multiply;

    private static ScalarInvertDelegate Invert { get; } = GkrGf2kTestSupport.Invert;

    private static ScalarReduceDelegate Reduce { get; } = GkrGf2kTestSupport.Reduce;

    private static FiatShamirHashDelegate Hash { get; } = GkrGf2kTestSupport.Hash;

    private static FiatShamirSqueezeDelegate Squeeze { get; } = GkrGf2kTestSupport.Squeeze;

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.gf2k.ch.test");

    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.gf2k.rng.v1");

    private static byte[] One { get; } = GkrGf2kTestSupport.One;

    //Eight (e, f, g) word triples — real SHA-256 working-variable shapes.
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
    public void ChooseFunctionEvaluatesBitExactOverTheBinaryField()
    {
        GkrCircuit circuit = BuildChooseCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..InputBytes];
        PackInputs(inputs);
        using GkrWireTables tables = circuit.EvaluateDataParallel(inputs, CopyCount, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);

        for(int c = 0; c < CopyCount; c++)
        {
            uint expected = (Words[c][0] & Words[c][1]) ^ (~Words[c][0] & Words[c][2]);
            ReadOnlySpan<byte> copyOutputs = tables.Table(0).Span.Slice(c * WordBits * ScalarSize, WordBits * ScalarSize);
            for(int bit = 0; bit < WordBits; bit++)
            {
                int actual = copyOutputs[(bit * ScalarSize) + ScalarSize - 1];
                Assert.AreEqual((int)((expected >> bit) & 1), actual, $"Copy {c} bit {bit} of Ch must match the uint oracle over GF(2^128).");
            }
        }
    }


    [TestMethod]
    public void HonestDataParallelProofVerifiesOverTheBinaryField()
    {
        GkrCircuit circuit = BuildChooseCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..InputBytes];
        PackInputs(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..OutputBytes];
        EvaluateOutputs(circuit, inputs, outputs);

        using FiatShamirTranscript proverTranscript = NewTranscript(inputs);
        using GkrDataParallelProverResult result = GkrDataParallelProver.Prove(
            circuit, inputs, CopyCount, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            proverTranscript, Squeeze, Hash, BaseMemoryPool.Shared);
        using GkrDataParallelProof proof = result.Proof;

        using FiatShamirTranscript verifierTranscript = NewTranscript(inputs);
        bool verified = GkrDataParallelVerifier.Verify(
            circuit, inputs, outputs, CopyCount, proof, Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            verifierTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        Assert.IsTrue(verified, "An honest data-parallel GKR proof over GF(2^128) must verify down to the inputs.");
    }


    [TestMethod]
    public void WrongOutputsAreRejectedOverTheBinaryField()
    {
        GkrCircuit circuit = BuildChooseCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..InputBytes];
        PackInputs(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..OutputBytes];
        EvaluateOutputs(circuit, inputs, outputs);

        using FiatShamirTranscript proverTranscript = NewTranscript(inputs);
        using GkrDataParallelProverResult result = GkrDataParallelProver.Prove(
            circuit, inputs, CopyCount, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            proverTranscript, Squeeze, Hash, BaseMemoryPool.Shared);
        using GkrDataParallelProof proof = result.Proof;

        //Flip one output bit of one copy.
        outputs[ScalarSize - 1] ^= 0x01;

        using FiatShamirTranscript verifierTranscript = NewTranscript(inputs);
        bool verified = GkrDataParallelVerifier.Verify(
            circuit, inputs, outputs, CopyCount, proof, Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            verifierTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "A flipped Ch output bit must be rejected over GF(2^128).");
    }


    [TestMethod]
    public void CommittedProofVerifiesOverTheBinaryField()
    {
        GkrCircuit circuit = BuildChooseCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..InputBytes];
        PackInputs(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..OutputBytes];
        EvaluateOutputs(circuit, inputs, outputs);

        //Bitness of every input bit rides as quadratic commitment constraints, exercising the
        //quadratic rows and their challenges over the binary field.
        LigeroQuadraticConstraint[] bitness = BuildBitnessConstraints();

        using FiatShamirTranscript proverTranscript = NewTranscript(inputs);
        using GkrCommittedProof proof = GkrGf2kTestSupport.Prove(circuit, inputs, CopyCount, RandomnessSeed, proverTranscript, bitness);

        using(FiatShamirTranscript verifierTranscript = NewTranscript(inputs))
        {
            Assert.IsTrue(
                GkrGf2kTestSupport.Verify(circuit, outputs, CopyCount, proof, verifierTranscript, bitness),
                "The committed Ch proof — Ligero commitment, walk and openings — must verify over GF(2^128).");
        }

        //Flip one output bit of one copy.
        outputs[ScalarSize - 1] ^= 0x01;
        using(FiatShamirTranscript verifierTranscript = NewTranscript(inputs))
        {
            Assert.IsFalse(
                GkrGf2kTestSupport.Verify(circuit, outputs, CopyCount, proof, verifierTranscript, bitness),
                "A flipped Ch output bit must be rejected over GF(2^128).");
        }
    }


    //One layer, three terms per output bit i: over GF(2) the choose function is
    //e_i·f_i + g_i + e_i·g_i, with the linear g term as its own square.
    private static GkrCircuit BuildChooseCircuit()
    {
        var terms = new GkrLayerTerm[3 * WordBits];
        for(int i = 0; i < WordBits; i++)
        {
            terms[3 * i] = new GkrLayerTerm(i, i, WordBits + i, One);
            terms[(3 * i) + 1] = new GkrLayerTerm(i, (2 * WordBits) + i, (2 * WordBits) + i, One);
            terms[(3 * i) + 2] = new GkrLayerTerm(i, i, (2 * WordBits) + i, One);
        }

        return new GkrCircuit([new GkrLayer(terms, WordBits)], InputCount);
    }


    //Per copy: the bits of e, f, g (least-significant first), zero padding.
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
        }
    }


    private static void EvaluateOutputs(GkrCircuit circuit, ReadOnlySpan<byte> inputs, Span<byte> outputs)
    {
        using GkrWireTables tables = circuit.EvaluateDataParallel(inputs, CopyCount, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);
        tables.Table(0).Span.CopyTo(outputs);
    }


    //The 96 committed word bits of every copy are bits: W[b]·W[b] = W[b].
    private static LigeroQuadraticConstraint[] BuildBitnessConstraints()
    {
        var quadratics = new List<LigeroQuadraticConstraint>();
        for(int c = 0; c < CopyCount; c++)
        {
            for(int wire = 0; wire < 3 * WordBits; wire++)
            {
                int index = (c * InputCount) + wire;
                quadratics.Add(new LigeroQuadraticConstraint(index, index, index));
            }
        }

        return [.. quadratics];
    }


    private static FiatShamirTranscript NewTranscript(ReadOnlySpan<byte> statement) =>
        GkrGf2kTestSupport.NewTranscript(Domain, "veridical.gkr.gf2k.ch.seed"u8, statement);
}
