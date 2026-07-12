using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The zero-mask (broken-RNG) rejection leg of the Longfellow prover gate: a
/// byte source that returns identically-zero bytes models the bug class where
/// an RNG wiring failure silently voids the zero-knowledge property while the
/// proof still verifies. The two blinding-generation sites — the proof pad the
/// ZK prover subtracts from the sumcheck transcript, and the Ligero
/// commitment's blinding rows and per-leaf Merkle nonces — must refuse to
/// build with such a source, throwing <see cref="InvalidOperationException"/>
/// at generation. Unit-level over the mask sites directly, the cheapest entry
/// that reaches them.
/// </summary>
[TestClass]
internal sealed class LongfellowZeroMaskRejectionTests
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSize = 32;

    //GF(2^128) byte sizes: the full field element is 16 bytes; the production
    //GF(2^16) subfield is 2 bytes.
    private const int FieldBytes = 16;
    private const int SubFieldBytes = 2;

    //The tiny commit shape the C.2 conformance gate also uses.
    private const int WitnessCount = 8;
    private const int QuadraticConstraintCount = 1;
    private const int InverseRate = 4;
    private const int OpenedColumnCount = 2;

    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();


    [TestMethod]
    public void ProofPadFillWithZeroSourceThrows()
    {
        //Every pad draw from a zero source is the field zero, so the pad
        //encrypts nothing; Fill must reject it at generation.
        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile profile = LongfellowFieldProfile.ForGf2k128(fft);
        LongfellowSumcheckCircuit circuit = SmallCircuit();

        Assert.ThrowsExactly<InvalidOperationException>(() =>
        {
            using LongfellowProofPad _ = LongfellowProofPad.Fill(
                circuit, ZeroSource, profile, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);
        });
    }


    [TestMethod]
    public void LigeroCommitWithZeroSourceThrows()
    {
        //A zero source zeroes the ILDT/IDOT/IQUAD blinding rows (the tableau's
        //whole hiding budget); Commit must reject before building the tree.
        using Lch14AdditiveFft fft = NewFft();
        var parameters = new LongfellowLigeroParameters(
            WitnessCount, QuadraticConstraintCount, InverseRate, OpenedColumnCount, FieldBytes, SubFieldBytes);

        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(WitnessCount * ScalarSize);
        Span<byte> witnesses = witnessOwner.Memory.Span[..(WitnessCount * ScalarSize)];
        BuildWitnesses(fft, witnesses);

        LigeroQuadraticConstraint[] quadraticConstraints = [new LigeroQuadraticConstraint(0, 1, 2)];
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        byte[] witnessBytes = witnesses.ToArray();
        byte[] root = new byte[DigestSize];

        try
        {
            Assert.ThrowsExactly<InvalidOperationException>(() =>
            {
                LongfellowLigeroCommitment.Commit(
                    parameters, witnessBytes, quadraticConstraints, SubFieldBytes, parameters.WitnessCount,
                    ZeroSource, encoderFactory, profile,
                    Add, Subtract, Multiply, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256,
                    CurveParameterSet.None, root, BaseMemoryPool.Shared);
            });
        }
        finally
        {
            Array.Clear(witnessBytes);
            witnesses.Clear();
        }
    }


    //A byte source that always produces zero bytes — the modelled RNG wiring
    //failure. Zero is below every field modulus, so the sample reject loop
    //accepts it and every drawn element is the field zero.
    private static void ZeroSource(Span<byte> destination)
    {
        destination.Clear();
    }


    //A minimal logc == 0 circuit shape: one layer with two hand rounds.
    private static LongfellowSumcheckCircuit SmallCircuit()
    {
        LongfellowSumcheckLayer layer = new(inputCount: 4, handRounds: 2, termCount: 0);
        byte[] id = new byte[LongfellowSumcheckCircuit.IdLength];

        return new LongfellowSumcheckCircuit(
            outputCount: 1, outputLogCount: 0, copyCount: 1, copyRounds: 0,
            inputCount: 4, publicInputCount: 0, id, [layer]);
    }


    //W[i] = of_scalar(i + 1), then W[2] = W[0]·W[1] so the one quadratic
    //constraint is satisfied — the same seeding the commit conformance gate
    //uses.
    private static void BuildWitnesses(Lch14AdditiveFft fft, Span<byte> witnesses)
    {
        int witnessCount = witnesses.Length / ScalarSize;
        for(int i = 0; i < witnessCount; i++)
        {
            fft.NodeElement((uint)(i + 1), witnesses.Slice(i * ScalarSize, ScalarSize));
        }

        Multiply(
            witnesses[..ScalarSize],
            witnesses.Slice(ScalarSize, ScalarSize),
            witnesses.Slice(2 * ScalarSize, ScalarSize),
            CurveParameterSet.None);
    }


    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    //The reference's node combine: SHA256(left || right).
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    //The one-shot leaf hash: SHA256 over the whole nonce-plus-column input span.
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        SHA256.HashData(input, output);
    }
}
