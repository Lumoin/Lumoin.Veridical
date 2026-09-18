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
internal sealed class LongfellowZeroMaskRejectionTests: IDisposable
{
    /// <summary>The independent compiler and circuit lifetime for this test.</summary>
    private LongfellowCircuitTestScope CircuitScope { get; } = new();

    /// <summary>Calls <see cref="Dispose"/> after each test, including when an assertion fails.</summary>
    [TestCleanup]
    public void DisposeCircuits()
    {
        Dispose();
    }


    /// <summary>Releases this test's compiler and circuit storage. Repeated calls have no effect.</summary>
    public void Dispose()
    {
        CircuitScope.Dispose();
    }


    /// <summary>The canonical scalar width in bytes.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The SHA-256 digest width in bytes.</summary>
    private const int DigestSize = 32;

    /// <summary>The full GF(2^128) field element width in bytes.</summary>
    private const int FieldBytes = 16;

    /// <summary>The production GF(2^16) subfield element width in bytes.</summary>
    private const int SubFieldBytes = 2;

    /// <summary>The witness count of the tiny commit shape the commitment-step conformance gate also uses.</summary>
    private const int WitnessCount = 8;

    /// <summary>The quadratic constraint count of the tiny commit shape the commitment-step conformance gate also uses.</summary>
    private const int QuadraticConstraintCount = 1;

    /// <summary>The inverse rate of the tiny commit shape the commitment-step conformance gate also uses.</summary>
    private const int InverseRate = 4;

    /// <summary>The opened column count of the tiny commit shape the commitment-step conformance gate also uses.</summary>
    private const int OpenedColumnCount = 2;

    /// <summary>The GF(2^128) field addition delegate.</summary>
    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) field subtraction delegate.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) field multiplication delegate.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) field inversion delegate.</summary>
    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();


    /// <summary>Pins that filling a proof pad from an always-zero byte source throws <see cref="InvalidOperationException"/> at generation, since every drawn pad element would be the field zero and the pad would encrypt nothing.</summary>
    [TestMethod]
    public void ProofPadFillWithZeroSourceThrows()
    {
        //Every pad draw from a zero source is the field zero, so the pad
        //encrypts nothing; Fill must reject it at generation.
        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowFieldProfile.ForGf2k128(fft, BaseMemoryPool.Shared);
        LongfellowSumcheckCircuit circuit = SmallCircuit();

        Assert.ThrowsExactly<InvalidOperationException>(() =>
        {
            using LongfellowProofPad _ = LongfellowProofPad.Fill(
                circuit, ZeroSource, profile, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);
        });
    }


    /// <summary>Pins that committing with an always-zero byte source throws <see cref="InvalidOperationException"/> before building the tree, since a zero source zeroes the tableau's whole hiding budget.</summary>
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
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
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


    /// <summary>A byte source that always produces zero bytes — the modelled RNG wiring failure. Zero is below every field modulus, so the sample reject loop accepts it and every drawn element is the field zero.</summary>
    private static void ZeroSource(Span<byte> destination)
    {
        destination.Clear();
    }


    /// <summary>Builds a minimal logc == 0 circuit shape — one layer with two hand rounds — whose owners are released at this test's cleanup.</summary>
    private LongfellowSumcheckCircuit SmallCircuit()
    {
        LongfellowSumcheckLayer layer = new(inputCount: 4, handRounds: 2, termCount: 0);
        byte[] id = new byte[LongfellowSumcheckCircuit.IdLength];

        return CircuitScope.CreateCircuit(
            outputCount: 1, outputLogCount: 0, copyCount: 1, copyRounds: 0,
            inputCount: 4, publicInputCount: 0, id, [layer]);
    }


    /// <summary>Fills W[i] = of_scalar(i + 1), then sets W[2] = W[0]·W[1] so the one quadratic constraint is satisfied — the same seeding the commitment-step conformance gate uses.</summary>
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


    /// <summary>Builds the GF(2^128) additive FFT at the production-16 subfield.</summary>
    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>The reference's node combine: SHA256(left || right).</summary>
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>The one-shot leaf hash: SHA256 over the whole nonce-plus-column input span.</summary>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        SHA256.HashData(input, output);
    }
}
