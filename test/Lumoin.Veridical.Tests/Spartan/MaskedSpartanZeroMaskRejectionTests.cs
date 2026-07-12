using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

using static Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// The zero-mask (broken-RNG) rejection leg of the masked Spartan2 gate: an
/// entropy delegate that returns identically-zero bytes models the real bug
/// class where an RNG wiring failure silently voids zero-knowledge while every
/// proof still verifies. The prover must refuse to produce such a proof —
/// <see cref="InvalidOperationException"/> at prove time from the mask
/// generation site — on both wired curves.
/// </summary>
[TestClass]
internal sealed class MaskedSpartanZeroMaskRejectionTests
{
    private static FiatShamirHashDelegate Bn254Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Bn254Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Bn254Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Bn254Add { get; } = TestScalarBackends.Bn254.Add;
    private static ScalarSubtractDelegate Bn254Subtract { get; } = TestScalarBackends.Bn254.Subtract;
    private static ScalarMultiplyDelegate Bn254Multiply { get; } = TestScalarBackends.Bn254.Multiply;
    private static ScalarInvertDelegate Bn254Invert { get; } = TestScalarBackends.Bn254.Invert;
    private static ScalarRandomDelegate Bn254ScalarRandom { get; } = Bn254BigIntegerScalarReference.GetRandom();
    private static G1AddDelegate Bn254G1Add { get; } = Bn254BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate Bn254G1ScalarMul { get; } = Bn254BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate Bn254G1Msm { get; } = TestG1Backends.Bn254Msm;
    private static G1HashToCurveDelegate Bn254HashToCurve { get; } = Bn254BigIntegerG1Reference.GetHashToCurve();
    private static MleEvaluateDelegate SharedMleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate SharedMleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    private static readonly BigInteger Bn254Order = Bn254BigIntegerScalarReference.FieldOrder;
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private const int HyraxVectorLength = 2;


    [TestMethod]
    public void Bls12Curve381ZeroMaskEntropyThrowsAtProveTime()
    {
        //The provider's own (healthy) sampler still blinds the commitments; the
        //zero delegate is threaded only into Prove, whose first draws are the
        //statistical sumcheck masks — so the throw is the mask-generation check.
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength: HyraxVectorLength);
        using RawR1csInstance instance = BuildOneMultiplyInstance();
        using RawR1csWitness witness = BuildOneMultiplyWitness();
        using FiatShamirTranscript transcript = FreshTranscript();

        Assert.ThrowsExactly<InvalidOperationException>(() =>
        {
            using MaskedSpartanProof _ = prover.Prove(
                instance, witness, transcript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ZeroScalarRandom,
                G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);
        });
    }


    [TestMethod]
    public void Bn254ZeroMaskEntropyThrowsAtProveTime()
    {
        using MaskedSpartanProver prover = BuildBn254MaskedProver();
        using RawR1csInstance instance = BuildBn254OneMultiplyInstance();
        using RawR1csWitness witness = BuildBn254OneMultiplyWitness();
        using FiatShamirTranscript bn254Transcript = FreshBn254Transcript();

        Assert.ThrowsExactly<InvalidOperationException>(() =>
        {
            using MaskedSpartanProof _ = prover.Prove(
                instance, witness, bn254Transcript,
                Bn254Hash, Bn254Squeeze, Bn254Reduce, Bn254Add, Bn254Subtract, Bn254Multiply, Bn254Invert, ZeroScalarRandom,
                Bn254G1Add, Bn254G1ScalarMul, Bn254G1Msm, SharedMleEvaluate, SharedMleFold, Pool);
        });
    }


    //An entropy delegate with the production signature that always returns
    //zero bytes — the modelled RNG wiring failure.
    private static Tag ZeroScalarRandom(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
    {
        destination.Clear();

        return inboundTag;
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned MaskedSpartanProver.")]
    private static MaskedSpartanProver BuildBn254MaskedProver() =>
        new(new SpartanProvingKey(BuildBn254Provider()));


    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildBn254Provider()
    {
        //The statistical masks' single-row vector commitments need more
        //generators than the small witness matrices; a longer key derives the
        //same per-index generators, so flooring is byte-neutral for the rest.
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            Math.Max(HyraxVectorLength, MaskedVectorLengthFloor),
            WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bn254, Bn254HashToCurve, Pool);

        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            CurveParameterSet.Bn254,
            Bn254Hash, Bn254Squeeze, Bn254Reduce, Bn254Add, Bn254Subtract, Bn254Multiply, Bn254Invert, Bn254ScalarRandom,
            Bn254G1Add, Bn254G1ScalarMul, Bn254G1Msm,
            ownsKey: true);
    }


    private static FiatShamirTranscript FreshBn254Transcript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Bn254Hash, Pool);
    }


    //One multiplication plus padding: c0 z[1]·z[2]=z[3], c1 z[0]·z[0]=z[0]. (m=2, n=4).
    private static RawR1csInstance BuildBn254OneMultiplyInstance()
    {
        int scalarSize = Scalar.SizeBytes;
        ReadOnlySpan<int> rows = [0, 1];
        ReadOnlySpan<int> aCols = [1, 0];
        ReadOnlySpan<int> bCols = [2, 0];
        ReadOnlySpan<int> cCols = [3, 0];

        Span<byte> ones = stackalloc byte[2 * scalarSize];
        WriteBn254Canonical(BigInteger.One, ones[..scalarSize]);
        WriteBn254Canonical(BigInteger.One, ones.Slice(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(rows, aCols, ones, 2, 4, CurveParameterSet.Bn254, Pool);
        R1csMatrix b = R1csMatrix.FromSortedTriples(rows, bCols, ones, 2, 4, CurveParameterSet.Bn254, Pool);
        R1csMatrix c = R1csMatrix.FromSortedTriples(rows, cCols, ones, 2, 4, CurveParameterSet.Bn254, Pool);

        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, Pool);
    }


    //z = (1, 3, 5, 15): c0 3·5=15, c1 1·1=1.
    private static RawR1csWitness BuildBn254OneMultiplyWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteBn254Canonical(new BigInteger(3), witness[..scalarSize]);
        WriteBn254Canonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        WriteBn254Canonical(new BigInteger(15), witness.Slice(2 * scalarSize, scalarSize));

        return RawR1csWitness.FromCanonical(witness, CurveParameterSet.Bn254, Pool);
    }


    private static void WriteBn254Canonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger nonNegative = ((value % Bn254Order) + Bn254Order) % Bn254Order;
        if(!nonNegative.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
