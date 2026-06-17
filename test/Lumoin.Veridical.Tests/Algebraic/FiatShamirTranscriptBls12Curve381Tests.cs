using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// BLS12-381 typed absorbs and the scalar-squeeze path on
/// <see cref="FiatShamirTranscript"/>: scalar/point/MLE/polynomial
/// absorbs are deterministic, distinct inputs produce distinct states,
/// the squeezed scalar is a valid canonical-form scalar, and the
/// Spartan2-shaped round (absorb polynomial, squeeze challenge,
/// evaluate, absorb result) is end-to-end deterministic.
/// </summary>
[TestClass]
internal sealed class FiatShamirTranscriptBls12Curve381Tests
{
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly PolynomialEvaluateDelegate PolyEvaluate = PolynomialBigIntegerReference.GetEvaluate();
    private static readonly FiatShamirDomainLabel DomainLabel = new("veridical.test.bls12curve381.v1");

    private const long IterationCount = 30;


    [TestMethod]
    public void AbsorbScalarIsDeterministic()
    {
        Gen.Byte.Array[Scalar.SizeBytes].Sample(rawBytes =>
        {
            using IMemoryOwner<byte> reducedOwner = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
            Span<byte> reduced = reducedOwner.Memory.Span[..Scalar.SizeBytes];
            Reduce(rawBytes, reduced, CurveParameterSet.Bls12Curve381);

            using Scalar scalarA = Scalar.FromCanonical(reduced, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
            using Scalar scalarB = Scalar.FromCanonical(reduced, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

            ReadOnlySpan<byte> seed = stackalloc byte[8];
            using FiatShamirTranscript a = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
            using FiatShamirTranscript b = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

            a.AbsorbScalar(new FiatShamirOperationLabel("test"), scalarA, Hash);
            b.AbsorbScalar(new FiatShamirOperationLabel("test"), scalarB, Hash);

            return a.AsReadOnlySpan().SequenceEqual(b.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void AbsorbDifferentScalarsProducesDifferentStates()
    {
        Gen.Select(Gen.Byte.Array[Scalar.SizeBytes], Gen.Byte.Array[Scalar.SizeBytes])
            .Where(t => !t.Item1.AsSpan().SequenceEqual(t.Item2))
            .Sample(t =>
            {
                using IMemoryOwner<byte> ra = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
                using IMemoryOwner<byte> rb = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
                Span<byte> reducedA = ra.Memory.Span[..Scalar.SizeBytes];
                Span<byte> reducedB = rb.Memory.Span[..Scalar.SizeBytes];
                Reduce(t.Item1, reducedA, CurveParameterSet.Bls12Curve381);
                Reduce(t.Item2, reducedB, CurveParameterSet.Bls12Curve381);
                if(reducedA.SequenceEqual(reducedB))
                {
                    //Both pre-reduction inputs differ but reduce to the same scalar
                    //(unlikely but possible). Skip this sample.
                    return true;
                }

                using Scalar scalarA = Scalar.FromCanonical(reducedA, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
                using Scalar scalarB = Scalar.FromCanonical(reducedB, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

                ReadOnlySpan<byte> seed = stackalloc byte[8];
                using FiatShamirTranscript a = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
                using FiatShamirTranscript b = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

                a.AbsorbScalar(new FiatShamirOperationLabel("test"), scalarA, Hash);
                b.AbsorbScalar(new FiatShamirOperationLabel("test"), scalarB, Hash);

                return !a.AsReadOnlySpan().SequenceEqual(b.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void AbsorbG1PointIsDeterministic()
    {
        ReadOnlySpan<byte> seed = stackalloc byte[16];
        using G1Point generatorA = G1Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using G1Point generatorB = G1Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using FiatShamirTranscript a = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        using FiatShamirTranscript b = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        FiatShamirOperationLabel label = new("g1.commitment");
        a.AbsorbG1Point(label, generatorA, Hash);
        b.AbsorbG1Point(label, generatorB, Hash);

        Assert.IsTrue(a.AsReadOnlySpan().SequenceEqual(b.AsReadOnlySpan()),
            "Same G1 point absorbed twice should produce identical states.");
    }


    [TestMethod]
    public void SqueezeScalarProducesCanonicalNonZeroResult()
    {
        Gen.Byte.Array[32].Sample(seedBytes =>
        {
            using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(
                DomainLabel,
                seedBytes,
                WellKnownHashAlgorithms.Blake3,
                Hash,
                BaseMemoryPool.Shared);

            using Scalar challenge = transcript.SqueezeScalar(
                new FiatShamirOperationLabel("challenge"),
                Squeeze,
                Hash,
                Reduce, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

            //Canonical-range check: less than the field order.
            BigInteger value = new(challenge.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
            BigInteger fieldOrder = Bls12Curve381BigIntegerScalarReference.FieldOrder;
            bool inRange = value < fieldOrder;

            //Probability of zero is ~2^-256; this assertion essentially never fails.
            bool nonZero = !challenge.IsZero;

            return inRange && nonZero;
        }, iter: IterationCount);
    }


    [TestMethod]
    public void AbsorbMultilinearExtensionRoundtrip()
    {
        const int VariableCount = 2;
        int elementSize = Scalar.SizeBytes;
        int evalCount = 1 << VariableCount;

        using IMemoryOwner<byte> bufferOwner = BaseMemoryPool.Shared.Rent(evalCount * elementSize);
        Span<byte> buffer = bufferOwner.Memory.Span[..(evalCount * elementSize)];
        for(int i = 0; i < evalCount; i++)
        {
            WriteCanonical(new(i + 1), buffer.Slice(i * elementSize, elementSize));
        }

        using MultilinearExtension mle = MultilinearExtension.FromEvaluations(buffer, VariableCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        ReadOnlySpan<byte> seed = stackalloc byte[8];
        using FiatShamirTranscript a = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        using FiatShamirTranscript b = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        FiatShamirOperationLabel label = new("mle.commitment");
        a.AbsorbMultilinearExtension(label, mle, Hash);
        b.AbsorbMultilinearExtension(label, mle, Hash);

        Assert.IsTrue(a.AsReadOnlySpan().SequenceEqual(b.AsReadOnlySpan()),
            "Absorbing the same MLE twice should produce identical post-absorb states.");
    }


    [TestMethod]
    public void AbsorbMultilinearExtensionRejectsForeignCurve()
    {
        //Fabricate an MLE with an unwired curve (Pallas) through the internal
        //constructor (IVT-unlocked from Core for tests). The absorb extension
        //is wired for Bls12Curve381 and Bn254, so a genuinely unwired curve is
        //needed to exercise the reject path; it should throw ArgumentException.
        const int VariableCount = 1;
        int elementSize = Scalar.SizeBytes;

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent((1 << VariableCount) * elementSize);
        owner.Memory.Span[..((1 << VariableCount) * elementSize)].Clear();
        Tag pallasTag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.MultilinearExtension),
            (typeof(CurveParameterSet), (object)CurveParameterSet.Pallas),
            (typeof(MultilinearExtensionDimensions), (object)new MultilinearExtensionDimensions(VariableCount, 1 << VariableCount)));
        using var foreignMle = new MultilinearExtension(owner, VariableCount, elementSize, CurveParameterSet.Pallas, pallasTag);

        ReadOnlySpan<byte> seed = stackalloc byte[8];
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        Assert.ThrowsExactly<ArgumentException>(() =>
            transcript.AbsorbMultilinearExtension(new FiatShamirOperationLabel("mle"), foreignMle, Hash));
    }


    [TestMethod]
    public void SpartanRoundShapeIsDeterministic()
    {
        //Sumcheck-shaped round: absorb a univariate polynomial, squeeze a
        //challenge, evaluate the polynomial at the challenge, absorb the
        //evaluation. The final state must be deterministic across two
        //independent runs.
        const int Degree = 3;
        int elementSize = Scalar.SizeBytes;

        using IMemoryOwner<byte> coeffOwner = BaseMemoryPool.Shared.Rent((Degree + 1) * elementSize);
        Span<byte> coefficients = coeffOwner.Memory.Span[..((Degree + 1) * elementSize)];
        WriteCanonical(new(1), coefficients.Slice(0, elementSize));
        WriteCanonical(new(2), coefficients.Slice(elementSize, elementSize));
        WriteCanonical(new(3), coefficients.Slice(2 * elementSize, elementSize));
        WriteCanonical(new(5), coefficients.Slice(3 * elementSize, elementSize));

        using Polynomial polynomial = Polynomial.FromCoefficients(coefficients, Degree, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        ReadOnlySpan<byte> seed = stackalloc byte[16];

        Span<byte> stateA = stackalloc byte[FiatShamirTranscript.StateSizeBytes];
        Span<byte> stateB = stackalloc byte[FiatShamirTranscript.StateSizeBytes];

        ExecuteRound(seed, polynomial, stateA);
        ExecuteRound(seed, polynomial, stateB);

        Assert.IsTrue(stateA.SequenceEqual(stateB),
            "Spartan-shaped round must reach the same final state across independent runs with identical inputs.");
    }


    private static void ExecuteRound(ReadOnlySpan<byte> seed, Polynomial polynomial, Span<byte> finalState)
    {
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(DomainLabel, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        transcript.AbsorbPolynomial(new FiatShamirOperationLabel("sumcheck.polynomial"), polynomial, Hash);
        using Scalar challenge = transcript.SqueezeScalar(
            new FiatShamirOperationLabel("sumcheck.challenge"),
            Squeeze,
            Hash,
            Reduce, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using Scalar evaluation = polynomial.Evaluate(challenge, PolyEvaluate, BaseMemoryPool.Shared);
        transcript.AbsorbScalar(new FiatShamirOperationLabel("sumcheck.evaluation"), evaluation, Hash);

        transcript.AsReadOnlySpan().CopyTo(finalState);
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger r = Bls12Curve381BigIntegerScalarReference.FieldOrder;
        BigInteger nonNegative = ((value % r) + r) % r;
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