using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// Binding / soundness tests: attempts to forge openings should fail.
/// Each test constructs a tampered prover input and confirms verify
/// rejects the resulting proof.
/// </summary>
[TestClass]
internal sealed class HyraxBindingTests
{
    private const string TranscriptDomain = "veridical.test.hyrax.binding.v1";

    private static readonly G1HashToCurveDelegate HashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static readonly G1AddDelegate G1Add = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static readonly G1ScalarMultiplyDelegate G1ScalarMul = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static readonly G1MultiScalarMultiplyDelegate G1Msm = TestG1Backends.Bls12Curve381Msm;
    private static readonly ScalarAddDelegate ScalarAdd = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate ScalarSubtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate ScalarMul = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate ScalarInvert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate ScalarReduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();


    [TestMethod]
    public void CannotOpenWithMismatchedMle()
    {
        const int VariableCount = 3;
        var dimensions = HyraxCommitmentDimensions.ForVariableCount(VariableCount);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);

        //Commit to mleA.
        using MultilinearExtension mleA = BuildMleWithValues(VariableCount, i => i + 1);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 5555);
        var (commitment, witness) = key.CommitMultilinearExtension(mleA, fixedRandom, G1Msm, BaseMemoryPool.Shared);

        using(commitment)
        using(witness)
        {
            //But open as if the underlying MLE were mleB. The prover-side
            //code computes f from mleB but the row blindings in `witness`
            //were sampled for mleA. The resulting proof should not verify
            //against `commitment` (which commits to mleA).
            using MultilinearExtension mleB = BuildMleWithValues(VariableCount, i => i + 100);
            using PointArray point = BuildPointArray(VariableCount);
            using FiatShamirTranscript proverTx = NewTranscript();
            using FiatShamirTranscript verifierTx = NewTranscript();

            var (proof, claimedValueFromBogus) = commitment.Open(
                witness, mleB, point.AsSpan, key, proverTx,
                Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
                G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

            using(proof)
            using(claimedValueFromBogus)
            {
                bool ok = commitment.VerifyOpening(
                    point.AsSpan, claimedValueFromBogus, proof, key, verifierTx,
                    Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
                    G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

                Assert.IsFalse(ok, "A proof generated for mleB cannot verify against a commitment to mleA — the IPA's structure binds f to the row commitments.");
            }
        }
    }


    [TestMethod]
    public void CannotOpenWithIncorrectWitnessBlindings()
    {
        const int VariableCount = 3;
        var dimensions = HyraxCommitmentDimensions.ForVariableCount(VariableCount);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);

        using MultilinearExtension mle = BuildMleWithValues(VariableCount, i => i + 1);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 6666);
        var (commitment, witness) = key.CommitMultilinearExtension(mle, fixedRandom, G1Msm, BaseMemoryPool.Shared);

        using(commitment)
        using(witness)
        {
            //Hand-build a forged witness with all-zero blindings. The
            //commitment was constructed with the real random blindings;
            //opening with zero-blinding witness will produce a Δr that
            //does not match the actual row-combined blinding, so the
            //C_f - C_combined ?= Δr·H check fails.
            IMemoryOwner<byte> forgedOwner = BaseMemoryPool.Shared.Rent(HyraxOpeningWitness.GetBufferSizeBytes(witness.RowCount));
            forgedOwner.Memory.Span[..HyraxOpeningWitness.GetBufferSizeBytes(witness.RowCount)].Clear();
            Tag forgedTag = Tag.Create(
                (typeof(AlgebraicRole), (object)AlgebraicRole.CommitmentWitness),
                (typeof(CurveParameterSet), (object)key.Curve),
                (typeof(CommitmentScheme), (object)CommitmentScheme.Hyrax));
            using var forgedWitness = new HyraxOpeningWitness(forgedOwner, witness.RowCount, key.Curve, forgedTag);

            using PointArray point = BuildPointArray(VariableCount);
            using FiatShamirTranscript proverTx = NewTranscript();
            using FiatShamirTranscript verifierTx = NewTranscript();

            var (proof, claimedValue) = commitment.Open(
                forgedWitness, mle, point.AsSpan, key, proverTx,
                Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
                G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

            using(proof)
            using(claimedValue)
            {
                bool ok = commitment.VerifyOpening(
                    point.AsSpan, claimedValue, proof, key, verifierTx,
                    Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
                    G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

                Assert.IsFalse(ok, "Verify must reject when the prover used incorrect witness blindings — the Δr check catches the mismatch.");
            }
        }
    }


    private static FiatShamirTranscript NewTranscript() =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(TranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    private static MultilinearExtension BuildMleWithValues(int variableCount, Func<int, int> valueAt)
    {
        int evalCount = 1 << variableCount;
        int elementSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> bufOwner = BaseMemoryPool.Shared.Rent(evalCount * elementSize);
        Span<byte> buf = bufOwner.Memory.Span[..(evalCount * elementSize)];
        for(int i = 0; i < evalCount; i++)
        {
            WriteCanonical(new BigInteger(valueAt(i)), buf.Slice(i * elementSize, elementSize));
        }


        return MultilinearExtension.FromEvaluations(buf, variableCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static PointArray BuildPointArray(int variableCount)
    {
        var scalars = new Scalar[variableCount];
        for(int i = 0; i < variableCount; i++)
        {
            scalars[i] = MakeScalar((i * 5) + 3);
        }


        return new PointArray(scalars);
    }


    private static Scalar MakeScalar(int value)
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
        Span<byte> span = owner.Memory.Span[..Scalar.SizeBytes];
        WriteCanonical(new BigInteger(value), span);
        return Scalar.FromCanonical(span, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
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


    private static ScalarRandomDelegate MakeFixedRandom(int seed)
    {
        int counter = 0;
        return Sample;

        Tag Sample(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> hashInput = stackalloc byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hashInput[..4], seed);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hashInput[4..], counter);
            counter++;

            Span<byte> wide = stackalloc byte[32];
            SHA256.HashData(hashInput, wide);
            ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
            reduce(wide, destination, curve);
            return inboundTag;
        }
    }


    private readonly struct PointArray: IDisposable
    {
        private readonly Scalar[] scalars;

        public PointArray(Scalar[] scalars) { this.scalars = scalars; }

        public ReadOnlySpan<Scalar> AsSpan => scalars;

        public void Dispose()
        {
            if(scalars is null)
            {
                return;
            }

            foreach(Scalar s in scalars)
            {
                s?.Dispose();
            }
        }
    }
}