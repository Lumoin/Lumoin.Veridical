using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// Foundational tests for the Pedersen vector commitment primitive
/// that backs Hyrax. Determinism, homomorphism, and randomness
/// dependence properties.
/// </summary>
[TestClass]
internal sealed class PedersenVectorCommitmentTests
{
    private const int VectorLength = 4;
    private static readonly G1HashToCurveDelegate HashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static readonly G1AddDelegate G1Add = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static readonly G1MultiScalarMultiplyDelegate G1Msm = TestG1Backends.Bls12Curve381Msm;
    private static readonly ScalarAddDelegate ScalarAdd = TestScalarBackends.Bls12Curve381.Add;


    [TestMethod]
    public void CommitIsDeterministicGivenBlinding()
    {
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(VectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, SensitiveMemoryPool<byte>.Shared);

        using PoolScalarArray values = BuildScalars([1, 2, 3, 4]);
        using Scalar blinding = MakeScalar(99);

        using G1Point first = key.Commit(values.AsSpan, blinding, G1Msm, SensitiveMemoryPool<byte>.Shared);
        using G1Point second = key.Commit(values.AsSpan, blinding, G1Msm, SensitiveMemoryPool<byte>.Shared);

        Assert.IsTrue(first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()),
            "Same vector + same blinding should produce identical Pedersen commitments.");
    }


    [TestMethod]
    public void DifferentBlindingsProduceDifferentCommitments()
    {
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(VectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, SensitiveMemoryPool<byte>.Shared);

        using PoolScalarArray values = BuildScalars([1, 2, 3, 4]);
        using Scalar blinding1 = MakeScalar(1);
        using Scalar blinding2 = MakeScalar(2);

        using G1Point first = key.Commit(values.AsSpan, blinding1, G1Msm, SensitiveMemoryPool<byte>.Shared);
        using G1Point second = key.Commit(values.AsSpan, blinding2, G1Msm, SensitiveMemoryPool<byte>.Shared);

        Assert.IsFalse(first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()),
            "Different blindings must produce different commitments.");
    }


    [TestMethod]
    public void HomomorphismHolds()
    {
        //Commit(a + b, r_a + r_b) == Commit(a, r_a) + Commit(b, r_b).
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(VectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, SensitiveMemoryPool<byte>.Shared);

        using PoolScalarArray a = BuildScalars([3, 5, 7, 11]);
        using PoolScalarArray b = BuildScalars([13, 17, 19, 23]);
        using Scalar rA = MakeScalar(31);
        using Scalar rB = MakeScalar(41);

        using PoolScalarArray sum = AddScalarVectors(a, b);
        using Scalar rSum = rA.Add(rB, ScalarAdd, SensitiveMemoryPool<byte>.Shared);

        using G1Point cSum = key.Commit(sum.AsSpan, rSum, G1Msm, SensitiveMemoryPool<byte>.Shared);
        using G1Point cA = key.Commit(a.AsSpan, rA, G1Msm, SensitiveMemoryPool<byte>.Shared);
        using G1Point cB = key.Commit(b.AsSpan, rB, G1Msm, SensitiveMemoryPool<byte>.Shared);

        using IMemoryOwner<byte> combinedOwner = SensitiveMemoryPool<byte>.Shared.Rent(WellKnownCurves.Bls12Curve381G1CompressedSizeBytes);
        Span<byte> combined = combinedOwner.Memory.Span[..WellKnownCurves.Bls12Curve381G1CompressedSizeBytes];
        G1Add(cA.AsReadOnlySpan(), cB.AsReadOnlySpan(), combined, CurveParameterSet.Bls12Curve381);

        Assert.IsTrue(cSum.AsReadOnlySpan().SequenceEqual(combined),
            "Pedersen commitments are additively homomorphic: Commit(a+b, r_a+r_b) == Commit(a, r_a) + Commit(b, r_b).");
    }


    private static PoolScalarArray BuildScalars(int[] values)
    {
        var scalars = new Scalar[values.Length];
        for(int i = 0; i < values.Length; i++)
        {
            scalars[i] = MakeScalar(values[i]);
        }


        return new PoolScalarArray(scalars);
    }


    private static PoolScalarArray AddScalarVectors(PoolScalarArray a, PoolScalarArray b)
    {
        Assert.AreEqual(a.AsSpan.Length, b.AsSpan.Length);
        var sum = new Scalar[a.AsSpan.Length];
        for(int i = 0; i < a.AsSpan.Length; i++)
        {
            sum[i] = a.AsSpan[i].Add(b.AsSpan[i], ScalarAdd, SensitiveMemoryPool<byte>.Shared);
        }


        return new PoolScalarArray(sum);
    }


    private static Scalar MakeScalar(int value)
    {
        using IMemoryOwner<byte> owner = SensitiveMemoryPool<byte>.Shared.Rent(Scalar.SizeBytes);
        Span<byte> span = owner.Memory.Span[..Scalar.SizeBytes];
        WriteCanonical(new BigInteger(value), span);
        return Scalar.FromCanonical(span, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
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


    private readonly struct PoolScalarArray: IDisposable
    {
        private readonly Scalar[] scalars;

        public PoolScalarArray(Scalar[] scalars) { this.scalars = scalars; }

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