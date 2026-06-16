using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Agreement gate for the AVX-512 lane-parallel Fp256 batch backend
/// <see cref="P256BaseFieldMontgomeryBatchBackendAvx512"/>, the AVX-512 mirror of
/// <see cref="P256BaseFieldMontgomeryBatchBackendAgreementTests"/>. Gated on
/// <see cref="System.Runtime.Intrinsics.X86.Avx512F"/> support, so it reports Inconclusive
/// (not failed) on a host without AVX-512.
/// </summary>
/// <remarks>
/// The bodies mirror the AVX2 gate: the load-bearing belt-and-suspenders test against the
/// scalar single-CIOS <see cref="P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery"/> on the
/// same Montgomery residues, the end-to-end test against the BigInteger oracle, the
/// multiply-by-mont(1) identity, and the tail-boundary sweep. <see cref="MainCount"/> is not a
/// multiple of the AVX-512 octet width, so the trailing-element fallback is exercised by every run.
/// Both the live generic <c>m·Modulus32</c> reduction
/// (<see cref="P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery"/>) and the retained
/// P-256-specialized signed-sparse reduction
/// (<see cref="P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomerySpecializedReduce"/>)
/// are driven against the same scalar oracle, so every test pins generic == specialized == scalar
/// <see cref="P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery"/>.
/// </remarks>
[TestClass]
internal sealed class P256BaseFieldMontgomeryBatchBackendAvx512AgreementTests
{
    private const long IterationCount = 200;

    //19 is not a multiple of 8 (the AVX-512 octet width), so every sample runs both the SIMD body and the tail.
    private const int MainCount = 19;

    private static readonly CurveParameterSet Curve = CurveParameterSet.None;

    private static readonly ScalarReduceDelegate ReferenceReduce = P256BaseFieldReference.GetReduce();
    private static readonly ScalarMultiplyDelegate ReferenceMultiply = P256BaseFieldReference.GetMultiply();
    private static readonly ScalarMultiplyDelegate ScalarMultiplyMontgomery = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();


    [TestInitialize]
    public void RequireAvx512() => InstructionSetRequirements.RequireAvx512();


    [TestMethod]
    public void BatchMontgomeryMultiplyAgreesWithScalarMontgomeryMultiply()
    {
        //The load-bearing gate: residue-in/residue-out, both batch reductions must equal the scalar
        //single-CIOS MultiplyMontgomery on the identical residues — NOT the canonical Multiply.
        ScalarBatchMultiplyDelegate batchGeneric = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery();
        ScalarBatchMultiplyDelegate batchSpecialized = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomerySpecializedReduce();

        int size = Scalar.SizeBytes;
        Gen<byte[]> batchGen = Gen.Byte.Array[MainCount * size];
        Gen.Select(batchGen, batchGen).Sample((leftRaw, rightRaw) =>
        {
            Span<byte> left = stackalloc byte[MainCount * size];
            Span<byte> right = stackalloc byte[MainCount * size];
            Span<byte> specialized = stackalloc byte[MainCount * size];
            Span<byte> generic = stackalloc byte[MainCount * size];
            Span<byte> expected = stackalloc byte[MainCount * size];

            for(int i = 0; i < MainCount; i++)
            {
                int offset = i * size;
                ToMontgomeryResidue(leftRaw.AsSpan(offset, size), left.Slice(offset, size));
                ToMontgomeryResidue(rightRaw.AsSpan(offset, size), right.Slice(offset, size));
            }

            batchSpecialized(left, right, specialized, MainCount, Curve);
            batchGeneric(left, right, generic, MainCount, Curve);

            for(int i = 0; i < MainCount; i++)
            {
                int offset = i * size;
                ScalarMultiplyMontgomery(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), Curve);
            }

            return specialized.SequenceEqual(expected) && generic.SequenceEqual(expected) && specialized.SequenceEqual(generic);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void BatchMontgomeryMultiplyAgreesWithBigIntegerMultiply()
    {
        //End-to-end: lift canonical operands in, batch-multiply in the Montgomery domain with each reduction,
        //drop out, and compare to the BigInteger oracle a·b mod p.
        ScalarBatchMultiplyDelegate batchGeneric = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery();
        ScalarBatchMultiplyDelegate batchSpecialized = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomerySpecializedReduce();

        int size = Scalar.SizeBytes;
        Gen<byte[]> batchGen = Gen.Byte.Array[MainCount * size];
        Gen.Select(batchGen, batchGen).Sample((leftRaw, rightRaw) =>
        {
            Span<byte> leftCanonical = stackalloc byte[MainCount * size];
            Span<byte> rightCanonical = stackalloc byte[MainCount * size];
            Span<byte> leftMont = stackalloc byte[MainCount * size];
            Span<byte> rightMont = stackalloc byte[MainCount * size];
            Span<byte> specializedMont = stackalloc byte[MainCount * size];
            Span<byte> genericMont = stackalloc byte[MainCount * size];

            for(int i = 0; i < MainCount; i++)
            {
                int offset = i * size;
                ReferenceReduce(leftRaw.AsSpan(offset, size), leftCanonical.Slice(offset, size), Curve);
                ReferenceReduce(rightRaw.AsSpan(offset, size), rightCanonical.Slice(offset, size), Curve);
                P256BaseFieldMontgomeryBackend.ToMontgomery(leftCanonical.Slice(offset, size), leftMont.Slice(offset, size));
                P256BaseFieldMontgomeryBackend.ToMontgomery(rightCanonical.Slice(offset, size), rightMont.Slice(offset, size));
            }

            batchSpecialized(leftMont, rightMont, specializedMont, MainCount, Curve);
            batchGeneric(leftMont, rightMont, genericMont, MainCount, Curve);

            Span<byte> actualSpecialized = stackalloc byte[size];
            Span<byte> actualGeneric = stackalloc byte[size];
            Span<byte> expected = stackalloc byte[size];
            for(int i = 0; i < MainCount; i++)
            {
                int offset = i * size;
                P256BaseFieldMontgomeryBackend.FromMontgomery(specializedMont.Slice(offset, size), actualSpecialized);
                P256BaseFieldMontgomeryBackend.FromMontgomery(genericMont.Slice(offset, size), actualGeneric);
                ReferenceMultiply(leftCanonical.Slice(offset, size), rightCanonical.Slice(offset, size), expected, Curve);
                if(!actualSpecialized.SequenceEqual(expected) || !actualGeneric.SequenceEqual(expected))
                {
                    return false;
                }
            }

            return true;
        }, iter: IterationCount);
    }


    [TestMethod]
    public void BatchMontgomeryMultiplyByOneIsIdentity()
    {
        //Multiplying each residue by mont(1) = R mod p leaves it unchanged (the Montgomery-domain identity),
        //and both reductions must hit that identity.
        ScalarBatchMultiplyDelegate batchGeneric = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery();
        ScalarBatchMultiplyDelegate batchSpecialized = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomerySpecializedReduce();

        int size = Scalar.SizeBytes;
        byte[] canonicalOne = new byte[size];
        canonicalOne[^1] = 1;
        byte[] montOne = new byte[size];
        P256BaseFieldMontgomeryBackend.ToMontgomery(canonicalOne, montOne);

        Gen<byte[]> batchGen = Gen.Byte.Array[MainCount * size];
        batchGen.Sample(raw =>
        {
            Span<byte> residues = stackalloc byte[MainCount * size];
            Span<byte> ones = stackalloc byte[MainCount * size];
            Span<byte> specialized = stackalloc byte[MainCount * size];
            Span<byte> generic = stackalloc byte[MainCount * size];

            for(int i = 0; i < MainCount; i++)
            {
                int offset = i * size;
                ToMontgomeryResidue(raw.AsSpan(offset, size), residues.Slice(offset, size));
                montOne.CopyTo(ones.Slice(offset, size));
            }

            batchSpecialized(residues, ones, specialized, MainCount, Curve);
            batchGeneric(residues, ones, generic, MainCount, Curve);

            return specialized.SequenceEqual(residues) && generic.SequenceEqual(residues);
        }, iter: IterationCount);
    }


    [TestMethod]
    public void BatchMontgomeryMultiplyTailBoundariesAgree()
    {
        //Sweep counts straddling the octet width so the SIMD body, the tail, and their interaction are all
        //covered: each count must agree element-for-element with the scalar single-CIOS multiply, for both
        //reductions.
        ScalarBatchMultiplyDelegate batchGeneric = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery();
        ScalarBatchMultiplyDelegate batchSpecialized = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomerySpecializedReduce();
        int[] counts = [1, 2, 3, 4, 5, 7, 8, 9, 16, 17];

        int size = Scalar.SizeBytes;
        foreach(int count in counts)
        {
            Gen<byte[]> batchGen = Gen.Byte.Array[count * size];
            Gen.Select(batchGen, batchGen).Sample((leftRaw, rightRaw) =>
            {
                Span<byte> left = stackalloc byte[count * size];
                Span<byte> right = stackalloc byte[count * size];
                Span<byte> specialized = stackalloc byte[count * size];
                Span<byte> generic = stackalloc byte[count * size];
                Span<byte> expected = stackalloc byte[count * size];

                for(int i = 0; i < count; i++)
                {
                    int offset = i * size;
                    ToMontgomeryResidue(leftRaw.AsSpan(offset, size), left.Slice(offset, size));
                    ToMontgomeryResidue(rightRaw.AsSpan(offset, size), right.Slice(offset, size));
                }

                batchSpecialized(left, right, specialized, count, Curve);
                batchGeneric(left, right, generic, count, Curve);

                for(int i = 0; i < count; i++)
                {
                    int offset = i * size;
                    ScalarMultiplyMontgomery(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), Curve);
                }

                return specialized.SequenceEqual(expected) && generic.SequenceEqual(expected) && specialized.SequenceEqual(generic);
            }, iter: IterationCount);
        }
    }


    private static void ToMontgomeryResidue(ReadOnlySpan<byte> raw, Span<byte> residue)
    {
        Span<byte> canonical = stackalloc byte[Scalar.SizeBytes];
        ReferenceReduce(raw, canonical, Curve);
        P256BaseFieldMontgomeryBackend.ToMontgomery(canonical, residue);
    }
}
