using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Tests for the BLS12-381 SHAKE-256 hash-to-scalar reference: RFC
/// 9380 <c>expand_message_xof</c> with SHAKE-256 producing 48
/// uniform bytes, interpreted as a big-endian integer, reduced
/// modulo the scalar field order.
/// </summary>
/// <remarks>
/// Structural property tests, mirroring
/// <see cref="Bls12Curve381ScalarHashToScalarTests"/> for the
/// SHA-256 variant. The load-bearing byte-faithful gate is the IETF
/// <c>draft-irtf-cfrg-bbs-signatures-10</c> BLS12-381-SHAKE-256
/// Appendix A vectors in the BBS+ test project.
/// </remarks>
[TestClass]
internal sealed class Bls12Curve381ScalarHashToScalarShake256Tests
{
    private static readonly ScalarHashToScalarDelegate HashToScalarShake256 =
        Bls12Curve381BigIntegerScalarReference.GetHashToScalarShake256();

    private static readonly ScalarHashToScalarDelegate HashToScalarSha256 =
        Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    private static readonly byte[] DefaultDst = Encoding.ASCII.GetBytes("LUMOIN-VERIDICAL-TEST-HASH-TO-SCALAR-SHAKE256");

    private const long IterationCount = 30;


    [TestMethod]
    public void HashToScalarIsDeterministic()
    {
        Gen.Byte.Array[0, 256].Sample(message =>
        {
            using Scalar a = Scalar.FromHashToScalar(message, DefaultDst, HashToScalarShake256, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
            using Scalar b = Scalar.FromHashToScalar(message, DefaultDst, HashToScalarShake256, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
            return a.AsReadOnlySpan().SequenceEqual(b.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void HashToScalarRespectsDomainSeparation()
    {
        byte[] dstA = Encoding.ASCII.GetBytes("LUMOIN-VERIDICAL-TEST-DST-A-SHAKE");
        byte[] dstB = Encoding.ASCII.GetBytes("LUMOIN-VERIDICAL-TEST-DST-B-SHAKE");

        Gen.Byte.Array[1, 256].Sample(message =>
        {
            using Scalar a = Scalar.FromHashToScalar(message, dstA, HashToScalarShake256, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
            using Scalar b = Scalar.FromHashToScalar(message, dstB, HashToScalarShake256, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
            return !a.AsReadOnlySpan().SequenceEqual(b.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void HashToScalarOutputIsInScalarField()
    {
        Gen.Byte.Array[0, 256].Sample(message =>
        {
            using Scalar produced = Scalar.FromHashToScalar(message, DefaultDst, HashToScalarShake256, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
            byte[] copy = produced.AsReadOnlySpan().ToArray();
            try
            {
                using Scalar reparsed = Scalar.FromCanonical(copy, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
                return reparsed.AsReadOnlySpan().SequenceEqual(produced.AsReadOnlySpan());
            }
            catch(ArgumentException)
            {
                return false;
            }
        }, iter: IterationCount);
    }


    [TestMethod]
    public void Sha256AndShake256ProduceDifferentScalars()
    {
        //Ciphersuite-separation invariant: the same (message, DST) under
        //the SHA-256 and SHAKE-256 hash-to-scalar delegates produces
        //byte-different scalars. This is the property that makes a
        //signature produced under one ciphersuite fail to verify under
        //the other.
        byte[] message = Encoding.ASCII.GetBytes("ciphersuite-separation probe");
        byte[] dst = Encoding.ASCII.GetBytes("common-DST");

        using Scalar sha = Scalar.FromHashToScalar(message, dst, HashToScalarSha256, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using Scalar shake = Scalar.FromHashToScalar(message, dst, HashToScalarShake256, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        Assert.IsFalse(sha.AsReadOnlySpan().SequenceEqual(shake.AsReadOnlySpan()),
            "SHA-256 and SHAKE-256 hash-to-scalar must produce distinct scalars for identical (message, DST).");
    }
}