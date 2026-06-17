using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Tests for the BLS12-381 hash-to-scalar reference: RFC 9380
/// <c>expand_message_xmd</c> with SHA-256 producing 48 uniform bytes,
/// interpreted as a big-endian integer, reduced modulo the scalar
/// field order.
/// </summary>
/// <remarks>
/// These are internal-consistency property tests; the IETF
/// <c>draft-irtf-cfrg-bbs-signatures</c> Appendix A vectors (which
/// exercise <c>hash_to_scalar</c> as part of BBS+ Sign and Verify)
/// provide the load-bearing external gate in the BBS+ test project.
/// </remarks>
[TestClass]
internal sealed class Bls12Curve381ScalarHashToScalarTests
{
    private static readonly ScalarHashToScalarDelegate HashToScalar =
        Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    private static readonly byte[] DefaultDst = Encoding.ASCII.GetBytes("LUMOIN-VERIDICAL-TEST-HASH-TO-SCALAR");

    private const long IterationCount = 30;


    [TestMethod]
    public void HashToScalarIsDeterministic()
    {
        Gen.Byte.Array[0, 256].Sample(message =>
        {
            using Scalar a = Scalar.FromHashToScalar(message, DefaultDst, HashToScalar, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
            using Scalar b = Scalar.FromHashToScalar(message, DefaultDst, HashToScalar, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
            return a.AsReadOnlySpan().SequenceEqual(b.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void HashToScalarRespectsDomainSeparation()
    {
        //Distinct DSTs on the same message must produce distinct
        //scalars. The collision probability with 256-bit outputs is
        //negligible for any non-pathological seed, but the test runs on
        //CsCheck's deterministic seeds so any "unlucky" collision would
        //be reproducible and visible.
        byte[] dstA = Encoding.ASCII.GetBytes("LUMOIN-VERIDICAL-TEST-DST-A");
        byte[] dstB = Encoding.ASCII.GetBytes("LUMOIN-VERIDICAL-TEST-DST-B");

        Gen.Byte.Array[1, 256].Sample(message =>
        {
            using Scalar a = Scalar.FromHashToScalar(message, dstA, HashToScalar, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
            using Scalar b = Scalar.FromHashToScalar(message, dstB, HashToScalar, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
            return !a.AsReadOnlySpan().SequenceEqual(b.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void HashToScalarOutputIsInScalarField()
    {
        //The reference reduces modulo the field order before writing,
        //so the output bytes always decode through FromCanonical without
        //throwing (FromCanonical only accepts strictly-less-than-r values).
        Gen.Byte.Array[0, 256].Sample(message =>
        {
            using Scalar produced = Scalar.FromHashToScalar(message, DefaultDst, HashToScalar, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
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
}