using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.IetfVectors;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Byte-faithful tests for <c>Bls12Curve381BigIntegerG1Reference.HashToCurve</c>
/// against the RFC 9380 Appendix J.9.1 published vectors for the suite
/// <c>BLS12381G1_XMD:SHA-256_SSWU_RO_</c>.
/// </summary>
/// <remarks>
/// <para>
/// This gate exists because BBS+ generator derivation depends on byte-
/// faithful agreement with the RFC 9380 §8.8.1 SSWU-RO + 11-isogeny +
/// cofactor-clearing construction. Algebraic-invariant tests (on-curve,
/// in-subgroup) are necessary but not sufficient — they did not catch
/// the try-and-increment divergence the BBS+.1 batch uncovered, because
/// try-and-increment also produces valid subgroup points. Byte equality
/// against published vectors does catch that class of bug.
/// </para>
/// <para>
/// The five vectors live as typed constants in
/// <see cref="Rfc9380J9_1Vectors"/>; see that class's remarks for the
/// y-parity flag convention applied to derive <c>ExpectedCompressed</c>
/// from the published <c>(P.x, P.y)</c>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Bls12Curve381G1HashToCurveByteFaithfulTests
{
    public static IEnumerable<object[]> VectorData =>
        Rfc9380J9_1Vectors.All.Select(v => new object[] { v });


    [TestMethod]
    [DynamicData(nameof(VectorData))]
    public void HashToCurveProducesPublishedCompressedEncoding(Rfc9380J9_1Vector vector)
    {
        byte[] msg = Encoding.ASCII.GetBytes(vector.MsgAscii);
        byte[] dst = Encoding.ASCII.GetBytes(Rfc9380J9_1Vectors.Dst);

        G1HashToCurveDelegate hashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
        using G1Point produced = G1Point.FromHashToCurve(
            msg,
            dst,
            hashToCurve, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        byte[] expectedBytes = Convert.FromHexString(vector.ExpectedCompressed);
        ReadOnlySpan<byte> producedBytes = produced.AsReadOnlySpan();

        Assert.IsTrue(
            producedBytes.SequenceEqual(expectedBytes),
            $"RFC 9380 §J.9.1 vector '{vector.Id}' ({vector.Description}) byte-equality failed.\n" +
            $"  msg (len {msg.Length}): '{(msg.Length > 50 ? string.Concat(vector.MsgAscii.AsSpan(0, 50), "...") : vector.MsgAscii)}'\n" +
            $"  expected: {vector.ExpectedCompressed}\n" +
            $"  produced: {Convert.ToHexStringLower(producedBytes)}");
    }


    [TestMethod]
    public void Sha256AndShake256HashToCurveProduceDifferentPoints()
    {
        //RFC 9380 does not publish SHAKE-256 G1 hash-to-curve vectors;
        //the byte-faithful gate for the full SHAKE-256 pipeline lives
        //at the BBS+ Appendix A layer (in the BBS+ test project). This
        //test ensures the SHAKE-256 hash-to-curve at least returns a
        //point distinct from the SHA-256 variant for the same
        //(message, dst) — a property without which the ciphersuites
        //would be indistinguishable at the G1 level.
        byte[] message = Encoding.ASCII.GetBytes("ciphersuite-separation probe");
        byte[] dst = Encoding.ASCII.GetBytes("common-DST");

        G1HashToCurveDelegate sha = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
        G1HashToCurveDelegate shake = Bls12Curve381BigIntegerG1Reference.GetHashToCurveShake256();

        using G1Point pSha = G1Point.FromHashToCurve(message, dst, sha, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using G1Point pShake = G1Point.FromHashToCurve(message, dst, shake, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        Assert.IsFalse(pSha.AsReadOnlySpan().SequenceEqual(pShake.AsReadOnlySpan()),
            "SHA-256 and SHAKE-256 G1 hash-to-curve must produce distinct points for identical (message, dst).");
    }
}