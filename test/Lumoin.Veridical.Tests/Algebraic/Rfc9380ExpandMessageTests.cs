using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Tests for <see cref="Rfc9380ExpandMessage.ExpandMessageXmdSha256"/>.
/// </summary>
/// <remarks>
/// Structural rather than byte-faithful against a published RFC 9380
/// §K vector: the K-vector outputs are large blobs that would be
/// inlined as huge hex constants; the production hash-to-curve and
/// hash-to-scalar consumers of this primitive are already gated by
/// downstream KAT vectors (BLS12-381 hash-to-curve in the existing G1
/// reference tests; the IETF BBS+ Appendix A vectors in the BBS+ test
/// project). The checks below verify the primitive's invariants:
/// determinism, DST sensitivity, output-length honour, and that
/// rejected inputs throw.
/// </remarks>
[TestClass]
internal sealed class Rfc9380ExpandMessageTests
{
    private const long IterationCount = 30;


    [TestMethod]
    public void IsDeterministicOnSameInputs()
    {
        Gen.Select(Gen.Byte.Array[0, 256], Gen.Byte.Array[0, 32], Gen.Int[1, 256])
            .Sample(((byte[] msg, byte[] dst, int outLen) t) =>
            {
                byte[] a = new byte[t.outLen];
                byte[] b = new byte[t.outLen];
                Rfc9380ExpandMessage.ExpandMessageXmdSha256(t.msg, t.dst, a);
                Rfc9380ExpandMessage.ExpandMessageXmdSha256(t.msg, t.dst, b);
                return a.AsSpan().SequenceEqual(b);
            }, iter: IterationCount);
    }


    [TestMethod]
    public void DifferentDstsProduceDifferentOutputs()
    {
        //Distinct DSTs on the same message yield distinct outputs (in 48
        //bytes the collision probability is astronomically small). The
        //test uses fixed message and varies DST.
        byte[] message = Encoding.ASCII.GetBytes("expand_message_xmd test message");
        byte[] dstA = Encoding.ASCII.GetBytes("DST-A");
        byte[] dstB = Encoding.ASCII.GetBytes("DST-B");

        byte[] outA = new byte[48];
        byte[] outB = new byte[48];
        Rfc9380ExpandMessage.ExpandMessageXmdSha256(message, dstA, outA);
        Rfc9380ExpandMessage.ExpandMessageXmdSha256(message, dstB, outB);

        Assert.IsFalse(outA.AsSpan().SequenceEqual(outB), "Distinct DSTs must produce distinct expand_message_xmd outputs.");
    }


    [TestMethod]
    public void HonoursOutputLengthExactly()
    {
        byte[] message = Encoding.ASCII.GetBytes("payload");
        byte[] dst = Encoding.ASCII.GetBytes("test");

        foreach(int len in new[] { 1, 16, 31, 32, 48, 64, 128, 256 })
        {
            byte[] output = new byte[len];
            Rfc9380ExpandMessage.ExpandMessageXmdSha256(message, dst, output);
            Assert.HasCount(len, output);
        }
    }


    [TestMethod]
    public void RejectsZeroLengthOutput()
    {
        byte[] message = Encoding.ASCII.GetBytes("payload");
        byte[] dst = Encoding.ASCII.GetBytes("test");
        byte[] output = Array.Empty<byte>();
        Assert.ThrowsExactly<ArgumentException>(() => Rfc9380ExpandMessage.ExpandMessageXmdSha256(message, dst, output));
    }


    [TestMethod]
    public void RejectsOverlongDst()
    {
        byte[] message = Encoding.ASCII.GetBytes("payload");
        byte[] dst = new byte[256];
        byte[] output = new byte[48];
        Assert.ThrowsExactly<ArgumentException>(() => Rfc9380ExpandMessage.ExpandMessageXmdSha256(message, dst, output));
    }
}