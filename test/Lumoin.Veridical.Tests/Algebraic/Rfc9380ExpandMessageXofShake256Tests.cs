using CsCheck;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Tests for <see cref="Rfc9380ExpandMessage.ExpandMessageXofShake256"/>.
/// </summary>
/// <remarks>
/// Byte-faithful against RFC 9380 Appendix K.6
/// (<c>expand_message_xof(SHAKE256)</c>) for the five short-output
/// vectors, plus structural invariants paralleling the
/// <see cref="Rfc9380ExpandMessageTests"/> sibling for the XMD variant.
/// The K.6 vectors are the right gate here — they catch any
/// off-by-one in the DST length byte or the I2OSP(len_in_bytes, 2)
/// big-endian encoding, which would otherwise only be visible at the
/// downstream BBS+ Appendix A layer.
/// </remarks>
[TestClass]
internal sealed class Rfc9380ExpandMessageXofShake256Tests
{
    //RFC 9380 Appendix K.6 — DST common to every vector in the section.
    private const string CanonicalDst = "QUUX-V01-CS02-with-expander-SHAKE256";


    [TestMethod]
    [DataRow("", "2ffc05c48ed32b95d72e807f6eab9f7530dd1c2f013914c8fed38c5ccc15ad76")]
    [DataRow("abc", "b39e493867e2767216792abce1f2676c197c0692aed061560ead251821808e07")]
    [DataRow("abcdef0123456789", "245389cf44a13f0e70af8665fe5337ec2dcd138890bb7901c4ad9cfceb054b65")]
    public void Rfc9380K6ShortMessageByteFaithful(string msgAscii, string expectedHex)
    {
        byte[] msg = Encoding.ASCII.GetBytes(msgAscii);
        byte[] dst = Encoding.ASCII.GetBytes(CanonicalDst);
        byte[] output = new byte[expectedHex.Length / 2];
        Rfc9380ExpandMessage.ExpandMessageXofShake256(msg, dst, output);
        Assert.AreEqual(expectedHex, Convert.ToHexStringLower(output),
            $"K.6 vector for msg='{msgAscii}' diverged.");
    }


    [TestMethod]
    public void Rfc9380K6Q128MessageByteFaithful()
    {
        byte[] msg = Encoding.ASCII.GetBytes("q128_" + new string('q', 128));
        byte[] dst = Encoding.ASCII.GetBytes(CanonicalDst);
        byte[] output = new byte[32];
        Rfc9380ExpandMessage.ExpandMessageXofShake256(msg, dst, output);
        Assert.AreEqual(
            "719b3911821e6428a5ed9b8e600f2866bcf23c8f0515e52d6c6c019a03f16f0e",
            Convert.ToHexStringLower(output));
    }


    [TestMethod]
    public void Rfc9380K6A512MessageByteFaithful()
    {
        byte[] msg = Encoding.ASCII.GetBytes("a512_" + new string('a', 512));
        byte[] dst = Encoding.ASCII.GetBytes(CanonicalDst);
        byte[] output = new byte[32];
        Rfc9380ExpandMessage.ExpandMessageXofShake256(msg, dst, output);
        Assert.AreEqual(
            "9181ead5220b1963f1b5951f35547a5ea86a820562287d6ca4723633d17ccbbc",
            Convert.ToHexStringLower(output));
    }


    [TestMethod]
    public void IsDeterministicOnSameInputs()
    {
        Gen.Select(Gen.Byte.Array[0, 256], Gen.Byte.Array[0, 32], Gen.Int[1, 256])
            .Sample(((byte[] msg, byte[] dst, int outLen) t) =>
            {
                byte[] a = new byte[t.outLen];
                byte[] b = new byte[t.outLen];
                Rfc9380ExpandMessage.ExpandMessageXofShake256(t.msg, t.dst, a);
                Rfc9380ExpandMessage.ExpandMessageXofShake256(t.msg, t.dst, b);
                return a.AsSpan().SequenceEqual(b);
            }, iter: 30);
    }


    [TestMethod]
    public void DifferentDstsProduceDifferentOutputs()
    {
        byte[] message = Encoding.ASCII.GetBytes("expand_message_xof test message");
        byte[] dstA = Encoding.ASCII.GetBytes("DST-A");
        byte[] dstB = Encoding.ASCII.GetBytes("DST-B");

        byte[] outA = new byte[48];
        byte[] outB = new byte[48];
        Rfc9380ExpandMessage.ExpandMessageXofShake256(message, dstA, outA);
        Rfc9380ExpandMessage.ExpandMessageXofShake256(message, dstB, outB);

        Assert.IsFalse(outA.AsSpan().SequenceEqual(outB),
            "Distinct DSTs must produce distinct expand_message_xof outputs.");
    }


    [TestMethod]
    public void XofAndXmdDifferOnIdenticalInputs()
    {
        //The two expand_message variants share input shape but the
        //byte composition differs at every step (XMD does
        //block-iteration with strxor; XOF emits the requested length
        //in one shot). Identical (msg, DST, len) must produce
        //byte-different outputs.
        byte[] message = Encoding.ASCII.GetBytes("ciphersuite separation probe");
        byte[] dst = Encoding.ASCII.GetBytes("common-DST");

        byte[] xmdOutput = new byte[48];
        byte[] xofOutput = new byte[48];
        Rfc9380ExpandMessage.ExpandMessageXmdSha256(message, dst, xmdOutput);
        Rfc9380ExpandMessage.ExpandMessageXofShake256(message, dst, xofOutput);

        Assert.IsFalse(xmdOutput.AsSpan().SequenceEqual(xofOutput),
            "expand_message_xmd(SHA-256) and expand_message_xof(SHAKE-256) must produce distinct outputs for identical (msg, dst, len).");
    }
}