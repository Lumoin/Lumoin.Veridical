using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Cryptography;
using Lumoin.Veridical.Hashing;
using System;
using System.Text;

namespace Lumoin.Veridical.Tests.Cryptography;

/// <summary>
/// Conformance gate for <see cref="Rfc6979DeterministicNonce"/> against the published RFC 6979 Appendix A.2.5
/// test vectors (NIST P-256, SHA-256): the deterministic nonce <c>k</c> derived from the spec's private key and
/// the SHA-256 digest of "sample" / "test" must equal the spec's <c>k</c> byte-for-byte. Getting the nonce right
/// is the whole point of RFC 6979 — a wrong nonce yields a different (still-valid) signature, and a non-uniform
/// or reused nonce leaks the private key — so this is gated against the standard's own vectors, with HMAC-SHA256
/// (<see cref="Sha256Hmac"/>) wired in as the injected primitive.
/// </summary>
[TestClass]
internal sealed class Rfc6979DeterministicNonceTests
{
    private const int ScalarSize = 32;

    //RFC 6979 Appendix A.2.5 P-256 private key x.
    private const string PrivateKeyHex = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

    private static HmacSha256Delegate Hmac { get; } = Sha256Hmac.Compute;


    [TestMethod]
    public void NonceMatchesRfc6979P256Sha256SampleVector()
    {
        AssertNonce("sample", "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
    }


    [TestMethod]
    public void NonceMatchesRfc6979P256Sha256TestVector()
    {
        AssertNonce("test", "D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0");
    }


    [TestMethod]
    public void AnOutOfRangeCandidateIsRejectedAndTheLoopRetries()
    {
        //The reject branch (RFC 6979 §3.2 step h.3) is never reached by the spec vectors — for P-256 the first
        //candidate is in [1, q−1] with overwhelming probability. Drive it with a SCRIPTED HMAC: the first
        //candidate T is exactly q (so k = q fails the k < q test and is rejected), and after the reject's K/V
        //update HMACs the next candidate is a valid in-range value, which must be returned. The HMAC call
        //sequence is RFC-fixed: 4 init calls (d/e/f/g), then per attempt one candidate call, with two extra
        //K/V-update calls on a reject — so candidate #1 is call 5 and candidate #2 is call 8.
        byte[] privateKey = Convert.FromHexString(PrivateKeyHex);
        Span<byte> hash = stackalloc byte[ScalarSize];
        Sha256.HashData(Encoding.ASCII.GetBytes("sample"), hash);

        byte[] order = OrderBytes();
        byte[] valid = new byte[ScalarSize];
        valid[ScalarSize - 1] = 0x2A;

        var scripted = new ScriptedHmac();
        scripted.SetOutput(5, order);    //candidate #1 = q → rejected (k < q is false).
        scripted.SetOutput(8, valid);    //candidate #2 = 42 → accepted.

        Span<byte> nonce = stackalloc byte[ScalarSize];
        Rfc6979DeterministicNonce.GenerateNonce(CurveParameterSet.P256, privateKey, hash, scripted.Compute, nonce);

        Assert.IsTrue(valid.AsSpan().SequenceEqual(nonce), "The out-of-range first candidate must be rejected and the next valid candidate returned.");
        Assert.AreEqual(8, scripted.CallCount, "The reject path must perform the two extra K/V-update HMAC calls before the second candidate.");
    }


    private static void AssertNonce(string message, string expectedNonceHex)
    {
        byte[] privateKey = Convert.FromHexString(PrivateKeyHex);

        Span<byte> hash = stackalloc byte[ScalarSize];
        Sha256.HashData(Encoding.ASCII.GetBytes(message), hash);

        Span<byte> nonce = stackalloc byte[ScalarSize];
        Rfc6979DeterministicNonce.GenerateNonce(CurveParameterSet.P256, privateKey, hash, Hmac, nonce);

        byte[] expected = Convert.FromHexString(expectedNonceHex);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(nonce), $"The RFC 6979 P-256/SHA-256 nonce for \"{message}\" must match the spec vector.");
    }


    //The P-256 order q as a 32-byte big-endian scalar.
    private static byte[] OrderBytes()
    {
        System.Numerics.BigInteger q = WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.P256);
        byte[] big = q.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] order = new byte[ScalarSize];
        big.CopyTo(order.AsSpan(ScalarSize - big.Length));

        return order;
    }


    //A deterministic HMAC stand-in for the reject-branch test: returns a per-call-index scripted 32-byte output
    //(default 0x01·32, a harmless valid candidate) so the reject path's exact HMAC sequence can be driven.
    private sealed class ScriptedHmac
    {
        private readonly System.Collections.Generic.Dictionary<int, byte[]> outputs = new();

        public int CallCount { get; private set; }

        public void SetOutput(int oneBasedCall, byte[] output) => outputs[oneBasedCall] = output;

        public void Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> mac)
        {
            CallCount++;
            if(outputs.TryGetValue(CallCount, out byte[]? scripted))
            {
                scripted.CopyTo(mac);
            }
            else
            {
                mac.Clear();
                mac[^1] = 0x01;
            }
        }
    }
}
