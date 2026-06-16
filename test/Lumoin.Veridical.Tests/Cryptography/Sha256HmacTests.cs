using Lumoin.Veridical.Hashing;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Cryptography;

/// <summary>
/// Conformance gate for <see cref="Sha256Hmac"/>: HMAC-SHA256 must be byte-identical to the BCL
/// <see cref="HMACSHA256"/> across the key/message size boundaries that exercise every construction branch
/// (short key zero-padding, exactly-a-block key, key longer than a block → hashed, and message sizes crossing
/// the 64-byte SHA-256 block), and must match the published RFC 4231 test vector. HMAC-SHA256 is the building
/// block of the RFC 6979 deterministic nonce, so a divergence here would silently corrupt every deterministic
/// signature.
/// </summary>
[TestClass]
internal sealed class Sha256HmacTests
{
    private const int MacSize = 32;


    [TestMethod]
    public void HmacSha256MatchesTheBclAcrossKeyAndMessageSizeBoundaries()
    {
        ReadOnlySpan<int> keySizes = [0, 1, 16, 32, 63, 64, 65, 100, 200];
        ReadOnlySpan<int> messageSizes = [0, 1, 32, 55, 56, 63, 64, 65, 100, 256];

        foreach(int keySize in keySizes)
        {
            foreach(int messageSize in messageSizes)
            {
                byte[] key = Pattern(keySize, 0x11 + keySize);
                byte[] message = Pattern(messageSize, 0x37 + messageSize);

                byte[] expected = HMACSHA256.HashData(key, message);
                byte[] actual = new byte[MacSize];
                Sha256Hmac.Compute(key, message, actual);

                Assert.IsTrue(expected.AsSpan().SequenceEqual(actual), $"HMAC-SHA256 must match the BCL for key={keySize}, message={messageSize}.");
            }
        }
    }


    [TestMethod]
    public void HmacSha256MatchesRfc4231TestCase1()
    {
        //RFC 4231 §4.2 test case 1: key = 20 bytes of 0x0b, data = "Hi There".
        byte[] key = new byte[20];
        key.AsSpan().Fill(0x0B);
        byte[] data = Encoding.ASCII.GetBytes("Hi There");
        byte[] expected = Convert.FromHexString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

        byte[] actual = new byte[MacSize];
        Sha256Hmac.Compute(key, data, actual);

        Assert.IsTrue(expected.AsSpan().SequenceEqual(actual), "HMAC-SHA256 must match RFC 4231 test case 1.");
    }


    //A deterministic patterned byte sequence (no System.Random, which CA5394 forbids): a failing case reproduces.
    private static byte[] Pattern(int length, int offset)
    {
        byte[] bytes = new byte[length];
        for(int i = 0; i < length; i++)
        {
            bytes[i] = (byte)(((i * 31) + offset) & 0xFF);
        }

        return bytes;
    }
}
