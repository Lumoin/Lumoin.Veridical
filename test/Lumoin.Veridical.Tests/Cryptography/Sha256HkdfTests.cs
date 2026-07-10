using Lumoin.Veridical.Hashing;
using System;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Cryptography;

/// <summary>
/// Conformance gate for <see cref="Sha256Hkdf"/>: HKDF-SHA256 must reproduce the published RFC 5869 Appendix A
/// test vectors byte-exactly — the PRK from <see cref="Sha256Hkdf.Extract"/> and the OKM from both
/// <see cref="Sha256Hkdf.Expand"/> and <see cref="Sha256Hkdf.DeriveKey"/> — and must match the BCL
/// <see cref="HKDF"/> across the input/output size boundaries that exercise every construction branch (IKM,
/// salt and info shorter than, equal to, and longer than a HashLen or a HMAC block; output lengths crossing
/// HMAC digest boundaries up to the RFC's 255·HashLen ceiling). HKDF-SHA256 is the KDF ISO 18013-5 stipulates
/// for ECDH-MAC's <c>EMacKey</c> derivation, so a divergence here would silently corrupt every session-transcript
/// MAC key.
/// </summary>
[TestClass]
internal sealed class Sha256HkdfTests
{
    [TestMethod]
    public void HkdfSha256MatchesRfc5869TestCase1Basic()
    {
        //RFC 5869 Appendix A.1: SHA-256, 22-byte IKM, 13-byte salt, 10-byte info, L = 42.
        byte[] ikm = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = Convert.FromHexString("000102030405060708090a0b0c");
        byte[] info = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9");
        byte[] expectedPrk = Convert.FromHexString("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        byte[] expectedOkm = Convert.FromHexString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

        AssertRfc5869Case(salt, ikm, info, expectedPrk, expectedOkm);
    }


    [TestMethod]
    public void HkdfSha256MatchesRfc5869TestCase2LongerInputs()
    {
        //RFC 5869 Appendix A.2: SHA-256, 80-byte IKM, 80-byte salt, 80-byte info, L = 82.
        byte[] ikm = Convert.FromHexString(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
            "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
        byte[] salt = Convert.FromHexString(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f" +
            "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        byte[] info = Convert.FromHexString(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0" +
            "e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        byte[] expectedPrk = Convert.FromHexString("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
        byte[] expectedOkm = Convert.FromHexString(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09d" +
            "a3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");

        AssertRfc5869Case(salt, ikm, info, expectedPrk, expectedOkm);
    }


    [TestMethod]
    public void HkdfSha256MatchesRfc5869TestCase3ZeroLengthSaltAndInfo()
    {
        //RFC 5869 Appendix A.3: SHA-256, 22-byte IKM, zero-length salt and info, L = 42.
        byte[] ikm = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = [];
        byte[] info = [];
        byte[] expectedPrk = Convert.FromHexString("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        byte[] expectedOkm = Convert.FromHexString("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");

        AssertRfc5869Case(salt, ikm, info, expectedPrk, expectedOkm);
    }


    [TestMethod]
    public void HkdfSha256MatchesTheBclAcrossInputAndOutputSizeBoundaries()
    {
        ReadOnlySpan<int> ikmSizes = [1, 32, 64, 100];
        ReadOnlySpan<int> saltSizes = [0, 13, 32, 80];
        ReadOnlySpan<int> infoSizes = [0, 10, 80];
        ReadOnlySpan<int> outputSizes = [1, 16, 31, 32, 33, 42, 64, 255, 8160];

        foreach(int ikmSize in ikmSizes)
        {
            byte[] ikm = Pattern(ikmSize, 0x11 + ikmSize);

            foreach(int saltSize in saltSizes)
            {
                byte[] salt = Pattern(saltSize, 0x37 + saltSize);

                byte[] expectedPrk = new byte[Sha256Hkdf.PseudoRandomKeySizeBytes];
                HKDF.Extract(HashAlgorithmName.SHA256, ikm, salt, expectedPrk);

                byte[] actualPrk = new byte[Sha256Hkdf.PseudoRandomKeySizeBytes];
                Sha256Hkdf.Extract(salt, ikm, actualPrk);
                Assert.IsTrue(expectedPrk.AsSpan().SequenceEqual(actualPrk), $"Extract must match the BCL for ikm={ikmSize}, salt={saltSize}.");

                foreach(int infoSize in infoSizes)
                {
                    byte[] info = Pattern(infoSize, 0x5B + infoSize);

                    foreach(int outputSize in outputSizes)
                    {
                        byte[] expectedOkm = new byte[outputSize];
                        HKDF.Expand(HashAlgorithmName.SHA256, expectedPrk, expectedOkm, info);

                        byte[] actualOkm = new byte[outputSize];
                        Sha256Hkdf.Expand(actualPrk, info, actualOkm);
                        Assert.IsTrue(expectedOkm.AsSpan().SequenceEqual(actualOkm),
                            $"Expand must match the BCL for ikm={ikmSize}, salt={saltSize}, info={infoSize}, output={outputSize}.");

                        byte[] expectedDeriveKeyOkm = new byte[outputSize];
                        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, expectedDeriveKeyOkm, salt, info);

                        byte[] actualDeriveKeyOkm = new byte[outputSize];
                        Sha256Hkdf.DeriveKey(salt, ikm, info, actualDeriveKeyOkm);
                        Assert.IsTrue(expectedDeriveKeyOkm.AsSpan().SequenceEqual(actualDeriveKeyOkm),
                            $"DeriveKey must match the BCL for ikm={ikmSize}, salt={saltSize}, info={infoSize}, output={outputSize}.");
                    }
                }
            }
        }
    }


    [TestMethod]
    public void ExtractRejectsAWrongLengthDestination()
    {
        byte[] salt = Pattern(13, 0x01);
        byte[] ikm = Pattern(22, 0x02);

        Assert.ThrowsExactly<ArgumentException>(() => Sha256Hkdf.Extract(salt, ikm, new byte[Sha256Hkdf.PseudoRandomKeySizeBytes - 1]));
    }


    [TestMethod]
    public void ExpandRejectsAPseudoRandomKeyShorterThanTheDigestSize()
    {
        byte[] shortPseudoRandomKey = Pattern(Sha256Hkdf.PseudoRandomKeySizeBytes - 1, 0x03);
        byte[] info = Pattern(10, 0x04);

        Assert.ThrowsExactly<ArgumentException>(() => Sha256Hkdf.Expand(shortPseudoRandomKey, info, new byte[16]));
    }


    [TestMethod]
    public void ExpandRejectsAnEmptyOutput()
    {
        byte[] pseudoRandomKey = Pattern(Sha256Hkdf.PseudoRandomKeySizeBytes, 0x05);
        byte[] info = Pattern(10, 0x06);

        Assert.ThrowsExactly<ArgumentException>(() => Sha256Hkdf.Expand(pseudoRandomKey, info, []));
    }


    [TestMethod]
    public void ExpandRejectsAnInfoLongerThanTheDocumentedBound()
    {
        byte[] pseudoRandomKey = Pattern(Sha256Hkdf.PseudoRandomKeySizeBytes, 0x0F);
        byte[] oversizedInfo = Pattern(Sha256Hkdf.MaxInfoSizeBytes + 1, 0x10);

        Assert.ThrowsExactly<ArgumentException>(() => Sha256Hkdf.Expand(pseudoRandomKey, oversizedInfo, new byte[16]));
    }


    [TestMethod]
    public void DeriveKeyRejectsAnInfoLongerThanTheDocumentedBound()
    {
        byte[] salt = Pattern(13, 0x11);
        byte[] ikm = Pattern(22, 0x12);
        byte[] oversizedInfo = Pattern(Sha256Hkdf.MaxInfoSizeBytes + 1, 0x13);

        Assert.ThrowsExactly<ArgumentException>(() => Sha256Hkdf.DeriveKey(salt, ikm, oversizedInfo, new byte[16]));
    }


    [TestMethod]
    public void ExpandAcceptsAnInfoAtTheDocumentedBoundAndMatchesTheBcl()
    {
        byte[] pseudoRandomKey = Pattern(Sha256Hkdf.PseudoRandomKeySizeBytes, 0x14);
        byte[] boundaryInfo = Pattern(Sha256Hkdf.MaxInfoSizeBytes, 0x15);

        byte[] expectedOkm = new byte[42];
        HKDF.Expand(HashAlgorithmName.SHA256, pseudoRandomKey, expectedOkm, boundaryInfo);

        byte[] actualOkm = new byte[42];
        Sha256Hkdf.Expand(pseudoRandomKey, boundaryInfo, actualOkm);

        Assert.IsTrue(expectedOkm.AsSpan().SequenceEqual(actualOkm), "Expand must match the BCL at the info bound.");
    }


    [TestMethod]
    public void ExpandRejectsAnOutputLongerThanTheRfcCeiling()
    {
        byte[] pseudoRandomKey = Pattern(Sha256Hkdf.PseudoRandomKeySizeBytes, 0x07);
        byte[] info = Pattern(10, 0x08);

        Assert.ThrowsExactly<ArgumentException>(() => Sha256Hkdf.Expand(pseudoRandomKey, info, new byte[Sha256Hkdf.MaxOutputSizeBytes + 1]));
    }


    [TestMethod]
    public void DeriveKeyRejectsAnEmptyOutput()
    {
        byte[] salt = Pattern(13, 0x09);
        byte[] ikm = Pattern(22, 0x0A);
        byte[] info = Pattern(10, 0x0B);

        Assert.ThrowsExactly<ArgumentException>(() => Sha256Hkdf.DeriveKey(salt, ikm, info, []));
    }


    [TestMethod]
    public void DeriveKeyRejectsAnOutputLongerThanTheRfcCeiling()
    {
        byte[] salt = Pattern(13, 0x0C);
        byte[] ikm = Pattern(22, 0x0D);
        byte[] info = Pattern(10, 0x0E);

        Assert.ThrowsExactly<ArgumentException>(() => Sha256Hkdf.DeriveKey(salt, ikm, info, new byte[Sha256Hkdf.MaxOutputSizeBytes + 1]));
    }


    //Asserts that Extract's PRK and both Expand's and DeriveKey's OKM match a published RFC 5869 test vector.
    private static void AssertRfc5869Case(byte[] salt, byte[] ikm, byte[] info, byte[] expectedPrk, byte[] expectedOkm)
    {
        byte[] prk = new byte[Sha256Hkdf.PseudoRandomKeySizeBytes];
        Sha256Hkdf.Extract(salt, ikm, prk);
        Assert.IsTrue(expectedPrk.AsSpan().SequenceEqual(prk), "Extract must match the RFC 5869 PRK.");

        byte[] okmFromExpand = new byte[expectedOkm.Length];
        Sha256Hkdf.Expand(prk, info, okmFromExpand);
        Assert.IsTrue(expectedOkm.AsSpan().SequenceEqual(okmFromExpand), "Expand must match the RFC 5869 OKM.");

        byte[] okmFromDeriveKey = new byte[expectedOkm.Length];
        Sha256Hkdf.DeriveKey(salt, ikm, info, okmFromDeriveKey);
        Assert.IsTrue(expectedOkm.AsSpan().SequenceEqual(okmFromDeriveKey), "DeriveKey must match the RFC 5869 OKM.");
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
