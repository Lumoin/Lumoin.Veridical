using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Hashing.Internal;
using Lumoin.Veridical.Tests.Hashing.Blake3Vectors;
using System.Text;

namespace Lumoin.Veridical.Tests.Hashing;

/// <summary>
/// Byte-faithful conformance tests for the portable scalar BLAKE3
/// backend against the canonical upstream test vectors. Every vector is
/// exercised under all three modes (hash, keyed_hash, derive_key) in
/// XOF mode, so the first 32 bytes of each output cover the default
/// fixed-output digest and the trailing bytes cover the extendable
/// output stream.
/// </summary>
[TestClass]
internal sealed class Blake3PortableConformanceTests
{
    private static readonly Blake3Backend Backend = Blake3PortableBackend.GetBackend();


    public static IEnumerable<object[]> AllVectors =>
        Blake3CanonicalVectors.All.Select(v => new object[] { v });


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void HashModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        byte[] input = BuildCanonicalInput(vector.InputLength);
        byte[] expected = Convert.FromHexString(vector.ExpectedHashHex);
        byte[] actual = new byte[expected.Length];

        using Blake3Hasher hasher = Blake3Hasher.Create(Backend);
        hasher.Update(input);
        hasher.FinalizeXof(actual);

        CollectionAssert.AreEqual(expected, actual);
    }


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void KeyedHashModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        byte[] input = BuildCanonicalInput(vector.InputLength);
        byte[] keyBytes = Encoding.ASCII.GetBytes(Blake3CanonicalVectors.Key);
        byte[] expected = Convert.FromHexString(vector.ExpectedKeyedHashHex);
        byte[] actual = new byte[expected.Length];

        using Blake3Hasher hasher = Blake3Hasher.CreateKeyed(keyBytes, Backend);
        hasher.Update(input);
        hasher.FinalizeXof(actual);

        CollectionAssert.AreEqual(expected, actual);
    }


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void DeriveKeyModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        byte[] keyMaterial = BuildCanonicalInput(vector.InputLength);
        byte[] expected = Convert.FromHexString(vector.ExpectedDeriveKeyHex);
        byte[] actual = new byte[expected.Length];

        using Blake3Hasher hasher = Blake3Hasher.CreateDeriveKey(
            Blake3CanonicalVectors.DeriveKeyContext, Backend);
        hasher.Update(keyMaterial);
        hasher.FinalizeXof(actual);

        CollectionAssert.AreEqual(expected, actual);
    }


    /// <summary>
    /// Builds the canonical input: the 251-byte cycling sequence
    /// <c>0, 1, 2, ..., 249, 250, 0, 1, ...</c> repeated to
    /// <paramref name="length"/> bytes. Defined in the upstream
    /// <c>test_vectors.json</c> header.
    /// </summary>
    private static byte[] BuildCanonicalInput(int length)
    {
        byte[] input = new byte[length];
        for(int i = 0; i < length; i++)
        {
            input[i] = (byte)(i % 251);
        }
        return input;
    }
}