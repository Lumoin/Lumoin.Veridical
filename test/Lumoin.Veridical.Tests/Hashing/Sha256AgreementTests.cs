using Lumoin.Veridical.Hashing;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Hashing;

/// <summary>
/// Byte-identity conformance for the managed SHA-256 against the .NET base
/// class library's <see cref="SHA256.HashData(System.ReadOnlySpan{byte}, System.Span{byte})"/>
/// oracle. Three independent assertions per case: the one-shot
/// <see cref="Sha256.HashData(System.ReadOnlySpan{byte}, System.Span{byte})"/>
/// matches the oracle; many small <see cref="Sha256Hasher.Update(System.ReadOnlySpan{byte})"/>
/// chunks equal the one-shot over the concatenation; and a value-copy fork
/// finalizes to the digest at its absorbed length while leaving the running
/// hasher undisturbed — the transcript's snapshot-then-keep-absorbing
/// pattern. Mirrors the Blake3 conformance tests in shape.
/// </summary>
[TestClass]
internal sealed class Sha256AgreementTests
{
    //Edge sizes spanning the Merkle-Damgard pad boundaries:
    //  0/1/31/32/33               around the first word and below one block,
    //  55/56/57                   the pad-into-this-block vs push-length-to-next-block edge,
    //  63/64/65                   the exact-block boundary,
    //  119/120/127/128/129        the two-block pad boundaries,
    //  1000/8192                  multi-block bulk,
    //  8_400_000                  the ~8.4 MB grown-buffer size that triggered the O(N^2) re-hash.
    private static readonly int[] EdgeSizes =
    [
        0, 1, 31, 32, 33,
        55, 56, 57,
        63, 64, 65,
        119, 120, 127, 128, 129,
        1000, 8192, 8_400_000,
    ];


    public static IEnumerable<object[]> Sizes => EdgeSizes.Select(s => new object[] { s });


    [TestMethod]
    [DynamicData(nameof(Sizes))]
    public void OneShotMatchesBclOracle(int length)
    {
        byte[] input = BuildPattern(length);

        byte[] expected = SHA256.HashData(input);
        byte[] actual = new byte[Sha256Hasher.DigestSizeBytes];
        Sha256.HashData(input, actual);

        CollectionAssert.AreEqual(expected, actual);
    }


    [TestMethod]
    [DynamicData(nameof(Sizes))]
    public void IncrementalUpdateMatchesOneShot(int length)
    {
        byte[] input = BuildPattern(length);
        byte[] expected = SHA256.HashData(input);

        foreach(int chunk in new[] { 1, 7, 13, 64, 1000 })
        {
            byte[] actual = HashInChunks(input, chunk);
            CollectionAssert.AreEqual(expected, actual, $"fixed chunk size {chunk} (input length {length})");
        }

        //A deterministic pseudo-random split: chunk sizes derived from the length so the test is repeatable.
        byte[] randomSplit = HashInRandomChunks(input, seed: unchecked((uint)length * 2654435761u + 1u));
        CollectionAssert.AreEqual(expected, randomSplit, $"random split (input length {length})");
    }


    [TestMethod]
    public void ForkFinalizesAtAbsorbedLengthWithoutDisturbingTheOriginal()
    {
        //The transcript's pattern: absorb a prefix, fork-and-finalize, keep absorbing, fork-and-finalize
        //again at the longer length, then fork once more to prove the running state was never consumed.
        byte[] part = BuildPattern(100);
        byte[] rest = BuildPattern(250);
        byte[] whole = new byte[part.Length + rest.Length];
        part.CopyTo(whole, 0);
        rest.CopyTo(whole, part.Length);

        byte[] expectedPart = SHA256.HashData(part);
        byte[] expectedWhole = SHA256.HashData(whole);

        Sha256Hasher live = Sha256Hasher.CreateAutoSelected();
        live.Update(part);

        Sha256Hasher fork1 = live;
        byte[] k1 = new byte[Sha256Hasher.DigestSizeBytes];
        fork1.Finalize(k1);
        CollectionAssert.AreEqual(expectedPart, k1, "fork at the prefix length");

        //The fork's finalize must not have consumed the live hasher: it keeps absorbing.
        live.Update(rest);

        Sha256Hasher fork2 = live;
        byte[] k2 = new byte[Sha256Hasher.DigestSizeBytes];
        fork2.Finalize(k2);
        CollectionAssert.AreEqual(expectedWhole, k2, "fork at the full length");

        //Forking the same live hasher a third time at the same length reproduces k2 — the running state
        //was untouched by the two prior fork-finalizes.
        Sha256Hasher fork3 = live;
        byte[] k3 = new byte[Sha256Hasher.DigestSizeBytes];
        fork3.Finalize(k3);
        CollectionAssert.AreEqual(expectedWhole, k3, "second fork at the full length reproduces the digest");
    }


    private static byte[] HashInChunks(ReadOnlySpan<byte> input, int chunkSize)
    {
        Sha256Hasher hasher = Sha256Hasher.CreateAutoSelected();
        for(int offset = 0; offset < input.Length; offset += chunkSize)
        {
            int take = Math.Min(chunkSize, input.Length - offset);
            hasher.Update(input.Slice(offset, take));
        }

        byte[] digest = new byte[Sha256Hasher.DigestSizeBytes];
        hasher.Finalize(digest);

        return digest;
    }


    private static byte[] HashInRandomChunks(ReadOnlySpan<byte> input, uint seed)
    {
        Sha256Hasher hasher = Sha256Hasher.CreateAutoSelected();
        uint rng = seed;
        int offset = 0;
        while(offset < input.Length)
        {
            //A small LCG step; chunk sizes in [1, 97].
            rng = unchecked(rng * 1664525u + 1013904223u);
            int chunk = (int)(rng % 97u) + 1;
            int take = Math.Min(chunk, input.Length - offset);
            hasher.Update(input.Slice(offset, take));
            offset += take;
        }

        byte[] digest = new byte[Sha256Hasher.DigestSizeBytes];
        hasher.Finalize(digest);

        return digest;
    }


    //A deterministic byte pattern so the test inputs are reproducible without storing fixtures.
    private static byte[] BuildPattern(int length)
    {
        byte[] data = new byte[length];
        for(int i = 0; i < length; i++)
        {
            data[i] = (byte)((i * 31) + 7);
        }

        return data;
    }
}
