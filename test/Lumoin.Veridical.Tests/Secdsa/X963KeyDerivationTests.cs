using Lumoin.Veridical.Secdsa;
using System;
using System.Security.Cryptography;
using static Lumoin.Veridical.Tests.Secdsa.SecdsaTestSupport;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Gates for the ANSI X9.63 key derivation over SHA-256 of SEC 1 section 3.6.1. No externally published vector is
/// used: the derivation is pinned structurally against an independent computation with the platform's SHA-256 of
/// the defining expression <c>Hash(Z ‖ Counter ‖ SharedInfo)</c> with a 4-byte big-endian counter that starts at 1,
/// block by block, plus the truncation, empty-shared-info and range properties.
/// </summary>
[TestClass]
internal sealed class X963KeyDerivationTests
{
    private const int CounterSize = 4;


    [TestMethod]
    public void EveryBlockIsTheHashOfSecretCounterAndSharedInfo()
    {
        using var pool = new BaseMemoryPool();
        Span<byte> secret = stackalloc byte[DigestSize];
        DeriveScalar("x963 shared secret"u8, secret);
        ReadOnlySpan<byte> sharedInfo = "the shared info"u8;

        Span<byte> output = stackalloc byte[3 * DigestSize];
        X963KeyDerivation.Derive(Hash, pool, secret, sharedInfo, output);

        Span<byte> input = stackalloc byte[secret.Length + CounterSize + sharedInfo.Length];
        Span<byte> expected = stackalloc byte[DigestSize];
        secret.CopyTo(input);
        sharedInfo.CopyTo(input[(secret.Length + CounterSize)..]);
        for(int block = 0; block < 3; block++)
        {
            input[secret.Length + CounterSize - 1] = (byte)(block + 1);
            SHA256.HashData(input, expected);

            Assert.IsTrue(output.Slice(block * DigestSize, DigestSize).SequenceEqual(expected), $"Block {block + 1} must be SHA-256(Z || counter || SharedInfo).");
        }
    }


    [TestMethod]
    public void ShorterOutputIsAPrefixOfLongerOutput()
    {
        using var pool = new BaseMemoryPool();
        Span<byte> secret = stackalloc byte[DigestSize];
        DeriveScalar("x963 prefix secret"u8, secret);

        Span<byte> longer = stackalloc byte[44];
        Span<byte> shorter = stackalloc byte[17];
        X963KeyDerivation.Derive(Hash, pool, secret, "info"u8, longer);
        X963KeyDerivation.Derive(Hash, pool, secret, "info"u8, shorter);

        Assert.IsTrue(longer[..shorter.Length].SequenceEqual(shorter));
    }


    [TestMethod]
    public void EmptySharedInfoHashesSecretAndCounterOnly()
    {
        using var pool = new BaseMemoryPool();
        Span<byte> secret = stackalloc byte[DigestSize];
        DeriveScalar("x963 empty info"u8, secret);

        Span<byte> output = stackalloc byte[DigestSize];
        X963KeyDerivation.Derive(Hash, pool, secret, ReadOnlySpan<byte>.Empty, output);

        Span<byte> input = stackalloc byte[secret.Length + CounterSize];
        secret.CopyTo(input);
        input[^1] = 0x01;
        Span<byte> expected = stackalloc byte[DigestSize];
        SHA256.HashData(input, expected);

        Assert.IsTrue(output.SequenceEqual(expected));
    }


    [TestMethod]
    public void SharedInfoAndSecretBothChangeTheOutput()
    {
        using var pool = new BaseMemoryPool();
        Span<byte> secret = stackalloc byte[DigestSize];
        DeriveScalar("x963 binding secret"u8, secret);
        Span<byte> otherSecret = stackalloc byte[DigestSize];
        DeriveScalar("x963 binding other secret"u8, otherSecret);

        Span<byte> baseline = stackalloc byte[DigestSize];
        Span<byte> changedInfo = stackalloc byte[DigestSize];
        Span<byte> changedSecret = stackalloc byte[DigestSize];
        X963KeyDerivation.Derive(Hash, pool, secret, "info"u8, baseline);
        X963KeyDerivation.Derive(Hash, pool, secret, "infp"u8, changedInfo);
        X963KeyDerivation.Derive(Hash, pool, otherSecret, "info"u8, changedSecret);

        Assert.IsFalse(baseline.SequenceEqual(changedInfo));
        Assert.IsFalse(baseline.SequenceEqual(changedSecret));
    }


    [TestMethod]
    public void BoundDelegateMatchesDirectDerivation()
    {
        using var pool = new BaseMemoryPool();
        Span<byte> secret = stackalloc byte[DigestSize];
        DeriveScalar("x963 delegate secret"u8, secret);

        EciesKeyDerivationDelegate bound = X963KeyDerivation.Create(Hash, pool);
        Span<byte> viaDelegate = stackalloc byte[44];
        Span<byte> direct = stackalloc byte[44];
        bound(secret, "info"u8, viaDelegate);
        X963KeyDerivation.Derive(Hash, pool, secret, "info"u8, direct);

        Assert.IsTrue(viaDelegate.SequenceEqual(direct));
    }


    [TestMethod]
    public void OutputLengthAndSecretAreRangeChecked()
    {
        using var pool = new BaseMemoryPool();

        Assert.ThrowsExactly<ArgumentException>(() => DeriveInto(pool, "secret"u8, 0));
        Assert.ThrowsExactly<ArgumentException>(() => DeriveInto(pool, "secret"u8, X963KeyDerivation.MaxOutputSizeBytes + 1));
        Assert.ThrowsExactly<ArgumentException>(() => DeriveInto(pool, ReadOnlySpan<byte>.Empty, 16));
        Assert.ThrowsExactly<ArgumentNullException>(() => X963KeyDerivation.Create(null!, pool));
    }


    private static void DeriveInto(BaseMemoryPool pool, ReadOnlySpan<byte> secret, int length)
    {
        Span<byte> output = stackalloc byte[Math.Max(length, 1)];
        X963KeyDerivation.Derive(Hash, pool, secret, ReadOnlySpan<byte>.Empty, output[..length]);
    }
}
