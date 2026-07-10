using Lumoin.Base.Sodium;
using System;
using System.Buffers;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Memory;

/// <summary>
/// Demonstrates the <see cref="AllocationKind.Native"/> tier end to end: a pool
/// wired with the libsodium backing serves a <c>Native</c> rent from guarded,
/// locked native memory (guard pages, best-effort memory locking, canary,
/// zero-on-free), which is what the small long-lived key material — the BBS
/// secret key — asks for. The library threads the pool from the top and never
/// names an allocator, so this is the deployment-side wiring the consumer
/// supplies.
/// </summary>
/// <remarks>
/// <para>
/// The native library resolves at runtime and is absent on hosts without a
/// deployed libsodium, exactly like the SIMD backends are absent without the
/// instruction set. The tests gate on <see cref="SodiumBacking.IsAvailable"/>
/// and report inconclusive rather than failing where the library is not
/// present, so they light up on capable hosts and CI without blocking the
/// default suite elsewhere.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SodiumProtectedNativeMemoryTests
{
    private const int SecretSizeBytes = 32;
    private const byte PoisonByte = 0xC7;


    [TestMethod]
    public void ANativeRentFromASodiumBackedPoolRoundTripsSecretBytes()
    {
        SkipIfSodiumUnavailable();

        using BaseMemoryPool pool = new(nativeBacking: SodiumBacking.Allocator);
        using IMemoryOwner<byte> owner = pool.Rent(SecretSizeBytes, AllocationKind.Native);

        Span<byte> secret = owner.Memory.Span[..SecretSizeBytes];
        for(int i = 0; i < SecretSizeBytes; i++)
        {
            secret[i] = (byte)(PoisonByte ^ i);
        }

        for(int i = 0; i < SecretSizeBytes; i++)
        {
            Assert.AreEqual((byte)(PoisonByte ^ i), secret[i],
                $"Guarded native memory must round-trip written bytes at index {i}.");
        }
    }


    [TestMethod]
    public void ANativeRentFromASodiumBackedPoolIsNotAManagedArray()
    {
        SkipIfSodiumUnavailable();

        using BaseMemoryPool pool = new(nativeBacking: SodiumBacking.Allocator);
        using IMemoryOwner<byte> owner = pool.Rent(SecretSizeBytes, AllocationKind.Native);

        //A libsodium-guarded allocation is off the managed heap, so it exposes
        //no backing array — the discriminator between the protected native tier
        //and the pinned-object-heap tier, which does expose one.
        Assert.IsFalse(MemoryMarshal.TryGetArray<byte>(owner.Memory, out _),
            "A Sodium-backed Native rent must not be a managed array; it is guarded off-heap memory.");
    }


    private static void SkipIfSodiumUnavailable()
    {
        if(!SodiumBacking.IsAvailable)
        {
            Assert.Inconclusive("libsodium is not available in this process; the protected native tier cannot be exercised on this host.");
        }
    }
}
