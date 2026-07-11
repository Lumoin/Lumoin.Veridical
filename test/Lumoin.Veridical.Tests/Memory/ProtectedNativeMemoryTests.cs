using Lumoin.Base.MemoryProtection;
using System;
using System.Buffers;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Memory;

/// <summary>
/// Demonstrates the dependency-free locked native tier: a pool wired with the
/// operating-system-twin backing (<c>VirtualLock</c> on Windows, <c>mlock</c>
/// plus best-effort <c>MADV_DONTDUMP</c> on Linux) serves an
/// <see cref="AllocationKind.Native"/> rent from page-aligned memory that is
/// locked out of the pagefile — the same protection the libsodium tier gives,
/// without a native library dependency, which is what the small long-lived key
/// material (the BBS secret key) can ride on where libsodium is not deployed.
/// </summary>
/// <remarks>
/// <para>
/// Unlike the libsodium tier, this backing imports only <c>kernel32</c> and
/// <c>libc</c>, which every supported operating system already ships, so the
/// lock actually runs on any real host including this one. The tests still
/// gate: on an unsupported operating system (<see cref="MemoryProtectionBacking.IsSupported"/>
/// is <see langword="false"/>) and when the platform refuses to lock even one
/// page because the locked-memory budget is exhausted (a constrained container
/// with a tiny <c>RLIMIT_MEMLOCK</c>), the pass or fail would depend on ambient
/// host limits rather than on correctness, so those report inconclusive.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ProtectedNativeMemoryTests
{
    private const int SecretSizeBytes = 32;
    private const byte PoisonByte = 0x9E;


    [TestMethod]
    public void ALockedNativeRentRoundTripsSecretBytes()
    {
        using BaseMemoryPool pool = NewLockedPool();
        using IMemoryOwner<byte> owner = RentLockedOrInconclusive(pool);

        Span<byte> secret = owner.Memory.Span[..SecretSizeBytes];
        for(int i = 0; i < SecretSizeBytes; i++)
        {
            secret[i] = (byte)(PoisonByte ^ i);
        }

        for(int i = 0; i < SecretSizeBytes; i++)
        {
            Assert.AreEqual((byte)(PoisonByte ^ i), secret[i],
                $"Locked native memory must round-trip written bytes at index {i}.");
        }
    }


    [TestMethod]
    public void ALockedNativeRentIsNotAManagedArray()
    {
        using BaseMemoryPool pool = NewLockedPool();
        using IMemoryOwner<byte> owner = RentLockedOrInconclusive(pool);

        //The locked region is page-aligned native memory, off the managed heap,
        //so it exposes no backing array — the discriminator between this tier
        //and the pinned-object-heap tier, which does expose one.
        Assert.IsFalse(MemoryMarshal.TryGetArray<byte>(owner.Memory, out _),
            "A locked Native rent must not be a managed array; it is page-locked off-heap memory.");
    }


    private static BaseMemoryPool NewLockedPool()
    {
        if(!MemoryProtectionBacking.IsSupported)
        {
            Assert.Inconclusive("This operating system has no supported memory-locking mechanism; the locked native tier cannot be exercised here.");
        }

        return new BaseMemoryPool(nativeBacking: MemoryProtectionBacking.Allocator);
    }


    //Locking a page can legitimately fail when the process locked-memory budget
    //is exhausted (Windows minimum working set, POSIX RLIMIT_MEMLOCK). That is a
    //host-capability limit, not a correctness failure, so it reports inconclusive.
    private static IMemoryOwner<byte> RentLockedOrInconclusive(BaseMemoryPool pool)
    {
        IMemoryOwner<byte>? owner = null;
        string? lockFailure = null;
        try
        {
            owner = pool.Rent(SecretSizeBytes, AllocationKind.Native);
        }
        catch(InsufficientMemoryException ex)
        {
            lockFailure = ex.Message;
        }

        if(lockFailure is not null)
        {
            Assert.Inconclusive($"The host refused to lock a page (locked-memory budget exhausted): {lockFailure}");
        }

        return owner!;
    }
}
