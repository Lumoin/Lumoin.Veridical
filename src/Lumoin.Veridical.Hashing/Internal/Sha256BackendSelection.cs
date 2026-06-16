namespace Lumoin.Veridical.Hashing.Internal;

/// <summary>
/// Picks the highest-capability SHA-256 backend the current CPU supports.
/// The selection runs once and the result is cached for the process
/// lifetime; consumers calling <see cref="Sha256Hasher.CreateAutoSelected"/>
/// repeatedly do not pay a per-call detection cost. Mirrors
/// <see cref="Blake3BackendSelection"/>.
/// </summary>
/// <remarks>
/// <para>
/// This phase ships only the portable scalar backend. The hardware-SHA
/// tiers (the SHA-NI intrinsics on x86, the SHA2 instructions on AArch64)
/// implement the same <see cref="Sha256CompressionDelegate"/> and slot in
/// above the portable fallback here when added; the seam is present so that
/// addition does not ripple. The performance win that motivated this module
/// is algorithmic — one incremental pass instead of an O(N^2) re-hash — not
/// per-block speed, so the portable backend already realises it.
/// </para>
/// </remarks>
internal static class Sha256BackendSelection
{
    private static readonly Sha256Backend Cached = ComputeBest();


    /// <summary>Returns the cached best-available backend for this process.</summary>
    public static Sha256Backend SelectBest() => Cached;


    private static Sha256Backend ComputeBest() => Sha256PortableBackend.GetBackend();
}
