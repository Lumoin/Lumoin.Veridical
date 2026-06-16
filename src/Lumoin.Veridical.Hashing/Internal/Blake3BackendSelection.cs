namespace Lumoin.Veridical.Hashing.Internal;

/// <summary>
/// Picks the highest-capability BLAKE3 backend the current CPU
/// supports. The selection runs once and the result is cached for the
/// process lifetime; consumers calling
/// <see cref="Blake3Hasher.CreateAutoSelected"/> repeatedly do not pay
/// a per-call detection cost.
/// </summary>
/// <remarks>
/// <para>
/// Capability ordering (highest to lowest):
/// </para>
/// <list type="number">
///   <item><description>AVX-512F — 16-chunk parallel batching via <see cref="Blake3Avx512Backend"/>.</description></item>
///   <item><description>AVX2 — 8-chunk parallel batching via <see cref="Blake3Avx2Backend"/>.</description></item>
///   <item><description>AArch64 NEON — 4-chunk parallel batching via <see cref="Blake3NeonBackend"/>.</description></item>
///   <item><description>WebAssembly PackedSimd — 4-chunk parallel batching via <see cref="Blake3WasmPackedSimdBackend"/>; activates under WASM hosts that implement the 128-bit SIMD proposal.</description></item>
///   <item><description>Portable scalar — single-chunk fallback via <see cref="Blake3PortableBackend"/>, always available.</description></item>
/// </list>
/// </remarks>
internal static class Blake3BackendSelection
{
    private static readonly Blake3Backend Cached = ComputeBest();


    /// <summary>Returns the cached best-available backend for this process.</summary>
    public static Blake3Backend SelectBest() => Cached;


    private static Blake3Backend ComputeBest()
    {
        if(Blake3Avx512Backend.IsSupported)
        {
            return Blake3Avx512Backend.GetBackend();
        }

        if(Blake3Avx2Backend.IsSupported)
        {
            return Blake3Avx2Backend.GetBackend();
        }

        if(Blake3NeonBackend.IsSupported)
        {
            return Blake3NeonBackend.GetBackend();
        }

        if(Blake3WasmPackedSimdBackend.IsSupported)
        {
            return Blake3WasmPackedSimdBackend.GetBackend();
        }

        return Blake3PortableBackend.GetBackend();
    }
}