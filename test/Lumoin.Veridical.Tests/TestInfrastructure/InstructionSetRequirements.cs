using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.Wasm;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// Per-ISA gates for tests that exercise a specific SIMD backend
/// directly rather than going through the dispatch facade. Each helper
/// throws <see cref="AssertInconclusiveException"/> with a clear cause
/// message when its instruction set is not available on the host CPU, so
/// the test surfaces as Inconclusive — the test did not fail, it simply
/// could not run.
/// </summary>
/// <remarks>
/// <para>
/// Call from <see cref="TestInitializeAttribute"/> or as the first line
/// of an individual test method:
/// </para>
/// <code>
/// [TestInitialize]
/// public void Initialize() => InstructionSetRequirements.RequireAvx2();
///
/// [TestMethod]
/// public void SomeAvx2SpecificTest() { ... }
/// </code>
/// <para>
/// The pattern matches the user-suggested skip-attribute hierarchy in
/// effect but stays within MSTest's standard surface: no
/// <see cref="TestMethodAttribute"/> subclassing, no per-test framework
/// extensibility plumbing. The trade-off is one extra line per gated
/// class (or per gated test); the win is no dependency on MSTest's
/// internal extensibility shape, which has shifted across major
/// versions.
/// </para>
/// </remarks>
internal static class InstructionSetRequirements
{
    /// <summary>Throws <see cref="AssertInconclusiveException"/> when AVX2 is not supported on the host CPU.</summary>
    public static void RequireAvx2()
    {
        if(!Avx2.IsSupported)
        {
            Assert.Inconclusive("AVX2 is not supported on this host CPU; skipping AVX2-specific test.");
        }
    }


    /// <summary>Throws <see cref="AssertInconclusiveException"/> when AVX-512F is not supported on the host CPU.</summary>
    public static void RequireAvx512()
    {
        if(!Avx512F.IsSupported)
        {
            Assert.Inconclusive("AVX-512F is not supported on this host CPU; skipping AVX-512-specific test.");
        }
    }


    /// <summary>Throws <see cref="AssertInconclusiveException"/> when AArch64 NEON is not supported on the host CPU.</summary>
    public static void RequireNeon()
    {
        if(!AdvSimd.Arm64.IsSupported)
        {
            Assert.Inconclusive("AArch64 NEON is not supported on this host CPU; skipping NEON-specific test.");
        }
    }


    /// <summary>Throws <see cref="AssertInconclusiveException"/> when the WebAssembly 128-bit SIMD surface is not supported on the host runtime.</summary>
    public static void RequirePackedSimd()
    {
        if(!PackedSimd.IsSupported)
        {
            Assert.Inconclusive("WebAssembly PackedSimd is not supported on this host runtime; skipping WASM-specific test.");
        }
    }
}