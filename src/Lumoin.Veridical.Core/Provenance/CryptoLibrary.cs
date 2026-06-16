using System.Diagnostics;
using System.Reflection;

namespace Lumoin.Veridical.Core.Provenance;

/// <summary>
/// Identifies the underlying cryptographic implementation that the
/// <see cref="ProviderLibrary"/> delegated to in order to produce a tagged
/// value, with its version.
/// </summary>
/// <param name="Name">The library name, for example <c>System.Security.Cryptography</c>, <c>blst</c>, or <c>arkworks</c>.</param>
/// <param name="Version">The library version, typically resolved at class initialization from the assembly metadata or the native library's published version string.</param>
/// <remarks>
/// <para>
/// <see cref="CryptoLibrary"/> distinguishes the underlying mathematical
/// implementation from the .NET assembly that wraps it (the
/// <see cref="ProviderLibrary"/>). For a managed backend the two often refer
/// to closely related artifacts; for a native backend the
/// <see cref="ProviderLibrary"/> is the .NET FFI shim and the
/// <see cref="CryptoLibrary"/> is the native library on disk (such as a
/// specific build of blst or arkworks).
/// </para>
/// <para>
/// In zero-knowledge contexts where verifiers depend on bit-level
/// reproducibility of pairing arithmetic, point compression, and subgroup
/// checks, this dimension is the one that lets a verifier answer "did the
/// proof I'm verifying come from the same field-arithmetic implementation as
/// my own" — at least to the precision of the recorded version string.
/// </para>
/// </remarks>
[DebuggerDisplay("{Name,nq} {Version,nq}")]
public readonly record struct CryptoLibrary(string Name, string Version)
{
    /// <summary>
    /// Identifies the Lumoin.Veridical.Bbs project as the producing
    /// cryptographic library, with its assembly version. Used by BBS+
    /// operations (KeyGen, Sign, Verify, GenerateProof, VerifyProof) to
    /// stamp produced values with their library of origin.
    /// </summary>
    /// <remarks>
    /// The version is resolved at type-initialisation time from
    /// <see cref="Assembly.GetName"/> of the assembly containing
    /// <see cref="CryptoLibrary"/> itself. Both BBS+ and Core ship from
    /// the same NuGet versioning scheme so this captures the user-facing
    /// release version regardless of whether the BBS+ assembly is loaded.
    /// </remarks>
    public static CryptoLibrary LumoinVeridicalBbs { get; } = new(
        Name: "Lumoin.Veridical.Bbs",
        Version: typeof(CryptoLibrary).Assembly.GetName().Version?.ToString() ?? "unknown");
}