using Lumoin.Veridical.Core.Provenance;
using System.Reflection;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// Shared provenance identities for the BBS+ Interface operations.
/// </summary>
/// <remarks>
/// <para>
/// All five BBS+ operations (KeyGen, Sign, Verify, GenerateProof,
/// VerifyProof) share the same <see cref="Core.Provenance.ProviderLibrary"/>,
/// <see cref="Core.Provenance.CryptoLibrary"/>, and
/// <see cref="Core.Provenance.ProviderClass"/> identities; only the
/// <see cref="Core.Provenance.ProviderOperation"/> differs per call.
/// Centralising the shared three here keeps each extension file's
/// stamping call self-contained while avoiding three identical
/// declarations.
/// </para>
/// </remarks>
internal static class WellKnownBbsProviderIdentities
{
    /// <summary>The Lumoin.Veridical.Bbs assembly identity, resolved once at type initialisation.</summary>
    public static ProviderLibrary Library { get; } = new(
        Name: typeof(WellKnownBbsProviderIdentities).Assembly.GetName().Name ?? "Lumoin.Veridical.Bbs",
        Version: typeof(WellKnownBbsProviderIdentities).Assembly.GetName().Version?.ToString() ?? "unknown");

    /// <summary>The underlying cryptographic library: BBS+ ships as managed C# inside the same assembly.</summary>
    public static CryptoLibrary Crypto { get; } = CryptoLibrary.LumoinVeridicalBbs;

    /// <summary>The taxonomic class: signature scheme.</summary>
    public static ProviderClass Class { get; } = ProviderClass.SignatureScheme;
}