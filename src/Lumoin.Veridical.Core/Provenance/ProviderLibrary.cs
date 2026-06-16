using System.Diagnostics;

namespace Lumoin.Veridical.Core.Provenance;

/// <summary>
/// Identifies the assembly (the host library that wraps and exposes the
/// underlying cryptographic primitive) that produced a tagged cryptographic
/// value.
/// </summary>
/// <param name="Name">The assembly name, typically resolved at class initialization via <c>Assembly.GetName().Name</c>.</param>
/// <param name="Version">The assembly version, typically resolved at class initialization via <c>Assembly.GetName().Version</c>.</param>
/// <remarks>
/// <para>
/// Together with <see cref="CryptoLibrary"/>, <see cref="ProviderClass"/>, and
/// <see cref="ProviderOperation"/>, this entry is one of the four provenance
/// dimensions stamped onto a <see cref="Tag"/> by the producing backend. Holding
/// any tagged cryptographic value lets a caller answer "which library produced
/// this and at what version" without out-of-band lookup, which matters in
/// zero-knowledge contexts where verification depends on the prover and verifier
/// agreeing on field-arithmetic implementations down to bit-level.
/// </para>
/// <para>
/// <see cref="ProviderLibrary"/> identifies the wrapping assembly — for example
/// <c>Lumoin.Veridical.Backends.Native</c>. <see cref="CryptoLibrary"/>
/// identifies the underlying cryptographic implementation that wrapping
/// assembly delegates to — for example <c>blst</c> or <c>arkworks</c>. The
/// distinction matters because the same wrapping assembly may delegate to
/// multiple underlying libraries for different operations.
/// </para>
/// </remarks>
[DebuggerDisplay("{Name,nq} {Version,nq}")]
public readonly record struct ProviderLibrary(string Name, string Version);