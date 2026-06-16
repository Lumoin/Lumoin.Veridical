using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Produces a uniformly random byte string of length
/// <paramref name="output"/>.Length from <paramref name="message"/>
/// and <paramref name="domainSeparationTag"/> per RFC 9380 §5.3
/// <c>expand_message</c>. The concrete construction (XMD with
/// SHA-256, XOF with SHAKE-256, etc.) is the implementation's
/// choice; the contract is just "uniform output bytes from this
/// (message, DST) pair, deterministic in the implementation".
/// </summary>
/// <param name="message">The application message bytes (the inner-hash input).</param>
/// <param name="domainSeparationTag">The protocol DST that separates this call from other uses of the same primitive on the same message space.</param>
/// <param name="output">Destination buffer sized to the desired uniform-output length.</param>
/// <remarks>
/// <para>
/// This delegate is the boundary at which higher-layer constructions
/// like BBS+'s <c>create_generators</c> and <c>hash_to_scalar</c>
/// reach into the underlying expand-message primitive without binding
/// themselves to a specific hash. A ciphersuite picks the
/// implementation (e.g. <see cref="Rfc9380ExpandMessage.ExpandMessageXmdSha256"/>
/// or <see cref="Rfc9380ExpandMessage.ExpandMessageXofShake256"/>);
/// the consumer code stays generic.
/// </para>
/// <para>
/// The delegate is curve-agnostic: <c>expand_message</c> only knows
/// about hashes and message bytes, not field orders, so the
/// signature does not carry a <see cref="CurveParameterSet"/>.
/// </para>
/// </remarks>
public delegate void ExpandMessageDelegate(
    ReadOnlySpan<byte> message,
    ReadOnlySpan<byte> domainSeparationTag,
    Span<byte> output);