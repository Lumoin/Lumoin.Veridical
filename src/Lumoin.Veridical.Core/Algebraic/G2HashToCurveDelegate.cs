using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Maps a message together with a domain-separation tag to a G2 point
/// per RFC 9380 §8.8.2 (BLS12-381 G2), writing the canonical-form
/// result and returning a tag with the backend's provenance stamped.
/// </summary>
/// <param name="message">The application message to map into G2.</param>
/// <param name="domainSeparationTag">The protocol-level DST binding this hash-to-curve invocation to a specific use.</param>
/// <param name="result">The destination span the backend writes the canonical compressed G2 encoding into.</param>
/// <param name="curve">Identifies the curve.</param>
/// <param name="inboundTag">The algebraic-identity tag the produced point already carries; the delegate adds provenance entries to it.</param>
/// <returns>A tag carrying the algebraic-identity entries plus four provenance entries identifying the producer.</returns>
/// <remarks>
/// <para>
/// The RFC 9380 §8.8.2 construction for BLS12-381 G2 uses
/// <c>expand_message_xmd</c> over SHA-256, the simplified SWU map to a
/// 3-isogenous curve <c>E'</c>, a 3-isogeny <c>E' → E</c>, and a
/// cofactor-clearing step. Backends are responsible for the full
/// construction including subgroup membership.
/// </para>
/// <para>
/// The domain-separation tag is required: omitting it allows two
/// protocols sharing the message space to collide on the same group
/// element, breaking the cryptographic separation the construction
/// provides.
/// </para>
/// </remarks>
public delegate Tag G2HashToCurveDelegate(
    ReadOnlySpan<byte> message,
    ReadOnlySpan<byte> domainSeparationTag,
    Span<byte> result,
    CurveParameterSet curve,
    Tag inboundTag);