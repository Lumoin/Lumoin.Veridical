using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Maps a message together with a domain-separation tag to a G1 point in the
/// curve identified by <paramref name="curve"/>, writing the canonical-form
/// result into <paramref name="result"/> and returning a tag that carries the
/// provenance entries identifying the producing backend.
/// </summary>
/// <param name="message">The application message to map into the group.</param>
/// <param name="domainSeparationTag">The protocol-level domain separation tag binding this hash-to-curve invocation to a specific use; required by RFC 9380 to keep mappings for different protocols disjoint.</param>
/// <param name="result">The destination span the backend writes the canonical compressed G1 encoding into.</param>
/// <param name="curve">Identifies the curve whose G1 group the result lives in.</param>
/// <param name="inboundTag">The algebraic-identity tag the produced point already carries; the delegate adds provenance entries to it.</param>
/// <returns>A tag carrying the algebraic-identity entries from <paramref name="inboundTag"/> plus four provenance entries identifying the producer (provider library, crypto library, provider class, provider operation).</returns>
/// <remarks>
/// <para>
/// This is a boundary delegate — a message from outside the system enters as
/// a G1 point with a known cryptographic provenance. The backend that
/// produces the bytes is responsible for emitting a point that is on the
/// curve and in the prime-order subgroup; RFC 9380 §3 makes the
/// subgroup-clearing step part of the hash-to-curve specification itself.
/// </para>
/// <para>
/// The domain-separation tag is always required: omitting it would let two
/// protocols using the same message space collide on the same group element,
/// breaking the cryptographic separation that the hash-to-curve construction
/// is meant to provide.
/// </para>
/// </remarks>
public delegate Tag G1HashToCurveDelegate(
    ReadOnlySpan<byte> message,
    ReadOnlySpan<byte> domainSeparationTag,
    Span<byte> result,
    CurveParameterSet curve,
    Tag inboundTag);