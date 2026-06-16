using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Maps a message together with a domain-separation tag to a canonical
/// scalar in the scalar field of the curve identified by
/// <paramref name="curve"/>, writing the canonical-form 32-byte (for
/// BLS12-381) big-endian scalar into <paramref name="result"/> and
/// returning a tag that carries the provenance entries identifying the
/// producing backend.
/// </summary>
/// <param name="message">The application message to hash into the scalar field.</param>
/// <param name="domainSeparationTag">The protocol-level DST binding this hash-to-scalar invocation to a specific use; required to keep mappings for different protocols disjoint.</param>
/// <param name="result">The destination span the backend writes the canonical scalar bytes into.</param>
/// <param name="curve">Identifies the curve whose scalar field the result lives in.</param>
/// <param name="inboundTag">The algebraic-identity tag the produced scalar already carries; the delegate adds provenance entries to it.</param>
/// <returns>A tag carrying the algebraic-identity entries from <paramref name="inboundTag"/> plus four provenance entries identifying the producer.</returns>
/// <remarks>
/// <para>
/// The standard construction is RFC 9380 §5 <c>expand_message_xmd</c>
/// to produce <c>L</c> uniform bytes, interpret them as a big-endian
/// integer, and reduce modulo the scalar-field order <c>r</c>. The IETF
/// draft <c>draft-irtf-cfrg-bbs-signatures</c> defines this operation
/// as <c>hash_to_scalar</c> with <c>L = ceil((ceil(log2(r)) + k) / 8)</c>
/// where <c>k</c> is the curve's security level in bits. For BLS12-381
/// with <c>k = 128</c>, <c>L = 48</c>.
/// </para>
/// <para>
/// Unlike <see cref="G1HashToCurveDelegate"/> and the corresponding G2
/// delegate, hash-to-scalar does not require a subgroup-clearing step:
/// the scalar field is already a flat finite field, and reduction
/// modulo <c>r</c> produces a uniformly distributed canonical scalar.
/// </para>
/// <para>
/// This is a boundary delegate — a message from outside the system
/// enters as a scalar with cryptographic provenance. The
/// <paramref name="inboundTag"/> already includes the algebraic-identity
/// entries (e.g. <c>(AlgebraicRole.Scalar, CurveParameterSet)</c>); the
/// delegate adds the four provenance entries (provider library, crypto
/// library, provider class, provider operation) so the resulting
/// scalar's tag identifies both what it is and where it came from.
/// </para>
/// </remarks>
public delegate Tag ScalarHashToScalarDelegate(
    ReadOnlySpan<byte> message,
    ReadOnlySpan<byte> domainSeparationTag,
    Span<byte> result,
    CurveParameterSet curve,
    Tag inboundTag);