using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Fills <paramref name="destination"/> with a uniformly random scalar in the
/// supplied curve's scalar field, returning a tag that carries every entry
/// from <paramref name="inboundTag"/> plus the provenance entries
/// identifying the producing backend.
/// </summary>
/// <param name="destination">The destination span the backend writes the canonical-form scalar bytes into.</param>
/// <param name="curve">Identifies the field the scalar is sampled from.</param>
/// <param name="inboundTag">The algebraic-identity tag the scalar already carries; the delegate adds provenance entries to it.</param>
/// <returns>A tag carrying the algebraic-identity entries from <paramref name="inboundTag"/> plus four provenance entries identifying the producer (provider library, crypto library, provider class, provider operation).</returns>
/// <remarks>
/// <para>
/// This is a boundary delegate — entropy crosses from outside the system
/// into a tagged cryptographic value. The backend that produces the bytes is
/// responsible for sampling uniformly modulo the field order (rejection
/// sampling or a hash-to-field construction are the two common approaches)
/// and for stamping its identity onto the tag so the value carries its
/// origin for the rest of its lifetime.
/// </para>
/// <para>
/// Unlike the inner-loop arithmetic delegates, this signature carries the
/// inbound tag explicitly. The delegate is expected to derive a new tag from
/// it via <see cref="Provenance.ProviderInstrumentation.StampTag"/> rather
/// than mutating any shared state.
/// </para>
/// </remarks>
public delegate Tag ScalarRandomDelegate(
    Span<byte> destination,
    CurveParameterSet curve,
    Tag inboundTag);