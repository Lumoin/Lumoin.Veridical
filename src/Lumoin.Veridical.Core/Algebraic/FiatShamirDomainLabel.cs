using System.Text;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// A protocol-identifying string that distinguishes one Fiat-Shamir
/// transcript construction from every other. Travels with the
/// transcript for its entire lifetime, both in the Tag and inside
/// every hash input.
/// </summary>
/// <param name="Value">The label string, intended to be a stable protocol identifier such as <c>"veridical.spartan2.v1"</c> or <c>"veridical.hyrax.v1"</c>.</param>
/// <remarks>
/// <para>
/// Distinct domain labels with the same hash function and the same
/// absorb sequence produce different challenges. The label is part of
/// the hash input at every absorb and every squeeze, so two
/// independent protocols can run side by side and never produce a
/// challenge collision even if their absorb sequences happen to match.
/// </para>
/// <para>
/// The label's bytes are its UTF-8 encoding. Consumers should treat
/// the label as opaque bytes; the string layer exists for readability,
/// not for matching against patterns. Protocol implementers pick the
/// label once when the protocol's version stabilises and never
/// change it for that version — changing the label after the protocol
/// ships invalidates every previously-generated proof.
/// </para>
/// </remarks>
public readonly record struct FiatShamirDomainLabel(string Value)
{
    /// <summary>
    /// Returns the UTF-8 encoding of <see cref="Value"/>. Allocates a
    /// fresh array per access; callers in tight loops should cache the
    /// result. The transcript caches this at construction and reuses
    /// the cached array across absorbs and squeezes.
    /// </summary>
    public byte[] Bytes => Encoding.UTF8.GetBytes(Value);
}