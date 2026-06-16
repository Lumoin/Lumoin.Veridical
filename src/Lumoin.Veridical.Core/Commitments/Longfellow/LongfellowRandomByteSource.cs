using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// Fills <paramref name="destination"/> with raw random bytes — the wire-format-conformant Ligero
/// commit's entropy source, a port of google/longfellow-zk's <c>RandomEngine::bytes</c>. The commit
/// consumes this stream in a fixed order (blinding rows, witness-row padding, quadratic-triple
/// padding, then one nonce per Merkle leaf), so a caller that supplies a reproducible stream gets a
/// deterministic commitment root — the property the conformance gate fixes its randomness with.
/// </summary>
/// <remarks>
/// <para>
/// This is the byte-level entropy interface, deliberately below the field abstraction: the reference's
/// <c>rng.elt(F)</c> reads <c>Field::kBytes</c> raw bytes and maps them through <c>of_bytes_field</c>,
/// and <c>rng.subfield_elt(F)</c> reads <c>Field::kSubFieldBytes</c> raw bytes through
/// <c>of_scalar</c>. The Longfellow commit performs those mappings itself over this raw stream so the
/// exact byte-consumption order matches the reference, which is what makes a fixed stream reproduce
/// the reference's tableau and nonces byte for byte.
/// </para>
/// <para>
/// A production caller wires a cryptographically secure source here. The conformance gate wires a
/// deterministic counter source (the k-th byte produced is <c>k &amp; 0xFF</c>) identical to the C++
/// oracle's <c>CounterRandomEngine</c>.
/// </para>
/// </remarks>
/// <param name="destination">The span to fill completely with random bytes.</param>
internal delegate void LongfellowRandomByteSource(Span<byte> destination);
