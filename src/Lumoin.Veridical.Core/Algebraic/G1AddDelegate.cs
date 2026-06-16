using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form group sum of two G1 points over the curve
/// identified by <paramref name="curve"/>, writing the result into
/// <paramref name="result"/>.
/// </summary>
/// <param name="a">The left operand in canonical compressed byte layout.</param>
/// <param name="b">The right operand in canonical compressed byte layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form sum into.</param>
/// <param name="curve">Identifies the curve the operands live over.</param>
/// <remarks>
/// <para>
/// The destination span must have the canonical compressed byte length for the
/// supplied curve's G1 group — for BLS12-381, 48 bytes. The high-byte flag
/// bits encode compression, infinity, and y-parity per the IETF/ZCash
/// convention (RFC 9380 Appendix M.5.3.1). Decompression cost is paid at the
/// operation boundary by the backend; this contract observes canonical
/// compressed bytes on both input and output.
/// </para>
/// <para>
/// This is an inner-loop arithmetic delegate. It does not stamp provenance
/// onto a tag, does not return a <c>CryptoEvent</c>, and does not allocate.
/// Provenance is a boundary concern stamped by entropy and hash-to-curve
/// producers, not by per-operation arithmetic that runs once per inner-loop
/// iteration of a multi-scalar multiplication.
/// </para>
/// </remarks>
public delegate void G1AddDelegate(
    ReadOnlySpan<byte> a,
    ReadOnlySpan<byte> b,
    Span<byte> result,
    CurveParameterSet curve);