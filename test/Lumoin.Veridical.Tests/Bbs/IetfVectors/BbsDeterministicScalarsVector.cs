using Lumoin.Veridical.Bbs;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Bbs.IetfVectors;

/// <summary>
/// The IETF <c>mocked_calculate_random_scalars</c> primitive
/// fixture per IETF <c>draft-irtf-cfrg-bbs-signatures-10</c>
/// Section 8.1. Expand <see cref="Seed"/> through the ciphersuite's
/// <c>expand_message</c> variant with <see cref="Dst"/> to
/// <c>Count * 48</c> uniform bytes, then chunk those bytes into
/// 48-byte slices and reduce each modulo the scalar field order.
/// All byte-typed fields are lowercase hex strings.
/// </summary>
/// <param name="Id">A stable identifier for the vector — short, kebab-case, ciphersuite-prefixed.</param>
/// <param name="Description">Human-readable description copied from the upstream fixture's <c>caseName</c>.</param>
/// <param name="Seed">Hex of the seed bytes the mocked source is keyed by; the canonical IETF seed is the ASCII encoding of the first 30 digits of π.</param>
/// <param name="Dst">Hex of <c>api_id || MOCK_RANDOM_SCALARS_DST_</c>, the DST the ciphersuite uses for the mocked RNG. Recorded per-vector to keep the case self-contained.</param>
/// <param name="Count">The number of scalars expected to be drawn from the mocked source.</param>
/// <param name="ExpectedScalars">Hex of each expected 32-byte canonical big-endian scalar, in draw order.</param>
internal sealed record BbsDeterministicScalarsVector(
    string Id,
    string Description,
    string Seed,
    string Dst,
    int Count,
    IReadOnlyList<string> ExpectedScalars);