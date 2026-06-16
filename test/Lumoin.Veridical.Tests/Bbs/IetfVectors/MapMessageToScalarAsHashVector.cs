using Lumoin.Veridical.Bbs;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Bbs.IetfVectors;

/// <summary>
/// The BBS+ <c>messages_to_scalars</c> primitive fixture per IETF
/// <c>draft-irtf-cfrg-bbs-signatures-10</c> Section 4.2.1. The
/// upstream fixture bundles many (message, scalar) cases under a
/// single ciphersuite-specific DST, so the vector type holds the
/// shared DST plus the list of cases. All byte-typed fields are
/// lowercase hex strings.
/// </summary>
/// <param name="Id">A stable identifier for the vector — short, kebab-case, ciphersuite-prefixed.</param>
/// <param name="Description">Human-readable description copied from the upstream fixture's <c>caseName</c>.</param>
/// <param name="Dst">Hex of <c>api_id || MAP_MSG_TO_SCALAR_AS_HASH_</c>, the DST the ciphersuite uses for the per-message hash-to-scalar. Recorded per-vector to keep the case self-contained.</param>
/// <param name="Cases">The (message, expected-scalar) pairs covered by the fixture.</param>
internal sealed record MapMessageToScalarAsHashVector(
    string Id,
    string Description,
    string Dst,
    IReadOnlyList<MapMessageToScalarAsHashCase> Cases);


/// <summary>
/// A single (message, expected-scalar) pair under a shared
/// <see cref="MapMessageToScalarAsHashVector.Dst"/>.
/// </summary>
/// <param name="Message">Hex of the input message bytes.</param>
/// <param name="ExpectedScalar">Hex of the expected 32-byte canonical big-endian scalar.</param>
internal sealed record MapMessageToScalarAsHashCase(
    string Message,
    string ExpectedScalar);