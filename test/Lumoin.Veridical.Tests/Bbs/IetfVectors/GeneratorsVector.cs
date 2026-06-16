using Lumoin.Veridical.Bbs;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Bbs.IetfVectors;

/// <summary>
/// The BBS+ generator-derivation primitive fixture per IETF
/// <c>draft-irtf-cfrg-bbs-signatures-10</c> Section 4.1.1. The
/// fixture pins the ciphersuite's <c>P1</c> constant and the
/// derived <c>Q_1, H_1, ..., H_L</c> for a fixed
/// <see cref="MessageGenerators"/>.Count. All byte-typed fields
/// are lowercase hex strings encoding 48-byte canonical compressed
/// G1 points.
/// </summary>
/// <param name="Id">A stable identifier for the vector — short, kebab-case, ciphersuite-prefixed.</param>
/// <param name="Description">Human-readable description copied from the upstream fixture's <c>caseName</c>; absent in the upstream JSON so synthesised from filename for clarity.</param>
/// <param name="P1">Hex of the canonical compressed ciphersuite <c>P1</c> base point.</param>
/// <param name="Q1">Hex of the canonical compressed first derived generator <c>Q_1</c> (the domain-related generator, distinct from <c>P1</c>).</param>
/// <param name="MessageGenerators">Hex of each canonical compressed message generator <c>H_1, ..., H_L</c> in derivation order. <see cref="MessageGenerators"/>.Count fixes <c>L</c>.</param>
internal sealed record GeneratorsVector(
    string Id,
    string Description,
    string P1,
    string Q1,
    IReadOnlyList<string> MessageGenerators);