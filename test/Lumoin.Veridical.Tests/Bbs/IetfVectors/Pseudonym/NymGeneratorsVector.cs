using Lumoin.Veridical.Bbs;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Pseudonym;

/// <summary>
/// A per-verifier-linkability generator-derivation primitive
/// fixture, per <see cref="PseudonymDraftRevision.Identifier"/>
/// Section 12.x.1/12.x.2. The pseudonym interface derives TWO
/// independent generator families from create_generators: the
/// signer-message generators (H_0..H_9) under the
/// <c>"H2G_HM2S_PSEUDONYM_"</c>-suffixed interface api_id, and the
/// blind/commitment generators (J_i) used by CommitWithNym under
/// <c>"BLIND_" || api_id</c> — this record covers both families, one
/// instance per family. All byte-typed fields are lowercase hex
/// strings encoding 48-byte canonical compressed G1 points, except
/// <see cref="ApiId"/> which is the hex of the ASCII api_id octets.
/// </summary>
/// <param name="Id">A stable identifier for the vector — short, kebab-case, ciphersuite-prefixed.</param>
/// <param name="Description">Human-readable description identifying which generator family (signer-message vs blind/commitment) and interface api_id this fixture covers.</param>
/// <param name="ApiId">Hex of the ASCII api_id octets this generator block is derived under — the DST create_generators uses.</param>
/// <param name="P1">Hex of the canonical compressed ciphersuite P1 base point (ciphersuite-fixed; identical across both generator families).</param>
/// <param name="Q1">Hex of the canonical compressed first derived generator (Q_1 for the signer-message family; Q_2 for the blind/commitment family — both printed as "Q1" by the draft).</param>
/// <param name="MessageGenerators">Hex of each canonical compressed generator in derivation order (H_0..H_9 for the signer-message family; J_0..J_5 for the blind/commitment family).</param>
internal sealed record NymGeneratorsVector(
    string Id,
    string Description,
    string ApiId,
    string P1,
    string Q1,
    IReadOnlyList<string> MessageGenerators);
