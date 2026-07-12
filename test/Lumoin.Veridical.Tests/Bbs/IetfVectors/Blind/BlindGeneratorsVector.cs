using Lumoin.Veridical.Bbs;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Blind;

/// <summary>
/// A blind-BBS generator-derivation primitive fixture, per
/// <see cref="BlindDraftRevision.CommitmentVectorSourceRevision"/>
/// Section 9.1.1/9.1.2 (and the -2 mirrors). Blind-BBS derives TWO
/// independent generator families from create_generators: the
/// signer-message generators (H_1..H_10) under the plain
/// <c>"BLIND_H2G_HM2S_"</c>-suffixed interface api_id, and the
/// blind/commitment generators (J_i) under
/// <c>"BLIND_" || api_id</c> — this record covers both families, one
/// instance per family. All byte-typed fields are lowercase hex
/// strings encoding 48-byte canonical compressed G1 points, except
/// <see cref="ApiId"/> which is the hex of the ASCII api_id octets.
/// </summary>
/// <param name="Id">A stable identifier for the vector — short, kebab-case, ciphersuite-prefixed.</param>
/// <param name="Description">Human-readable description identifying which generator family (signer-message vs blind/commitment) and interface api_id this fixture covers.</param>
/// <param name="ApiId">Hex of the ASCII api_id octets this generator block is derived under — the DST create_generators uses.</param>
/// <param name="P1">Hex of the canonical compressed ciphersuite P1 base point (ciphersuite-fixed; identical across both generator families).</param>
/// <param name="Q1">Hex of the canonical compressed first derived generator (Q_1 for the signer-message family; Q_2 for the blind/commitment family — both printed as "Q1" by the upstream fixture).</param>
/// <param name="MessageGenerators">Hex of each canonical compressed generator in derivation order (H_1..H_10 for the signer-message family; J_0..J_4 for the blind/commitment family).</param>
internal sealed record BlindGeneratorsVector(
    string Id,
    string Description,
    string ApiId,
    string P1,
    string Q1,
    IReadOnlyList<string> MessageGenerators);
