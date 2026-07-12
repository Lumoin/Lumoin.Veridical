using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Pseudonym.Sha256;

/// <summary>
/// CommitWithNym vectors for the BLS12-381-SHA-256 ciphersuite,
/// transcribed verbatim from
/// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section
/// 12.1.3, with the <see cref="NymCommitVector.ProverNym"/> field
/// recovered per that record's field doc (the draft prints it as
/// "undefined").
/// </summary>
internal static class Sha256NymCommitVectors
{
    /// <summary>
    /// valid no committed messages commitment with proof (draft-irtf-cfrg-bbs-per-verifier-linkability-03, §12.1.3.1).
    /// </summary>
    public static NymCommitVector Vector001 { get; } = new(
        Id: "sha256-nym-commit-001",
        Description: "valid no committed messages commitment with proof",
        DraftSection: "12.1.3.1",
        CommittedMessages: [],
        MockedScalarSeed: "332e313431353932363533353839373933323338343632363433333833323739",
        MockedScalarDst: "4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f434f4d4d49545f4d4f434b5f52414e444f4d5f5343414c4152535f4453545f",
        ProverNym: "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418",
        ProverBlind: "3ba0a2583bc7229fa9f2ae3a6697091032947c3a48f302b7fd2b08ca9d193041",
        STilde: "3a3b481c984f4396a13b1f65368aa393d08455fbfd351ab80f593aa5de8b4b1d",
        MTildes: [
            "5e82a40ae25e65fb04d7722f36ecd62fa4f07c8815e74f0a14a7e0a6547a36ce",
        ],
        CommitmentWithProof: "b989fc492e2047f602504eb3e236c0acb04224c77ad0d4cbd31c887b9eb05a1f27d7acfb266fe0ae062914bfa060984c5c2ac3247080eb71fefc7e9622ffae372425a699a298ba991a0bc5c6a3d9211347d0ce98d5c0550667269df1fb81f8fa30c07d4917c7c0786411ee5c05b00b9d501d3f8e244b860b7b11140cddc9787a3ab54ec7fd0a8950dae339f396f2641b");


    /// <summary>
    /// valid multiple committed messages commitment with proof (draft-irtf-cfrg-bbs-per-verifier-linkability-03, §12.1.3.2).
    /// </summary>
    public static NymCommitVector Vector002 { get; } = new(
        Id: "sha256-nym-commit-002",
        Description: "valid multiple committed messages commitment with proof",
        DraftSection: "12.1.3.2",
        CommittedMessages:
        [
            "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3",
            "a75d8b634891af92282cc81a675972d1929d3149863c1fc0",
            "835889a40744813a892eff9deb1edaeb",
            "e1ca9729410dc6ba",
            "",
        ],
        MockedScalarSeed: "332e313431353932363533353839373933323338343632363433333833323739",
        MockedScalarDst: "4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f434f4d4d49545f4d4f434b5f52414e444f4d5f5343414c4152535f4453545f",
        ProverNym: "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418",
        ProverBlind: "15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8",
        STilde: "691b0c56dff95cd15fc221a7d66ec71742fa8161a435ac51ffaa0f593b05989a",
        MTildes:
        [
            "2df678f035e3b5c2628d40645c3b53d30b77b992b4d1663aa313892d08a78e85",
            "2c0add8de9779bf9e3ba6ef2a863cec5e0375b66c44d326f301914eb73cabb46",
            "57ea3273104c990cba7c65f88c766b013c326857be408a55fefea46c71f51a48",
            "4ffdcbebe564f0aeac3e40c58cc42964b1948b581671070f85bf003ba61caafe",
            "19fbc9539129d0fe065c6a19d2df1588207232d163e098f127b270c3ad25fa08",
            "682afdc2c093d95b88e5e145514744d9a254cace1ecd92f20cde388da9adc20f",
        ],
        CommitmentWithProof: "99efccc0ccd91efabb8821ee33edacb823b1dd999682aaa54f38a9c4585e7e7aa746357b2842d38c008f6d732dd501c70eed41caf3eafdd4bb6151ce2c0289401c7d13381e7db90137d7aa2a64224aa2499a4548b2654481a2f0dd16d799116fe41db7b7a5c3ae8b1c64bef6a89a46f5040a5178d2e1126f7f35189f0f6cea3803e679ce92eff73856b164425ac4ff8405a934f65ada8ccbe21558ab66db113662ea17ce0c9aa0280db20dcf79301c61269ddfdbdcc22025b85f7089c4ebebc224a938b745daae833ac4698d9d32bfa8382b4bbb2679ae232d2f6e8e19239e6ea919665ea736b45a61bbd0e4f4d7431f3038c3db25833b9a0cc1a7709419ac241fb6f02ee13e51101743f1983d3fa69b5d344b984c48a265ee6a7b0df8450004ceec7c1997b859be16af624e3da2cf44");

    /// <summary>Every Sha256-ciphersuite CommitWithNym vector currently transcribed (covers §12.1.3.{<i>n</i>}).</summary>
    public static IReadOnlyList<NymCommitVector> All { get; } = new[] { Vector001, Vector002 };
}
