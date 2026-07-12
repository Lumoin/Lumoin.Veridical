using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Pseudonym.Sha256;

/// <summary>
/// BlindSignWithNym / FinalizeBlindSignWithNym vectors for the
/// BLS12-381-SHA-256 ciphersuite, transcribed verbatim from
/// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section
/// 12.1.4, with the <see cref="NymSignatureVector.ProverNym"/> and
/// <see cref="NymSignatureVector.NymSecret"/> fields recovered per
/// those record fields' docs (the draft prints them as "undefined").
/// </summary>
internal static class Sha256NymSignatureVectors
{
    /// <summary>
    /// valid no prover committed messages, no signer messages signature (draft-irtf-cfrg-bbs-per-verifier-linkability-03, §12.1.4.1).
    /// </summary>
    public static NymSignatureVector Vector001 { get; } = new(
        Id: "sha256-nym-signature-001",
        Description: "valid no prover committed messages, no signer messages signature",
        DraftSection: "12.1.4.1",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Header: "11223344556677889900aabbccddeeff",
        Messages: [],
        CommittedMessages: [],
        CommitmentWithProof: "b989fc492e2047f602504eb3e236c0acb04224c77ad0d4cbd31c887b9eb05a1f27d7acfb266fe0ae062914bfa060984c5c2ac3247080eb71fefc7e9622ffae372425a699a298ba991a0bc5c6a3d9211347d0ce98d5c0550667269df1fb81f8fa30c07d4917c7c0786411ee5c05b00b9d501d3f8e244b860b7b11140cddc9787a3ab54ec7fd0a8950dae339f396f2641b",
        SignerNymEntropy: "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5",
        ProverBlind: "3ba0a2583bc7229fa9f2ae3a6697091032947c3a48f302b7fd2b08ca9d193041",
        ProverNym: "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418",
        NymSecret: "3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc",
        TraceB: "8b74e51a16d305b01d3ca60329e697a3cbc8f3272cd6d65d398b529656b5159f9589293b1ba4507d8e7eec9f2d4d1a79",
        TraceDomain: "01b0b85ea47afe36f772bbce626fb8064f85a3aa6233c33776194a170f45fa61",
        Signature: "aabc3014c598f3cd8fcc162950ff9aa9ac93c0877d33d1cc0b71b31964e3b109715d5af307e580b498b0ec8c0b8f848028ba9d881be84bf405295f27f02131028498c50c4fa3f6bb93483bf676ef1f1c");


    /// <summary>
    /// valid multi prover committed messages, no signer messages signature (draft-irtf-cfrg-bbs-per-verifier-linkability-03, §12.1.4.2).
    /// </summary>
    public static NymSignatureVector Vector002 { get; } = new(
        Id: "sha256-nym-signature-002",
        Description: "valid multi prover committed messages, no signer messages signature",
        DraftSection: "12.1.4.2",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Header: "11223344556677889900aabbccddeeff",
        Messages: [],
        CommittedMessages:
        [
            "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3",
            "a75d8b634891af92282cc81a675972d1929d3149863c1fc0",
            "835889a40744813a892eff9deb1edaeb",
            "e1ca9729410dc6ba",
            "",
        ],
        CommitmentWithProof: "99efccc0ccd91efabb8821ee33edacb823b1dd999682aaa54f38a9c4585e7e7aa746357b2842d38c008f6d732dd501c70eed41caf3eafdd4bb6151ce2c0289401c7d13381e7db90137d7aa2a64224aa2499a4548b2654481a2f0dd16d799116fe41db7b7a5c3ae8b1c64bef6a89a46f5040a5178d2e1126f7f35189f0f6cea3803e679ce92eff73856b164425ac4ff8405a934f65ada8ccbe21558ab66db113662ea17ce0c9aa0280db20dcf79301c61269ddfdbdcc22025b85f7089c4ebebc224a938b745daae833ac4698d9d32bfa8382b4bbb2679ae232d2f6e8e19239e6ea919665ea736b45a61bbd0e4f4d7431f3038c3db25833b9a0cc1a7709419ac241fb6f02ee13e51101743f1983d3fa69b5d344b984c48a265ee6a7b0df8450004ceec7c1997b859be16af624e3da2cf44",
        SignerNymEntropy: "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5",
        ProverBlind: "15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8",
        ProverNym: "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418",
        NymSecret: "3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc",
        TraceB: "8aa0835565a69418b9010e4e2cb82757a97c729d26ca8227863941659a9a37a14728461dd0a6f5338e2acdcb34498c84",
        TraceDomain: "3f7830ef29ea1742aa66c15c4b9748ea8b1bd40a83f2204d419c4baabdf8b31f",
        Signature: "88b2a07b490f81f8be334fe30b4034f90bbf77d7ccacc488fa8bfd7d98996f95ca7a02bfa5fef4983240f80e5956e7836b4630d6bc54a0a28b246bed38f83b0c4bb378ef315e51b581abd6d8f3a6fded");


    /// <summary>
    /// valid no prover committed messages, multiple signer messages signature (draft-irtf-cfrg-bbs-per-verifier-linkability-03, §12.1.4.3).
    /// </summary>
    public static NymSignatureVector Vector003 { get; } = new(
        Id: "sha256-nym-signature-003",
        Description: "valid no prover committed messages, multiple signer messages signature",
        DraftSection: "12.1.4.3",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Header: "11223344556677889900aabbccddeeff",
        Messages:
        [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
            "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
            "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
            "496694774c5604ab1b2544eababcf0f53278ff50",
            "515ae153e22aae04ad16f759e07237b4",
            "d183ddc6e2665aa4e2f088af",
            "ac55fb33a75909ed",
            "96012096",
            "",
        ],
        CommittedMessages: [],
        CommitmentWithProof: "b989fc492e2047f602504eb3e236c0acb04224c77ad0d4cbd31c887b9eb05a1f27d7acfb266fe0ae062914bfa060984c5c2ac3247080eb71fefc7e9622ffae372425a699a298ba991a0bc5c6a3d9211347d0ce98d5c0550667269df1fb81f8fa30c07d4917c7c0786411ee5c05b00b9d501d3f8e244b860b7b11140cddc9787a3ab54ec7fd0a8950dae339f396f2641b",
        SignerNymEntropy: "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5",
        ProverBlind: "3ba0a2583bc7229fa9f2ae3a6697091032947c3a48f302b7fd2b08ca9d193041",
        ProverNym: "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418",
        NymSecret: "3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc",
        TraceB: "b6c39d33218bc3adaa6cd9d5539f51c66c75c30ee129d7f981e135c0ee5716d60cb5ee82f709224e0c8d9efefa778a38",
        TraceDomain: "55891afaaadc4df689ca0d112e8aef3ea38b4256db93226ede05546eb8f1daf2",
        Signature: "9737d3d2ae17d170b3320329df8af1639b41ef2251e07437908786fd6421465ac46f98ff8091455d5bfd9394262a818631b7034648ef8a6c940a0b8232e7b160e4e71d8c676958b2d587da285bbf890a");


    /// <summary>
    /// valid multiple signer and prover committed messages signature (draft-irtf-cfrg-bbs-per-verifier-linkability-03, §12.1.4.4).
    /// </summary>
    public static NymSignatureVector Vector004 { get; } = new(
        Id: "sha256-nym-signature-004",
        Description: "valid multiple signer and prover committed messages signature",
        DraftSection: "12.1.4.4",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Header: "11223344556677889900aabbccddeeff",
        Messages:
        [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
            "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
            "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
            "496694774c5604ab1b2544eababcf0f53278ff50",
            "515ae153e22aae04ad16f759e07237b4",
            "d183ddc6e2665aa4e2f088af",
            "ac55fb33a75909ed",
            "96012096",
            "",
        ],
        CommittedMessages:
        [
            "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3",
            "a75d8b634891af92282cc81a675972d1929d3149863c1fc0",
            "835889a40744813a892eff9deb1edaeb",
            "e1ca9729410dc6ba",
            "",
        ],
        CommitmentWithProof: "99efccc0ccd91efabb8821ee33edacb823b1dd999682aaa54f38a9c4585e7e7aa746357b2842d38c008f6d732dd501c70eed41caf3eafdd4bb6151ce2c0289401c7d13381e7db90137d7aa2a64224aa2499a4548b2654481a2f0dd16d799116fe41db7b7a5c3ae8b1c64bef6a89a46f5040a5178d2e1126f7f35189f0f6cea3803e679ce92eff73856b164425ac4ff8405a934f65ada8ccbe21558ab66db113662ea17ce0c9aa0280db20dcf79301c61269ddfdbdcc22025b85f7089c4ebebc224a938b745daae833ac4698d9d32bfa8382b4bbb2679ae232d2f6e8e19239e6ea919665ea736b45a61bbd0e4f4d7431f3038c3db25833b9a0cc1a7709419ac241fb6f02ee13e51101743f1983d3fa69b5d344b984c48a265ee6a7b0df8450004ceec7c1997b859be16af624e3da2cf44",
        SignerNymEntropy: "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5",
        ProverBlind: "15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8",
        ProverNym: "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418",
        NymSecret: "3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc",
        TraceB: "b677b21f402d69919483418900e0647b1a73aada9e081808b313cf5f83c43f0522b8682857659aa7920bb511ef4a477f",
        TraceDomain: "18a554af90e12ae7a81bd511901abfe1cf882387033796cc47df19b244a15894",
        Signature: "818f434f737d58ed13b7cbb53885b7a19fe9b4b7d7dc34d8fcc53ca1bfe376bd569053d8733a89b97fed23da4a04833c57ce2b42cfd0d60e1b862f7774431e80b0ed910a217f37837ab90a94dc1253bb");

    /// <summary>Every Sha256-ciphersuite BlindSignWithNym vector currently transcribed (covers §12.1.4.{<i>n</i>}).</summary>
    public static IReadOnlyList<NymSignatureVector> All { get; } = new[] { Vector001, Vector002, Vector003, Vector004 };
}
