using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Pseudonym.Shake256;

/// <summary>
/// BlindSignWithNym / FinalizeBlindSignWithNym vectors for the
/// BLS12-381-SHAKE-256 ciphersuite, transcribed verbatim from
/// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section
/// 12.2.4, with the <see cref="NymSignatureVector.ProverNym"/> and
/// <see cref="NymSignatureVector.NymSecret"/> fields recovered per
/// those record fields' docs (the draft prints them as "undefined").
/// </summary>
internal static class Shake256NymSignatureVectors
{
    /// <summary>
    /// valid no prover committed messages, no signer messages signature (draft-irtf-cfrg-bbs-per-verifier-linkability-03, §12.2.4.1).
    /// </summary>
    public static NymSignatureVector Vector001 { get; } = new(
        Id: "shake256-nym-signature-001",
        Description: "valid no prover committed messages, no signer messages signature",
        DraftSection: "12.2.4.1",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Header: "11223344556677889900aabbccddeeff",
        Messages: [],
        CommittedMessages: [],
        CommitmentWithProof: "990c1837a8af86843213e5b12fbfc962efcaf8fd0e5812a6237b91b00a47b5a34714a60b4c365f72b47a4d9b656dde4753a18a8286aca2bf58e8bb9a3d77a3e0052aefc427e5e47b666255e53cfcaa7d34d36adc13da01798b8eb041652a57c3b595ace54ed5eee43370c1697eb5ce996020d88ca5d811c011cde10c6c07dc2f4acbc89bd5652414d5b8823a250ed40b",
        SignerNymEntropy: "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5",
        ProverBlind: "643a0c0bc86a50e0d8c00bfe6c8debd85373597e1aef6cc912838bf7dc376e48",
        ProverNym: "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418",
        NymSecret: "3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc",
        TraceB: "8d8c93a08cad41749cbd944e778027984498382efe5fd6a110ff9cc741ae65b1d5087d9bd0edffaefa492d8cffc1be3a",
        TraceDomain: "65f5322d0c1035ffcc8a93ded3cf56ab258257d5169d6cef81caab0cbebe5bc4",
        Signature: "8c184a9844d7220ac2d65ac2ea9319f8a9fbe56e59e58e8c89e4c095a2f2c63675c85aa04e368e2f2cd451af94558c390660c636807b1f74412310271761d398e7cb48719aaec0d21043cbdb94d45f2a");


    /// <summary>
    /// valid multi prover committed messages, no signer messages signature (draft-irtf-cfrg-bbs-per-verifier-linkability-03, §12.2.4.2).
    /// </summary>
    public static NymSignatureVector Vector002 { get; } = new(
        Id: "shake256-nym-signature-002",
        Description: "valid multi prover committed messages, no signer messages signature",
        DraftSection: "12.2.4.2",
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
        CommitmentWithProof: "a9577c3e2f15081c03d2e86789c1d9208bc04409b1ca33c25d06017c8fef5d139aee028ac96b9c09636a45846e9a5ee51f83bfd55f12193061e3f707d11d9993d6e08293de7f3dd0a298c21f369208b43b7b401706a9a0a5dcfa12d28d5a59b09da337b435cf4aa2a869842c8e1409004865ce6ff78d345e5c8142c9c440b677824ce06a8f70c50bbbb01838a91eb0041fd853c2005109d3aec272dd03346f37fc90828490fbedc4fc88e7307662b785653aba1a28a45bca913b7dd778e8bd141652e6f0507c3f836c8852b8ddbf2c62659dbd7b83f096e7b351f2f0dc6046bce3c8d0c5bb892a7a3d76d6bac899b3d356b099f88287ac25e6879d5808f832927c8e28acae41ab3699b5c0f9da4f58bf67d7e87c5ddb6dadd80fe281e158cc7a24bc398f84022dc0dc3a123971f7546c",
        SignerNymEntropy: "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5",
        ProverBlind: "1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3",
        ProverNym: "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418",
        NymSecret: "3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc",
        TraceB: "a3e9e31869a174bd298fdb5510dfa387362aa26a91ebcfeb2290e75a6eb844a2fcaf874cd75b74e242e59fc25b2ff5ce",
        TraceDomain: "347edba7f30d3b0fe44611797091bcfc61c118b246125050fd609ecabef1b908",
        Signature: "a861c09a27a58197416e8df99c55d6500eeb01b007df418c5871e0da3cd9741c3e80e8a83c7ccb2ff697bbee1c22953a4adcc9627ecb16654b4a9b19c0346c5d5fa79d20c8b77208f4bc4deceff065ba");


    /// <summary>
    /// valid no prover committed messages, multiple signer messages signature (draft-irtf-cfrg-bbs-per-verifier-linkability-03, §12.2.4.3).
    /// </summary>
    public static NymSignatureVector Vector003 { get; } = new(
        Id: "shake256-nym-signature-003",
        Description: "valid no prover committed messages, multiple signer messages signature",
        DraftSection: "12.2.4.3",
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
        CommitmentWithProof: "990c1837a8af86843213e5b12fbfc962efcaf8fd0e5812a6237b91b00a47b5a34714a60b4c365f72b47a4d9b656dde4753a18a8286aca2bf58e8bb9a3d77a3e0052aefc427e5e47b666255e53cfcaa7d34d36adc13da01798b8eb041652a57c3b595ace54ed5eee43370c1697eb5ce996020d88ca5d811c011cde10c6c07dc2f4acbc89bd5652414d5b8823a250ed40b",
        SignerNymEntropy: "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5",
        ProverBlind: "643a0c0bc86a50e0d8c00bfe6c8debd85373597e1aef6cc912838bf7dc376e48",
        ProverNym: "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418",
        NymSecret: "3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc",
        TraceB: "8a2d9aced02797ca4a20dd7655dba6e27a442d482225af27a9ed7da592d196618c41ea235f3774b5656ecd7d3f4813e1",
        TraceDomain: "0777a5e4e6f3a1c64efe741339dc9c68a50aebaf279b5c0138e70c874e97959f",
        Signature: "ad0a0326d2d8196fb7942f3d0c5dbdc1d7e7277e5cba6ab3ce6bc9794855f2242b1eb198228c78f4aaa20725ffda015438f11e13cd7fd21dc2247844c26ce34e82264ca2554ef337648ddd66d75c8cf5");


    /// <summary>
    /// valid multiple signer and prover committed messages signature (draft-irtf-cfrg-bbs-per-verifier-linkability-03, §12.2.4.4).
    /// </summary>
    public static NymSignatureVector Vector004 { get; } = new(
        Id: "shake256-nym-signature-004",
        Description: "valid multiple signer and prover committed messages signature",
        DraftSection: "12.2.4.4",
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
        CommitmentWithProof: "a9577c3e2f15081c03d2e86789c1d9208bc04409b1ca33c25d06017c8fef5d139aee028ac96b9c09636a45846e9a5ee51f83bfd55f12193061e3f707d11d9993d6e08293de7f3dd0a298c21f369208b43b7b401706a9a0a5dcfa12d28d5a59b09da337b435cf4aa2a869842c8e1409004865ce6ff78d345e5c8142c9c440b677824ce06a8f70c50bbbb01838a91eb0041fd853c2005109d3aec272dd03346f37fc90828490fbedc4fc88e7307662b785653aba1a28a45bca913b7dd778e8bd141652e6f0507c3f836c8852b8ddbf2c62659dbd7b83f096e7b351f2f0dc6046bce3c8d0c5bb892a7a3d76d6bac899b3d356b099f88287ac25e6879d5808f832927c8e28acae41ab3699b5c0f9da4f58bf67d7e87c5ddb6dadd80fe281e158cc7a24bc398f84022dc0dc3a123971f7546c",
        SignerNymEntropy: "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5",
        ProverBlind: "1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3",
        ProverNym: "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418",
        NymSecret: "3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc",
        TraceB: "8df28b59593bf5e65a4c3785c0bddc06958b18ae9376bdc2a973c86a9c91c3dcc6d6a8af8391f21f6352285df948123f",
        TraceDomain: "28ef090980cdc152a3c1e56f778a09a54eeffb4117d051892df580f38e362afd",
        Signature: "b6bb95cb52f5f44ca1ff76ae305b03f014945746871b057ea08c2e45c24846bccd26f14858afdcb942896630cc16439002f802e700bc2c83347064b3ff69bfdc8552119ab13b07b52e233d908f859237");

    /// <summary>Every Shake256-ciphersuite BlindSignWithNym vector currently transcribed (covers §12.2.4.{<i>n</i>}).</summary>
    public static IReadOnlyList<NymSignatureVector> All { get; } = new[] { Vector001, Vector002, Vector003, Vector004 };
}
