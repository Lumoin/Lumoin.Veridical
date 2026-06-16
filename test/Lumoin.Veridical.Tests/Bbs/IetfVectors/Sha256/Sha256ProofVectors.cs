using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Sha256;

/// <summary>
/// IETF Appendix A BBS+ proof vectors for the BLS12-381-SHA-256
/// ciphersuite, transcribed verbatim from <c>draft-irtf-cfrg-bbs-signatures-10</c>.
/// The property numbering matches the IETF draft's
/// sub-section numbering, so gaps are visible when only a subset
/// of vectors has been transcribed.
/// </summary>
internal static class Sha256ProofVectors
{
    /// <summary>
    /// valid single message signature, single-message revealed proof (draft-irtf-cfrg-bbs-signatures-10, §8.4.5.1).
    /// </summary>
    public static BbsProofVector Vector001 { get; } = new(
        Id: "sha256-proof-001",
        Description: "valid single message signature, single-message revealed proof",
        DraftSection: "8.4.5.1",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Signature: "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0",
        Header: "11223344556677889900aabbccddeeff",
        PresentationHeader: "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501",
        Messages: [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
        ],
        DisclosedIndexes: [0],
        Seed: "332e313431353932363533353839373933323338343632363433333833323739",
        Proof: "94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aadaeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf29417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418",
        ExpectedValid: true,
        InvalidReason: null);


    /// <summary>
    /// valid multi-message signature, all messages revealed proof (draft-irtf-cfrg-bbs-signatures-10, §8.4.5.2).
    /// </summary>
    public static BbsProofVector Vector002 { get; } = new(
        Id: "sha256-proof-002",
        Description: "valid multi-message signature, all messages revealed proof",
        DraftSection: "8.4.5.2",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Signature: "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8",
        Header: "11223344556677889900aabbccddeeff",
        PresentationHeader: "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501",
        Messages: [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
            "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
            "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
            "496694774c5604ab1b2544eababcf0f53278ff50",
            "515ae153e22aae04ad16f759e07237b4",
            "d183ddc6e2665aa4e2f088af",
            "ac55fb33a75909ed",
            "96012096",
            ""
        ],
        DisclosedIndexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        Seed: "332e313431353932363533353839373933323338343632363433333833323739",
        Proof: "b1f468aec2001c4f54cb56f707c6222a43e5803a25b2253e67b2210ab2ef9eab52db2d4b379935c4823281eaf767fd37b08ce80dc65de8f9769d27099ae649ad4c9b4bd2cc23edcba52073a298087d2495e6d57aaae051ef741adf1cbce65c64a73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c67327365763f5aa9fb85ddcbc2975449b8c03db1216ca66b310f07d0ccf12ab460cdc6003b677fed36d0a23d0818a9d4d098d44f749e91008cf50e8567ef936704c8277b7710f41ab7e6e16408ab520edc290f9801349aee7b7b4e318e6a76e028e1dea911e2e7baec6a6a174da1a22362717fbae1cd961d7bf4adce1d31c2ab",
        ExpectedValid: true,
        InvalidReason: null);


    /// <summary>
    /// valid multi-message signature, multiple messages revealed proof (draft-irtf-cfrg-bbs-signatures-10, §8.4.5.3).
    /// </summary>
    public static BbsProofVector Vector003 { get; } = new(
        Id: "sha256-proof-003",
        Description: "valid multi-message signature, multiple messages revealed proof",
        DraftSection: "8.4.5.3",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Signature: "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8",
        Header: "11223344556677889900aabbccddeeff",
        PresentationHeader: "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501",
        Messages: [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
            "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
            "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
            "496694774c5604ab1b2544eababcf0f53278ff50",
            "515ae153e22aae04ad16f759e07237b4",
            "d183ddc6e2665aa4e2f088af",
            "ac55fb33a75909ed",
            "96012096",
            ""
        ],
        DisclosedIndexes: [0, 2, 4, 6],
        Seed: "332e313431353932363533353839373933323338343632363433333833323739",
        Proof: "a2ed608e8e12ed21abc2bf154e462d744a367c7f1f969bdbf784a2a134c7db2d340394223a5397a3011b1c340ebc415199462ba6f31106d8a6da8b513b37a47afe93c9b3474d0d7a354b2edc1b88818b063332df774c141f7a07c48fe50d452f897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481356918cd38025d86b28650e909defe9604a7259f44386b861608be742af7775a2e71a6070e5836f5f54dc43c60096834a5b6da295bf8f081f72b7cdf7f3b4347fb3ff19edaa9e74055c8ba46dbcb7594fb2b06633bb5324192eb9be91be0d33e453b4d3127459de59a5e2193c900816f049a02cb9127dac894418105fa1641d5a206ec9c42177af9316f433417441478276ca0303da8f941bf2e0222a43251cf5c2bf6eac1961890aa740534e519c1767e1223392a3a286b0f4d91f7f25217a7862b8fcc1810cdcfddde2a01c80fcc90b632585fec12dc4ae8fea1918e9ddeb9414623a457e88f53f545841f9d5dcb1f8e160d1560770aa79d65e2eca8edeaecb73fb7e995608b820c4a64de6313a370ba05dc25ed7c1d185192084963652f2870341bdaa4b1a37f8c06348f38a4f80c5a2650a21d59f09e8305dcd3fc3ac30e2a",
        ExpectedValid: true,
        InvalidReason: null);


    /// <summary>
    /// invalid multi-message signature, all messages revealed proof (different presentation header) (draft-irtf-cfrg-bbs-signatures-10, §8.4.5.4).
    /// </summary>
    public static BbsProofVector Vector004 { get; } = new(
        Id: "sha256-proof-004",
        Description: "invalid multi-message signature, all messages revealed proof (different presentation header)",
        DraftSection: "8.4.5.4",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Signature: "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8",
        Header: "11223344556677889900aabbccddeeff",
        PresentationHeader: "011594ba7f95b3b470ea4102dd5899de3a042e5104d3ea01d15e6780d831d2be",
        Messages: [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
            "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
            "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
            "496694774c5604ab1b2544eababcf0f53278ff50",
            "515ae153e22aae04ad16f759e07237b4",
            "d183ddc6e2665aa4e2f088af",
            "ac55fb33a75909ed",
            "96012096",
            ""
        ],
        DisclosedIndexes: [0, 2, 4, 6],
        Seed: "332e313431353932363533353839373933323338343632363433333833323739",
        Proof: "a2ed608e8e12ed21abc2bf154e462d744a367c7f1f969bdbf784a2a134c7db2d340394223a5397a3011b1c340ebc415199462ba6f31106d8a6da8b513b37a47afe93c9b3474d0d7a354b2edc1b88818b063332df774c141f7a07c48fe50d452f897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481356918cd38025d86b28650e909defe9604a7259f44386b861608be742af7775a2e71a6070e5836f5f54dc43c60096834a5b6da295bf8f081f72b7cdf7f3b4347fb3ff19edaa9e74055c8ba46dbcb7594fb2b06633bb5324192eb9be91be0d33e453b4d3127459de59a5e2193c900816f049a02cb9127dac894418105fa1641d5a206ec9c42177af9316f433417441478276ca0303da8f941bf2e0222a43251cf5c2bf6eac1961890aa740534e519c1767e1223392a3a286b0f4d91f7f25217a7862b8fcc1810cdcfddde2a01c80fcc90b632585fec12dc4ae8fea1918e9ddeb9414623a457e88f53f545841f9d5dcb1f8e160d1560770aa79d65e2eca8edeaecb73fb7e995608b820c4a64de6313a370ba05dc25ed7c1d185192084963652f2870341bdaa4b1a37f8c06348f38a4f80c5a2650a21d59f09e8305dcd3fc3ac30e2a",
        ExpectedValid: false,
        InvalidReason: "different presentation header");


    /// <summary>
    /// invalid multi-message signature, all messages revealed proof (wrong public key) (draft-irtf-cfrg-bbs-signatures-10, §8.4.5.5).
    /// </summary>
    public static BbsProofVector Vector005 { get; } = new(
        Id: "sha256-proof-005",
        Description: "invalid multi-message signature, all messages revealed proof (wrong public key)",
        DraftSection: "8.4.5.5",
        SignerPublicKey: "b064bd8d1ba99503cbb7f9d7ea00bce877206a85b1750e5583dd9399828a4d20610cb937ea928d90404c239b2835ffb104220a9c66a4c9ed3b54c0cac9ea465d0429556b438ceefb59650ddf67e7a8f103677561b7ef7fe3c3357ec6b94d41c6",
        Signature: "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8",
        Header: "11223344556677889900aabbccddeeff",
        PresentationHeader: "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501",
        Messages: [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
            "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
            "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
            "496694774c5604ab1b2544eababcf0f53278ff50",
            "515ae153e22aae04ad16f759e07237b4",
            "d183ddc6e2665aa4e2f088af",
            "ac55fb33a75909ed",
            "96012096",
            ""
        ],
        DisclosedIndexes: [0, 2, 4, 6],
        Seed: "332e313431353932363533353839373933323338343632363433333833323739",
        Proof: "a2ed608e8e12ed21abc2bf154e462d744a367c7f1f969bdbf784a2a134c7db2d340394223a5397a3011b1c340ebc415199462ba6f31106d8a6da8b513b37a47afe93c9b3474d0d7a354b2edc1b88818b063332df774c141f7a07c48fe50d452f897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481356918cd38025d86b28650e909defe9604a7259f44386b861608be742af7775a2e71a6070e5836f5f54dc43c60096834a5b6da295bf8f081f72b7cdf7f3b4347fb3ff19edaa9e74055c8ba46dbcb7594fb2b06633bb5324192eb9be91be0d33e453b4d3127459de59a5e2193c900816f049a02cb9127dac894418105fa1641d5a206ec9c42177af9316f433417441478276ca0303da8f941bf2e0222a43251cf5c2bf6eac1961890aa740534e519c1767e1223392a3a286b0f4d91f7f25217a7862b8fcc1810cdcfddde2a01c80fcc90b632585fec12dc4ae8fea1918e9ddeb9414623a457e88f53f545841f9d5dcb1f8e160d1560770aa79d65e2eca8edeaecb73fb7e995608b820c4a64de6313a370ba05dc25ed7c1d185192084963652f2870341bdaa4b1a37f8c06348f38a4f80c5a2650a21d59f09e8305dcd3fc3ac30e2a",
        ExpectedValid: false,
        InvalidReason: "wrong public key");

    /// <summary>Every Sha256-ciphersuite proof vector currently transcribed (covers IETF §8.4.5.{<i>n</i>}; partial set if numbering has gaps).</summary>
    public static IReadOnlyList<BbsProofVector> All { get; } = new[] { Vector001, Vector002, Vector003, Vector004, Vector005 };
}