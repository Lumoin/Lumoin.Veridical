using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Sha256;

/// <summary>
/// IETF Appendix A BBS+ signature vectors for the BLS12-381-SHA-256
/// ciphersuite, transcribed verbatim from <c>draft-irtf-cfrg-bbs-signatures-10</c>.
/// The property numbering matches the IETF draft's
/// sub-section numbering, so gaps are visible when only a subset
/// of vectors has been transcribed.
/// </summary>
internal static class Sha256SignatureVectors
{
    /// <summary>
    /// valid single message signature (draft-irtf-cfrg-bbs-signatures-10, §8.4.4.1).
    /// </summary>
    public static BbsSignatureVector Vector001 { get; } = new(
        Id: "sha256-signature-001",
        Description: "valid single message signature",
        DraftSection: "8.4.4.1",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Header: "11223344556677889900aabbccddeeff",
        Messages: [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
        ],
        Signature: "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0",
        ExpectedValid: true,
        InvalidReason: null);


    /// <summary>
    /// invalid single message signature (modified message) (draft-irtf-cfrg-bbs-signatures-10, §8.4.4.2).
    /// </summary>
    public static BbsSignatureVector Vector002 { get; } = new(
        Id: "sha256-signature-002",
        Description: "invalid single message signature (modified message)",
        DraftSection: "8.4.4.2",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Header: "11223344556677889900aabbccddeeff",
        Messages: [
            ""
        ],
        Signature: "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0",
        ExpectedValid: false,
        InvalidReason: "modified message");


    /// <summary>
    /// invalid single message signature (extra unsigned message) (draft-irtf-cfrg-bbs-signatures-10, §8.4.4.3).
    /// </summary>
    public static BbsSignatureVector Vector003 { get; } = new(
        Id: "sha256-signature-003",
        Description: "invalid single message signature (extra unsigned message)",
        DraftSection: "8.4.4.3",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Header: "11223344556677889900aabbccddeeff",
        Messages: [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
        ],
        Signature: "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0",
        ExpectedValid: false,
        InvalidReason: "extra unsigned message");


    /// <summary>
    /// valid multi-message signature (draft-irtf-cfrg-bbs-signatures-10, §8.4.4.4).
    /// </summary>
    public static BbsSignatureVector Vector004 { get; } = new(
        Id: "sha256-signature-004",
        Description: "valid multi-message signature",
        DraftSection: "8.4.4.4",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Header: "11223344556677889900aabbccddeeff",
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
        Signature: "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8",
        ExpectedValid: true,
        InvalidReason: null);


    /// <summary>
    /// invalid multi-message signature (missing messages) (draft-irtf-cfrg-bbs-signatures-10, §8.4.4.5).
    /// </summary>
    public static BbsSignatureVector Vector005 { get; } = new(
        Id: "sha256-signature-005",
        Description: "invalid multi-message signature (missing messages)",
        DraftSection: "8.4.4.5",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Header: "11223344556677889900aabbccddeeff",
        Messages: [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
        ],
        Signature: "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8",
        ExpectedValid: false,
        InvalidReason: "missing messages");


    /// <summary>
    /// invalid multi-message signature (re-ordered messages) (draft-irtf-cfrg-bbs-signatures-10, §8.4.4.6).
    /// </summary>
    public static BbsSignatureVector Vector006 { get; } = new(
        Id: "sha256-signature-006",
        Description: "invalid multi-message signature (re-ordered messages)",
        DraftSection: "8.4.4.6",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Header: "11223344556677889900aabbccddeeff",
        Messages: [
            "",
            "96012096",
            "ac55fb33a75909ed",
            "d183ddc6e2665aa4e2f088af",
            "515ae153e22aae04ad16f759e07237b4",
            "496694774c5604ab1b2544eababcf0f53278ff50",
            "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
            "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
            "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
        ],
        Signature: "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8",
        ExpectedValid: false,
        InvalidReason: "re-ordered messages");


    /// <summary>
    /// invalid multi-message signature (wrong public key) (draft-irtf-cfrg-bbs-signatures-10, §8.4.4.7).
    /// </summary>
    public static BbsSignatureVector Vector007 { get; } = new(
        Id: "sha256-signature-007",
        Description: "invalid multi-message signature (wrong public key)",
        DraftSection: "8.4.4.7",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "b064bd8d1ba99503cbb7f9d7ea00bce877206a85b1750e5583dd9399828a4d20610cb937ea928d90404c239b2835ffb104220a9c66a4c9ed3b54c0cac9ea465d0429556b438ceefb59650ddf67e7a8f103677561b7ef7fe3c3357ec6b94d41c6",
        Header: "11223344556677889900aabbccddeeff",
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
        Signature: "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8",
        ExpectedValid: false,
        InvalidReason: "wrong public key");


    /// <summary>
    /// invalid multi-message signature (different header) (draft-irtf-cfrg-bbs-signatures-10, §8.4.4.8).
    /// </summary>
    public static BbsSignatureVector Vector008 { get; } = new(
        Id: "sha256-signature-008",
        Description: "invalid multi-message signature (different header)",
        DraftSection: "8.4.4.8",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Header: "ffeeddccbbaa00998877665544332211",
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
        Signature: "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8",
        ExpectedValid: false,
        InvalidReason: "different header");


    /// <summary>
    /// invalid multi-message signature (re-ordered(randomly shuffled) messages) (draft-irtf-cfrg-bbs-signatures-10, §8.4.4.9).
    /// </summary>
    public static BbsSignatureVector Vector009 { get; } = new(
        Id: "sha256-signature-009",
        Description: "invalid multi-message signature (re-ordered(randomly shuffled) messages)",
        DraftSection: "8.4.4.9",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Header: "11223344556677889900aabbccddeeff",
        Messages: [
            "ac55fb33a75909ed",
            "",
            "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
            "d183ddc6e2665aa4e2f088af",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "96012096",
            "515ae153e22aae04ad16f759e07237b4",
            "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
            "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
            "496694774c5604ab1b2544eababcf0f53278ff50"
        ],
        Signature: "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8",
        ExpectedValid: false,
        InvalidReason: "re-ordered(randomly shuffled) messages");


    /// <summary>
    /// valid multi-message signature, no header (draft-irtf-cfrg-bbs-signatures-10, §8.4.4.10).
    /// </summary>
    public static BbsSignatureVector Vector010 { get; } = new(
        Id: "sha256-signature-010",
        Description: "valid multi-message signature, no header",
        DraftSection: "8.4.4.10",
        SignerSecretKey: "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        SignerPublicKey: "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
        Header: "",
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
        Signature: "8c87e2080859a97299c148427cd2fcf390d24bea850103a9748879039262ecf4f42206f6ef767f298b6a96b424c1e86c26f8fba62212d0e05b95261c2cc0e5fdc63a32731347e810fd12e9c58355aa0d",
        ExpectedValid: true,
        InvalidReason: null);

    /// <summary>Every Sha256-ciphersuite signature vector currently transcribed (covers IETF §8.4.4.{<i>n</i>}; partial set if numbering has gaps).</summary>
    public static IReadOnlyList<BbsSignatureVector> All { get; } = new[] { Vector001, Vector002, Vector003, Vector004, Vector005, Vector006, Vector007, Vector008, Vector009, Vector010 };
}