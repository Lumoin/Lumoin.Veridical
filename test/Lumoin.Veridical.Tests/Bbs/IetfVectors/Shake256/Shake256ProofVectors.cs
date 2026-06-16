using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Shake256;

/// <summary>
/// IETF Appendix A BBS+ proof vectors for the BLS12-381-SHAKE-256
/// ciphersuite, transcribed verbatim from <c>draft-irtf-cfrg-bbs-signatures-10</c>.
/// The property numbering matches the IETF draft's
/// sub-section numbering, so gaps are visible when only a subset
/// of vectors has been transcribed.
/// </summary>
internal static class Shake256ProofVectors
{
    /// <summary>
    /// valid single message signature, single-message revealed proof (draft-irtf-cfrg-bbs-signatures-10, §8.5.5.1).
    /// </summary>
    public static BbsProofVector Vector001 { get; } = new(
        Id: "shake256-proof-001",
        Description: "valid single message signature, single-message revealed proof",
        DraftSection: "8.5.5.1",
        SignerPublicKey: "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        Signature: "b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef",
        Header: "11223344556677889900aabbccddeeff",
        PresentationHeader: "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501",
        Messages: [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
        ],
        DisclosedIndexes: [0],
        Seed: "332e313431353932363533353839373933323338343632363433333833323739",
        Proof: "89e4ab0c160880e0c2f12a754b9c051ed7f5fccfee3d5cbbb62e1239709196c737fff4303054660f8fcd08267a5de668a2e395ebe8866bdcb0dff9786d7014fa5e3c8cf7b41f8d7510e27d307f18032f6b788e200b9d6509f40ce1d2f962ceedb023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b43d8e2eb59ce31f34d68b39f05bb2c625e4de5e61e95ff38bfd62ab07105d016414b45b01625c69965ad3c8a933e7b25d93daeb777302b966079827a99178240e6c3f13b7db2fb1f14790940e239d775ab32f539bdf9f9b582b250b05882996832652f7f5d3b6e04744c73ada1702d6791940ccbd75e719537f7ace6ee817298d",
        ExpectedValid: true,
        InvalidReason: null);


    /// <summary>
    /// valid multi-message signature, multiple messages revealed proof (draft-irtf-cfrg-bbs-signatures-10, §8.5.5.3).
    /// </summary>
    public static BbsProofVector Vector003 { get; } = new(
        Id: "shake256-proof-003",
        Description: "valid multi-message signature, multiple messages revealed proof",
        DraftSection: "8.5.5.3",
        SignerPublicKey: "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        Signature: "956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e",
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
        Proof: "b1f8bf99a11c39f04e2a032183c1ead12956ad322dd06799c50f20fb8cf6b0ac279210ef5a2920a7be3ec2aa0911ace7b96811a98f3c1cceba4a2147ae763b3ba036f47bc21c39179f2b395e0ab1ac49017ea5b27848547bedd27be481c1dfc0b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af356dd39bf8bcbfd41bf95d913f4c9b2979e1ed2ca10ac7e881bb6a271722549681e398d29e9ba4eac8848b168eddd5e4acec7df4103e2ed165e6e32edc80f0a3b28c36fb39ca19b4b8acee570deadba2da9ec20d1f236b571e0d4c2ea3b826fe924175ed4dfffbf18a9cfa98546c241efb9164c444d970e8c89849bc8601e96cf228fdefe38ab3b7e289cac859e68d9cbb0e648faf692b27df5ff6539c30da17e5444a65143de02ca64cee7b0823be65865cdc310be038ec6b594b99280072ae067bad1117b0ff3201a5506a8533b925c7ffae9cdb64558857db0ac5f5e0f18e750ae77ec9cf35263474fef3f78138c7a1ef5cfbc878975458239824fad3ce05326ba3969b1f5451bd82bd1f8075f3d32ece2d61d89a064ab4804c3c892d651d11bc325464a71cd7aacc2d956a811aaff13ea4c35cef7842b656e8ba4758e7558",
        ExpectedValid: true,
        InvalidReason: null);


    /// <summary>
    /// invalid multi-message signature, all messages revealed proof (different presentation header) (draft-irtf-cfrg-bbs-signatures-10, §8.5.5.4).
    /// </summary>
    public static BbsProofVector Vector004 { get; } = new(
        Id: "shake256-proof-004",
        Description: "invalid multi-message signature, all messages revealed proof (different presentation header)",
        DraftSection: "8.5.5.4",
        SignerPublicKey: "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        Signature: "956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e",
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
        Proof: "b1f8bf99a11c39f04e2a032183c1ead12956ad322dd06799c50f20fb8cf6b0ac279210ef5a2920a7be3ec2aa0911ace7b96811a98f3c1cceba4a2147ae763b3ba036f47bc21c39179f2b395e0ab1ac49017ea5b27848547bedd27be481c1dfc0b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af356dd39bf8bcbfd41bf95d913f4c9b2979e1ed2ca10ac7e881bb6a271722549681e398d29e9ba4eac8848b168eddd5e4acec7df4103e2ed165e6e32edc80f0a3b28c36fb39ca19b4b8acee570deadba2da9ec20d1f236b571e0d4c2ea3b826fe924175ed4dfffbf18a9cfa98546c241efb9164c444d970e8c89849bc8601e96cf228fdefe38ab3b7e289cac859e68d9cbb0e648faf692b27df5ff6539c30da17e5444a65143de02ca64cee7b0823be65865cdc310be038ec6b594b99280072ae067bad1117b0ff3201a5506a8533b925c7ffae9cdb64558857db0ac5f5e0f18e750ae77ec9cf35263474fef3f78138c7a1ef5cfbc878975458239824fad3ce05326ba3969b1f5451bd82bd1f8075f3d32ece2d61d89a064ab4804c3c892d651d11bc325464a71cd7aacc2d956a811aaff13ea4c35cef7842b656e8ba4758e7558",
        ExpectedValid: false,
        InvalidReason: "different presentation header");

    /// <summary>Every Shake256-ciphersuite proof vector currently transcribed (covers IETF §8.5.5.{<i>n</i>}; partial set if numbering has gaps).</summary>
    public static IReadOnlyList<BbsProofVector> All { get; } = new[] { Vector001, Vector003, Vector004 };
}