using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Shake256;

/// <summary>
/// IETF Appendix A BBS+ signature vectors for the BLS12-381-SHAKE-256
/// ciphersuite, transcribed verbatim from <c>draft-irtf-cfrg-bbs-signatures-10</c>.
/// The property numbering matches the IETF draft's
/// sub-section numbering, so gaps are visible when only a subset
/// of vectors has been transcribed.
/// </summary>
internal static class Shake256SignatureVectors
{
    /// <summary>
    /// valid single message signature (draft-irtf-cfrg-bbs-signatures-10, §8.5.4.1).
    /// </summary>
    public static BbsSignatureVector Vector001 { get; } = new(
        Id: "shake256-signature-001",
        Description: "valid single message signature",
        DraftSection: "8.5.4.1",
        SignerSecretKey: "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079",
        SignerPublicKey: "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        Header: "11223344556677889900aabbccddeeff",
        Messages: [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
        ],
        Signature: "b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef",
        ExpectedValid: true,
        InvalidReason: null);


    /// <summary>
    /// invalid single message signature (modified message) (draft-irtf-cfrg-bbs-signatures-10, §8.5.4.2).
    /// </summary>
    public static BbsSignatureVector Vector002 { get; } = new(
        Id: "shake256-signature-002",
        Description: "invalid single message signature (modified message)",
        DraftSection: "8.5.4.2",
        SignerSecretKey: "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079",
        SignerPublicKey: "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
        Header: "11223344556677889900aabbccddeeff",
        Messages: [
            ""
        ],
        Signature: "b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef",
        ExpectedValid: false,
        InvalidReason: "modified message");


    /// <summary>
    /// valid multi-message signature, no header (draft-irtf-cfrg-bbs-signatures-10, §8.5.4.10).
    /// </summary>
    public static BbsSignatureVector Vector010 { get; } = new(
        Id: "shake256-signature-010",
        Description: "valid multi-message signature, no header",
        DraftSection: "8.5.4.10",
        SignerSecretKey: "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079",
        SignerPublicKey: "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
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
        Signature: "88beeb970f803160d3058eacde505207c576a8c9e4e5dc7c5249cbcf2a046c15f8df047031eef3436e04b779d92a9cdb1fe4c6cc035ba1634f1740f9dd49816d3ca745ecbe39f655ea61fb700137fded",
        ExpectedValid: true,
        InvalidReason: null);

    /// <summary>Every Shake256-ciphersuite signature vector currently transcribed (covers IETF §8.5.4.{<i>n</i>}; partial set if numbering has gaps).</summary>
    public static IReadOnlyList<BbsSignatureVector> All { get; } = new[] { Vector001, Vector002, Vector010 };
}