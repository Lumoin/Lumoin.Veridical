using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Shake256;

/// <summary>
/// IETF Appendix A BBS+ KeyGen vectors for the BLS12-381-SHAKE-256 ciphersuite,
/// transcribed verbatim from <c>draft-irtf-cfrg-bbs-signatures-10</c>.
/// </summary>
internal static class Shake256KeyGenVectors
{
    /// <summary>
    /// key pair fixture (draft-irtf-cfrg-bbs-signatures-10, §8.5.1).
    /// </summary>
    public static BbsKeyGenVector Vector001 { get; } = new(
        Id: "shake256-keygen-001",
        Description: "key pair fixture",
        DraftSection: "8.5.1",
        KeyMaterial: "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579",
        KeyInfo: "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e",
        KeyDst: "4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4832475f484d32535f4b455947454e5f4453545f",
        ExpectedSecretKey: "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079",
        ExpectedPublicKey: "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5");


    /// <summary>Every Shake256-ciphersuite KeyGen vector currently transcribed.</summary>
    public static IReadOnlyList<BbsKeyGenVector> All { get; } = new[] { Vector001 };
}