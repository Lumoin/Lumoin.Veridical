using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Pseudonym.Sha256;

/// <summary>
/// Per-verifier-linkability generator-derivation primitive vectors
/// for the BLS12-381-SHA-256 ciphersuite, transcribed verbatim from
/// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section
/// 12.1.1/12.1.2.
/// </summary>
internal static class Sha256NymGeneratorsVectors
{
    /// <summary>
    /// Signer-message generators (H_0..H_9) under the pseudonym
    /// interface api_id (draft-irtf-cfrg-bbs-per-verifier-linkability-03, §12.1.1).
    /// </summary>
    public static NymGeneratorsVector Vector001 { get; } = new(
        Id: "sha256-nym-generators-001",
        Description: "signer-message generators under the pseudonym interface api_id",
        ApiId: "4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f50534555444f4e594d5f",
        P1: "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9",
        Q1: "a87fa55cfc29d0d0ef43b7816018c6162b9c4a5ddd5239ed24d9799f8e105c267d81ccb22f6379853c4070c28c71f13c",
        MessageGenerators: new[]
        {
            "8c6de69580b83b7c6d773857ae64b4495955eb06e67ebc5855af89c72cd8d9bea9fd7f71eca20c6a3388dfa67b1e7ccf",
            "aed1785c1c00d00893413e5011ecdc98706958a2ccf175be8a42afa56ef19c86ca6c14afe7e74a72596704fe34b6611d",
            "b5b5142c6314a918882439b634adb926cf42a55da2962865bcf09fe746554851ae075d9a4a03add64a0bec997eb708a8",
            "b54f25df3ba79539da4ceb375522625518590eebd52211d40cf1083f8a9e8c1bb19212f1f31711fd333678002a362830",
            "8fcb548cd1e5cddba514a7f90e3b0ebd00bd82bd66158f70cc7fffdb09f14ac8fc56ef9587cc41a82614533444494e75",
            "94a1d50478150c469711ccd09fa4544a590a1903f16445a4a5bc0ab639f1a408580f2464972198d128f1bb4a4fa41b0b",
            "b36ceb6c0cc0850fd3a2e64fa534a1c15566f99688ec6134c5223a33de83ce5534d43c0973a2769ce887d5bac8481519",
            "a4e6dff6038ab2e8265d9c177d110c742bc97f3a32bd70123ecd67176181b2068a0ae8323db6e061e4d8e62db6f283ad",
            "90977c482711c97318d1e4c4205308847727ca7dbf3ca7d1c55f1906aeca21aae22b7f43e73feae41c9a9be75319015d",
            "a435ee46442dd320426a1eb163176154bb144a7f829900d0e14ec7c28d882572acc1b4f670ef7cf5b41a4bea2efae6c6",
        });


    /// <summary>
    /// Blind/commitment generators (J_0..J_5) used by CommitWithNym
    /// (draft-irtf-cfrg-bbs-per-verifier-linkability-03, §12.1.2).
    /// </summary>
    public static NymGeneratorsVector Vector002 { get; } = new(
        Id: "sha256-nym-generators-002",
        Description: "blind/commitment generators used by CommitWithNym",
        ApiId: "424c494e445f4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f50534555444f4e594d5f",
        P1: "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9",
        Q1: "a264ef107598f1caaeb323b65164bcea80e88814810efc61ea27412e879c7cb9344b1b513118d3cf5c79bfa81268ef36",
        MessageGenerators: new[]
        {
            "8af923aaeaad46bf889049b2e5de19ff17778343114e589d716cde6eaa553c9e54fd6805afb244e445be2939ac789b35",
            "aa6c94da21fafb4cd604029cf599df139aa88ca1cf3676fb7da1e12ec6a8dc83c3d7fdbf33a79e760d810c4fbac37f6a",
            "8f65ebef29b60b81447821ea2d5a201d339b0c092021bd71eeee2d1f39d4972d3688c98c21831490583285c12f6da579",
            "b94e4549a9ecbec9b83c004d86649f0aa6510ba292a2e68d982e79ad4de0e5bd2972313a95170f4c5881d7a5b790c205",
            "a1d1d4460ee7475aa66fcd4c803b11cef74a75b9d4bfe9924de20434e01f35707855299c9d4ead6af5b93f57d9392d56",
            "8852ab63577b0a382df12320c5fc900bce57680d47e371ced873399bd9c5adc793ee890a919fb9c293e55acb4ab0312b",
        });

    /// <summary>Every Sha256-ciphersuite pseudonym-generators primitive vector currently transcribed.</summary>
    public static IReadOnlyList<NymGeneratorsVector> All { get; } = new[] { Vector001, Vector002 };
}
