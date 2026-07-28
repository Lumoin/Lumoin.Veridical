namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The SHAKE256 test vectors transcribed from google/longfellow-zk
/// <c>circuits/tests/sha3/shake_test_vectors.h</c> (<c>GetShake256TestVectors()</c>) at the pinned
/// reference commit, in the reference's order: vector 0 has the empty input, vector 1 the
/// three-byte <c>abc</c> input the reference's ZK round-trip shape hard-codes.
/// </summary>
internal static class LongfellowSha3TestVectors
{
    /// <summary>One SHAKE256 vector.</summary>
    /// <param name="Input">The input bytes as lowercase hexadecimal (empty string for the empty input).</param>
    /// <param name="Output">The expected squeezed bytes as lowercase hexadecimal.</param>
    internal sealed record ShakeVector(string Input, string Output);

    /// <summary>The reference's SHAKE256 vectors, in order.</summary>
    public static System.Collections.Generic.IReadOnlyList<ShakeVector> Shake256Vectors { get; } =
    [
        new(
            Input: "",
            Output: "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b5"),
        new(
            Input: "616263",
            Output: "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5"),
        new(
            Input: "001326394c5f728598abbed1e4f70a1d",
            Output: "6a77eaa316cb8699fe749d258ce8cecc90c5348b6c899b6828a3ff3a3e25ecea"),
        new(
            Input: "05182b3e5164778a9db0c3d6e9fc0f2235485b6e8194a7ba",
            Output: "978dce955871945b6dc82b43254bd813174db51688c0493f5cd0654f732858cfbea99fe2eaf93fac483172f95a7494c6"),
        new(
            Input: "0a1d304356697c8fa2b5c8dbee0114273a4d60738699acbfd2e5f80b1e314457",
            Output: "da45ec168f8f31d90c9edc4610f87d0b6fbfc94a1b46e64d9985d289804d61cf14e29398b6df07256a7eea82b3e6acd0"
                + "981333263562c42593428ad258a2d527"),
        new(
            Input: "0f2235485b6e8194a7bacde0f306192c3f5265788b9eb1c4d7eafd102336495c6f8295a8bbcee1f4",
            Output: "18d71629c2364e31b1f0f35b954fd8eaa13f0f220af8f8f68630ce14ad21619c4bfeeb78b1d27d8ea87a22521ec66b88"
                + "0b680ce241a20dca4504b9e88ad3e9f945e453dbf665d15000f15e8a3b9ac00e"),
        new(
            Input: "14273a4d60738699acbfd2e5f80b1e3144576a7d90a3b6c9dcef0215283b4e6174879aadc0d3e6f90c1f3245586b7e91",
            Output: "73dfbff171d43a8fcb713e28ea32b414d66f88e10cda5181cc78655daf956da5980bf0e0754fdbdfd3e7f9735595d052"
                + "4e9fdf5e6ca594a883370f2278d6aaeda3058fcf3c4a0fc32a673f74a018b310600ed14fbeb6619e7f6a3d5c543182cb"),
        new(
            Input: "192c3f5265788b9eb1c4d7eafd102336495c6f8295a8bbcee1f4071a2d405366798c9fb2c5d8ebfe1124374a5d708396"
                + "a9bccfe2f5081b2e",
            Output: "22a4d7db0154c229ad703145d2216a0b23feb3533a1349cffbf65c770fd3b8f8c6e6312330c78d42c66af8ca4f0f860a"
                + "f4ac9b2974873c8f9c2d729405a8a86c752b2532856111de28d60e587a565576db6f25bdfb5b8fc1bd14405cdd451d34"
                + "bd775f073a87eb6d101a731d1129a36b"),
        new(
            Input: "1e3144576a7d90a3b6c9dcef0215283b4e6174879aadc0d3e6f90c1f3245586b7e91a4b7caddf00316293c4f6275889b"
                + "aec1d4e7fa0d203346596c7f92a5b8cb",
            Output: "a408e809a3d89115c1d01fb7ea6b74e77e48a32b80f94f5d24ebe3cd1c17ea7114532fb7c1e066f9774aa3f56893012a"
                + "19f983ef8ae639183689b1e2c584c402d8594b1c74c797e5dda7caec44582d900692a3c84643730ed6109cee334254a7"
                + "7db665610084e522ae2cf60d9fbf129318e2fcafdb0acdc6dd1e53be713e1104"),
        new(
            Input: "2336495c6f8295a8bbcee1f4071a2d405366798c9fb2c5d8ebfe1124374a5d708396a9bccfe2f5081b2e4154677a8da0"
                + "b3c6d9ecff1225384b5e718497aabdd0e3f6091c2f425568",
            Output: "58bf33942ce572cfca9eaf7ffd9629d55afa2dbadc56dd1282daafde37327a99185ffb00f38a83ea5bc98a722bed9c5d"
                + "ab64ddf51f5ab2364fd40bf05db337572036c32324ffac2d3980a2311d5f3a4c8a7b21d542e369d29fbb48ee68a8a398"
                + "c47a5098164fe78335c54408ddb07040531fa7a5bb92c986c3f27c3d58cc59b6e8f89907657186cae19e5647c26ffca6"),
        new(
            Input: "283b4e6174879aadc0d3e6f90c1f3245586b7e91a4b7caddf00316293c4f6275889baec1d4e7fa0d203346596c7f92a5"
                + "b8cbdef104172a3d506376899cafc2d5e8fb0e2134475a6d8093a6b9ccdff205",
            Output: "145218cd40db229f5a8582ba30f79ee9f0337e5fe82be46d4022c226f7dd8cdf1182ab6a6cf6017be32bfcc8d8a24385"
                + "f4c82d565c199a3d049cf65a7106ef1703f54c34d4408fde3078e591b4a88844327572901fa54fe679cc2633db9186c4"
                + "544b686c4caca5761c329097c24953d7cc1d71cacffa621bf18b92367473767e72bbbb6858af200155a4e55115d477ab"
                + "76dba2dcf74caba500027fbc0deafab9"),
        new(
            Input: "2d405366798c9fb2c5d8ebfe1124374a5d708396a9bccfe2f5081b2e4154677a8da0b3c6d9ecff1225384b5e718497aa"
                + "bdd0e3f6091c2f4255687b8ea1b4c7daed001326394c5f728598abbed1e4f70a1d304356697c8fa2",
            Output: "c58f9ec734ae4889ba25f78e479495c6c7c15bc962d4a04290655b62fb2e1a0bcf7691d47d110cd0faa654c8dde6b1c4"
                + "6090ebfb3b81e8853e7e570dbc66cd3dd360d94fba14d2353fe8acd183775675e8f22253d525a7c65709ad237d311cec"
                + "586f58c991630c274c693860cd9caa38649d7e326ee37054ff5db674562912a44c2621585ee1d2b77747a8e9ebcb7b31"
                + "d222236e3e53a2549a858b7d705862a6d89ca7eecae5d2afe409cb0f1a77394e"),
        new(
            Input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            Output: "69f07c8840ce80024db30939882c3d5bbc9c98b3e31e4513ebd2ca9b4503cdd3"),
        new(
            Input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
                + "303132333435363738393a3b3c3d3e3f",
            Output: "755e8863a2b2bc067f51c1637a71c819d524dc37c17ba7a29c6ee3767c996a49"),
        new(
            Input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
                + "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                + "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283848586",
            Output: "c45dae624ad8a2f5aa7bac9d7557737fd91c96eedb70a6be5574d57a844eade0"),
        new(
            Input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
                + "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                + "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384858687",
            Output: "b7ff4073b3f5a8eabd6e17705ca7f6761a31058f9df781a6a47e3a3063b9d67a"),
        new(
            Input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
                + "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                + "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788",
            Output: "01d90952c642a5eb2a8fc9d713f843a45d7ac05132dddcb2efc9bebc27e37bcb"),
        new(
            Input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
                + "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                + "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
                + "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                + "c0c1c2c3c4c5c6c7",
            Output: "4ee1ca03272b05d3bfb1e1c79a967f823b9fc5e4bb3987b1ba9e9cb5afb07a5e"),
        new(
            Input: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            Output: "69f07c8840ce80024db30939882c3d5bbc9c98b3e31e4513ebd2ca9b4503cdd3c9c90742452c7173d4a75ac49163e14e"
                + "e0cc24ef7035b272d19a7af1099b333f617465d69b5f5b78ae914e4a1b1cecc921f6d5791830ae3f914bee9b0292b288"
                + "337cecabc4be915f1453607bff6f0632ca7f3e8eab53456eba47300ad61fe0dcebf06c17e42bba3cdc"),
        new(
            Input: "2c424d337b8ee0ffe653810d56b1639853756756a28cc395f82a0e1f7f698a71",
            Output: "327ae31ed03fb2c40ad776fc9a7cf156d0f9cb1b5af92ab4f34c8d0644f0019c459d5c249c10bca14899d742f9d0c78b"
                + "a042aaa1c798116b338f0bd232a128ee692c40d1ae979f8d6e95c55ab4fd541e219a5fbf27db6a9aecfc757f2ce4a081"
                + "7a697145f59a15b24a142809fa130d398aaee6bde4d2a050fa1c0f9350d05ff7e202cdad0ca6a528890902e93fa3e6bc"
                + "2e0c70189a36ea5cc1759097f5ca3e01d0c53fc8877376b212702d5f98ca5c99b5b20dc6b20eb8e5a672ed5b68d4c7f1"
                + "ba40e5b47e76cd67f9711922ce9b638fe8c7002d296a724d9cd528d915d5a008f8e496266879f1a97ba7b1b9f8770ff8"
                + "f841ee9f0d35ab6e3f2cd4c2a92367ae1214baad1db171465dbc4da5bd7210e0")
    ];
}
