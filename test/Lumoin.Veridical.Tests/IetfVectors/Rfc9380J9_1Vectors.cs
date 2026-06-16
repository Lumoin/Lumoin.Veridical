namespace Lumoin.Veridical.Tests.IetfVectors;

/// <summary>
/// The five RFC 9380 Appendix J.9.1 hash-to-curve vectors for
/// the suite <c>BLS12381G1_XMD:SHA-256_SSWU_RO_</c>, transcribed
/// verbatim from RFC 9380.
/// </summary>
/// <remarks>
/// <para>
/// Load-bearing byte-faithful gate: BBS+ generator derivation
/// reaches into this hash-to-curve suite, so any divergence here
/// would surface in every BBS+ Appendix A vector. Algebraic-
/// invariant tests (on-curve, in-subgroup) are necessary but not
/// sufficient — they did not catch the try-and-increment
/// divergence the BBS+.1 batch uncovered, because try-and-increment
/// also produces valid subgroup points.
/// </para>
/// <para>
/// The numbering matches the RFC's vector ordering (empty, "abc",
/// "abcdef0123456789", q128_, a512_); there are no gaps because
/// the RFC publishes exactly five vectors for this suite.
/// </para>
/// </remarks>
internal static class Rfc9380J9_1Vectors
{
    /// <summary>The suite identifier from the RFC §J.9.1 header.</summary>
    public const string Suite = "BLS12381G1_XMD:SHA-256_SSWU_RO_";

    /// <summary>The DST every vector in §J.9.1 uses, pinned at the section header.</summary>
    public const string Dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";


    /// <summary>Empty-message vector.</summary>
    public static Rfc9380J9_1Vector Vector001 { get; } = new(
        Id: "empty",
        Description: "Empty message.",
        MsgAscii: "",
        ExpectedCompressed: "852926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1");


    /// <summary>Three-byte ASCII message <c>"abc"</c>.</summary>
    public static Rfc9380J9_1Vector Vector002 { get; } = new(
        Id: "abc",
        Description: "Three-byte ASCII message.",
        MsgAscii: "abc",
        ExpectedCompressed: "83567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903");


    /// <summary>Sixteen-byte ASCII message <c>"abcdef0123456789"</c>.</summary>
    public static Rfc9380J9_1Vector Vector003 { get; } = new(
        Id: "abcdef0123456789",
        Description: "Sixteen-byte ASCII message.",
        MsgAscii: "abcdef0123456789",
        ExpectedCompressed: "91e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98");


    /// <summary>Long message: <c>"q128_"</c> followed by 128 <c>'q'</c> characters (total 133 bytes).</summary>
    public static Rfc9380J9_1Vector Vector004 { get; } = new(
        Id: "q128",
        Description: "Long message: 'q128_' followed by 128 'q' characters (total 133 bytes).",
        MsgAscii: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        ExpectedCompressed: "b5f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488");


    /// <summary>Very long message: <c>"a512_"</c> followed by 512 <c>'a'</c> characters (total 517 bytes).</summary>
    public static Rfc9380J9_1Vector Vector005 { get; } = new(
        Id: "a512",
        Description: "Very long message: 'a512_' followed by 512 'a' characters (total 517 bytes).",
        MsgAscii: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ExpectedCompressed: "882aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe");


    /// <summary>Every transcribed vector, in <see cref="Id"/> order, for <c>[DynamicData]</c> consumption.</summary>
    public static IReadOnlyList<Rfc9380J9_1Vector> All { get; } = new[]
    {
        Vector001, Vector002, Vector003, Vector004, Vector005,
    };
}