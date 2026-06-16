using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors;

/// <summary>
/// A single IETF Appendix A KeyGen test vector for BBS+. All
/// byte-typed fields are lowercase hex strings; tests decode them
/// via <see cref="System.Convert.FromHexString(string)"/> at
/// consumption time so the byte arrays land in pool-rented buffers
/// inside the operation under test.
/// </summary>
/// <param name="Id">A stable identifier for the vector — short, kebab-case, ciphersuite-prefixed.</param>
/// <param name="Description">Human-readable description copied from the upstream fixture's <c>caseName</c>.</param>
/// <param name="DraftSection">The IETF draft Appendix A section the vector comes from (for example <c>"8.4.1"</c>).</param>
/// <param name="KeyMaterial">Hex of the secret entropy bytes passed to KeyGen.</param>
/// <param name="KeyInfo">Hex of the optional key-info string. Empty for vectors that use the default empty key info.</param>
/// <param name="KeyDst">Hex of <c>api_id || KEYGEN_DST_</c>, the DST passed to <c>hash_to_scalar</c> inside KeyGen. Recorded per-vector to keep the case self-contained even though the value is fixed per ciphersuite.</param>
/// <param name="ExpectedSecretKey">Hex of the expected 32-byte canonical big-endian secret-key scalar.</param>
/// <param name="ExpectedPublicKey">Hex of the expected 96-byte canonical compressed G2 public-key encoding.</param>
internal sealed record BbsKeyGenVector(
    string Id,
    string Description,
    string DraftSection,
    string KeyMaterial,
    string KeyInfo,
    string KeyDst,
    string ExpectedSecretKey,
    string ExpectedPublicKey);