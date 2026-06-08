using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors;

/// <summary>
/// A single hash-to-scalar primitive test vector exercising the
/// ciphersuite's <c>hash_to_scalar</c> delegate per IETF
/// <c>draft-irtf-cfrg-bbs-signatures-10</c> Section 4.2. All
/// byte-typed fields are lowercase hex strings; tests decode them
/// via <see cref="System.Convert.FromHexString(string)"/> at
/// consumption time so the byte arrays land in pool-rented buffers
/// inside the operation under test.
/// </summary>
/// <param name="Id">A stable identifier for the vector — short, kebab-case, ciphersuite-prefixed.</param>
/// <param name="Description">Human-readable description copied from the upstream fixture's <c>caseName</c>.</param>
/// <param name="Message">Hex of the input message bytes.</param>
/// <param name="Dst">Hex of <c>api_id || H2S_</c>, the DST the ciphersuite uses for <c>hash_to_scalar</c>. Recorded per-vector to keep the case self-contained.</param>
/// <param name="ExpectedScalar">Hex of the expected 32-byte canonical big-endian scalar.</param>
internal sealed record HashToScalarVector(
    string Id,
    string Description,
    string Message,
    string Dst,
    string ExpectedScalar);