using Lumoin.Veridical.Bbs;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Bbs.IetfVectors;

/// <summary>
/// A single IETF Appendix A signature test vector for BBS+ Sign
/// and Verify. All byte-typed fields are lowercase hex strings.
/// </summary>
/// <param name="Id">A stable identifier for the vector — short, kebab-case, ciphersuite-prefixed.</param>
/// <param name="Description">Human-readable description copied from the upstream fixture's <c>caseName</c>.</param>
/// <param name="DraftSection">The IETF draft Appendix A section the vector comes from.</param>
/// <param name="SignerSecretKey">Hex of the signer's 32-byte secret key.</param>
/// <param name="SignerPublicKey">Hex of the signer's 96-byte public key.</param>
/// <param name="Header">Hex of the header bytes the signer bound into the signature. Empty for the "no header" case.</param>
/// <param name="Messages">Hex of each message in the signed vector, in signing order. Empty strings denote empty messages.</param>
/// <param name="Signature">Hex of the 80-byte signature. For <see cref="ExpectedValid"/> = <see langword="true"/> this is both the expected Sign output (byte-equality target) and the Verify input (returns true). For <see cref="ExpectedValid"/> = <see langword="false"/> this is only the Verify input (returns false); Sign is not called.</param>
/// <param name="ExpectedValid">Whether <see cref="Signature"/> is a valid signature under the listed inputs.</param>
/// <param name="InvalidReason">For <see cref="ExpectedValid"/> = <see langword="false"/>, the spec-text reason from the upstream fixture's <c>result.reason</c>. Null for valid vectors.</param>
internal sealed record BbsSignatureVector(
    string Id,
    string Description,
    string DraftSection,
    string SignerSecretKey,
    string SignerPublicKey,
    string Header,
    IReadOnlyList<string> Messages,
    string Signature,
    bool ExpectedValid,
    string? InvalidReason);