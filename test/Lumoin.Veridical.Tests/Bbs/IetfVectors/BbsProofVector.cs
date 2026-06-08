using Lumoin.Veridical.Bbs;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Bbs.IetfVectors;

/// <summary>
/// A single IETF Appendix A proof test vector for BBS+
/// GenerateProof and VerifyProof. All byte-typed fields are
/// lowercase hex strings.
/// </summary>
/// <param name="Id">A stable identifier for the vector — short, kebab-case, ciphersuite-prefixed.</param>
/// <param name="Description">Human-readable description copied from the upstream fixture's <c>caseName</c>.</param>
/// <param name="DraftSection">The IETF draft Appendix A section the vector comes from.</param>
/// <param name="SignerPublicKey">Hex of the signer's 96-byte public key.</param>
/// <param name="Signature">Hex of the 80-byte signature the proof is constructed against (input to GenerateProof; not byte-checked by these tests).</param>
/// <param name="Header">Hex of the header bytes the signer bound into the signature.</param>
/// <param name="PresentationHeader">Hex of the presentation-header bytes the Prover binds into this proof.</param>
/// <param name="Messages">Hex of each message in the signed vector, in signing order.</param>
/// <param name="DisclosedIndexes">The indices of disclosed messages (strictly ascending, in <c>[0, Messages.Count)</c>).</param>
/// <param name="Seed">Hex of the seed fed into <c>BbsDeterministicScalars.FromSeed</c> to reproduce the proof's random scalars deterministically. Set to the canonical IETF pi-prefix seed per Section 7.4 (the same value for both ciphersuites; recorded per-vector to keep the case self-contained).</param>
/// <param name="Proof">Hex of the proof bytes. For <see cref="ExpectedValid"/> = <see langword="true"/> this is both the expected GenerateProof output (byte-equality target) and the VerifyProof input (returns true). For <see cref="ExpectedValid"/> = <see langword="false"/> this is only the VerifyProof input (returns false); GenerateProof is not called.</param>
/// <param name="ExpectedValid">Whether <see cref="Proof"/> is a valid proof under the listed inputs.</param>
/// <param name="InvalidReason">For <see cref="ExpectedValid"/> = <see langword="false"/>, the spec-text reason from the upstream fixture's <c>result.reason</c>. Null for valid vectors.</param>
internal sealed record BbsProofVector(
    string Id,
    string Description,
    string DraftSection,
    string SignerPublicKey,
    string Signature,
    string Header,
    string PresentationHeader,
    IReadOnlyList<string> Messages,
    IReadOnlyList<int> DisclosedIndexes,
    string Seed,
    string Proof,
    bool ExpectedValid,
    string? InvalidReason);