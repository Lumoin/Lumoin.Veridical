using System;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// Compresses two equal-length inputs into a single digest. This is the
/// two-to-one compression the binary Merkle tree applies at every internal
/// node: an internal node's digest is the hash of its two children's bytes
/// concatenated left-then-right.
/// </summary>
/// <remarks>
/// <para>
/// The application wires a concrete hash here — the default for BaseFold is
/// BLAKE3 in its 32-byte fixed-output mode (see
/// <see cref="WellKnownMerkleHashParameters"/>), available through the
/// hashing backends. The delegate keeps the commitment infrastructure
/// hash-agnostic: BaseFold composes with any collision-resistant hash, and
/// the choice of which is the application's, made at wiring time exactly as
/// the curve and scalar backends are.
/// </para>
/// <para>
/// The construction follows the binary Merkle commitment BaseFold uses to
/// commit to a codeword (Zeilberger, Chen, Fisch, "BaseFold: Efficient
/// Field-Agnostic Polynomial Commitment Schemes from Foldable Codes", CRYPTO
/// 2024, IACR ePrint 2023/1705); structural inspiration only, no code
/// dependency. As in the reference, there is no domain separation between
/// leaf and internal-node hashing: every node digest is the two-to-one
/// compression of its children, and the leaves are the codeword position
/// values themselves.
/// </para>
/// <para>
/// <paramref name="left"/> and <paramref name="right"/> have the same length
/// (the node digest size); <paramref name="output"/> is exactly the digest
/// size. The implementation must not retain the spans beyond the call.
/// </para>
/// </remarks>
/// <param name="left">The left child's bytes.</param>
/// <param name="right">The right child's bytes.</param>
/// <param name="output">The destination for the parent digest; exactly the digest size in length.</param>
public delegate void MerkleHashDelegate(
    ReadOnlySpan<byte> left,
    ReadOnlySpan<byte> right,
    Span<byte> output);
