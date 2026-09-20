using System;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// Compresses two inputs into a single node-wide digest. This is the
/// two-to-one compression the binary Merkle tree applies at every internal
/// node: an internal node's digest is the hash of its two children's bytes
/// concatenated left-then-right. A scheme's leaf commitment reuses the same
/// compression to bring a committed value to node width.
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
/// For internal compression <paramref name="left"/> and
/// <paramref name="right"/> are both one node wide. A leaf commitment calls
/// the same compression with a value-wide <paramref name="left"/> and a
/// salt-wide or empty <paramref name="right"/>. Only
/// <paramref name="output"/> is defined to be the node width, and a wired
/// implementation must honour <c>output.Length</c> rather than assume its
/// own natural digest size. The implementation must not retain the spans
/// beyond the call.
/// </para>
/// </remarks>
/// <param name="left">The left input: a node for internal compression, the committed value for a leaf commitment.</param>
/// <param name="right">The right input: a node for internal compression, the salt — possibly empty — for a leaf commitment.</param>
/// <param name="output">The destination for the produced node; exactly the node width in length.</param>
public delegate void MerkleHashDelegate(
    ReadOnlySpan<byte> left,
    ReadOnlySpan<byte> right,
    Span<byte> output);
