namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// Names the default Merkle commitment hash parameter set BaseFold uses to
/// commit to codewords: BLAKE3 in its 32-byte fixed-output mode, over a
/// binary tree.
/// </summary>
/// <remarks>
/// <para>
/// The Merkle infrastructure is hash-agnostic at the type level — the hash is
/// supplied by a <see cref="MerkleHashDelegate"/> the application wires, and a
/// tree's node digest size travels with the data rather than being pinned to
/// a static type. This class records the canonical default so that wiring code
/// and documentation reference one named parameter set rather than scattering
/// the literal sizes.
/// </para>
/// <para>
/// BLAKE3 is the default because it already ships in the codebase with
/// per-ISA backends and its 32-byte digest matches the scalar-field element
/// size of the wired curves, which keeps the codeword-commitment tree uniform
/// (every node, leaf or internal, is one digest wide).
/// </para>
/// </remarks>
public static class WellKnownMerkleHashParameters
{
    /// <summary>The default Merkle hash algorithm name. BLAKE3 in 32-byte fixed-output mode.</summary>
    public const string DefaultHashAlgorithm = WellKnownHashAlgorithms.Blake3;

    /// <summary>The default Merkle node digest size in bytes. BLAKE3 produces 32-byte digests.</summary>
    public const int DefaultDigestSizeBytes = WellKnownHashAlgorithms.Blake3DefaultSizeBytes;

    /// <summary>
    /// The Merkle tree arity. The construction is a binary tree: every internal
    /// node compresses exactly two children, so a codeword of length
    /// <c>2^k</c> yields a tree of depth <c>k</c>.
    /// </summary>
    public const int TreeArity = 2;

    /// <summary>
    /// The largest node digest size the verifier reserves stack space for when
    /// recomputing an authentication path. BLAKE3's 32 bytes fit comfortably;
    /// the bound leaves room for a wider hash without a heap allocation.
    /// </summary>
    public const int MaximumDigestSizeBytes = 64;
}
