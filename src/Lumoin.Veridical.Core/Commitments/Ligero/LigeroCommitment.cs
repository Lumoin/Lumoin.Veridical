using Lumoin.Veridical.Core.Commitments.BaseFold;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// A standing Ligero commitment: the built tableau, its Merkle tree over the extension columns,
/// and the witness and quadratic constraints it was built over. Produced by
/// <see cref="LigeroProver.Commit"/> so the commit and the prove can be separate steps — a
/// commit-then-challenge protocol absorbs <see cref="Root"/> first and proves constraints that
/// depend on later challenges from the same tableau, without rebuilding and re-encoding it.
/// </summary>
/// <remarks>
/// Disposable and sensitive: the tableau holds the witness values and the prover's blinding
/// randomness, and the commitment retains a copy of the witness vector (for the prove-time
/// constraint satisfaction check), so <see cref="Dispose"/> clears and releases all of it.
/// </remarks>
public sealed class LigeroCommitment: IDisposable
{
    private readonly LigeroTableau tableau;
    private readonly MerkleTree tree;
    private readonly LigeroQuadraticConstraint[] quadraticConstraints;
    private IMemoryOwner<byte>? witnessOwner;
    private readonly int witnessLength;


    /// <summary>The layout the tableau was built to.</summary>
    public LigeroParameters Parameters { get; }

    /// <summary>The Merkle root over the tableau's extension columns — the commitment value.</summary>
    public MerkleRoot Root => tree.Root;

    internal string HashAlgorithm { get; }

    internal LigeroTableau Tableau => tableau;

    internal MerkleTree Tree => tree;

    internal ReadOnlySpan<LigeroQuadraticConstraint> QuadraticConstraints => quadraticConstraints;

    internal ReadOnlySpan<byte> Witnesses =>
        (witnessOwner ?? throw new ObjectDisposedException(nameof(LigeroCommitment))).Memory.Span[..witnessLength];


    internal LigeroCommitment(
        LigeroParameters parameters,
        LigeroTableau tableau,
        MerkleTree tree,
        IMemoryOwner<byte> witnessOwner,
        int witnessLength,
        LigeroQuadraticConstraint[] quadraticConstraints,
        string hashAlgorithm)
    {
        Parameters = parameters;
        this.tableau = tableau;
        this.tree = tree;
        this.witnessOwner = witnessOwner;
        this.witnessLength = witnessLength;
        this.quadraticConstraints = quadraticConstraints;
        HashAlgorithm = hashAlgorithm;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        IMemoryOwner<byte>? local = witnessOwner;
        if(local is not null)
        {
            witnessOwner = null;
            local.Memory.Span[..witnessLength].Clear();
            local.Dispose();
        }

        tree.Dispose();
        tableau.Dispose();
    }
}
