using Lumoin.Veridical.Core.Commitments.Ligero;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The standing state a <see cref="LongfellowZkProver"/> retains between its <c>commit</c> and <c>prove</c>
/// steps, the holder google/longfellow-zk's <c>ZkProver</c> keeps across <c>ZkProver::commit</c> and
/// <c>ZkProver::prove</c> (<c>lib/zk/zk_prover.h</c>): the standing Ligero commitment over
/// <c>[private inputs ‖ pad]</c>, the proof pad whose values decrypt the sumcheck transcript, the
/// per-layer claim-pad quadratic constraints (<c>setup_lqc</c>) the commitment binds, and the 32-byte
/// commitment root.
/// </summary>
/// <remarks>
/// <para>
/// The split mirrors the dual-field driver's need to commit BOTH circuits first, absorb both roots, squeeze
/// the shared MAC key, patch the public mac/av region, and only THEN finish both proofs — exactly the
/// <see cref="LongfellowZkVerifier.RecvCommitment"/> / <see cref="LongfellowZkVerifier.VerifyFromAbsorbedRoot"/>
/// shape on the verify side. <see cref="LongfellowZkProver.Commit"/> produces this holder (without absorbing
/// the root — the driver absorbs it); <see cref="LongfellowZkProver.ProveFromCommitment"/> consumes it.
/// </para>
/// <para>
/// Disposable and sensitive: it owns the commitment (the witness tableau and the per-leaf nonces) and the
/// pad (the transcript-decrypting randomness), and the pooled root, all released by <see cref="Dispose"/>.
/// </para>
/// </remarks>
internal sealed class LongfellowZkCommitment: IDisposable
{
    /// <summary>The byte width of the fixed-width commitment root.</summary>
    private const int DigestLength = 32;

    /// <summary>The owned, fixed-width commitment root.</summary>
    private IMemoryOwner<byte>? root;

    /// <summary>The owned standing Ligero commitment, surfaced by <see cref="Commitment"/> until disposed.</summary>
    private LongfellowLigeroCommitment? commitment;

    /// <summary>The owned proof pad, surfaced by <see cref="Pad"/> until disposed.</summary>
    private LongfellowProofPad? pad;


    /// <summary>Copies the root into the supplied pool and takes ownership of the commitment and pad on success.</summary>
    /// <remarks>A short root retains zero padding; a failed copy releases its rental.</remarks>
    internal LongfellowZkCommitment(LongfellowLigeroCommitment commitment, LongfellowProofPad pad, LigeroQuadraticConstraint[] quadraticConstraints, ReadOnlySpan<byte> root, BaseMemoryPool pool)
    {
        this.commitment = commitment;
        this.pad = pad;
        QuadraticConstraints = quadraticConstraints;
        IMemoryOwner<byte>? owner = pool.Rent(DigestLength);
        try
        {
            Span<byte> bytes = owner.Memory.Span[..DigestLength];
            bytes.Clear();
            root.CopyTo(bytes);
            this.root = owner;
            owner = null;
        }
        finally
        {
            owner?.Dispose();
        }
    }


    /// <summary>The standing Ligero commitment the prove step opens.</summary>
    internal LongfellowLigeroCommitment Commitment =>
        commitment ?? throw new ObjectDisposedException(nameof(LongfellowZkCommitment));

    /// <summary>The proof pad whose values decrypt the sumcheck transcript and feed the claim-pad quadratics.</summary>
    internal LongfellowProofPad Pad =>
        pad ?? throw new ObjectDisposedException(nameof(LongfellowZkCommitment));

    /// <summary>The per-layer claim-pad quadratic constraints (<c>setup_lqc</c>) the commitment binds.</summary>
    internal LigeroQuadraticConstraint[] QuadraticConstraints { get; }

    /// <summary>The 32-byte commitment root the driver absorbs (<c>recv_commitment</c>) before squeezing.</summary>
    /// <exception cref="ObjectDisposedException">The holder has released its pooled root.</exception>
    internal ReadOnlySpan<byte> RootSpan =>
        (root ?? throw new ObjectDisposedException(nameof(LongfellowZkCommitment))).Memory.Span[..DigestLength];


    /// <inheritdoc/>
    public void Dispose()
    {
        IMemoryOwner<byte>? localRoot = root;
        if(localRoot is not null)
        {
            root = null;
            localRoot.Dispose();
        }

        LongfellowLigeroCommitment? localCommitment = commitment;
        if(localCommitment is not null)
        {
            commitment = null;
            localCommitment.Dispose();
        }

        LongfellowProofPad? localPad = pad;
        if(localPad is not null)
        {
            pad = null;
            localPad.Dispose();
        }
    }
}
