using Lumoin.Veridical.Core.Commitments.Ligero;
using System;

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
/// pad (the transcript-decrypting randomness), so <see cref="Dispose"/> clears and releases both.
/// </para>
/// </remarks>
internal sealed class LongfellowZkCommitment: IDisposable
{
    private const int DigestLength = 32;

    private readonly byte[] root;

    private LongfellowLigeroCommitment? commitment;
    private LongfellowProofPad? pad;


    internal LongfellowZkCommitment(LongfellowLigeroCommitment commitment, LongfellowProofPad pad, LigeroQuadraticConstraint[] quadraticConstraints, ReadOnlySpan<byte> root)
    {
        this.commitment = commitment;
        this.pad = pad;
        QuadraticConstraints = quadraticConstraints;
        this.root = new byte[DigestLength];
        root.CopyTo(this.root);
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
    internal ReadOnlySpan<byte> RootSpan => root;


    /// <inheritdoc/>
    public void Dispose()
    {
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
