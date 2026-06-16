using System;
using System.Buffers;
using System.Diagnostics;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// The statistical-ZK mask side of a <see cref="BaseFoldEvaluationProof"/>
/// (design <c>ZK-STATMASK-DESIGN.md</c> §2 v3): the sum-of-univariates
/// sumcheck mask's coefficient vector, extended by laundering filler, is
/// committed (salted and lifted) as <see cref="CommitmentRoot"/>; the mask sum
/// <c>σ</c> and the filler sum <c>σ_F</c> are precommitted alongside it before
/// the blend challenge <c>ρ</c>; and the terminal mask evaluation is bound by
/// <see cref="WeightedOpening"/> — a nested hiding weighted opening proving
/// <c>⟨C*, w⁺(r)⟩ = s(r) + σ_F</c> against the public weights the verifier
/// derives from the basis and its own challenges.
/// </summary>
/// <remarks>
/// The verifier never receives <c>s(r)</c>: it derives it from the masked
/// chain (<c>claim = f(r)·eq_z(r) + ρ·s(r)</c>) and checks the weighted
/// opening against <c>s(r) + σ_F</c>, so the mask section carries exactly one
/// root, two scalars, and the nested proof.
/// </remarks>
[DebuggerDisplay("BaseFoldMaskOpening (WeightedOpening d = {WeightedOpening.Parameters.LayerCount})")]
public sealed class BaseFoldMaskOpening: IDisposable
{
    private MerkleRoot? commitmentRoot;
    private IMemoryOwner<byte>? sigma;
    private IMemoryOwner<byte>? fillerSum;
    private BaseFoldEvaluationProof? weightedOpening;
    private readonly int scalarSize;


    internal BaseFoldMaskOpening(
        MerkleRoot commitmentRoot,
        IMemoryOwner<byte> sigma,
        IMemoryOwner<byte> fillerSum,
        int scalarSize,
        BaseFoldEvaluationProof weightedOpening)
    {
        this.commitmentRoot = commitmentRoot;
        this.sigma = sigma;
        this.fillerSum = fillerSum;
        this.scalarSize = scalarSize;
        this.weightedOpening = weightedOpening;
    }


    /// <summary>The Merkle root of the salted, lifted coefficient commitment <c>com(C*)</c>; absorbed before <c>ρ</c>.</summary>
    /// <exception cref="ObjectDisposedException">When the opening has been disposed.</exception>
    public MerkleRoot CommitmentRoot => commitmentRoot ?? throw new ObjectDisposedException(nameof(BaseFoldMaskOpening));

    /// <summary>The mask sum <c>σ = Σ_b s(b)</c> as canonical big-endian scalar bytes; absorbed before <c>ρ</c>.</summary>
    /// <exception cref="ObjectDisposedException">When the opening has been disposed.</exception>
    public ReadOnlySpan<byte> Sigma
    {
        get
        {
            IMemoryOwner<byte> local = sigma ?? throw new ObjectDisposedException(nameof(BaseFoldMaskOpening));
            return local.Memory.Span[..scalarSize];
        }
    }

    /// <summary>The filler sum <c>σ_F</c> as canonical big-endian scalar bytes; absorbed before <c>ρ</c> so the terminal claim <c>s(r) + σ_F</c> is fixed by the commitment.</summary>
    /// <exception cref="ObjectDisposedException">When the opening has been disposed.</exception>
    public ReadOnlySpan<byte> FillerSum
    {
        get
        {
            IMemoryOwner<byte> local = fillerSum ?? throw new ObjectDisposedException(nameof(BaseFoldMaskOpening));
            return local.Memory.Span[..scalarSize];
        }
    }

    /// <summary>The nested hiding weighted opening binding <c>⟨C*, w⁺(r)⟩ = s(r) + σ_F</c> against <see cref="CommitmentRoot"/>.</summary>
    /// <exception cref="ObjectDisposedException">When the opening has been disposed.</exception>
    public BaseFoldEvaluationProof WeightedOpening => weightedOpening ?? throw new ObjectDisposedException(nameof(BaseFoldMaskOpening));


    /// <inheritdoc/>
    public void Dispose()
    {
        commitmentRoot?.Dispose();
        commitmentRoot = null;

        IMemoryOwner<byte>? localSigma = sigma;
        if(localSigma is not null)
        {
            sigma = null;
            localSigma.Memory.Span[..scalarSize].Clear();
            localSigma.Dispose();
        }

        IMemoryOwner<byte>? localFillerSum = fillerSum;
        if(localFillerSum is not null)
        {
            fillerSum = null;
            localFillerSum.Memory.Span[..scalarSize].Clear();
            localFillerSum.Dispose();
        }

        weightedOpening?.Dispose();
        weightedOpening = null;
    }
}
