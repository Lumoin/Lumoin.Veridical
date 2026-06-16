using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// A BaseFold evaluation-protocol proof: an attestation that a committed
/// multilinear polynomial evaluates to a claimed value at a point. It bundles
/// the interleaved sumcheck's per-round polynomials with the BaseFold IOPP's
/// fold-layer commitments, cleartext base codeword, and per-query openings.
/// Together with the public commitment (the Merkle root of <c>π_d</c>), the
/// evaluation point, the claimed value, and the reconstructed foldable code,
/// this lets a verifier check the claimed evaluation.
/// </summary>
/// <remarks>
/// <para>
/// Layout, following Protocol 4 / Fig. 3 (Zeilberger, Chen, Fisch, CRYPTO 2024,
/// IACR ePrint 2023/1705):
/// </para>
/// <list type="bullet">
///   <item><description><see cref="RoundPolynomials"/>: the <c>d</c> compressed sumcheck round polynomials <c>h_d, h_{d-1}, …, h_1</c> in send order (<c>h_d</c> first). Each is the degree-2 polynomial of <c>f · eq_z</c> in that round's bound variable.</description></item>
///   <item><description><see cref="FoldRoots"/>: the Merkle roots of the folded codewords <c>π_{d-1}, …, π_1</c> in commit order. The input codeword's root <c>π_d</c> is the public commitment; the base codeword <c>π_0</c> is sent in the clear as <see cref="FinalOracle"/>.</description></item>
///   <item><description><see cref="FinalOracle"/>: the base-layer codeword <c>π_0</c> (<c>n_0 = c·k0</c> scalars) revealed so the verifier can check it is a valid base-code (repetition) word and tie it to the sumcheck's final claim.</description></item>
///   <item><description><see cref="Openings"/>: a jagged array indexed <c>[query][layerStep]</c>; layer step 0 is the top layer <c>d</c>, step <c>d-1</c> is layer 1.</description></item>
/// </list>
/// <para>
/// Disposable: disposes every round polynomial, every fold root, the
/// final-oracle buffer, and every query step.
/// </para>
/// </remarks>
[DebuggerDisplay("BaseFoldEvaluationProof (LayerCount = {Parameters.LayerCount}, QueryCount = {QueryCount})")]
public sealed class BaseFoldEvaluationProof: IDisposable
{
    private CompressedRoundPolynomial[]? roundPolynomials;
    private MerkleRoot[]? foldRoots;
    private IMemoryOwner<byte>? finalOracle;
    private BaseFoldQueryStep[][]? openings;
    private BaseFoldMaskOpening? mask;
    private readonly int finalOracleLengthBytes;


    /// <summary>The code parameters this proof was produced under.</summary>
    public FoldableCodeParameters Parameters { get; }

    /// <summary>The number of verifier queries (the IOPP repetition count).</summary>
    public int QueryCount { get; }


    internal BaseFoldEvaluationProof(
        FoldableCodeParameters parameters,
        int queryCount,
        CompressedRoundPolynomial[] roundPolynomials,
        MerkleRoot[] foldRoots,
        IMemoryOwner<byte> finalOracle,
        int finalOracleLengthBytes,
        BaseFoldQueryStep[][] openings)
        : this(parameters, queryCount, roundPolynomials, foldRoots, finalOracle, finalOracleLengthBytes, openings, mask: null)
    {
    }


    internal BaseFoldEvaluationProof(
        FoldableCodeParameters parameters,
        int queryCount,
        CompressedRoundPolynomial[] roundPolynomials,
        MerkleRoot[] foldRoots,
        IMemoryOwner<byte> finalOracle,
        int finalOracleLengthBytes,
        BaseFoldQueryStep[][] openings,
        BaseFoldMaskOpening? mask)
    {
        Parameters = parameters;
        QueryCount = queryCount;
        this.roundPolynomials = roundPolynomials;
        this.foldRoots = foldRoots;
        this.finalOracle = finalOracle;
        this.finalOracleLengthBytes = finalOracleLengthBytes;
        this.openings = openings;
        this.mask = mask;
    }


    /// <summary>
    /// The compressed sumcheck round polynomials in send order: index 0 is
    /// <c>h_d</c>, the last is <c>h_1</c>. Length is <c>LayerCount</c>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public IReadOnlyList<CompressedRoundPolynomial> RoundPolynomials =>
        roundPolynomials ?? throw new ObjectDisposedException(nameof(BaseFoldEvaluationProof));

    /// <summary>
    /// The fold-layer Merkle roots in commit order: index 0 is the root of
    /// <c>π_{d-1}</c>, the last is the root of <c>π_1</c>. Length is
    /// <c>LayerCount - 1</c>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public IReadOnlyList<MerkleRoot> FoldRoots => foldRoots ?? throw new ObjectDisposedException(nameof(BaseFoldEvaluationProof));

    /// <summary>The cleartext base-layer codeword <c>π_0</c>: <c>n_0 = c·k0</c> consecutive scalars.</summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public ReadOnlySpan<byte> FinalOracle
    {
        get
        {
            IMemoryOwner<byte> local = finalOracle ?? throw new ObjectDisposedException(nameof(BaseFoldEvaluationProof));
            return local.Memory.Span[..finalOracleLengthBytes];
        }
    }

    /// <summary>
    /// The per-query openings, indexed <c>[query][layerStep]</c>; layer step 0
    /// is the top layer <c>d</c>, step <c>LayerCount-1</c> is layer 1.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public IReadOnlyList<IReadOnlyList<BaseFoldQueryStep>> Openings =>
        openings ?? throw new ObjectDisposedException(nameof(BaseFoldEvaluationProof));

    /// <summary>
    /// The zero-knowledge mask side, present only for a
    /// <see cref="BaseFoldOpeningMode.ZeroKnowledge"/> opening; <see langword="null"/>
    /// for a <see cref="BaseFoldOpeningMode.Plain"/> or
    /// <see cref="BaseFoldOpeningMode.Hiding"/> opening.
    /// </summary>
    public BaseFoldMaskOpening? Mask => mask;


    /// <inheritdoc/>
    public void Dispose()
    {
        CompressedRoundPolynomial[]? localPolynomials = roundPolynomials;
        if(localPolynomials is not null)
        {
            roundPolynomials = null;
            foreach(CompressedRoundPolynomial polynomial in localPolynomials)
            {
                polynomial?.Dispose();
            }
        }

        MerkleRoot[]? localRoots = foldRoots;
        if(localRoots is not null)
        {
            foldRoots = null;
            foreach(MerkleRoot root in localRoots)
            {
                root?.Dispose();
            }
        }

        IMemoryOwner<byte>? localFinal = finalOracle;
        if(localFinal is not null)
        {
            finalOracle = null;
            try
            {
                localFinal.Memory.Span[..finalOracleLengthBytes].Clear();
                localFinal.Dispose();
            }
            catch
            {
                //Disposal must not throw; an orphaned buffer beats a crash.
            }
        }

        BaseFoldQueryStep[][]? localOpenings = openings;
        if(localOpenings is not null)
        {
            openings = null;
            foreach(BaseFoldQueryStep[] query in localOpenings)
            {
                foreach(BaseFoldQueryStep step in query)
                {
                    step?.Dispose();
                }
            }
        }

        BaseFoldMaskOpening? localMask = mask;
        if(localMask is not null)
        {
            mask = null;
            localMask.Dispose();
        }
    }
}
