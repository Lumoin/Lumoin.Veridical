using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// A BaseFold IOPP proof of proximity: the fold-layer Merkle roots, the
/// cleartext base-layer codeword, and one set of per-layer query openings for
/// each verifier query. Together with the public input commitment (the Merkle
/// root of the codeword being tested) and the reconstructed foldable code, this
/// lets a verifier check that the committed oracle is close to a codeword.
/// </summary>
/// <remarks>
/// <para>
/// Layout, following the standalone BaseFold IOPP (Zeilberger, Chen, Fisch,
/// CRYPTO 2024, IACR ePrint 2023/1705, Section 4):
/// </para>
/// <list type="bullet">
///   <item><description><see cref="FoldRoots"/>: the Merkle roots of the folded codewords <c>π_{d-1}, …, π_1</c> in commit order (<c>π_{d-1}</c> first). The input codeword's root <c>π_d</c> is the public commitment and is not carried here; the base codeword <c>π_0</c> is sent in the clear as <see cref="FinalOracle"/>.</description></item>
///   <item><description><see cref="FinalOracle"/>: the base-layer codeword <c>π_0</c> (<c>n_0 = c·k0</c> scalars) revealed in full so the verifier can check it is a valid base-code (repetition) codeword directly.</description></item>
///   <item><description><see cref="Openings"/>: a jagged array indexed <c>[query][layerStep]</c>. Each query contributes one <see cref="BaseFoldQueryStep"/> per layer, from the top layer <c>d</c> (step 0) down to layer <c>1</c> (step <c>d-1</c>).</description></item>
/// </list>
/// <para>
/// Disposable: disposes every fold root, the final-oracle buffer, and every
/// query step.
/// </para>
/// </remarks>
[DebuggerDisplay("BaseFoldIoppProof (LayerCount = {Parameters.LayerCount}, QueryCount = {QueryCount})")]
public sealed class BaseFoldIoppProof: IDisposable
{
    private MerkleRoot[]? foldRoots;
    private IMemoryOwner<byte>? finalOracle;
    private BaseFoldQueryStep[][]? openings;
    private readonly int finalOracleLengthBytes;


    /// <summary>The code parameters this proof was produced under.</summary>
    public FoldableCodeParameters Parameters { get; }

    /// <summary>The number of verifier queries (the repetition count).</summary>
    public int QueryCount { get; }


    internal BaseFoldIoppProof(
        FoldableCodeParameters parameters,
        int queryCount,
        MerkleRoot[] foldRoots,
        IMemoryOwner<byte> finalOracle,
        int finalOracleLengthBytes,
        BaseFoldQueryStep[][] openings)
    {
        Parameters = parameters;
        QueryCount = queryCount;
        this.foldRoots = foldRoots;
        this.finalOracle = finalOracle;
        this.finalOracleLengthBytes = finalOracleLengthBytes;
        this.openings = openings;
    }


    /// <summary>
    /// The fold-layer Merkle roots in commit order: index 0 is the root of
    /// <c>π_{d-1}</c>, the last is the root of <c>π_1</c>. Length is
    /// <c>LayerCount - 1</c>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public IReadOnlyList<MerkleRoot> FoldRoots => foldRoots ?? throw new ObjectDisposedException(nameof(BaseFoldIoppProof));

    /// <summary>The cleartext base-layer codeword <c>π_0</c>: <c>n_0 = c·k0</c> consecutive scalars.</summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public ReadOnlySpan<byte> FinalOracle
    {
        get
        {
            IMemoryOwner<byte> local = finalOracle ?? throw new ObjectDisposedException(nameof(BaseFoldIoppProof));
            return local.Memory.Span[..finalOracleLengthBytes];
        }
    }

    /// <summary>
    /// The per-query openings, indexed <c>[query][layerStep]</c>; layer step 0
    /// is the top layer <c>d</c>, step <c>LayerCount-1</c> is layer <c>1</c>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public IReadOnlyList<IReadOnlyList<BaseFoldQueryStep>> Openings =>
        openings ?? throw new ObjectDisposedException(nameof(BaseFoldIoppProof));


    /// <inheritdoc/>
    public void Dispose()
    {
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
    }
}
