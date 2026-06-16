using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// A Ligero argument: the column commitment together with the prover's
/// low-degree, dot-product and quadratic responses and the opened columns with
/// their Merkle authentication paths. The verifier replays the Fiat-Shamir
/// schedule against the commitment, absorbs these responses, re-derives the
/// opened-column indices and checks the openings against the responses.
/// </summary>
/// <remarks>
/// <para>
/// The opened-column <em>indices</em> are not carried: they are a deterministic
/// function of the transcript (the commitment and the absorbed responses), so
/// the verifier re-derives them and pairs the <c>j</c>-th derived index with the
/// <c>j</c>-th opened column and path. This keeps the prover from choosing which
/// columns it opens.
/// </para>
/// <para>
/// Disposable: the response and opened-column buffers, the root and the paths
/// are all pooled or sensitive, so <see cref="Dispose"/> releases them. The
/// proof owns the <see cref="Root"/> copied out of the prover's tree, so it
/// stays valid after the tree is disposed.
/// </para>
/// </remarks>
[DebuggerDisplay("LigeroProof (RowCount = {Parameters.RowCount}, OpenedColumns = {Parameters.OpenedColumnCount})")]
public sealed class LigeroProof: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    private IMemoryOwner<byte>? responses;
    private IMemoryOwner<byte>? openedColumns;
    private MerkleRoot? root;
    private MerkleAuthenticationPath[]? paths;

    private readonly int dotOffsetBytes;
    private readonly int quadraticLowOffsetBytes;
    private readonly int quadraticHighOffsetBytes;
    private readonly int totalResponseBytes;


    /// <summary>The layout the proof was produced under.</summary>
    public LigeroParameters Parameters { get; }

    /// <summary>The column Merkle root — the commitment the responses are bound to.</summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public MerkleRoot Root => root ?? throw new ObjectDisposedException(nameof(LigeroProof));


    internal LigeroProof(
        LigeroParameters parameters,
        MerkleRoot root,
        IMemoryOwner<byte> responses,
        IMemoryOwner<byte> openedColumns,
        MerkleAuthenticationPath[] paths)
    {
        Parameters = parameters;
        this.root = root;
        this.responses = responses;
        this.openedColumns = openedColumns;
        this.paths = paths;

        //The response buffer packs y_ldt | y_dot | y_quad_0 | y_quad_2 back to
        //back; cache the section offsets so the accessors are slice-only.
        dotOffsetBytes = parameters.Block * ScalarSize;
        quadraticLowOffsetBytes = dotOffsetBytes + (parameters.DoubleBlock * ScalarSize);
        quadraticHighOffsetBytes = quadraticLowOffsetBytes + (parameters.RandomCount * ScalarSize);
        totalResponseBytes = quadraticHighOffsetBytes + ((parameters.DoubleBlock - parameters.Block) * ScalarSize);
    }


    /// <summary>The total byte length of the packed response buffer (<c>y_ldt | y_dot | y_quad_0 | y_quad_2</c>).</summary>
    internal static int ResponseBufferSize(LigeroParameters parameters) =>
        ((parameters.Block + parameters.DoubleBlock + parameters.RandomCount + (parameters.DoubleBlock - parameters.Block)) * ScalarSize);


    /// <summary>The low-degree-test response <c>y_ldt</c>: <see cref="LigeroParameters.Block"/> scalars.</summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public ReadOnlySpan<byte> LowDegreeResponse => ResponseSpan()[..dotOffsetBytes];

    /// <summary>The dot-product-test response <c>y_dot</c>: <see cref="LigeroParameters.DoubleBlock"/> scalars.</summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public ReadOnlySpan<byte> DotResponse => ResponseSpan()[dotOffsetBytes..quadraticLowOffsetBytes];

    /// <summary>The low half of the quadratic-test response <c>y_quad_0 = y_quad[0..r)</c>: <see cref="LigeroParameters.RandomCount"/> scalars.</summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public ReadOnlySpan<byte> QuadraticResponseLow => ResponseSpan()[quadraticLowOffsetBytes..quadraticHighOffsetBytes];

    /// <summary>The high half of the quadratic-test response <c>y_quad_2 = y_quad[block..dblock)</c>: <c>DoubleBlock − Block</c> scalars (the omitted witness block is zero).</summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public ReadOnlySpan<byte> QuadraticResponseHigh => ResponseSpan()[quadraticHighOffsetBytes..];

    /// <summary>The combined transmitted quadratic response <c>y_quad_0 ‖ y_quad_2</c>, in transcript-absorb order.</summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public ReadOnlySpan<byte> QuadraticResponse => ResponseSpan()[quadraticLowOffsetBytes..];


    /// <summary>
    /// The <paramref name="openedColumnIndex"/>-th opened column — one tableau
    /// entry per row, top to bottom (<see cref="LigeroParameters.RowCount"/>
    /// scalars), drawn in the verifier's index order.
    /// </summary>
    /// <param name="openedColumnIndex">The draw position in <c>[0, OpenedColumnCount)</c>.</param>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="openedColumnIndex"/> is out of range.</exception>
    public ReadOnlySpan<byte> OpenedColumn(int openedColumnIndex)
    {
        IMemoryOwner<byte> local = openedColumns ?? throw new ObjectDisposedException(nameof(LigeroProof));
        ArgumentOutOfRangeException.ThrowIfNegative(openedColumnIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(openedColumnIndex, Parameters.OpenedColumnCount);

        int columnBytes = Parameters.RowCount * ScalarSize;
        return local.Memory.Span.Slice(openedColumnIndex * columnBytes, columnBytes);
    }


    /// <summary>
    /// The Merkle authentication path for the <paramref name="openedColumnIndex"/>-th
    /// opened column, authenticating its committed leaf against <see cref="Root"/>.
    /// </summary>
    /// <param name="openedColumnIndex">The draw position in <c>[0, OpenedColumnCount)</c>.</param>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="openedColumnIndex"/> is out of range.</exception>
    public MerkleAuthenticationPath GetPath(int openedColumnIndex)
    {
        MerkleAuthenticationPath[] local = paths ?? throw new ObjectDisposedException(nameof(LigeroProof));
        ArgumentOutOfRangeException.ThrowIfNegative(openedColumnIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(openedColumnIndex, local.Length);

        return local[openedColumnIndex];
    }


    //The writable bytes of the j-th opened column. Internal so only the assembly
    //and its InternalsVisibleTo peers can mutate committed proof bytes — used by
    //a future deserialiser and by the tamper-rejection tests.
    internal Span<byte> OpenedColumnMutable(int openedColumnIndex)
    {
        IMemoryOwner<byte> local = openedColumns ?? throw new ObjectDisposedException(nameof(LigeroProof));
        ArgumentOutOfRangeException.ThrowIfNegative(openedColumnIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(openedColumnIndex, Parameters.OpenedColumnCount);

        int columnBytes = Parameters.RowCount * ScalarSize;
        return local.Memory.Span.Slice(openedColumnIndex * columnBytes, columnBytes);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(paths is not null)
        {
            foreach(MerkleAuthenticationPath path in paths)
            {
                path.Dispose();
            }

            paths = null;
        }

        root?.Dispose();
        root = null;

        ClearAndDispose(ref responses);
        ClearAndDispose(ref openedColumns);
    }


    private Span<byte> ResponseSpan()
    {
        IMemoryOwner<byte> local = responses ?? throw new ObjectDisposedException(nameof(LigeroProof));
        return local.Memory.Span[..totalResponseBytes];
    }


    private static void ClearAndDispose(ref IMemoryOwner<byte>? owner)
    {
        IMemoryOwner<byte>? local = owner;
        if(local is not null)
        {
            owner = null;
            try
            {
                local.Memory.Span.Clear();
                local.Dispose();
            }
            catch
            {
                //Disposal must not throw; an orphaned buffer is preferable to a crash.
            }
        }
    }
}
