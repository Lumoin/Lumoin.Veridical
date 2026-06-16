using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// A wire-format-conformant Ligero proof, a faithful port of google/longfellow-zk's
/// <c>LigeroProof&lt;Field&gt;</c> (<c>lib/ligero/ligero_param.h</c>). It carries the three tests'
/// response rows, the opened-column elements, and the Merkle opening (per-leaf nonces plus the
/// compressed multi-proof path) — every field the reference's proof object holds, in the same shapes,
/// so the C.5 serializer can lay them into the ZkSpec envelope and a verifier can replay the flow.
/// </summary>
/// <remarks>
/// <para>
/// The members and sizes mirror the reference exactly:
/// </para>
/// <list type="bullet">
///   <item><description><see cref="LowDegreeResponse"/> (<c>y_ldt</c>): <c>block</c> field elements, the low-degree-test answer row.</description></item>
///   <item><description><see cref="DotResponse"/> (<c>y_dot</c>): <c>dblock</c> field elements, the linear (dot-product) answer row.</description></item>
///   <item><description><see cref="QuadraticResponseLow"/> (<c>y_quad_0</c>): <c>r</c> field elements, the first part of the quadratic answer row.</description></item>
///   <item><description><see cref="QuadraticResponseHigh"/> (<c>y_quad_2</c>): <c>dblock − block</c> field elements, the last part of the quadratic answer row. The middle <c>w</c> elements of <c>y_quad</c> are provably zero and not transmitted.</description></item>
///   <item><description><see cref="OpenedColumns"/> (<c>req</c>): a <c>nrow × nreq</c> row-major matrix; <c>req[i, j]</c> is row <c>i</c>'s element in the <c>j</c>-th opened column.</description></item>
///   <item><description><see cref="OpenedColumnIndices"/> (<c>idx</c>): the <c>nreq</c> distinct opened columns in <c>[0, block_ext)</c>, in selection order.</description></item>
///   <item><description><see cref="Nonces"/> (<c>merkle.nonce</c>): the <c>nreq</c> per-leaf nonces of the opened columns.</description></item>
///   <item><description><see cref="MerklePath"/> (<c>merkle.path</c>): the variable-length compressed multi-proof, in the reference's node-selection order.</description></item>
/// </list>
/// <para>
/// Disposable: the response and opened-column buffers and the Merkle path are pool-rented and cleared
/// on disposal. The response rows and opened columns are not secret (they are sent to the verifier),
/// but the proof is pooled by the library's default discipline.
/// </para>
/// </remarks>
internal sealed class LongfellowLigeroProof: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The reference's MerkleNonce::kLength and Digest::kLength: nonce and digest are 32 bytes.
    private const int NonceLength = 32;
    private const int DigestLength = 32;

    private IMemoryOwner<byte>? responseOwner;
    private IMemoryOwner<byte>? openedColumnsOwner;
    private IMemoryOwner<byte>? nonceOwner;
    private IMemoryOwner<byte>? merklePathOwner;
    private IMemoryOwner<byte>? indicesOwner;

    private readonly int block;
    private readonly int doubleBlock;
    private readonly int randomCount;
    private readonly int rowCount;
    private readonly int openedColumnCount;
    private readonly int merklePathLength;


    /// <summary>The layout the proof was produced for.</summary>
    public LongfellowLigeroParameters Parameters { get; }

    /// <summary>The low-degree-test response row <c>y_ldt</c>: <c>block</c> canonical scalars.</summary>
    public ReadOnlySpan<byte> LowDegreeResponse => Responses[..(block * ScalarSize)];

    /// <summary>The dot-product (linear) response row <c>y_dot</c>: <c>dblock</c> canonical scalars.</summary>
    public ReadOnlySpan<byte> DotResponse => Responses.Slice(block * ScalarSize, doubleBlock * ScalarSize);

    /// <summary>The first part of the quadratic response row <c>y_quad_0</c>: <c>r</c> canonical scalars.</summary>
    public ReadOnlySpan<byte> QuadraticResponseLow => Responses.Slice((block + doubleBlock) * ScalarSize, randomCount * ScalarSize);

    /// <summary>The last part of the quadratic response row <c>y_quad_2</c>: <c>dblock − block</c> canonical scalars.</summary>
    public ReadOnlySpan<byte> QuadraticResponseHigh => Responses[(((block + doubleBlock) * ScalarSize) + (randomCount * ScalarSize))..];

    /// <summary>The opened columns <c>req</c>, row-major <c>[nrow, nreq]</c> canonical scalars.</summary>
    public ReadOnlySpan<byte> OpenedColumns =>
        (openedColumnsOwner ?? throw new ObjectDisposedException(nameof(LongfellowLigeroProof))).Memory.Span[..(rowCount * openedColumnCount * ScalarSize)];

    /// <summary>The opened-column indices <c>idx</c>: <c>nreq</c> distinct columns in <c>[0, block_ext)</c>, in selection order.</summary>
    public ReadOnlySpan<int> OpenedColumnIndices =>
        MemoryMarshal.Cast<byte, int>((indicesOwner ?? throw new ObjectDisposedException(nameof(LongfellowLigeroProof))).Memory.Span[..(openedColumnCount * sizeof(int))]);

    /// <summary>The per-leaf nonces of the opened columns: <c>nreq</c> · 32 bytes.</summary>
    public ReadOnlySpan<byte> Nonces =>
        (nonceOwner ?? throw new ObjectDisposedException(nameof(LongfellowLigeroProof))).Memory.Span[..(openedColumnCount * NonceLength)];

    /// <summary>The compressed Merkle multi-proof path: <see cref="MerklePathLength"/> · 32 bytes, in selection order.</summary>
    public ReadOnlySpan<byte> MerklePath =>
        (merklePathOwner ?? throw new ObjectDisposedException(nameof(LongfellowLigeroProof))).Memory.Span[..(merklePathLength * DigestLength)];

    /// <summary>The number of digests in the compressed Merkle multi-proof.</summary>
    public int MerklePathLength => merklePathLength;


    /// <summary>Returns the element of opened-column row <paramref name="rowIndex"/> at opened slot <paramref name="slot"/>.</summary>
    public ReadOnlySpan<byte> OpenedColumnElement(int rowIndex, int slot) =>
        OpenedColumns.Slice(((rowIndex * openedColumnCount) + slot) * ScalarSize, ScalarSize);

    /// <summary>Returns the per-leaf nonce of opened slot <paramref name="slot"/>.</summary>
    public ReadOnlySpan<byte> Nonce(int slot) => Nonces.Slice(slot * NonceLength, NonceLength);

    /// <summary>Returns the <paramref name="index"/>-th compressed multi-proof digest.</summary>
    public ReadOnlySpan<byte> PathDigest(int index) => MerklePath.Slice(index * DigestLength, DigestLength);


    private Span<byte> Responses =>
        (responseOwner ?? throw new ObjectDisposedException(nameof(LongfellowLigeroProof))).Memory.Span[..ResponseBufferSize(Parameters)];


    internal LongfellowLigeroProof(
        LongfellowLigeroParameters parameters,
        IMemoryOwner<byte> responseOwner,
        IMemoryOwner<byte> openedColumnsOwner,
        IMemoryOwner<byte> indicesOwner,
        IMemoryOwner<byte> nonceOwner,
        IMemoryOwner<byte> merklePathOwner,
        int merklePathLength)
    {
        Parameters = parameters;
        this.responseOwner = responseOwner;
        this.openedColumnsOwner = openedColumnsOwner;
        this.indicesOwner = indicesOwner;
        this.nonceOwner = nonceOwner;
        this.merklePathOwner = merklePathOwner;
        this.merklePathLength = merklePathLength;

        block = parameters.Block;
        doubleBlock = parameters.DoubleBlock;
        randomCount = parameters.RandomCount;
        rowCount = parameters.RowCount;
        openedColumnCount = parameters.OpenedColumnCount;
    }


    /// <summary>
    /// The byte size of the packed response buffer holding <c>y_ldt | y_dot | y_quad_0 | y_quad_2</c>:
    /// <c>(block + dblock + r + (dblock − block)) · 32</c>.
    /// </summary>
    /// <param name="parameters">The layout the buffer is sized for.</param>
    internal static int ResponseBufferSize(LongfellowLigeroParameters parameters)
    {
        int low = parameters.Block;
        int dot = parameters.DoubleBlock;
        int quadLow = parameters.RandomCount;
        int quadHigh = parameters.DoubleBlock - parameters.Block;

        return (low + dot + quadLow + quadHigh) * ScalarSize;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        IMemoryOwner<byte>? localResponse = responseOwner;
        if(localResponse is not null)
        {
            responseOwner = null;
            localResponse.Memory.Span[..ResponseBufferSize(Parameters)].Clear();
            localResponse.Dispose();
        }

        IMemoryOwner<byte>? localColumns = openedColumnsOwner;
        if(localColumns is not null)
        {
            openedColumnsOwner = null;
            localColumns.Memory.Span[..(rowCount * openedColumnCount * ScalarSize)].Clear();
            localColumns.Dispose();
        }

        IMemoryOwner<byte>? localNonce = nonceOwner;
        if(localNonce is not null)
        {
            nonceOwner = null;
            localNonce.Memory.Span[..(openedColumnCount * NonceLength)].Clear();
            localNonce.Dispose();
        }

        IMemoryOwner<byte>? localPath = merklePathOwner;
        if(localPath is not null)
        {
            merklePathOwner = null;
            localPath.Memory.Span[..(merklePathLength * DigestLength)].Clear();
            localPath.Dispose();
        }

        IMemoryOwner<byte>? localIndices = indicesOwner;
        if(localIndices is not null)
        {
            indicesOwner = null;
            localIndices.Memory.Span[..(openedColumnCount * sizeof(int))].Clear();
            localIndices.Dispose();
        }
    }
}
