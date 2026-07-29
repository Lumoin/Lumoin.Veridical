using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The systematic Reed–Solomon row interpolator over the FIPS 204 sextic circuit field
/// <c>F_q[x]/(x^6 − 7)</c>, a faithful port of google/longfellow-zk's
/// <c>lib/algebra/reed_solomon_extension.h</c> <c>ReedSolomonExtension6</c>: the evaluation points are the
/// consecutive integers of the base field, so the extension-field encode decomposes exactly into six
/// independent base-field encodes, one per polynomial coordinate, through one shared
/// <see cref="Fp24ReedSolomon"/> engine.
/// </summary>
/// <remarks>
/// In-place over a caller span of <c>m · 32</c> canonical scalars in the sextic layout (six 4-byte
/// big-endian limbs in the container's low 24 bytes, limb 0 least significant). The inputs are trusted
/// residues from the prover's own pipeline — the reference's <c>interpolate</c> validates nothing per
/// element either. The per-limb gather column is pool-rented and retained; rows of one shape are
/// extended sequentially, never concurrently.
/// </remarks>
[System.Diagnostics.DebuggerDisplay("Fp24 sextic RS (N={scalarEngine.Dimension}, M={scalarEngine.BlockLength})")]
internal sealed class Fp24SexticReedSolomon: IDisposable
{
    /// <summary>The canonical scalar container width each sextic element occupies in a row.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The sextic extension degree: six base-field coordinates per element (the sextic container layout places limb <c>d</c>'s 4 big-endian bytes at container offset <c>28 − 4d</c>).</summary>
    private const int LimbCount = 6;

    /// <summary>One base-field coordinate's width in bytes inside the canonical container.</summary>
    private const int LimbBytes = 4;

    /// <summary>The canonical container's leading zero bytes above the six coordinates.</summary>
    private const int ZeroPrefixBytes = ScalarSize - (LimbCount * LimbBytes);

    /// <summary>The shared base-field engine all six coordinates encode through (the reference constructs one <c>RSF::make(n, m)</c> for all coordinates).</summary>
    private readonly Fp24ReedSolomon scalarEngine;

    /// <summary>The pool the gather column rents from.</summary>
    private readonly BaseMemoryPool pool;

    /// <summary>The retained per-coordinate gather column (<c>m</c> residues); <see langword="null"/> once disposed.</summary>
    private IMemoryOwner<byte>? column;


    /// <summary>
    /// Builds the interpolator for the given dimensions.
    /// </summary>
    /// <param name="dimension">The number of input points <c>n</c> (≥ 1).</param>
    /// <param name="blockLength">The number of output points <c>m</c> (≥ <paramref name="dimension"/>).</param>
    /// <param name="pool">Pool the engine tables and the gather column rent from.</param>
    /// <exception cref="ArgumentNullException">When the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a dimension is out of range.</exception>
    public Fp24SexticReedSolomon(int dimension, int blockLength, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        this.pool = pool;
        scalarEngine = new Fp24ReedSolomon(dimension, blockLength, pool);
        try
        {
            column = pool.Rent(blockLength * sizeof(uint));
            ColumnSpan(column, blockLength).Clear();
        }
        catch
        {
            scalarEngine.Dispose();
            throw;
        }
    }


    /// <summary>The RS dimension (input evaluation count <c>n</c>).</summary>
    public int Dimension => scalarEngine.Dimension;

    /// <summary>The RS block length (output evaluation count <c>m</c>).</summary>
    public int BlockLength => scalarEngine.BlockLength;


    /// <summary>
    /// Extends the <c>n</c> input evaluations in the prefix of <paramref name="evaluations"/> to all
    /// <c>m</c> evaluations in place, coordinate by coordinate — the reference's
    /// <c>ReedSolomonExtension6::interpolate</c>. The first <c>n</c> containers are unchanged; the
    /// extension containers are fully written, including their zero prefix.
    /// </summary>
    /// <param name="evaluations"><c>m</c> canonical sextic scalars (<c>m · 32</c> bytes); the first <c>n</c> are the inputs.</param>
    /// <exception cref="ObjectDisposedException">When the interpolator has been disposed.</exception>
    /// <exception cref="ArgumentException">When the span is the wrong length.</exception>
    public void Interpolate(Span<byte> evaluations)
    {
        IMemoryOwner<byte> columnOwner = column ?? throw new ObjectDisposedException(nameof(Fp24SexticReedSolomon));
        int dimension = scalarEngine.Dimension;
        int blockLength = scalarEngine.BlockLength;
        if(evaluations.Length != blockLength * ScalarSize)
        {
            throw new ArgumentException($"The evaluation buffer must be {blockLength * ScalarSize} bytes; received {evaluations.Length}.", nameof(evaluations));
        }

        //The extension containers are rewritten limb by limb; their zero prefix is established once here
        //so a stale buffer tail cannot leak into the committed row.
        for(int k = dimension; k < blockLength; k++)
        {
            evaluations.Slice(k * ScalarSize, ZeroPrefixBytes).Clear();
        }

        Span<uint> columnValues = ColumnSpan(columnOwner, blockLength);
        for(int limb = 0; limb < LimbCount; limb++)
        {
            int offset = ScalarSize - LimbBytes - (limb * LimbBytes);
            for(int i = 0; i < dimension; i++)
            {
                columnValues[i] = BinaryPrimitives.ReadUInt32BigEndian(evaluations.Slice((i * ScalarSize) + offset, LimbBytes));
            }

            scalarEngine.Interpolate(columnValues);

            for(int k = dimension; k < blockLength; k++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(evaluations.Slice((k * ScalarSize) + offset, LimbBytes), columnValues[k]);
            }
        }

        columnValues.Clear();
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        IMemoryOwner<byte>? localColumn = column;
        if(localColumn is not null)
        {
            column = null;
            ColumnSpan(localColumn, scalarEngine.BlockLength).Clear();
            localColumn.Dispose();
        }

        scalarEngine.Dispose();
    }


    /// <summary>Views the pooled column rent as its leading <paramref name="count"/> base-field residues.</summary>
    /// <param name="owner">The pooled rent.</param>
    /// <param name="count">The number of residues.</param>
    /// <returns>The residue span.</returns>
    private static Span<uint> ColumnSpan(IMemoryOwner<byte> owner, int count) => MemoryMarshal.Cast<byte, uint>(owner.Memory.Span)[..count];
}
