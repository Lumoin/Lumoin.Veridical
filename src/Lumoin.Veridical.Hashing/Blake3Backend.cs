using System;

namespace Lumoin.Veridical.Hashing;

/// <summary>
/// A bundle of BLAKE3 compression delegates that implement a single
/// per-ISA backend. The single-compression delegate is the fallback for
/// per-block work that does not benefit from chunk parallelism (the
/// partial tail block, parent nodes, root XOF expansion). The
/// many-chunks delegate carries the parallel chunk path; its
/// <see cref="ManyChunksBatchSize"/> indicates the natural batch the
/// backend operates on.
/// </summary>
/// <remarks>
/// <para>
/// Construct via the factories on the backend classes
/// (<see cref="Internal.Blake3PortableBackend"/>,
/// <see cref="Internal.Blake3Avx2Backend"/>,
/// <see cref="Internal.Blake3Avx512Backend"/>,
/// <see cref="Internal.Blake3NeonBackend"/>) or via
/// <see cref="Internal.Blake3BackendSelection.SelectBest"/> for runtime
/// auto-selection.
/// </para>
/// </remarks>
public readonly struct Blake3Backend: IEquatable<Blake3Backend>
{
    /// <summary>The single-compression delegate used for per-block work.</summary>
    public Blake3CompressionDelegate Compression { get; }

    /// <summary>The chunk-parallel delegate that hashes a contiguous run of full chunks.</summary>
    public Blake3ManyChunksDelegate ManyChunks { get; }

    /// <summary>
    /// The chunk count this backend processes per parallel batch
    /// (8 for AVX2, 16 for AVX-512, 4 for NEON, 1 for the portable
    /// scalar baseline). <see cref="ManyChunks"/> still accepts any
    /// chunk count; the value indicates the granularity at which the
    /// backend's SIMD parallelism is realised.
    /// </summary>
    public int ManyChunksBatchSize { get; }


    /// <summary>Constructs a backend bundle. Internal because backends construct themselves via their static factories.</summary>
    internal Blake3Backend(
        Blake3CompressionDelegate compression,
        Blake3ManyChunksDelegate manyChunks,
        int manyChunksBatchSize)
    {
        ArgumentNullException.ThrowIfNull(compression);
        ArgumentNullException.ThrowIfNull(manyChunks);
        ArgumentOutOfRangeException.ThrowIfLessThan(manyChunksBatchSize, 1);

        Compression = compression;
        ManyChunks = manyChunks;
        ManyChunksBatchSize = manyChunksBatchSize;
    }


    /// <inheritdoc/>
    public bool Equals(Blake3Backend other) =>
        Compression == other.Compression
        && ManyChunks == other.ManyChunks
        && ManyChunksBatchSize == other.ManyChunksBatchSize;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is Blake3Backend other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(Compression, ManyChunks, ManyChunksBatchSize);

    /// <inheritdoc/>
    public static bool operator ==(Blake3Backend left, Blake3Backend right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(Blake3Backend left, Blake3Backend right) => !left.Equals(right);
}