using System;

namespace Lumoin.Veridical.Hashing;

/// <summary>
/// A single per-ISA SHA-256 backend, carrying the one block-compression
/// delegate that folds a 64-byte message block into the eight-word
/// chaining state. Mirrors <see cref="Blake3Backend"/>, minus the
/// many-chunks delegate: SHA-256's Merkle-Damgard construction is strictly
/// sequential, so there is no chunk-parallel path to bundle.
/// </summary>
/// <remarks>
/// <para>
/// Construct via the factory on the backend class
/// (<see cref="Internal.Sha256PortableBackend"/>) or via
/// <see cref="Internal.Sha256BackendSelection.SelectBest"/> for runtime
/// auto-selection.
/// </para>
/// </remarks>
public readonly struct Sha256Backend: IEquatable<Sha256Backend>
{
    /// <summary>The block-compression delegate used to fold each 64-byte block into the state.</summary>
    public Sha256CompressionDelegate Compression { get; }


    /// <summary>Constructs a backend bundle. Internal because backends construct themselves via their static factories.</summary>
    internal Sha256Backend(Sha256CompressionDelegate compression)
    {
        ArgumentNullException.ThrowIfNull(compression);

        Compression = compression;
    }


    /// <inheritdoc/>
    public bool Equals(Sha256Backend other) => Compression == other.Compression;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is Sha256Backend other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => Compression.GetHashCode();

    /// <inheritdoc/>
    public static bool operator ==(Sha256Backend left, Sha256Backend right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(Sha256Backend left, Sha256Backend right) => !left.Equals(right);
}
