using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// A random foldable linear code instance: the base code plus the random
/// diagonal matrices that define its <c>d</c> foldable layers. Encoding maps a
/// message of <c>k_d</c> field elements to a codeword of <c>n_d</c> elements;
/// folding collapses a codeword one layer at a time under a verifier
/// challenge.
/// </summary>
/// <remarks>
/// <para>
/// Implements the random foldable code of Zeilberger, Chen, Fisch (CRYPTO
/// 2024, IACR ePrint 2023/1705, Definition 9). The generator recursion is
/// <c>G_i = [[G_{i-1}, G_{i-1}·T_{i-1}], [G_{i-1}, -G_{i-1}·T_{i-1}]]</c>, with
/// each diagonal <c>T_{i-1}</c> holding <c>n_{i-1}</c> uniform non-zero field
/// entries. Structural inspiration only, no code dependency.
/// </para>
/// <para>
/// The diagonals are derived deterministically from a seed via hash-to-scalar,
/// so the same seed and parameters reproduce the same code — the verifier
/// reconstructs the identical code the prover committed under. The entries are
/// rejected and re-derived in the (cryptographically negligible) event that
/// hash-to-scalar yields the field zero, since the construction requires
/// non-zero diagonal entries.
/// </para>
/// <para>
/// The wired configuration is base dimension <c>k0 = 1</c>, whose base code is
/// the <c>[c, 1, c]</c> repetition code (an MDS code): <c>Enc_0(m)</c> repeats
/// the single message element <c>c</c> times. A general <c>k0 &gt; 1</c> base
/// code needs an explicit MDS generator matrix and is a separate addition, not
/// part of this configuration.
/// </para>
/// </remarks>
[DebuggerDisplay("FoldableCode (c = {Parameters.InverseRate}, k0 = {Parameters.BaseDimension}, d = {Parameters.LayerCount}, MessageLength = {Parameters.MessageLength})")]
public sealed class FoldableCode: IDisposable
{
    /// <summary>The canonical scalar width in bytes.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The maximum number of hash-to-scalar attempts per diagonal entry. A zero result has probability about 2^-254, so a single attempt all but always suffices; the bound only guards the loop.</summary>
    private const int MaximumDerivationAttempts = 8;

    /// <summary>The owned diagonal-entry storage, or null for a zero-layer code; cleared and released on disposal.</summary>
    private IMemoryOwner<byte>? diagonals;

    /// <summary>The total number of diagonal scalar entries across every layer.</summary>
    private int TotalDiagonalScalars { get; }

    /// <summary>The caller's pool, retained for lazy fold tables.</summary>
    private BaseMemoryPool Pool { get; }

    /// <summary>Whether the owned storage has been released.</summary>
    private bool isDisposed;

    /// <summary>
    /// The inverse-diagonal owner. It is published last, so once a caller
    /// observes this field non-null, <see cref="halfScalar"/> is guaranteed
    /// already published as well, and a concurrent first fold sees both
    /// tables fully populated.
    /// </summary>
    private OwnedByteBuffer? inverseDiagonals;
    /// <summary>
    /// The cached inverse-of-two owner. It is published before
    /// <see cref="inverseDiagonals"/>, which is what lets that field's
    /// visibility stand in for both tables being ready.
    /// </summary>
    private OwnedByteBuffer? halfScalar;

    /// <summary>Guards the one-time build of the fold acceleration tables against concurrent first folds.</summary>
    private object InverseBuildLock { get; } = new();


    /// <summary>The parameters defining this code.</summary>
    public FoldableCodeParameters Parameters { get; }


    /// <summary>Takes ownership of the diagonal storage and retains its pool for lazy tables.</summary>
    /// <param name="parameters">The code shape.</param>
    /// <param name="diagonals">The diagonal rental, or null for a zero-layer code.</param>
    /// <param name="totalDiagonalScalars">The logical diagonal element count.</param>
    /// <param name="pool">The caller's pool, which must outlive the code.</param>
    private FoldableCode(FoldableCodeParameters parameters, IMemoryOwner<byte>? diagonals, int totalDiagonalScalars, BaseMemoryPool pool)
    {
        Parameters = parameters;
        this.diagonals = diagonals;
        this.TotalDiagonalScalars = totalDiagonalScalars;
        this.Pool = pool;
    }


    /// <summary>
    /// Derives the code deterministically from <paramref name="seed"/>: every
    /// diagonal entry is a non-zero scalar produced by hash-to-scalar over the
    /// seed, the layer index, and the position index.
    /// </summary>
    /// <param name="parameters">The code shape. Base dimension must be 1 (the repetition base code).</param>
    /// <param name="seed">The seed binding this code; the same seed reproduces the same code.</param>
    /// <param name="hashToScalar">The hash-to-scalar backend that maps seed material to canonical scalars.</param>
    /// <param name="pool">The pool supplying diagonals and lazy fold tables; it must outlive the code.</param>
    /// <returns>The derived code; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="hashToScalar"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the base dimension is not 1.</exception>
    /// <exception cref="InvalidOperationException">When hash-to-scalar fails to produce a non-zero entry within the attempt bound.</exception>
    public static FoldableCode Derive(
        FoldableCodeParameters parameters,
        ReadOnlySpan<byte> seed,
        ScalarHashToScalarDelegate hashToScalar,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(pool);

        if(parameters.BaseDimension != 1)
        {
            throw new ArgumentException(
                $"This foldable code supports base dimension 1 (the repetition base code); received {parameters.BaseDimension}.",
                nameof(parameters));
        }

        CurveParameterSet curve = parameters.Curve;
        int c = parameters.InverseRate;
        int k0 = parameters.BaseDimension;
        int d = parameters.LayerCount;

        //Total diagonal entries across all d layers: layer i holds n_i =
        //c·k0·2^i entries, so the sum is c·k0·(2^d − 1).
        int totalScalars = checked((c * k0) * ((1 << d) - 1));

        int length = checked(totalScalars * ScalarSize);
        IMemoryOwner<byte>? owner = length == 0 ? null : pool.Rent(length);
        try
        {
            Span<byte> buffer = owner is null ? Span<byte>.Empty : owner.Memory.Span[..length];

            ReadOnlySpan<byte> dst = Encoding.ASCII.GetBytes(WellKnownFoldableCodeParameters.DiagonalDerivationDomainSeparationTag);
            Tag scalarTag = WellKnownAlgebraicTags.ScalarFor(curve);

            int scalarIndex = 0;
            for(int layer = 0; layer < d; layer++)
            {
                int layerLength = (c * k0) << layer;
                for(int position = 0; position < layerLength; position++)
                {
                    Span<byte> entry = buffer.Slice(scalarIndex * ScalarSize, ScalarSize);
                    DeriveNonZeroScalar(seed, layer, position, dst, curve, scalarTag, hashToScalar, entry);
                    scalarIndex++;
                }
            }

            FoldableCode code = new(parameters, owner, totalScalars, pool);
            owner = null;

            return code;
        }
        finally
        {
            owner?.Dispose();
        }
    }


    /// <summary>
    /// Returns the diagonal entries of layer <paramref name="layer"/> (the
    /// matrix <c>T_layer</c>): <c>n_layer = c · k0 · 2^layer</c> consecutive
    /// scalars. Layer <paramref name="layer"/> combines the two level-
    /// <paramref name="layer"/> encodings into a level-<c>(layer+1)</c> one.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When the code has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="layer"/> is outside <c>[0, LayerCount)</c>.</exception>
    /// <returns>A borrowed table view valid until code disposal.</returns>
    internal ReadOnlySpan<byte> GetDiagonal(int layer)
    {
        ObjectDisposedException.ThrowIf(isDisposed, this);
        IMemoryOwner<byte>? local = diagonals;
        ArgumentOutOfRangeException.ThrowIfNegative(layer);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(layer, Parameters.LayerCount);

        int baseUnit = Parameters.InverseRate * Parameters.BaseDimension;

        //Offset of layer i is the sum of all earlier layer lengths:
        //c·k0·(2^layer − 1) scalars.
        int offsetScalars = baseUnit * ((1 << layer) - 1);
        int lengthScalars = baseUnit << layer;

        return local!.Memory.Span.Slice(offsetScalars * ScalarSize, lengthScalars * ScalarSize);
    }


    /// <summary>
    /// Returns the elementwise inverses of layer <paramref name="layer"/>'s
    /// diagonal — same slicing as <see cref="GetDiagonal"/>. The caller must
    /// have run <see cref="EnsureFoldTablesBuilt"/> on this code first.
    /// </summary>
    /// <exception cref="InvalidOperationException">When the tables have not been built.</exception>
    /// <returns>A borrowed table view valid until code disposal.</returns>
    /// <exception cref="ObjectDisposedException">When the code has been disposed.</exception>
    internal ReadOnlySpan<byte> GetDiagonalInverse(int layer)
    {
        ObjectDisposedException.ThrowIf(isDisposed, this);
        OwnedByteBuffer local = Volatile.Read(ref inverseDiagonals)
            ?? throw new InvalidOperationException("The fold tables have not been built; call EnsureFoldTablesBuilt first.");
        ArgumentOutOfRangeException.ThrowIfNegative(layer);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(layer, Parameters.LayerCount);

        int baseUnit = Parameters.InverseRate * Parameters.BaseDimension;
        int offsetScalars = baseUnit * ((1 << layer) - 1);
        int lengthScalars = baseUnit << layer;

        return local.Bytes.Slice(offsetScalars * ScalarSize, lengthScalars * ScalarSize);
    }


    /// <summary>Returns the cached <c>2⁻¹</c>; requires <see cref="EnsureFoldTablesBuilt"/>.</summary>
    /// <exception cref="InvalidOperationException">When the tables have not been built.</exception>
    /// <returns>A borrowed scalar view valid until code disposal.</returns>
    /// <exception cref="ObjectDisposedException">When the code has been disposed.</exception>
    internal ReadOnlySpan<byte> GetHalfScalar()
    {
        ObjectDisposedException.ThrowIf(isDisposed, this);
        OwnedByteBuffer local = Volatile.Read(ref halfScalar)
            ?? throw new InvalidOperationException("The fold tables have not been built; call EnsureFoldTablesBuilt first.");

        return local.Bytes;
    }


    /// <summary>
    /// Builds the fold acceleration tables if not yet built: every diagonal
    /// entry's inverse via Montgomery batch inversion, and the constant
    /// <c>2⁻¹</c>. Idempotent and safe under concurrent first folds.
    /// </summary>
    /// <param name="multiply">The scalar multiplication backend.</param>
    /// <param name="invert">The scalar inversion backend.</param>
    /// <exception cref="ObjectDisposedException">When the code has been disposed.</exception>
    internal void EnsureFoldTablesBuilt(ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert)
    {
        ObjectDisposedException.ThrowIf(isDisposed, this);
        if(Volatile.Read(ref inverseDiagonals) is not null)
        {
            return;
        }

        lock(InverseBuildLock)
        {
            if(Volatile.Read(ref inverseDiagonals) is not null)
            {
                return;
            }

            ObjectDisposedException.ThrowIf(isDisposed, this);
            if(TotalDiagonalScalars == 0)
            {
                return;
            }

            IMemoryOwner<byte> local = diagonals!;
            ReadOnlySpan<byte> source = local.Memory.Span[..(TotalDiagonalScalars * ScalarSize)];
            CurveParameterSet curve = Parameters.Curve;

            //Montgomery batch inversion over the whole diagonal buffer (every
            //entry is non-zero by derivation): prefix products forward, one
            //inversion of the total, then walk back emitting each inverse.
            int length = checked(TotalDiagonalScalars * ScalarSize);
            OwnedByteBuffer? inversesOwner = OwnedByteBuffer.Rent(length, Pool);
            OwnedByteBuffer? halfOwner = null;
            try
            {
                Span<byte> inverses = inversesOwner.Bytes;
                using IMemoryOwner<byte> prefixesOwner = Pool.Rent(length);
                Span<byte> prefixes = prefixesOwner.Memory.Span[..length];
                source[..ScalarSize].CopyTo(prefixes);
                for(int i = 1; i < TotalDiagonalScalars; i++)
                {
                    multiply(
                        prefixes.Slice((i - 1) * ScalarSize, ScalarSize),
                        source.Slice(i * ScalarSize, ScalarSize),
                        prefixes.Slice(i * ScalarSize, ScalarSize),
                        curve);
                }

                Span<byte> running = stackalloc byte[ScalarSize];
                invert(prefixes.Slice((TotalDiagonalScalars - 1) * ScalarSize, ScalarSize), running, curve);
                for(int i = TotalDiagonalScalars - 1; i >= 1; i--)
                {
                    multiply(running, prefixes.Slice((i - 1) * ScalarSize, ScalarSize), inverses.Slice(i * ScalarSize, ScalarSize), curve);
                    multiply(running, source.Slice(i * ScalarSize, ScalarSize), running, curve);
                }

                running.CopyTo(inverses.Slice(0, ScalarSize));

                halfOwner = OwnedByteBuffer.Rent(ScalarSize, Pool);
                Span<byte> half = halfOwner.Bytes;
                half.Clear();
                half[^1] = 0x02;
                invert(half, half, curve);

                Volatile.Write(ref halfScalar, halfOwner);
                halfOwner = null;
                Volatile.Write(ref inverseDiagonals, inversesOwner);
                inversesOwner = null;
            }
            finally
            {
                halfOwner?.Dispose();
                inversesOwner?.Dispose();
            }
        }
    }


    /// <summary>Derives one non-zero diagonal entry by hash-to-scalar over the seed, layer, and position, retrying with a new attempt index on the cryptographically negligible zero result.</summary>
    /// <param name="seed">The code's derivation seed.</param>
    /// <param name="layer">The layer index.</param>
    /// <param name="position">The entry's position within the layer.</param>
    /// <param name="dst">The domain-separation tag bytes.</param>
    /// <param name="curve">The curve the scalar belongs to.</param>
    /// <param name="scalarTag">The algebraic tag for the produced scalar.</param>
    /// <param name="hashToScalar">The hash-to-scalar backend.</param>
    /// <param name="entry">Receives the derived non-zero scalar.</param>
    /// <exception cref="InvalidOperationException">When every attempt yields the field zero.</exception>
    private static void DeriveNonZeroScalar(
        ReadOnlySpan<byte> seed,
        int layer,
        int position,
        ReadOnlySpan<byte> dst,
        CurveParameterSet curve,
        Tag scalarTag,
        ScalarHashToScalarDelegate hashToScalar,
        Span<byte> entry)
    {
        //Derivation message: seed || layer || position || attempt, each index
        //a four-byte big-endian integer, so distinct positions map to
        //independent scalars and a rare zero can be retried with a new attempt.
        Span<byte> message = stackalloc byte[seed.Length + (3 * sizeof(int))];
        seed.CopyTo(message);
        BinaryPrimitives.WriteInt32BigEndian(message.Slice(seed.Length, sizeof(int)), layer);
        BinaryPrimitives.WriteInt32BigEndian(message.Slice(seed.Length + sizeof(int), sizeof(int)), position);

        for(int attempt = 0; attempt < MaximumDerivationAttempts; attempt++)
        {
            BinaryPrimitives.WriteInt32BigEndian(message.Slice(seed.Length + (2 * sizeof(int)), sizeof(int)), attempt);
            _ = hashToScalar(message, dst, entry, curve, scalarTag);

            if(entry.IndexOfAnyExcept((byte)0) >= 0)
            {
                return;
            }
        }

        throw new InvalidOperationException(
            "Hash-to-scalar produced the field zero on every attempt for a foldable-code diagonal entry; this is cryptographically implausible and indicates a backend fault.");
    }


    /// <summary>Clears and releases diagonal storage and any cached fold tables. Repeated disposal has no effect.</summary>
    /// <remarks>All folds and borrowed table reads must finish before disposal; concurrent disposal and use are unsupported.</remarks>
    public void Dispose()
    {
        lock(InverseBuildLock)
        {
            if(isDisposed)
            {
                return;
            }

            isDisposed = true;
            IMemoryOwner<byte>? local = diagonals;
            diagonals = null;
            inverseDiagonals?.Dispose();
            inverseDiagonals = null;
            halfScalar?.Dispose();
            halfScalar = null;
            if(local is not null)
            {
                try
                {
                    local.Memory.Span[..(TotalDiagonalScalars * ScalarSize)].Clear();
                    local.Dispose();
                }
                catch
                {
                    //Disposal must not throw; an orphaned buffer beats a crash.
                }
            }
        }
    }
}
