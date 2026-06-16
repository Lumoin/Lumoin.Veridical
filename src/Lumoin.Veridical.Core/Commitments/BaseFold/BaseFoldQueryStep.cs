using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// One layer's worth of a single BaseFold IOPP query: the two codeword entries
/// that share a fold pair at the queried position, each with its Merkle
/// authentication path against that layer's committed root. Folding these two
/// entries under the round's challenge yields the entry the next layer down
/// must contain at the same position — the consistency the verifier checks.
/// </summary>
/// <remarks>
/// <para>
/// The two entries are the layer-<see cref="Level"/> codeword values at the
/// queried position <c>p</c> and at <c>p + n_{level-1}</c> (BaseFold's Type-2
/// ordering, where fold partners are a half-layer apart). The verifier
/// authenticates each against the layer root using the leaf index it derives
/// itself from the squeezed query index, not from any value carried here, so a
/// malformed index cannot be smuggled in through the proof.
/// </para>
/// <para>
/// Disposable: clears the pair-value buffer and disposes the two paths. The
/// values are public (they are revealed in the proof), but the pooled
/// lifecycle is uniform with the rest of the library's cryptographic buffers.
/// </para>
/// </remarks>
[DebuggerDisplay("BaseFoldQueryStep (Level = {Level})")]
public sealed class BaseFoldQueryStep: IDisposable
{
    //A BaseFold fold pair is exactly two entries (the queried position and its
    //Type-2 partner a half-layer apart), so the value buffer — and, when hiding,
    //the salt buffer — holds two contiguous elements.
    private const int FoldPairEntryCount = 2;

    private IMemoryOwner<byte>? pairValues;
    private IMemoryOwner<byte>? pairSalts;
    private MerkleAuthenticationPath? firstPath;
    private MerkleAuthenticationPath? secondPath;
    private readonly int scalarSize;
    private readonly int saltSize;


    /// <summary>The layer this step folds from; in <c>[1, LayerCount]</c>. The fold produces a layer-<c>(Level-1)</c> entry.</summary>
    public int Level { get; }

    /// <summary>
    /// Whether this step carries leaf salts — true for a hiding (ZK BaseFold)
    /// opening, where the authenticated leaf is <c>hash(value ‖ salt)</c> rather
    /// than the value verbatim, false for the plain non-hiding opening.
    /// </summary>
    public bool IsSalted => pairSalts is not null;


    internal BaseFoldQueryStep(
        int level,
        IMemoryOwner<byte> pairValues,
        MerkleAuthenticationPath firstPath,
        MerkleAuthenticationPath secondPath,
        int scalarSize)
        : this(level, pairValues, pairSalts: null, firstPath, secondPath, scalarSize, saltSize: 0)
    {
    }


    internal BaseFoldQueryStep(
        int level,
        IMemoryOwner<byte> pairValues,
        IMemoryOwner<byte>? pairSalts,
        MerkleAuthenticationPath firstPath,
        MerkleAuthenticationPath secondPath,
        int scalarSize,
        int saltSize)
    {
        Level = level;
        this.pairValues = pairValues;
        this.pairSalts = pairSalts;
        this.firstPath = firstPath;
        this.secondPath = secondPath;
        this.scalarSize = scalarSize;
        this.saltSize = saltSize;
    }


    /// <summary>The codeword entry at the queried position <c>p</c> (the first of the fold pair).</summary>
    /// <exception cref="ObjectDisposedException">When the step has been disposed.</exception>
    public ReadOnlySpan<byte> First
    {
        get
        {
            IMemoryOwner<byte> local = pairValues ?? throw new ObjectDisposedException(nameof(BaseFoldQueryStep));
            return local.Memory.Span[..scalarSize];
        }
    }

    /// <summary>The codeword entry at <c>p + n_{level-1}</c> (the second of the fold pair).</summary>
    /// <exception cref="ObjectDisposedException">When the step has been disposed.</exception>
    public ReadOnlySpan<byte> Second
    {
        get
        {
            IMemoryOwner<byte> local = pairValues ?? throw new ObjectDisposedException(nameof(BaseFoldQueryStep));
            return local.Memory.Span.Slice(scalarSize, scalarSize);
        }
    }

    /// <summary>The salt of the first leaf — only valid when <see cref="IsSalted"/>; the authenticated leaf is <c>hash(First ‖ FirstSalt)</c>.</summary>
    /// <exception cref="ObjectDisposedException">When the step has been disposed.</exception>
    /// <exception cref="InvalidOperationException">When the step carries no salts.</exception>
    public ReadOnlySpan<byte> FirstSalt
    {
        get
        {
            IMemoryOwner<byte> local = pairSalts ?? throw SaltAbsent();
            return local.Memory.Span[..saltSize];
        }
    }

    /// <summary>The salt of the second leaf — only valid when <see cref="IsSalted"/>; the authenticated leaf is <c>hash(Second ‖ SecondSalt)</c>.</summary>
    /// <exception cref="ObjectDisposedException">When the step has been disposed.</exception>
    /// <exception cref="InvalidOperationException">When the step carries no salts.</exception>
    public ReadOnlySpan<byte> SecondSalt
    {
        get
        {
            IMemoryOwner<byte> local = pairSalts ?? throw SaltAbsent();
            return local.Memory.Span.Slice(saltSize, saltSize);
        }
    }

    /// <summary>The authentication path for <see cref="First"/> against the layer-<see cref="Level"/> root.</summary>
    /// <exception cref="ObjectDisposedException">When the step has been disposed.</exception>
    public MerkleAuthenticationPath FirstPath => firstPath ?? throw new ObjectDisposedException(nameof(BaseFoldQueryStep));

    /// <summary>The authentication path for <see cref="Second"/> against the layer-<see cref="Level"/> root.</summary>
    /// <exception cref="ObjectDisposedException">When the step has been disposed.</exception>
    public MerkleAuthenticationPath SecondPath => secondPath ?? throw new ObjectDisposedException(nameof(BaseFoldQueryStep));


    /// <summary>
    /// Builds a step by copying the two pair-value spans into a fresh pooled
    /// buffer and taking ownership of the two paths.
    /// </summary>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a value span is not one scalar wide.</exception>
    internal static BaseFoldQueryStep Create(
        int level,
        ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second,
        MerkleAuthenticationPath firstPath,
        MerkleAuthenticationPath secondPath,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(firstPath);
        ArgumentNullException.ThrowIfNull(secondPath);
        ArgumentNullException.ThrowIfNull(pool);

        if(first.Length != second.Length || first.Length == 0)
        {
            throw new ArgumentException("Both pair values must be the same non-zero scalar width.", nameof(first));
        }

        int scalarSize = first.Length;
        IMemoryOwner<byte> owner = pool.Rent(FoldPairEntryCount * scalarSize);
        first.CopyTo(owner.Memory.Span[..scalarSize]);
        second.CopyTo(owner.Memory.Span.Slice(scalarSize, scalarSize));

        return new BaseFoldQueryStep(level, owner, firstPath, secondPath, scalarSize);
    }


    /// <summary>
    /// Builds a hiding step that, alongside the two pair values and paths, copies
    /// the two leaf salts into a fresh pooled buffer. The authenticated leaf for
    /// each value is <c>hash(value ‖ salt)</c>, so the verifier needs the salt to
    /// recompute it.
    /// </summary>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a value span is not one scalar wide, or the two salt spans differ in width or are empty.</exception>
    internal static BaseFoldQueryStep CreateSalted(
        int level,
        ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second,
        ReadOnlySpan<byte> firstSalt,
        ReadOnlySpan<byte> secondSalt,
        MerkleAuthenticationPath firstPath,
        MerkleAuthenticationPath secondPath,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(firstPath);
        ArgumentNullException.ThrowIfNull(secondPath);
        ArgumentNullException.ThrowIfNull(pool);

        if(first.Length != second.Length || first.Length == 0)
        {
            throw new ArgumentException("Both pair values must be the same non-zero scalar width.", nameof(first));
        }

        if(firstSalt.Length != secondSalt.Length || firstSalt.Length == 0)
        {
            throw new ArgumentException("Both salts must be the same non-zero digest width.", nameof(firstSalt));
        }

        int scalarSize = first.Length;
        int saltSize = firstSalt.Length;

        IMemoryOwner<byte>? valuesOwner = pool.Rent(FoldPairEntryCount * scalarSize);
        IMemoryOwner<byte>? saltsOwner = null;
        try
        {
            first.CopyTo(valuesOwner.Memory.Span[..scalarSize]);
            second.CopyTo(valuesOwner.Memory.Span.Slice(scalarSize, scalarSize));

            saltsOwner = pool.Rent(FoldPairEntryCount * saltSize);
            firstSalt.CopyTo(saltsOwner.Memory.Span[..saltSize]);
            secondSalt.CopyTo(saltsOwner.Memory.Span.Slice(saltSize, saltSize));

            BaseFoldQueryStep step = new(level, valuesOwner!, saltsOwner, firstPath, secondPath, scalarSize, saltSize);
            saltsOwner = null;
            valuesOwner = null;

            return step;
        }
        finally
        {
            saltsOwner?.Dispose();
            valuesOwner?.Dispose();
        }
    }


    private static InvalidOperationException SaltAbsent()
    {
        return new InvalidOperationException("This query step carries no salts; it is a non-hiding opening.");
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        IMemoryOwner<byte>? localValues = pairValues;
        if(localValues is not null)
        {
            pairValues = null;
            try
            {
                localValues.Memory.Span[..(FoldPairEntryCount * scalarSize)].Clear();
                localValues.Dispose();
            }
            catch
            {
                //Disposal must not throw; an orphaned buffer beats a crash.
            }
        }

        IMemoryOwner<byte>? localSalts = pairSalts;
        if(localSalts is not null)
        {
            pairSalts = null;
            try
            {
                localSalts.Memory.Span[..(FoldPairEntryCount * saltSize)].Clear();
                localSalts.Dispose();
            }
            catch
            {
                //Disposal must not throw; an orphaned buffer beats a crash.
            }
        }

        firstPath?.Dispose();
        firstPath = null;
        secondPath?.Dispose();
        secondPath = null;
    }
}
