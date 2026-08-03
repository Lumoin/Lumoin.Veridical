using Lumoin.Veridical.Core.Commitments.BaseFold;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// One WHIR query opening: the <c>2^k</c> coset values a query reads from an
/// oracle as a single symbol, plus the Merkle authentication path of the
/// coset's leaf. The leaf digest itself is recomputed from the values by the
/// verifier, so it does not travel.
/// </summary>
public sealed class WhirQueryOpening: IDisposable
{
    private IMemoryOwner<byte>? valuesOwner;
    private readonly int valuesLength;


    /// <summary>The authentication path of the coset leaf against the oracle's root.</summary>
    public MerkleAuthenticationPath Path { get; }

    /// <summary>The queried coset values in block order, <c>2^k</c> elements.</summary>
    /// <exception cref="ObjectDisposedException">When the opening has been disposed.</exception>
    public ReadOnlyMemory<byte> BlockValues =>
        (valuesOwner ?? throw new ObjectDisposedException(nameof(WhirQueryOpening))).Memory[..valuesLength];


    /// <summary>
    /// Wraps a values buffer and a path into an opening. The opening takes
    /// ownership of both.
    /// </summary>
    /// <param name="valuesOwner">The pool-rented coset values.</param>
    /// <param name="valuesLength">The logical byte length of the values.</param>
    /// <param name="path">The leaf's authentication path.</param>
    internal WhirQueryOpening(IMemoryOwner<byte> valuesOwner, int valuesLength, MerkleAuthenticationPath path)
    {
        this.valuesOwner = valuesOwner;
        this.valuesLength = valuesLength;
        Path = path;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        //The pool zeroes rented buffers on return, so no explicit scrub is
        //needed for the witness-derived values.
        IMemoryOwner<byte>? local = valuesOwner;
        if(local is not null)
        {
            valuesOwner = null;
            local.Dispose();
        }

        Path.Dispose();
    }
}
