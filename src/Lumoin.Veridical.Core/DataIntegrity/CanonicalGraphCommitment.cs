using Lumoin.Veridical.Core.Commitments.BaseFold;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Core.DataIntegrity;

/// <summary>
/// A binding Merkle commitment to the canonical quad set of an RDF document,
/// with per-quad membership proofs for selective disclosure. Canonicalization is
/// supplied by an injected <see cref="RdfCanonicalizeDelegate"/>; this type
/// content-addresses each opaque canonical quad and commits the set through
/// <see cref="MerkleSetCommitment"/> — the "tell a counterparty a subset of a
/// credential's statements, cryptographically bound to the whole, without
/// revealing the rest" primitive.
/// </summary>
/// <remarks>
/// <para>
/// A quad set is a set, not a map, so each canonical quad is committed as the
/// entry <c>(H(quad), H(quad))</c>: the key carries the sortable set identity and
/// the value mirrors it, since a bare quad has no separate payload. <c>H</c> is
/// SHA-256 over the canonical quad bytes; the tree's two-to-one compression is the
/// injected <see cref="MerkleHashDelegate"/>. Entries are ordered by digest and
/// deduplicated, the canonical set order the underlying commitment requires, so
/// the same graph always yields the same root.
/// </para>
/// <para>
/// The commitment is <b>binding, not hiding</b>: the leaves are unsalted, so a
/// verifier who can guess a low-entropy quad can test its membership. Disclosing a
/// subset reveals exactly those quads, each bound to the single root; the privacy
/// of the undisclosed quads rests on their own entropy, not on the commitment. A
/// hiding variant over salted leaves is a follow-on.
/// </para>
/// </remarks>
[DebuggerDisplay("CanonicalGraphCommitment (QuadCount = {QuadCount})")]
public sealed class CanonicalGraphCommitment: IDisposable
{
    //SHA-256 content addresses each quad; the wired tree digest is the same width.
    private const int DigestSizeBytes = 32;

    private MerkleTree? tree;
    private readonly ReadOnlyMemory<byte>[] sortedQuads;


    /// <summary>The number of distinct canonical quads committed.</summary>
    public int QuadCount => sortedQuads.Length;

    /// <summary>The set commitment: the root over the canonical quad set. Owned by this instance.</summary>
    /// <exception cref="ObjectDisposedException">When this commitment has been disposed.</exception>
    public MerkleRoot Root => (tree ?? throw new ObjectDisposedException(nameof(CanonicalGraphCommitment))).Root;


    private CanonicalGraphCommitment(MerkleTree tree, ReadOnlyMemory<byte>[] sortedQuads)
    {
        this.tree = tree;
        this.sortedQuads = sortedQuads;
    }


    /// <summary>
    /// Canonicalizes <paramref name="rdfDocument"/> through <paramref name="canonicalize"/>
    /// and commits the resulting quad set. The returned commitment's
    /// <see cref="Root"/> is the set commitment; keep it to produce membership
    /// proofs for a disclosed subset.
    /// </summary>
    /// <param name="rdfDocument">The RDF document to commit, as opaque bytes the delegate accepts.</param>
    /// <param name="canonicalize">The injected canonicalizer producing the canonical quad set.</param>
    /// <param name="treeHash">The two-to-one compression for the leaves and the tree.</param>
    /// <param name="pool">The pool to rent working buffers from.</param>
    /// <returns>The committed set; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the canonical quad set is empty.</exception>
    /// <exception cref="InvalidOperationException">When the delegate returns <see langword="null"/>.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The committed tree transfers ownership to the returned CanonicalGraphCommitment, which releases it through its own Dispose; the working buffers are disposed here.")]
    public static CanonicalGraphCommitment Commit(
        ReadOnlyMemory<byte> rdfDocument,
        RdfCanonicalizeDelegate canonicalize,
        MerkleHashDelegate treeHash,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(canonicalize);
        ArgumentNullException.ThrowIfNull(treeHash);
        ArgumentNullException.ThrowIfNull(pool);

        IReadOnlyList<ReadOnlyMemory<byte>> quads = canonicalize(rdfDocument)
            ?? throw new InvalidOperationException(
                "The canonicalization delegate returned null; it must return the canonical quad set.");

        int rawCount = quads.Count;
        if(rawCount == 0)
        {
            throw new ArgumentException(
                "The canonical quad set is empty; there is nothing to commit.", nameof(rdfDocument));
        }

        //Content-address every quad up front so the sort and the dedup compare
        //digests, not variable-length quads.
        using IMemoryOwner<byte> digestsOwner = pool.Rent(rawCount * DigestSizeBytes);
        Span<byte> digests = digestsOwner.Memory.Span[..(rawCount * DigestSizeBytes)];
        for(int i = 0; i < rawCount; i++)
        {
            HashQuad(quads[i].Span, digests.Slice(i * DigestSizeBytes, DigestSizeBytes));
        }

        //Order the quads by digest — the strictly-ascending canonical key order the
        //set commitment enforces. The comparison closes over the pooled owner and
        //slices fresh spans inside, so no ref struct is captured.
        using IMemoryOwner<byte> orderOwner = pool.Rent(rawCount * sizeof(int));
        Span<int> order = MemoryMarshal.Cast<byte, int>(orderOwner.Memory.Span)[..rawCount];
        for(int i = 0; i < rawCount; i++)
        {
            order[i] = i;
        }

        order.Sort((left, right) =>
            digestsOwner.Memory.Span.Slice(left * DigestSizeBytes, DigestSizeBytes)
                .SequenceCompareTo(digestsOwner.Memory.Span.Slice(right * DigestSizeBytes, DigestSizeBytes)));

        //A canonical quad set is already duplicate-free; the dedup keeps the
        //unique-key contract honest if the delegate returns repeats.
        int count = 0;
        for(int k = 0; k < rawCount; k++)
        {
            if(k == 0 || !DigestsEqual(digests, order[k - 1], order[k]))
            {
                count++;
            }
        }

        int entrySize = 2 * DigestSizeBytes;
        using IMemoryOwner<byte> entriesOwner = pool.Rent(count * entrySize);
        Span<byte> entries = entriesOwner.Memory.Span[..(count * entrySize)];
        ReadOnlyMemory<byte>[] sortedQuads = new ReadOnlyMemory<byte>[count];

        int next = 0;
        for(int k = 0; k < rawCount; k++)
        {
            if(k > 0 && DigestsEqual(digests, order[k - 1], order[k]))
            {
                continue;
            }

            int source = order[k];
            ReadOnlySpan<byte> digest = digests.Slice(source * DigestSizeBytes, DigestSizeBytes);
            Span<byte> entry = entries.Slice(next * entrySize, entrySize);
            digest.CopyTo(entry[..DigestSizeBytes]);
            digest.CopyTo(entry[DigestSizeBytes..]);
            sortedQuads[next] = quads[source];
            next++;
        }

        MerkleTree built = MerkleSetCommitment.Commit(entries, count, DigestSizeBytes, treeHash, pool);

        return new CanonicalGraphCommitment(built, sortedQuads);
    }


    /// <summary>
    /// Returns the canonical quad at <paramref name="index"/> in the committed
    /// (digest-ordered) set — the bytes a prover discloses for that position.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is outside <c>[0, QuadCount)</c>.</exception>
    public ReadOnlyMemory<byte> GetQuad(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, sortedQuads.Length);

        return sortedQuads[index];
    }


    /// <summary>
    /// Produces the membership proof of the quad at <paramref name="quadIndex"/>:
    /// its authentication path in the committed tree. A verifier additionally
    /// needs the quad bytes and the index.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ObjectDisposedException">When this commitment has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When the index is outside the tree's leaf range.</exception>
    public MerkleAuthenticationPath ProveMembership(int quadIndex, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        MerkleTree local = tree ?? throw new ObjectDisposedException(nameof(CanonicalGraphCommitment));

        return MerkleSetCommitment.ProveMembership(local, quadIndex, pool);
    }


    /// <summary>
    /// Verifies that <paramref name="canonicalQuad"/> is a member of the graph
    /// committed by <paramref name="root"/> at <paramref name="quadIndex"/>:
    /// content-addresses the quad and authenticates it under <paramref name="path"/>.
    /// Exception-safe against malformed inputs — a shape mismatch is a non-match.
    /// </summary>
    /// <returns><see langword="true"/> iff the disclosed quad authenticates against the committed root.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    public static bool VerifyMembership(
        MerkleRoot root,
        int quadIndex,
        ReadOnlySpan<byte> canonicalQuad,
        MerkleAuthenticationPath path,
        MerkleHashDelegate treeHash)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(treeHash);

        Span<byte> digest = stackalloc byte[DigestSizeBytes];
        HashQuad(canonicalQuad, digest);

        return MerkleSetCommitment.VerifyMembership(root, quadIndex, digest, digest, path, treeHash);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        tree?.Dispose();
        tree = null;
    }


    private static void HashQuad(ReadOnlySpan<byte> canonicalQuad, Span<byte> digest)
    {
        SHA256.HashData(canonicalQuad, digest);
    }


    private static bool DigestsEqual(ReadOnlySpan<byte> digests, int left, int right)
    {
        return digests.Slice(left * DigestSizeBytes, DigestSizeBytes)
            .SequenceEqual(digests.Slice(right * DigestSizeBytes, DigestSizeBytes));
    }
}
