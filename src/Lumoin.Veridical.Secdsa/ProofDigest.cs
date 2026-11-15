using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// A 32-byte SHA-256 hash of the transferable proof: the primary hash <c>H1 = H(e₀ ‖ … ‖ eₙ)</c> or the secondary
/// hash <c>H2 = H(H1)</c> (Verheul Algorithms 22 to 24). The kind is recorded in the tag.
/// </summary>
/// <remarks>
/// <b>Secrecy.</b> <c>H2</c> is public: it travels in the challenge. <c>H1</c> is the prover's response and becomes
/// public with it, but a party that learns <c>H1</c> before the prover has signed it could answer in the prover's
/// place for the challenger, so the holder of an unsigned <c>H1</c> keeps it private. Comparisons of digests in
/// the algorithms are constant-time.
/// </remarks>
public sealed class ProofDigest: SensitiveMemory
{
    /// <summary>The digest length in bytes: SHA-256.</summary>
    public const int SizeBytes = 32;


    /// <summary>The kind of this digest, from its tag.</summary>
    public ProofDigestKind Kind => Tag.Get<ProofDigestKind>();


    /// <summary>Wraps an already-populated rental; only <see cref="FromCanonical"/> and the algorithms construct a digest.</summary>
    internal ProofDigest(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies caller-supplied digest bytes into a pool-rented buffer and returns a digest wrapping it.</summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes.</param>
    /// <param name="kind">Which hash of the proof this is.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>A digest wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length.</exception>
    public static ProofDigest FromCanonical(ReadOnlySpan<byte> canonicalBytes, ProofDigestKind kind, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.Length != SizeBytes)
        {
            throw new ArgumentException($"A proof digest must be exactly {SizeBytes} bytes; received {canonicalBytes.Length}.", nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);
        Tag baseTag = tag ?? Tag.Empty;

        return new ProofDigest(owner, baseTag.With(SecdsaStructureKind.ProofDigest).With(kind));
    }


    /// <summary>Returns the digest bytes.</summary>
    public ReadOnlySpan<byte> GetBytes() => AsReadOnlySpan();
}
