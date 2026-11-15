using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The 256-bit seed from which the ephemeral private keys of a transferable challenge are derived (Verheul
/// Algorithm 22 steps 1 and 4). The challenger encrypts it towards the prover next to the additional secret data;
/// the prover recovers it, recomputes the keys from it and checks that they yield the ephemeral public key it was
/// sent, which reinstates the uniform choice of the keys on which the soundness proof rests.
/// </summary>
/// <remarks>
/// <b>Secret.</b> The seed is known to the challenger and, after decryption, to the prover. Soundness rests on the
/// challenger not disclosing it to the prover other than inside the ECIES envelope; the holder disposes it, which
/// clears its memory (Algorithm 22 step 12).
/// </remarks>
public sealed class ProofSeed: SensitiveMemory
{
    /// <summary>The seed length in bytes: 256 bits.</summary>
    public const int SizeBytes = 32;


    /// <summary>The tag every seed carries: its structure kind.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(SecdsaStructureKind.ProofSeed);


    /// <summary>Wraps an already-populated rental; only <see cref="FromCanonical"/> and <see cref="Generate"/> construct a seed.</summary>
    internal ProofSeed(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies caller-supplied seed bytes into a pool-rented buffer and returns a seed wrapping it.</summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entry.</param>
    /// <returns>A seed wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length.</exception>
    public static ProofSeed FromCanonical(ReadOnlySpan<byte> canonicalBytes, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.Length != SizeBytes)
        {
            throw new ArgumentException($"A proof seed must be exactly {SizeBytes} bytes; received {canonicalBytes.Length}.", nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);
        Tag baseTag = tag ?? Tag.Empty;

        return new ProofSeed(owner, baseTag.With(SecdsaStructureKind.ProofSeed));
    }


    /// <summary>Draws a fresh seed from the entropy source (Algorithm 22 step 1).</summary>
    /// <param name="entropy">The entropy source.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>A fresh seed, owned by the caller.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static ProofSeed Generate(SecdsaEntropySource entropy, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(entropy);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        try
        {
            entropy(owner.Memory.Span);
        }
        catch
        {
            owner.Dispose();

            throw;
        }

        return new ProofSeed(owner, AlgebraicTag);
    }


    /// <summary>Returns the seed bytes.</summary>
    public ReadOnlySpan<byte> GetBytes() => AsReadOnlySpan();
}
