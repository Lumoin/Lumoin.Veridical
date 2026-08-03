using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// A Longfellow JWT statement zero-knowledge proof: the byte envelope
/// <c>[32-byte commitment root ‖ sumcheck proof ‖ Ligero proof]</c> over the P-256 base field the prover emits
/// and the verifier consumes. Pool-rented and tagged with the zero-knowledge-proof algebraic role.
/// </summary>
/// <remarks>
/// The proof is public material — it carries no witness — but it rides the same pool-backed, tagged wrapper
/// as every other library byte product so that allocation, provenance and lifetime stay uniform. The
/// sumcheck/Ligero sub-proof split is data-dependent and needs the circuit parameters to parse, so nothing
/// beyond the fixed-length commitment root is validated here.
/// </remarks>
public sealed class LongfellowJwtProof: SensitiveMemory
{
    /// <summary>The smallest well-formed envelope: the commitment root ahead of the two sub-proofs.</summary>
    public const int MinimumSizeBytes = 32;


    //The envelope carries no witness, so the tag records the zero-knowledge-proof role only, matching the
    //other proof leaf types.
    private static Tag AlgebraicTag { get; } = Tag.Create(AlgebraicRole.ZkProof);


    private LongfellowJwtProof(IMemoryOwner<byte> owner, Tag tag)
        : base(owner, tag)
    {
    }


    /// <summary>
    /// Copies a caller-supplied envelope into a pool-rented buffer and returns a proof wrapping it.
    /// </summary>
    /// <param name="envelope">The full proof envelope; at least <see cref="MinimumSizeBytes"/> bytes.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; the algebraic-identity entry is merged in unconditionally.</param>
    /// <returns>A proof wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="envelope"/> is shorter than <see cref="MinimumSizeBytes"/>.</exception>
    public static LongfellowJwtProof FromCanonical(ReadOnlySpan<byte> envelope, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(envelope.Length < MinimumSizeBytes)
        {
            throw new ArgumentException($"A Longfellow JWT proof is at least {MinimumSizeBytes} bytes; received {envelope.Length}.", nameof(envelope));
        }

        IMemoryOwner<byte> owner = pool.Rent(envelope.Length);
        envelope.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? AlgebraicTag
            : tag.With(AlgebraicRole.ZkProof);

        return new LongfellowJwtProof(owner, effectiveTag);
    }
}
