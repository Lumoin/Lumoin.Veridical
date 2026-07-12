using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// A Longfellow dual-field mdoc zero-knowledge proof: the byte envelope
/// <c>[6 MAC values] ‖ [GF(2^128) hash ZkProof] ‖ [P-256 signature ZkProof]</c> the dual-field prover emits
/// and the verifier consumes. Pool-rented and tagged with the zero-knowledge-proof algebraic role.
/// </summary>
/// <remarks>
/// The proof is public material — it carries no witness — but it rides the same pool-backed, tagged wrapper
/// as every other library byte product so that allocation, provenance and lifetime stay uniform. The envelope
/// spans two fields, so it has no single <see cref="CurveParameterSet"/>; the tag records only the algebraic
/// role. The hash/signature sub-proof split is data-dependent and needs the circuit parameters to parse, so
/// only the fixed-length MAC prefix is exposed.
/// </remarks>
public sealed class LongfellowMdocProof: SensitiveMemory
{
    /// <summary>The byte length of the six-MAC prefix every envelope begins with (<c>6 · 16</c>).</summary>
    public const int MacRegionBytes = 96;

    /// <summary>The smallest well-formed envelope: the MAC prefix ahead of the two sub-proofs.</summary>
    public const int MinimumSizeBytes = MacRegionBytes;


    //A dual-field envelope spans GF(2^128) and P-256, so no single CurveParameterSet applies; the tag records
    //the zero-knowledge-proof role only, matching the other proof leaf types.
    private static readonly Tag AlgebraicTag = Tag.Create(AlgebraicRole.ZkProof);


    private LongfellowMdocProof(IMemoryOwner<byte> owner, Tag tag)
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
    public static LongfellowMdocProof FromCanonical(ReadOnlySpan<byte> envelope, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(envelope.Length < MinimumSizeBytes)
        {
            throw new ArgumentException($"A Longfellow mdoc proof is at least {MinimumSizeBytes} bytes; received {envelope.Length}.", nameof(envelope));
        }

        IMemoryOwner<byte> owner = pool.Rent(envelope.Length);
        envelope.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? AlgebraicTag
            : tag.With(AlgebraicRole.ZkProof);

        return new LongfellowMdocProof(owner, effectiveTag);
    }


    /// <summary>Returns the six-MAC prefix the cross-field binding commits to.</summary>
    public ReadOnlySpan<byte> GetMacRegion() => AsReadOnlySpan()[..MacRegionBytes];
}
