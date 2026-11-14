using Lumoin.Veridical.Core.Commitments.Longfellow;
using System;
using System.Threading;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The prover's random byte stream for exactly one proof: the blinding rows, witness-row padding,
/// quadratic-triple padding, per-leaf Merkle nonces and the proof pad are all drawn from it.
/// </summary>
/// <remarks>
/// <para>
/// The caller supplies plain random bytes and nothing else. The prover maps those bytes to field
/// elements itself: each element is drawn by the field's own mask-then-reject rule, so a draw at or
/// above the field modulus is discarded and a fresh block is read. The supplier therefore never
/// implements below-prime sampling and cannot get it wrong.
/// </para>
/// <para>
/// The number of bytes a proof consumes is not fixed in advance. It depends on the circuit and
/// parameters, and on how many rejection redraws the stream provokes (about one in 2<sup>32</sup> per
/// P-256 base-field element), so a precomputed buffer of exact length cannot be promised to suffice.
/// The stream is therefore pulled on demand through the fill delegate, and <see cref="BytesDrawn"/>
/// reports how much a finished proof used.
/// </para>
/// <para>Invariants the supplier must uphold, and which this type enforces where it can:</para>
/// <list type="bullet">
/// <item><description>The bytes come from a cryptographically secure random generator; a predictable or
/// repeating stream voids the zero-knowledge property while every proof still verifies.</description></item>
/// <item><description>The bytes are fresh for each proof. An instance serves one proof: handing a spent
/// instance to a second proof throws <see cref="InvalidOperationException"/>.</description></item>
/// <item><description>The bytes are never reused across proofs, never logged and never persisted.</description></item>
/// <item><description>The fill delegate is non-null; this is validated at construction. Degenerate output
/// (an all-zero blinding block or nonce set) is rejected by the prover at proof time, and
/// <see cref="LongfellowRandomnessChecks"/> lets a supplier test its source up front.</description></item>
/// </list>
/// </remarks>
public sealed class LongfellowProverRandomness
{
    private readonly LongfellowEntropyDelegate source;
    private int spent;
    private long bytesDrawn;


    /// <summary>Wraps a secure random byte source for one proof.</summary>
    /// <param name="source">Fills a span with cryptographically secure random bytes, fresh on every call.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="source"/> is <see langword="null"/>.</exception>
    public LongfellowProverRandomness(LongfellowEntropyDelegate source)
    {
        ArgumentNullException.ThrowIfNull(source);
        this.source = source;
    }


    /// <summary>Whether a proof has already taken this stream; a spent instance cannot serve another proof.</summary>
    public bool IsSpent => Volatile.Read(ref spent) != 0;

    /// <summary>The number of random bytes the proof has drawn from this stream so far.</summary>
    public long BytesDrawn => Interlocked.Read(ref bytesDrawn);


    /// <summary>Takes the stream for one proof and returns the byte source the prover draws from.</summary>
    /// <returns>The prover-facing byte source.</returns>
    /// <exception cref="InvalidOperationException">When a proof has already taken this stream.</exception>
    internal LongfellowRandomByteSource Take()
    {
        if(Interlocked.Exchange(ref spent, 1) != 0)
        {
            throw new InvalidOperationException("The prover randomness has already served a proof; random bytes must be fresh for every proof.");
        }

        return destination =>
        {
            source(destination);
            Interlocked.Add(ref bytesDrawn, destination.Length);
        };
    }
}
