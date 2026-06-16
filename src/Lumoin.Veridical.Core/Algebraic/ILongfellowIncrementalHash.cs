using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// A forkable incremental hash, the Core-side seam the Longfellow
/// transcript holds to snapshot its absorbed byte stream in one pass
/// instead of re-hashing the whole buffer on every challenge squeeze.
/// </summary>
/// <remarks>
/// <para>
/// Core does not reference the hashing assembly (the dependency arrow runs
/// the other way), so the transcript cannot name a concrete SHA-256 hasher.
/// This interface is the injection seam — the same delegate-injection style
/// the transcript already uses for its one-shot hash and its block cipher.
/// A downstream wiring layer (the managed backends, or the test wiring)
/// implements it over the real incremental SHA-256 hasher.
/// </para>
/// <para>
/// The contract mirrors the reference transcript's incremental SHA usage:
/// <see cref="Update"/> absorbs bytes (the reference's
/// <c>sha_.Update(data, n)</c>); <see cref="Fork"/> produces an independent
/// copy of the running state (the reference's
/// <c>SHA256 tmp; tmp.CopyState(sha_);</c>); <see cref="FinalizeInto"/>
/// finalizes the fork into a 32-byte key (the reference's
/// <c>tmp.DigestData(key)</c>). The transcript forks-then-finalizes on every
/// squeeze so the running state keeps absorbing undisturbed, and forks on
/// clone so the clone carries the same running state.
/// </para>
/// </remarks>
public interface ILongfellowIncrementalHash
{
    /// <summary>Absorbs bytes into the running hash state.</summary>
    /// <param name="data">The bytes to absorb; the same bytes, in the same order, the transcript appends to its absorbed stream.</param>
    void Update(ReadOnlySpan<byte> data);


    /// <summary>
    /// Produces an independent copy of the running hash state. Updating or
    /// finalizing the returned instance must not disturb this one, and vice
    /// versa.
    /// </summary>
    /// <returns>A fork carrying the same absorbed state as this instance.</returns>
    ILongfellowIncrementalHash Fork();


    /// <summary>
    /// Finalizes this instance's state into <paramref name="digest"/>,
    /// applying the hash's padding. Intended to be called on a
    /// <see cref="Fork"/> so the original running state is left undisturbed.
    /// </summary>
    /// <param name="digest">Receives the 32-byte digest.</param>
    void FinalizeInto(Span<byte> digest);
}


/// <summary>
/// Creates a fresh <see cref="ILongfellowIncrementalHash"/> seeded to the
/// empty state, the factory the Longfellow transcript invokes once at
/// construction to obtain its running hash. Injected the same way the
/// one-shot hash and block cipher are, so Core stays decoupled from the
/// concrete hashing implementation.
/// </summary>
/// <returns>A fresh incremental hash with nothing absorbed yet.</returns>
public delegate ILongfellowIncrementalHash LongfellowIncrementalHashFactory();
