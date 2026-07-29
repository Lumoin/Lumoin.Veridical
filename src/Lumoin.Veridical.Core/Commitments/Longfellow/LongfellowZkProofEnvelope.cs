using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// A serialized Longfellow proof envelope as a semantic, pooled container: the single-field kernel
/// envelope <c>com ‖ sc ‖ com_proof</c> (the reference's <c>ZkProof</c> wire image) or the
/// dual-field mdoc composition <c>[macs] ‖ [hash ZkProof] ‖ [sig ZkProof]</c>. The proof bytes live
/// in one pooled rent, exposed read-only, cleared and released on disposal — the provers return
/// this instead of a naked byte array so proof material stays tracked and wiped like every other
/// pooled buffer in the stack.
/// </summary>
[System.Diagnostics.DebuggerDisplay("Longfellow ZK proof envelope ({Length} bytes)")]
internal sealed class LongfellowZkProofEnvelope: IDisposable
{
    /// <summary>The pooled rent holding the envelope bytes; <see langword="null"/> once disposed.</summary>
    private IMemoryOwner<byte>? bytes;

    /// <summary>The envelope's byte length inside the rent.</summary>
    private readonly int length;


    /// <summary>
    /// Wraps a pooled rent whose leading <paramref name="length"/> bytes hold the serialized
    /// envelope; the wrapper takes ownership of the rent.
    /// </summary>
    /// <param name="bytes">The pooled rent to own.</param>
    /// <param name="length">The envelope's byte length.</param>
    /// <exception cref="ArgumentNullException">When the rent is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When the length is negative or exceeds the rent.</exception>
    public LongfellowZkProofEnvelope(IMemoryOwner<byte> bytes, int length)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(length, bytes.Memory.Length);

        this.bytes = bytes;
        this.length = length;
    }


    /// <summary>The envelope's byte length.</summary>
    public int Length => length;

    /// <summary>The envelope bytes.</summary>
    /// <exception cref="ObjectDisposedException">When the envelope has been disposed.</exception>
    public ReadOnlySpan<byte> Bytes => Owner().Memory.Span[..length];

    /// <summary>The envelope bytes as memory, for capture across lambda boundaries.</summary>
    /// <exception cref="ObjectDisposedException">When the envelope has been disposed.</exception>
    public ReadOnlyMemory<byte> Memory => ((ReadOnlyMemory<byte>)Owner().Memory)[..length];


    /// <summary>Clears and releases the pooled rent, idempotently.</summary>
    public void Dispose()
    {
        IMemoryOwner<byte>? local = bytes;
        if(local is not null)
        {
            bytes = null;
            local.Memory.Span[..length].Clear();
            local.Dispose();
        }
    }


    /// <summary>The live rent, guarded against use after disposal.</summary>
    /// <returns>The pooled rent.</returns>
    /// <exception cref="ObjectDisposedException">When the envelope has been disposed.</exception>
    private IMemoryOwner<byte> Owner() => bytes ?? throw new ObjectDisposedException(nameof(LongfellowZkProofEnvelope));
}
