using System;
using System.Buffers;
using System.Diagnostics;

namespace Lumoin.Veridical.Core.Memory;

/// <summary>
/// Pool-backed wrapper for cryptographic byte material. Owns an
/// <see cref="IMemoryOwner{T}"/> rented from a <see cref="MemoryPool{T}"/>,
/// carries a <see cref="Tag"/> describing what the bytes
/// represent, and clears the buffer on disposal.
/// </summary>
/// <remarks>
/// <para>
/// Every leaf algebraic type the library exposes — scalars, base-field
/// elements, group points, polynomials, commitments, openings, proofs —
/// derives from this class. The base type owns the buffer and its lifecycle;
/// the leaf type fixes the role and validates the byte length. The leaf
/// types are curve-broad: a single <c>Scalar</c> / <c>G1Point</c> / … serves
/// every enumerated curve, and the curve a value belongs to travels in its
/// <see cref="Tag"/> (surfaced as a <c>Curve</c> property)
/// rather than in the static type. Cross-curve mismatch is therefore a
/// runtime check, not a compile-time one: the arithmetic extension entry
/// points assert that two operands share a curve and throw
/// <see cref="ArgumentException"/> when they do not.
/// </para>
/// <para>
/// The pool-backed pattern matters in two places. The prover hot path
/// allocates many short-lived field and group elements per multi-scalar
/// multiplication and per FFT round; pool-backed allocation keeps that off
/// the GC. And the same allocation pattern translates to an arena allocator
/// in another runtime, so a port to a different language preserves the
/// memory model without restructuring.
/// </para>
/// <para>
/// Reads are exposed via <see cref="AsReadOnlySpan"/> and are public. Writes
/// are exposed via <see cref="AsSpan"/> and are <c>protected internal</c>:
/// derived leaf types and friend backend assemblies (added via
/// <c>InternalsVisibleTo</c>) can populate buffers; arbitrary callers cannot.
/// </para>
/// <para>
/// <see cref="Dispose"/> clears the buffer and returns it to the pool. There
/// is deliberately NO finalizer: a finalizer that clears or returns the
/// buffer races with in-flight span reads. In a chained expression such as
/// <c>a.Add(b, …).Add(c, …)</c> the intermediate wrapper becomes unreachable
/// the moment the outer call is invoked, while the callee is still reading
/// its span — the span keeps the underlying array alive but not the wrapper
/// or its rental. A buffer-touching finalizer can then return the segment to
/// the pool mid-read and a concurrent renter overwrites it: a use-after-free
/// that produced one-shot, irreproducible wrong results in the CI property
/// tests on the ARM64 legs. A missed <see cref="Dispose"/> therefore orphans
/// the pool slot instead: the segment is never returned, never re-rented,
/// and its contents are never handed to a next renter — a bounded leak, not
/// corruption. Derived types must not add a finalizer that touches the
/// buffer; the SensitiveMemoryLifetimeTests contract tests pin this.
/// </para>
/// </remarks>
[DebuggerDisplay("{Tag,nq} ({Length} bytes)")]
public abstract class SensitiveMemory: IDisposable
{
    private IMemoryOwner<byte>? owner;


    /// <summary>Gets the runtime tag identifying what this memory represents.</summary>
    public Tag Tag { get; }

    /// <summary>Gets the logical length of the data in bytes (may be smaller than the rented buffer).</summary>
    public int Length { get; }

    /// <summary>Gets a value indicating whether this instance has been disposed.</summary>
    public bool IsDisposed => owner is null;


    /// <summary>
    /// Initializes a new instance with the supplied buffer, logical length,
    /// and tag. The instance takes ownership of <paramref name="owner"/> and
    /// is responsible for disposing it.
    /// </summary>
    /// <param name="owner">The pool-rented buffer that owns the bytes.</param>
    /// <param name="length">The logical length of the data within the buffer.</param>
    /// <param name="tag">The runtime tag identifying what the bytes represent.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="owner"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="length"/> is negative or exceeds the buffer's capacity.</exception>
    protected SensitiveMemory(IMemoryOwner<byte> owner, int length, Tag tag)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(length, owner.Memory.Length);

        this.owner = owner;
        Length = length;
        Tag = tag;
    }


    /// <summary>
    /// Returns a read-only view of the data. The span is valid until the next
    /// call that mutates the buffer or until the instance is disposed.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When this instance has already been disposed.</exception>
    public ReadOnlySpan<byte> AsReadOnlySpan()
    {
        ObjectDisposedException.ThrowIf(owner is null, this);

        return owner.Memory.Span[..Length];
    }


    /// <summary>
    /// Returns a writable view of the data. Available to derived leaf types
    /// and to backend assemblies granted friend access via
    /// <c>InternalsVisibleTo</c>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When this instance has already been disposed.</exception>
    protected internal Span<byte> AsSpan()
    {
        ObjectDisposedException.ThrowIf(owner is null, this);

        return owner.Memory.Span[..Length];
    }


    /// <summary>
    /// Clears the buffer and returns it to the pool. Safe to call multiple
    /// times; subsequent calls are no-ops.
    /// </summary>
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }


    /// <summary>
    /// Performs the actual cleanup. Override in derived types only when
    /// additional disposal work is needed beyond clearing and returning the
    /// pool-rented buffer; chained overrides should call the base implementation.
    /// </summary>
    /// <param name="disposing">
    /// Always <see langword="true"/>: this type has no finalizer (see the class
    /// remarks — a buffer-touching finalizer is a use-after-free against
    /// in-flight span reads), so the only caller is <see cref="Dispose()"/>.
    /// The parameter keeps the standard inheritable-IDisposable shape. Derived
    /// types must not add a finalizer that touches the buffer.
    /// </param>
    protected virtual void Dispose(bool disposing)
    {
        var local = owner;
        if(local is null)
        {
            return;
        }

        owner = null;
        try
        {
            // Clear the bytes before returning to the pool so the next renter
            // cannot observe sensitive material. Not all cryptographic material
            // is secret (a public group point, a polynomial commitment) but the
            // pattern applies uniformly: the pool slot is left in a known state.
            local.Memory.Span[..Length].Clear();
            local.Dispose();
        }
        catch
        {
            // Swallowing is deliberate — if the pool throws on return there is
            // no recovery anyway, and the buffer becomes orphaned rather than
            // crashing the process.
        }
    }
}