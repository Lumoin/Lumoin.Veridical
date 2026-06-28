using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// A scalar in a curve's scalar field, carried as 32 canonical big-endian
/// bytes strictly less than that curve's field order. The curve identity
/// travels in <see cref="Curve"/> (sourced from the <see cref="Tag"/>),
/// not in the static type.
/// </summary>
/// <remarks>
/// <para>
/// The type is curve-broad and sealed: a single <see cref="Scalar"/> type
/// serves every enumerated curve, and the curve a given scalar belongs to
/// is read from its <see cref="Curve"/> property. Cross-curve mixing is no
/// longer a compile-time error; it is a runtime <see cref="ArgumentException"/>
/// raised by the arithmetic extension entry points
/// (<see cref="ScalarArithmeticExtensions"/>) when two operands disagree on
/// their curve.
/// </para>
/// <para>
/// The type owns the buffer through the <see cref="SensitiveMemory"/> base,
/// validates its length, and carries the runtime algebraic identity through
/// the tag. It does not expose arithmetic, predicates, or formatters as
/// instance members; those are surfaced through <c>extension(Scalar)</c>
/// blocks in <see cref="ScalarArithmeticExtensions"/> and
/// <see cref="ScalarInspectionExtensions"/>.
/// </para>
/// <para>
/// Four static factories cover the ways a scalar can enter the system, each
/// taking the curve as an explicit, non-defaultable argument — a scalar must
/// know which curve it lives in. <see cref="FromCanonical"/> copies bytes the
/// caller already knows to be reduced. <see cref="FromBytesReduced"/> accepts
/// arbitrary-width bytes and dispatches to a backend reducer.
/// <see cref="FromRandom"/> delegates to a backend that fills the buffer with
/// a uniformly random reduced scalar and stamps its provenance.
/// <see cref="FromHashToScalar"/> maps a message plus domain-separation tag
/// to a scalar via a backend. The internal constructor is reached by friend
/// assemblies that have rented the buffer themselves.
/// </para>
/// <para>
/// Arithmetic results reuse the per-curve cached tag from
/// <see cref="WellKnownAlgebraicTags.ScalarFor"/> by reference. Inner-loop
/// operations are event-less and do not stamp provenance per operation, so
/// every product of arithmetic carries the same algebraic-identity tag
/// without per-operation tag allocation. Provenance stamping is paid once at
/// the boundary where a scalar enters the system (random generation,
/// hash-to-field, deserialisation), not at every intermediate addition or
/// multiplication.
/// </para>
/// </remarks>
public sealed class Scalar: SensitiveMemory
{
    /// <summary>
    /// The canonical byte length of a scalar. Every enumerated curve has a
    /// scalar field of at most 254 bits, so 32 bytes is sufficient and shared;
    /// P-384 and P-521 (48- and 66-byte scalars) are out of scope until they
    /// have a confirmed consumer.
    /// </summary>
    public const int SizeBytes = 32;


    /// <summary>The curve whose scalar field this value belongs to.</summary>
    public CurveParameterSet Curve { get; }


    /// <summary>
    /// Constructs a scalar over a buffer the caller has already populated. The
    /// instance takes ownership of <paramref name="owner"/> and is responsible
    /// for clearing and returning it on disposal.
    /// </summary>
    /// <param name="owner">A pool-rented buffer whose first <see cref="SizeBytes"/> bytes hold the canonical big-endian scalar bytes.</param>
    /// <param name="curve">The curve whose scalar field the value belongs to.</param>
    /// <param name="tag">The runtime tag; should at minimum carry the algebraic identity entries from <see cref="WellKnownAlgebraicTags.ScalarFor"/> plus any provenance the producer stamps.</param>
    internal Scalar(IMemoryOwner<byte> owner, CurveParameterSet curve, Tag tag) : base(owner, tag)
    {
        Curve = curve;
    }


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented buffer and
    /// returns a scalar wrapping it.
    /// </summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes, big-endian, strictly less than the curve's field order. The caller is responsible for the reduction; this factory does not validate the value against the modulus, only the length.</param>
    /// <param name="curve">The curve whose scalar field the value belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries. The algebraic-identity entries are merged in unconditionally; if no tag is supplied, the result carries only the per-curve algebraic tag.</param>
    /// <returns>A scalar wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length.</exception>
    /// <remarks>
    /// Modulus validation is deliberately not performed here. A backend that
    /// needs a reduced scalar reduces at the operation boundary (which it has
    /// to do anyway when converting to its preferred internal representation).
    /// For an entry point that accepts arbitrary-width bytes and reduces them
    /// via a backend delegate, use <see cref="FromBytesReduced"/>.
    /// </remarks>
    public static Scalar FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.Length != SizeBytes)
        {
            throw new ArgumentException(
                $"Scalars must be exactly {SizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? WellKnownAlgebraicTags.ScalarFor(curve)
            : MergeWithAlgebraicTag(tag, curve);

        return new Scalar(owner, curve, effectiveTag);
    }


    /// <summary>
    /// Rents a buffer, hands it to <paramref name="reduce"/> for canonical-form
    /// production from arbitrary-width input, and returns a scalar wrapping
    /// the result.
    /// </summary>
    /// <param name="input">Source bytes of any length, interpreted as a big-endian unsigned integer that the backend reduces modulo the scalar field order.</param>
    /// <param name="reduce">The backend implementation of modular reduction.</param>
    /// <param name="curve">The curve whose scalar field the value belongs to.</param>
    /// <param name="pool">The pool to rent the destination buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries. The algebraic-identity entries are merged in unconditionally.</param>
    /// <returns>A scalar wrapping a pool-rented buffer containing the canonical-form reduced value.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="reduce"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// <para>
    /// Hash-to-field constructions per RFC 9380 expand a seed plus DST into
    /// an output wider than the field order (typically 48 bytes for BLS12-381
    /// at 128-bit security) precisely so that the modular reduction at this
    /// step produces uniformly-distributed scalars. Tests that generate
    /// 32-byte uniform inputs and pass them through this factory observe a
    /// small bias toward small values; that bias is acceptable for testing
    /// algebraic laws but is not acceptable for security-critical scalar
    /// sampling.
    /// </para>
    /// <para>
    /// Unlike <see cref="FromRandom"/>, this factory does not stamp provenance.
    /// The reduce delegate is a transformation, not an entropy source; if the
    /// input bytes carry their own provenance, the caller is responsible for
    /// composing that with the supplied <paramref name="tag"/>.
    /// </para>
    /// </remarks>
    public static Scalar FromBytesReduced(
        ReadOnlySpan<byte> input,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        reduce(input, owner.Memory.Span[..SizeBytes], curve);

        Tag effectiveTag = tag is null
            ? WellKnownAlgebraicTags.ScalarFor(curve)
            : MergeWithAlgebraicTag(tag, curve);

        return new Scalar(owner, curve, effectiveTag);
    }


    /// <summary>
    /// Rents a buffer, hands it to <paramref name="random"/> for filling, and
    /// returns a scalar wrapping the result with provenance entries stamped
    /// by the delegate.
    /// </summary>
    /// <param name="random">The entropy-sourced delegate that fills the buffer with a uniformly random scalar and stamps its provenance entries onto the supplied tag.</param>
    /// <param name="curve">The curve whose scalar field the value belongs to.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>A scalar wrapping a freshly randomised, pool-rented buffer.</returns>
    /// <exception cref="ArgumentNullException">When either delegate argument or the pool is <see langword="null"/>.</exception>
    /// <remarks>
    /// This is a boundary operation: a scalar enters the system from outside
    /// (the entropy source). The delegate is responsible for sampling
    /// uniformly modulo the field order — a backend that returns non-reduced
    /// bytes is non-conformant. Provenance stamping happens inside the
    /// delegate so the producing backend identifies itself end-to-end.
    /// </remarks>
    public static Scalar FromRandom(
        ScalarRandomDelegate random,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        Tag stamped = random(owner.Memory.Span[..SizeBytes], curve, WellKnownAlgebraicTags.ScalarFor(curve));

        return new Scalar(owner, curve, stamped);
    }


    /// <summary>
    /// Hashes <paramref name="message"/> together with
    /// <paramref name="domainSeparationTag"/> into a canonical scalar via the
    /// supplied backend delegate.
    /// </summary>
    /// <param name="message">The application message bytes.</param>
    /// <param name="domainSeparationTag">The protocol-level DST binding this hash-to-scalar call to a specific use, per RFC 9380 §3.</param>
    /// <param name="hashToScalar">The backend implementation of hash-to-scalar.</param>
    /// <param name="curve">The curve whose scalar field the value belongs to.</param>
    /// <param name="pool">The pool to rent the destination buffer from.</param>
    /// <returns>A scalar wrapping a freshly rented buffer that holds the canonical big-endian scalar, with the producing backend's provenance entries already merged into the tag.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="hashToScalar"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// Boundary operation: a message from outside the system enters as a
    /// tagged scalar with cryptographic provenance. The wrapped tag is
    /// the one the delegate returned; it carries the algebraic-identity
    /// entries from <see cref="WellKnownAlgebraicTags.ScalarFor"/> merged with
    /// the four provenance entries (provider library, crypto library, provider
    /// class, provider operation). The delegate is responsible for the
    /// cryptographic correctness of the mapping — RFC 9380
    /// <c>expand_message_xmd</c> plus modular reduction in the canonical
    /// reference path.
    /// </remarks>
    public static Scalar FromHashToScalar(
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> domainSeparationTag,
        ScalarHashToScalarDelegate hashToScalar,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        Tag stamped = hashToScalar(
            message,
            domainSeparationTag,
            owner.Memory.Span[..SizeBytes],
            curve,
            WellKnownAlgebraicTags.ScalarFor(curve));

        return new Scalar(owner, curve, stamped);
    }


    /// <summary>
    /// Returns a tag that carries every entry from <paramref name="tag"/> and
    /// the per-curve algebraic-identity entries, with the algebraic-identity
    /// entries taking precedence on key conflict.
    /// </summary>
    private static Tag MergeWithAlgebraicTag(Tag tag, CurveParameterSet curve)
    {
        return tag.With(AlgebraicRole.Scalar)
            .With(curve);
    }
}