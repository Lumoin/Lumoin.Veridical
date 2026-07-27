using System;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// A ported single-bit value, a faithful port of google/longfellow-zk's <c>Logic&lt;Field,
/// Backend&gt;::BitW</c> (<c>logic.h</c>): the boolean bit is not always the wire's raw value, it is
/// the affine reading <c>ConstantTerm + LinearCoefficient·Wire</c>, where <see cref="Wire"/> holds a
/// backend wire handle and <see cref="ConstantTerm"/>/<see cref="LinearCoefficient"/> are compile-time
/// field constants (the reference's <c>c0</c>/<c>c1</c>/<c>x</c>). The standard basis
/// (<c>ConstantTerm = 0</c>, <c>LinearCoefficient = 1</c>) reads the wire's raw value directly; other
/// bases arise from rebasing tricks the gadget layer uses to fold an extra affine transform into an
/// existing multiplication (for instance the odd-prime <c>lxor</c> gadget's <c>(1, −2)</c> and
/// <c>(half, −half)</c> bases).
/// </summary>
/// <remarks>
/// Both coefficients are precomputed field elements known before compilation, never backend wires
/// themselves, so they carry no backend dependency; only <see cref="Wire"/> ties a
/// <see cref="LongfellowBitWire"/> to the backend that produced it.
/// </remarks>
internal readonly struct LongfellowBitWire
{
    /// <summary>The affine reading's constant term (the reference's <c>c0</c>), canonical big-endian.</summary>
    public ReadOnlyMemory<byte> ConstantTerm { get; }

    /// <summary>The affine reading's linear coefficient on <see cref="Wire"/> (the reference's <c>c1</c>), canonical big-endian.</summary>
    public ReadOnlyMemory<byte> LinearCoefficient { get; }

    /// <summary>The underlying backend wire handle (the reference's <c>x</c>).</summary>
    public int Wire { get; }


    /// <summary>
    /// Constructs a bit over an arbitrary affine basis, the form the gadget layer's rebasing tricks
    /// produce.
    /// </summary>
    /// <param name="constantTerm">The affine reading's constant term, canonical big-endian, <see cref="Scalar.SizeBytes"/> bytes.</param>
    /// <param name="linearCoefficient">The affine reading's linear coefficient, canonical big-endian, <see cref="Scalar.SizeBytes"/> bytes.</param>
    /// <param name="wire">The underlying backend wire handle.</param>
    /// <exception cref="ArgumentException">When a coefficient is not exactly <see cref="Scalar.SizeBytes"/> bytes.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="wire"/> is negative.</exception>
    public LongfellowBitWire(ReadOnlyMemory<byte> constantTerm, ReadOnlyMemory<byte> linearCoefficient, int wire)
    {
        if(constantTerm.Length != Scalar.SizeBytes || linearCoefficient.Length != Scalar.SizeBytes)
        {
            throw new ArgumentException($"The affine basis coefficients are canonical {Scalar.SizeBytes}-byte scalars.");
        }

        ArgumentOutOfRangeException.ThrowIfNegative(wire);

        ConstantTerm = constantTerm;
        LinearCoefficient = linearCoefficient;
        Wire = wire;
    }


    /// <summary>
    /// Constructs a bit over the standard basis (<c>ConstantTerm = 0</c>, <c>LinearCoefficient = 1</c>):
    /// the wire's raw value read directly as the bit.
    /// </summary>
    /// <param name="field">The field-operation bundle supplying the zero and one constants.</param>
    /// <param name="wire">The underlying backend wire handle.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="field"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="wire"/> is negative.</exception>
    public LongfellowBitWire(LongfellowLogicFieldOperations field, int wire)
    {
        ArgumentNullException.ThrowIfNull(field);
        ArgumentOutOfRangeException.ThrowIfNegative(wire);

        ConstantTerm = field.Compiler.Zero;
        LinearCoefficient = field.Compiler.One;
        Wire = wire;
    }
}
