using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="Fp2Element"/> that
/// produce a new Fp2 element by dispatching to a backend-supplied
/// delegate.
/// </summary>
/// <remarks>
/// Same shape as the G1 arithmetic extensions: rent a destination
/// buffer from the pool, hand the operands' read-only spans and the
/// destination's writable span to the supplied delegate, and wrap the
/// destination buffer in a fresh <see cref="Fp2Element"/>.
/// The delegate is responsible for producing canonical-form output;
/// this extension class neither validates the result nor stamps
/// provenance per call.
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class Fp2ElementArithmeticExtensions
{
    extension(Fp2Element a)
    {
        //Result size and the curve handed to the delegate are taken from the
        //operand's own curve (a.Curve), not a fixed BLS12-381 constant, so a
        //single curve-broad extension block serves every curve's Fp2.
        /// <summary>Returns <c>a + b</c> in Fp2.</summary>
        public Fp2Element Add(
            Fp2Element b,
            Fp2AddDelegate add,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);
            ArgumentNullException.ThrowIfNull(add);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp2SizeBytes(a.Curve));
            add(a.AsReadOnlySpan(), b.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp2SizeBytes(a.Curve)], a.Curve);
            return new Fp2Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>a − b</c> in Fp2.</summary>
        public Fp2Element Subtract(
            Fp2Element b,
            Fp2SubtractDelegate subtract,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);
            ArgumentNullException.ThrowIfNull(subtract);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp2SizeBytes(a.Curve));
            subtract(a.AsReadOnlySpan(), b.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp2SizeBytes(a.Curve)], a.Curve);
            return new Fp2Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>a · b</c> in Fp2.</summary>
        public Fp2Element Multiply(
            Fp2Element b,
            Fp2MultiplyDelegate multiply,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);
            ArgumentNullException.ThrowIfNull(multiply);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp2SizeBytes(a.Curve));
            multiply(a.AsReadOnlySpan(), b.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp2SizeBytes(a.Curve)], a.Curve);
            return new Fp2Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>a²</c> in Fp2.</summary>
        public Fp2Element Square(
            Fp2SquareDelegate square,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(square);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp2SizeBytes(a.Curve));
            square(a.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp2SizeBytes(a.Curve)], a.Curve);
            return new Fp2Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>−a</c> in Fp2.</summary>
        public Fp2Element Negate(
            Fp2NegateDelegate negate,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(negate);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp2SizeBytes(a.Curve));
            negate(a.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp2SizeBytes(a.Curve)], a.Curve);
            return new Fp2Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>a^(-1)</c> in Fp2. Behaviour on the zero element is backend-defined.</summary>
        public Fp2Element Invert(
            Fp2InvertDelegate invert,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(invert);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp2SizeBytes(a.Curve));
            invert(a.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp2SizeBytes(a.Curve)], a.Curve);
            return new Fp2Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns the conjugate <c>c0 − c1·u</c> of <c>a = c0 + c1·u</c>. Over Fp2 with <c>u² = −1</c> this equals the Frobenius operator <c>a^p</c>.</summary>
        public Fp2Element Conjugate(
            Fp2ConjugateDelegate conjugate,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(conjugate);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp2SizeBytes(a.Curve));
            conjugate(a.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp2SizeBytes(a.Curve)], a.Curve);
            return new Fp2Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }
    }
}