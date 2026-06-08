using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="Fp6Element"/> that
/// produce a new Fp6 element by dispatching to a backend-supplied
/// delegate.
/// </summary>
/// <remarks>
/// Same shape as the Fp2 arithmetic extensions: rent a destination
/// buffer from the pool, hand the operands' read-only spans and the
/// destination's writable span to the supplied delegate, and wrap the
/// destination buffer in a fresh <see cref="Fp6Element"/>.
/// The delegate is responsible for producing canonical-form output.
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class Fp6ElementArithmeticExtensions
{
    extension(Fp6Element a)
    {
        //Result size and the curve handed to the delegate are taken from the
        //operand's own curve (a.Curve), not a fixed BLS12-381 constant, so a
        //single curve-broad extension block serves every curve's Fp6.
        /// <summary>Returns <c>a + b</c> in Fp6.</summary>
        public Fp6Element Add(
            Fp6Element b,
            Fp6AddDelegate add,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);
            ArgumentNullException.ThrowIfNull(add);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp6SizeBytes(a.Curve));
            add(a.AsReadOnlySpan(), b.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp6SizeBytes(a.Curve)], a.Curve);
            return new Fp6Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>a − b</c> in Fp6.</summary>
        public Fp6Element Subtract(
            Fp6Element b,
            Fp6SubtractDelegate subtract,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);
            ArgumentNullException.ThrowIfNull(subtract);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp6SizeBytes(a.Curve));
            subtract(a.AsReadOnlySpan(), b.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp6SizeBytes(a.Curve)], a.Curve);
            return new Fp6Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>a · b</c> in Fp6.</summary>
        public Fp6Element Multiply(
            Fp6Element b,
            Fp6MultiplyDelegate multiply,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);
            ArgumentNullException.ThrowIfNull(multiply);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp6SizeBytes(a.Curve));
            multiply(a.AsReadOnlySpan(), b.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp6SizeBytes(a.Curve)], a.Curve);
            return new Fp6Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>a²</c> in Fp6.</summary>
        public Fp6Element Square(
            Fp6SquareDelegate square,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(square);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp6SizeBytes(a.Curve));
            square(a.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp6SizeBytes(a.Curve)], a.Curve);
            return new Fp6Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>−a</c> in Fp6.</summary>
        public Fp6Element Negate(
            Fp6NegateDelegate negate,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(negate);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp6SizeBytes(a.Curve));
            negate(a.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp6SizeBytes(a.Curve)], a.Curve);
            return new Fp6Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>a^(-1)</c> in Fp6. Behaviour on the zero element is backend-defined.</summary>
        public Fp6Element Invert(
            Fp6InvertDelegate invert,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(invert);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp6SizeBytes(a.Curve));
            invert(a.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp6SizeBytes(a.Curve)], a.Curve);
            return new Fp6Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }
    }
}