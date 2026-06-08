using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="Fp12Element"/> that
/// produce a new Fp12 element by dispatching to a backend-supplied
/// delegate.
/// </summary>
/// <remarks>
/// Same shape as the lower-tower arithmetic extensions: rent a
/// destination buffer from the pool, hand the operands' spans and the
/// destination's writable span to the supplied delegate, wrap the
/// result.
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class Fp12ElementArithmeticExtensions
{
    extension(Fp12Element a)
    {
        //Result size and the curve handed to the delegate are taken from the
        //operand's own curve (a.Curve), not a fixed BLS12-381 constant, so a
        //single curve-broad extension block serves every curve's Fp12.
        /// <summary>Returns <c>a + b</c> in Fp12.</summary>
        public Fp12Element Add(
            Fp12Element b,
            Fp12AddDelegate add,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);
            ArgumentNullException.ThrowIfNull(add);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp12SizeBytes(a.Curve));
            add(a.AsReadOnlySpan(), b.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp12SizeBytes(a.Curve)], a.Curve);
            return new Fp12Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>a − b</c> in Fp12.</summary>
        public Fp12Element Subtract(
            Fp12Element b,
            Fp12SubtractDelegate subtract,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);
            ArgumentNullException.ThrowIfNull(subtract);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp12SizeBytes(a.Curve));
            subtract(a.AsReadOnlySpan(), b.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp12SizeBytes(a.Curve)], a.Curve);
            return new Fp12Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>a · b</c> in Fp12.</summary>
        public Fp12Element Multiply(
            Fp12Element b,
            Fp12MultiplyDelegate multiply,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);
            ArgumentNullException.ThrowIfNull(multiply);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp12SizeBytes(a.Curve));
            multiply(a.AsReadOnlySpan(), b.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp12SizeBytes(a.Curve)], a.Curve);
            return new Fp12Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>a²</c> in Fp12.</summary>
        public Fp12Element Square(
            Fp12SquareDelegate square,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(square);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp12SizeBytes(a.Curve));
            square(a.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp12SizeBytes(a.Curve)], a.Curve);
            return new Fp12Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>−a</c> in Fp12.</summary>
        public Fp12Element Negate(
            Fp12NegateDelegate negate,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(negate);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp12SizeBytes(a.Curve));
            negate(a.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp12SizeBytes(a.Curve)], a.Curve);
            return new Fp12Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns <c>a^(-1)</c> in Fp12. Behaviour on the zero element is backend-defined.</summary>
        public Fp12Element Invert(
            Fp12InvertDelegate invert,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(invert);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp12SizeBytes(a.Curve));
            invert(a.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp12SizeBytes(a.Curve)], a.Curve);
            return new Fp12Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns the Fp12 conjugate <c>c0 − c1·w</c> of <c>a = c0 + c1·w</c>.</summary>
        public Fp12Element Conjugate(
            Fp12ConjugateDelegate conjugate,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(conjugate);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp12SizeBytes(a.Curve));
            conjugate(a.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp12SizeBytes(a.Curve)], a.Curve);
            return new Fp12Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns the Frobenius <c>a^p</c> in Fp12.</summary>
        public Fp12Element Frobenius(
            Fp12FrobeniusDelegate frobenius,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(frobenius);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp12SizeBytes(a.Curve));
            frobenius(a.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp12SizeBytes(a.Curve)], a.Curve);
            return new Fp12Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }


        /// <summary>Returns the cyclotomic square <c>a²</c> in Fp12. Valid only when <paramref name="a"/> lies in the cyclotomic subgroup; behaviour outside is backend-defined.</summary>
        public Fp12Element CyclotomicSquare(
            Fp12CyclotomicSquareDelegate cyclotomicSquare,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(cyclotomicSquare);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(WellKnownCurves.GetFp12SizeBytes(a.Curve));
            cyclotomicSquare(a.AsReadOnlySpan(), owner.Memory.Span[..WellKnownCurves.GetFp12SizeBytes(a.Curve)], a.Curve);
            return new Fp12Element(owner, a.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(a.Curve));
        }
    }
}