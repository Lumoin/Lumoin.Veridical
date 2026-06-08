using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Sumcheck;

/// <summary>
/// Extension verbs that bridge between <see cref="Polynomial"/> and
/// <see cref="CompressedRoundPolynomial"/> for BLS12-381 sumcheck round
/// polynomials: <c>Compress</c> drops the linear term, <c>Decompress</c>
/// reconstructs it from the running sumcheck claim.
/// </summary>
/// <remarks>
/// <para>
/// The compression is lossless conditioned on the sumcheck identity
/// <c>e = poly(0) + poly(1)</c> being supplied at decompress time. Both
/// prover and verifier track that running claim by construction, so the
/// identity always holds across one honest round.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
[SuppressMessage("Naming", "CA1708", Justification = "C# 14 extension blocks for two distinct receiver types (Polynomial, CompressedRoundPolynomial) are surfaced under the same nested member name; both receivers are clearly distinct types and the rule is a false positive for extension-block-bearing classes.")]
public static class CompressedRoundPolynomialArithmeticExtensions
{
    extension(Polynomial polynomial)
    {
        /// <summary>
        /// Drops the linear-term coefficient of a univariate polynomial,
        /// returning a <see cref="CompressedRoundPolynomial"/> over the same
        /// remaining coefficients in storage order
        /// <c>(c_0, c_2, c_3, ..., c_d)</c>.
        /// </summary>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A compressed round polynomial of the same algebraic degree.</returns>
        /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the receiver is not over BLS12-381 or has storage degree less than 2.</exception>
        public CompressedRoundPolynomial Compress(SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(polynomial);
            ArgumentNullException.ThrowIfNull(pool);

            WellKnownCurves.ThrowIfCurveNotWired(polynomial.Curve);

            CurveParameterSet curve = polynomial.Curve;
            if(polynomial.Degree < 2)
            {
                throw new ArgumentException(
                    $"Compression requires a polynomial of degree at least 2; received degree {polynomial.Degree}. The linear term cannot be elided when there is no higher-degree term to reconstruct against.");
            }

            int elementSize = polynomial.FieldElementSizeBytes;
            int degree = polynomial.Degree;
            int compressedLength = degree * elementSize;

            IMemoryOwner<byte> owner = pool.Rent(compressedLength);
            Span<byte> destination = owner.Memory.Span[..compressedLength];
            ReadOnlySpan<byte> source = polynomial.AsReadOnlySpan();

            //Copy c_0 into storage slot 0.
            source[..elementSize].CopyTo(destination[..elementSize]);

            //Skip c_1 (the linear term); copy c_2 through c_d into storage
            //slots 1 through degree - 1.
            for(int k = 2; k <= degree; k++)
            {
                source.Slice(k * elementSize, elementSize)
                    .CopyTo(destination.Slice((k - 1) * elementSize, elementSize));
            }

            Tag tag = Tag.Create(
                (typeof(AlgebraicRole), (object)AlgebraicRole.CompressedRoundPolynomial),
                (typeof(CurveParameterSet), (object)curve),
                (typeof(CompressedRoundPolynomialDegree), (object)new CompressedRoundPolynomialDegree(degree)));

            return new CompressedRoundPolynomial(owner, degree, elementSize, curve, tag);
        }
    }


    extension(CompressedRoundPolynomial compressed)
    {
        /// <summary>
        /// Reconstructs the full polynomial from its compressed form and
        /// the running sumcheck claim. The linear term is recovered as
        /// <c>c_1 = claim − 2·c_0 − c_2 − c_3 − … − c_d</c>; the remaining
        /// coefficients are copied from the compressed storage.
        /// </summary>
        /// <param name="claim">The sumcheck claim satisfying <c>claim = poly(0) + poly(1)</c>.</param>
        /// <param name="subtract">The scalar-subtract backend.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A <see cref="Polynomial"/> with storage degree equal to the compressed polynomial's algebraic degree.</returns>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the receiver is not over BLS12-381.</exception>
        public Polynomial Decompress(
            Scalar claim,
            ScalarSubtractDelegate subtract,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(compressed);
            ArgumentNullException.ThrowIfNull(claim);
            ArgumentNullException.ThrowIfNull(subtract);
            ArgumentNullException.ThrowIfNull(pool);

            WellKnownCurves.ThrowIfCurveNotWired(compressed.Curve);

            CurveParameterSet curve = compressed.Curve;

            int elementSize = compressed.FieldElementSizeBytes;
            int degree = compressed.Degree;
            int decompressedLength = (degree + 1) * elementSize;

            IMemoryOwner<byte> destinationOwner = pool.Rent(decompressedLength);
            Span<byte> destination = destinationOwner.Memory.Span[..decompressedLength];
            ReadOnlySpan<byte> source = compressed.AsReadOnlySpan();
            ReadOnlySpan<byte> constantTerm = source[..elementSize];

            //Slot 0: c_0. Copy directly.
            constantTerm.CopyTo(destination[..elementSize]);

            //Slots 2..degree: c_2, c_3, ..., c_d. Copy from compressed slots
            //1..degree - 1.
            for(int k = 2; k <= degree; k++)
            {
                source.Slice((k - 1) * elementSize, elementSize)
                    .CopyTo(destination.Slice(k * elementSize, elementSize));
            }

            //Slot 1: c_1 = claim - 2*c_0 - c_2 - c_3 - ... - c_d. Compute
            //in-place in the slot-1 region of destination so the linear
            //term reaches its final location without an extra copy.
            Span<byte> linearSlot = destination.Slice(elementSize, elementSize);
            claim.AsReadOnlySpan().CopyTo(linearSlot);
            subtract(linearSlot, constantTerm, linearSlot, curve);
            subtract(linearSlot, constantTerm, linearSlot, curve);
            for(int k = 2; k <= degree; k++)
            {
                ReadOnlySpan<byte> coefficient = destination.Slice(k * elementSize, elementSize);
                subtract(linearSlot, coefficient, linearSlot, curve);
            }

            Tag tag = Tag.Create(
                (typeof(AlgebraicRole), (object)AlgebraicRole.PolynomialCoefficients),
                (typeof(CurveParameterSet), (object)curve),
                (typeof(PolynomialDegree), (object)new PolynomialDegree(degree)));

            return new Polynomial(destinationOwner, degree, elementSize, curve, tag);
        }
    }


}