using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Typed accessors that materialise <see cref="SpartanProof"/> byte
/// slices as leaf-typed instances. Each call rents a fresh pool buffer
/// and copies the relevant slice; the originating <see cref="SpartanProof"/>
/// remains the canonical owner of the combined bytes.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class SpartanProofExtensions
{
    extension(SpartanProof proof)
    {
        /// <summary>
        /// Materialises the outer-sumcheck terminating <c>(Az(r_x), Bz(r_x), Cz(r_x))</c>
        /// triple as three fresh BLS12-381 scalars.
        /// </summary>
        /// <param name="pool">The pool to rent the destination buffers from.</param>
        /// <returns>A tuple of three scalars; the caller owns their lifetime.</returns>
        [SuppressMessage("Reliability", "CA2000", Justification = "All three returned scalars take ownership of their pool-rented buffers and are returned to the caller for disposal.")]
        public (Scalar Az, Scalar Bz, Scalar Cz) GetOuterClaims(BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(pool);

            var az = Scalar.FromCanonical(proof.GetClaimAzBytes(), proof.Curve, pool);
            Scalar bz;
            Scalar cz;
            try
            {
                bz = Scalar.FromCanonical(proof.GetClaimBzBytes(), proof.Curve, pool);
            }
            catch
            {
                az.Dispose();
                throw;
            }
            try
            {
                cz = Scalar.FromCanonical(proof.GetClaimCzBytes(), proof.Curve, pool);
            }
            catch
            {
                az.Dispose();
                bz.Dispose();
                throw;
            }


            return (az, bz, cz);
        }


        /// <summary>
        /// Materialises the witness MLE evaluation <c>eval_W</c> as a
        /// fresh BLS12-381 scalar.
        /// </summary>
        public Scalar GetEvalW(BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(pool);

            return Scalar.FromCanonical(proof.GetEvalWBytes(), proof.Curve, pool);
        }


        /// <summary>
        /// Materialises the outer sumcheck round at <paramref name="roundIndex"/>
        /// as a fresh <see cref="CompressedRoundPolynomial"/>.
        /// </summary>
        public CompressedRoundPolynomial GetOuterSumcheckRound(int roundIndex, BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(pool);

            return CompressedRoundPolynomial.FromCompressedBytes(
                proof.GetOuterRoundCompressedBytes(roundIndex),
                degree: 3,
                proof.Curve,
                pool);
        }


        /// <summary>
        /// Materialises the inner sumcheck round at <paramref name="roundIndex"/>
        /// as a fresh <see cref="CompressedRoundPolynomial"/>.
        /// </summary>
        public CompressedRoundPolynomial GetInnerSumcheckRound(int roundIndex, BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(pool);

            return CompressedRoundPolynomial.FromCompressedBytes(
                proof.GetInnerRoundCompressedBytes(roundIndex),
                degree: 2,
                proof.Curve,
                pool);
        }
    }
}