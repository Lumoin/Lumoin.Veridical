using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members that compose a G1 point with a G2 point through a
/// backend-supplied <see cref="PairingDelegate"/> to produce the pairing value
/// as a fresh <see cref="Fp12Element"/>.
/// </summary>
/// <remarks>
/// <para>
/// The pairing is the only operation in this library that consumes elements
/// from three different leaf types at once (G1, G2, the field-tower target),
/// so it lives in its own extension file rather than being grafted onto the
/// G1 or G2 arithmetic extensions.
/// </para>
/// <para>
/// The extension method is hung off G1 by convention — reading
/// <c>g1.PairWith(g2, …)</c> at a call site keeps the argument order in step
/// with the mathematical convention <c>e(P, Q)</c>. Both operands must be on
/// the same curve; the runtime check replaces the compile-time guarantee the
/// per-curve leaf types used to give. The Fp12 target type is unified in a
/// later sub-batch.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class PairingExtensions
{
    extension(G1Point p)
    {
        /// <summary>
        /// Returns the pairing <c>e(p, q) ∈ Fp12</c> produced by the supplied
        /// <paramref name="pairing"/> delegate.
        /// </summary>
        /// <param name="q">The G2 right-hand operand.</param>
        /// <param name="pairing">The backend pairing implementation.</param>
        /// <param name="pool">The pool to rent the destination Fp12 buffer from.</param>
        /// <returns>An <see cref="Fp12Element"/> wrapping the freshly computed canonical-form pairing value.</returns>
        /// <exception cref="ArgumentException">When the operands are on different curves.</exception>
        public Fp12Element PairWith(
            G2Point q,
            PairingDelegate pairing,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(p);
            ArgumentNullException.ThrowIfNull(q);
            ArgumentNullException.ThrowIfNull(pairing);
            ArgumentNullException.ThrowIfNull(pool);
            if(p.Curve.Code != q.Curve.Code)
            {
                throw new ArgumentException(
                    $"Cannot pair operands over different curves: {p.Curve} and {q.Curve}.");
            }

            //Result size comes from the operands' curve, not a fixed BLS12-381
            //constant — the same curve-broadening the Fp tower extensions needed
            //in U.4 (the pairing target is an Fp12 element, sized per curve).
            int fp12Size = WellKnownCurves.GetFp12SizeBytes(p.Curve);
            IMemoryOwner<byte> owner = pool.Rent(fp12Size);
            pairing(
                p.AsReadOnlySpan(),
                q.AsReadOnlySpan(),
                owner.Memory.Span[..fp12Size],
                p.Curve);

            return new Fp12Element(owner, p.Curve, WellKnownAlgebraicTags.ExtensionFieldElementFor(p.Curve));
        }
    }
}