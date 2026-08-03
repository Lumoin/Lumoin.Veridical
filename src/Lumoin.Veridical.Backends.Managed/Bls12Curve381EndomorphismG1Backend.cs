using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Endomorphism-based prime-order-subgroup membership test for BLS12-381 G1
/// (M. Scott, "A note on group membership tests for G1, G2 and GT on BLS
/// pairing-friendly curves", IACR ePrint 2021/1130, section 6): a candidate
/// point <c>P</c> is accepted iff <c>ψ(P) = [−u²]P</c>, where
/// <c>ψ(x, y) = (β·x, y)</c> for the cube root of unity <c>β</c> paired with
/// the eigenvalue <c>λ = −u²</c>, and <c>u</c> is the BLS parameter. The
/// scalar <c>u²</c> is 128 bits against the naive test's 255-bit group
/// order, roughly halving the dominant scalar-multiplication cost.
/// </summary>
/// <remarks>
/// <para>
/// Soundness holds on the whole curve group of order <c>h·r</c> and does not
/// depend on the choice of <c>β</c>: the automorphism <c>ψ</c> has order 3 in
/// the endomorphism ring, which is an integral domain, so
/// <c>ψ² + ψ + 1 = 0</c> identically. An accepting point therefore satisfies
/// <c>ψ²(P) = [u⁴]P</c> and
/// <c>O = ψ²(P) + ψ(P) + P = [u⁴ − u² + 1]P = [r]P</c>, forcing <c>P</c> into
/// the <c>r</c>-torsion. Pairing <c>ψ</c> with the wrong cube root can only
/// break completeness — honest points rejected — which the eigenvalue pin on
/// the canonical generator catches loudly; it can never accept an
/// off-subgroup point. The agreement suite additionally locks this test to
/// the reference's naive <c>[r]P == O</c> predicate over the off-subgroup
/// torsion corpus (points of every prime order dividing the cofactor) and
/// honest generator multiples.
/// </para>
/// <para>
/// The identity is a subgroup member and accepted, and undecodable or
/// off-curve input is rejected, both matching the reference predicate. The
/// test takes only public verify-time inputs, so like the reference
/// predicates it is not constant-time.
/// </para>
/// </remarks>
internal static class Bls12Curve381EndomorphismG1Backend
{
    /// <summary>
    /// The cube root of unity modulo the base field prime that realises the
    /// eigenvalue <c>λ = −u² mod r</c> on the prime-order subgroup, so that
    /// <c>ψ(P) = (β·x, y) = [−u²]P</c> holds exactly for subgroup members.
    /// The other non-trivial root realises <c>u² − 1</c> (the pairing used by
    /// S. Bowe, IACR ePrint 2019/814); both satisfy <c>β² + β + 1 ≡ 0 mod p</c>,
    /// which the test suite pins together with the generator eigenvalue.
    /// </summary>
    internal static BigInteger Beta { get; } = BigInteger.Parse(
        "5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    /// <summary>
    /// The square of the BLS parameter, <c>u² = 0xd201000000010000²</c>. The
    /// leading hex digit of the literal is padded with a zero so the parse is
    /// positive.
    /// </summary>
    internal static BigInteger USquared { get; } = BigInteger.Parse(
        "0ac45a4010001a4020000000100000000",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    /// <summary>Returns the endomorphism-based G1 prime-order-subgroup validation delegate.</summary>
    public static G1IsInPrimeOrderSubgroupDelegate GetIsInPrimeOrderSubgroup() => IsInPrimeOrderSubgroup;


    private static bool IsInPrimeOrderSubgroup(ReadOnlySpan<byte> point, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1IsInPrimeOrderSubgroup, curve);

        if(!Bls12Curve381BigIntegerG1Reference.TryDecode(point, out Bls12Curve381BigIntegerG1Reference.AffinePoint p))
        {
            return false;
        }

        if(p.IsInfinity)
        {
            return true;
        }

        //psi(P) = (beta*x, y). TryDecode guarantees x in [0, p) and Beta is a
        //positive canonical residue, so the raw % is an exact field reduction;
        //the group order is odd so no finite point has y = 0 and the negation
        //below never degenerates. [u^2]P stays finite for every finite P
        //because u^2 is coprime to the group exponent, and if a backend change
        //ever violated that the hardcoded IsInfinity: false on psi makes the
        //record comparison reject rather than accept.
        var psi = new Bls12Curve381BigIntegerG1Reference.AffinePoint(
            p.X * Beta % Bls12Curve381BigIntegerG1Reference.BaseFieldPrime,
            p.Y,
            IsInfinity: false);
        Bls12Curve381BigIntegerG1Reference.AffinePoint minusUSquaredP =
            Bls12Curve381BigIntegerG1Reference.PointNegate(
                Bls12Curve381BigIntegerG1Reference.ScalarMultiplyPoint(USquared, p));

        return psi == minusUSquaredP;
    }
}
