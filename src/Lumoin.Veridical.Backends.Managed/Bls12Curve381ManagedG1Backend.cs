using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The public composition root for BLS12-381 G1 group arithmetic: assembles a
/// <see cref="G1ArithmeticBackend"/> over the portable BigInteger reference for the
/// single-operation group law and the Pippenger bucket method for multi-scalar
/// multiplication. An application calls <see cref="Create"/> once and passes the
/// bundle's delegates into the protocol code.
/// </summary>
/// <remarks>
/// <para>
/// The underlying implementations remain internal — callers compose through this
/// factory and the <see cref="G1ArithmeticBackend"/> bundle rather than naming a
/// specific reference. Scalar multiplication — the one group operation that takes a
/// secret scalar at the BBS signing and proof seams — runs through the constant-time
/// ladder; the remaining operations (add, negate, multi-scalar multiplication, the
/// predicates) take only public inputs and are not constant-time. The
/// prime-order-subgroup predicate runs the endomorphism test of
/// <see cref="Bls12Curve381EndomorphismG1Backend"/> (agreement-gated against the
/// BigInteger reference's naive <c>[r]P == O</c> test over the off-subgroup torsion
/// corpus); the other predicates stay on the correctness-first BigInteger reference
/// and the Pippenger bucket method. Nothing is hardware-accelerated.
/// </para>
/// <para>
/// Hash-to-curve is ciphersuite-keyed, so it is exposed as the explicit
/// <see cref="GetHashToCurveSha256"/> and <see cref="GetHashToCurveShake256"/>
/// factories rather than baked into the ciphersuite-agnostic group bundle.
/// </para>
/// </remarks>
public static class Bls12Curve381ManagedG1Backend
{
    /// <summary>
    /// Builds the BLS12-381 G1 backend bundle: add and negate from the BigInteger
    /// reference, scalar-multiply from the constant-time ladder (byte-identical to
    /// the reference, agreement-gated), multi-scalar multiplication from the caching
    /// Pippenger backend, the on-curve predicate from the BigInteger reference, and
    /// the prime-order-subgroup predicate from the endomorphism test
    /// (agreement-gated against the reference's naive test).
    /// </summary>
    public static G1ArithmeticBackend Create()
    {
        return new G1ArithmeticBackend(
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381BigIntegerG1Reference.GetAdd(),
            Bls12Curve381BigIntegerG1Reference.GetNegate(),
            Bls12Curve381ConstantTimeG1Backend.GetScalarMultiply(),
            Bls12Curve381PippengerG1Backend.CreateCachingMultiScalarMultiply(),
            Bls12Curve381BigIntegerG1Reference.GetIsOnCurve(),
            Bls12Curve381EndomorphismG1Backend.GetIsInPrimeOrderSubgroup());
    }


    /// <summary>The G1 hash-to-curve for the BLS12-381-SHA-256 ciphersuite (RFC 9380 XMD-SHA-256 SSWU_RO).</summary>
    public static G1HashToCurveDelegate GetHashToCurveSha256()
    {
        return Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    }


    /// <summary>The G1 hash-to-curve for the BLS12-381-SHAKE-256 ciphersuite (RFC 9380 XOF-SHAKE-256 SSWU_RO).</summary>
    public static G1HashToCurveDelegate GetHashToCurveShake256()
    {
        return Bls12Curve381BigIntegerG1Reference.GetHashToCurveShake256();
    }
}
