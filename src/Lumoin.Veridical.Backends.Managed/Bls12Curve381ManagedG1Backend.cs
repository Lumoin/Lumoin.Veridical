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
/// specific reference. The arithmetic is correctness-first BigInteger (the same
/// ground-truth the production backends are validated against); it is not
/// constant-time and not hardware-accelerated.
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
    /// Builds the BLS12-381 G1 backend bundle: add, negate, and scalar-multiply from
    /// the BigInteger reference, multi-scalar multiplication from the caching
    /// Pippenger backend, and the on-curve and prime-order-subgroup predicates.
    /// </summary>
    public static G1ArithmeticBackend Create()
    {
        return new G1ArithmeticBackend(
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381BigIntegerG1Reference.GetAdd(),
            Bls12Curve381BigIntegerG1Reference.GetNegate(),
            Bls12Curve381BigIntegerG1Reference.GetScalarMultiply(),
            Bls12Curve381PippengerG1Backend.CreateCachingMultiScalarMultiply(),
            Bls12Curve381BigIntegerG1Reference.GetIsOnCurve(),
            Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup());
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
