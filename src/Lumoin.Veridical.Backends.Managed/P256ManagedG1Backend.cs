using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The public composition root for NIST P-256 (secp256r1) group arithmetic:
/// assembles a <see cref="G1ArithmeticBackend"/> over the portable BigInteger
/// reference. An application calls <see cref="Create"/> once and passes the bundle's
/// delegates into the protocol code (for example ECDSA / SECDSA point operations).
/// </summary>
/// <remarks>
/// The underlying implementation remains internal — callers compose through this
/// factory and the <see cref="G1ArithmeticBackend"/> bundle. The arithmetic is
/// correctness-first BigInteger; it is not constant-time and not hardware-
/// accelerated, and its multi-scalar multiplication is the reference's naive
/// accumulate (P-256 has no Pippenger backend). P-256 is not a pairing curve and has
/// no G2 or pairing backend; its reference does not surface the membership predicates
/// as delegates (P-256 has cofactor 1, so subgroup membership is just on-curve, and
/// the on-curve test exists internally only for decode validation), so
/// <see cref="G1ArithmeticBackend.IsOnCurve"/> and
/// <see cref="G1ArithmeticBackend.IsInPrimeOrderSubgroup"/> are <see langword="null"/>.
/// It supplies only the group law; scalar-field (mod n) arithmetic for ECDSA / SECDSA
/// comes from <see cref="P256ManagedScalarBackend"/>.
/// </remarks>
public static class P256ManagedG1Backend
{
    /// <summary>Builds the P-256 G1 backend bundle: add, negate, scalar-multiply, and multi-scalar multiplication from the BigInteger reference.</summary>
    public static G1ArithmeticBackend Create()
    {
        return new G1ArithmeticBackend(
            CurveParameterSet.P256,
            P256BigIntegerG1Reference.GetAdd(),
            P256BigIntegerG1Reference.GetNegate(),
            P256BigIntegerG1Reference.GetScalarMultiply(),
            P256BigIntegerG1Reference.GetMultiScalarMultiply());
    }
}
