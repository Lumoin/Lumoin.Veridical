using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The public composition root for BN254 G1 group arithmetic: assembles a
/// <see cref="G1ArithmeticBackend"/> over the portable BigInteger reference for the
/// single-operation group law and the Pippenger bucket method for multi-scalar
/// multiplication. An application calls <see cref="Create"/> once and passes the
/// bundle's delegates into the protocol code.
/// </summary>
/// <remarks>
/// The underlying implementations remain internal — callers compose through this
/// factory and the <see cref="G1ArithmeticBackend"/> bundle. The arithmetic is
/// correctness-first BigInteger; it is not constant-time and not hardware-
/// accelerated. BN254 ships a single hash-to-curve, exposed as
/// <see cref="GetHashToCurve"/>.
/// </remarks>
public static class Bn254ManagedG1Backend
{
    /// <summary>
    /// Builds the BN254 G1 backend bundle: add, negate, and scalar-multiply from the
    /// BigInteger reference, multi-scalar multiplication from the caching Pippenger
    /// backend, and the on-curve and prime-order-subgroup predicates.
    /// </summary>
    public static G1ArithmeticBackend Create()
    {
        return new G1ArithmeticBackend(
            CurveParameterSet.Bn254,
            Bn254BigIntegerG1Reference.GetAdd(),
            Bn254BigIntegerG1Reference.GetNegate(),
            Bn254BigIntegerG1Reference.GetScalarMultiply(),
            Bn254PippengerG1Backend.CreateCachingMultiScalarMultiply(),
            Bn254BigIntegerG1Reference.GetIsOnCurve(),
            Bn254BigIntegerG1Reference.GetIsInPrimeOrderSubgroup());
    }


    /// <summary>The BN254 G1 hash-to-curve.</summary>
    public static G1HashToCurveDelegate GetHashToCurve()
    {
        return Bn254BigIntegerG1Reference.GetHashToCurve();
    }
}
