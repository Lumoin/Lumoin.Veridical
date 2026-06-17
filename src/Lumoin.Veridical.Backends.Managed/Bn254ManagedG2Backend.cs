using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The public composition root for BN254 G2 group arithmetic: assembles a
/// <see cref="G2ArithmeticBackend"/> over the portable BigInteger reference. An
/// application calls <see cref="Create"/> once and passes the bundle's delegates
/// into the protocol code.
/// </summary>
/// <remarks>
/// The underlying implementation remains internal — callers compose through this
/// factory and the <see cref="G2ArithmeticBackend"/> bundle. The arithmetic is
/// correctness-first BigInteger over the Fp2 twist; it is not constant-time and not
/// hardware-accelerated.
/// </remarks>
public static class Bn254ManagedG2Backend
{
    /// <summary>
    /// Builds the BN254 G2 backend bundle: add, negate, scalar-multiply, and the
    /// on-curve and prime-order-subgroup predicates, from the BigInteger reference.
    /// </summary>
    public static G2ArithmeticBackend Create()
    {
        return new G2ArithmeticBackend(
            CurveParameterSet.Bn254,
            Bn254BigIntegerG2Reference.GetAdd(),
            Bn254BigIntegerG2Reference.GetNegate(),
            Bn254BigIntegerG2Reference.GetScalarMultiply(),
            Bn254BigIntegerG2Reference.GetIsOnCurve(),
            Bn254BigIntegerG2Reference.GetIsInPrimeOrderSubgroup());
    }
}
