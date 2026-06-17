using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The public composition root for BLS12-381 G2 group arithmetic: assembles a
/// <see cref="G2ArithmeticBackend"/> over the portable BigInteger reference. An
/// application calls <see cref="Create"/> once and passes the bundle's delegates
/// into the protocol code (for example BBS+ verification).
/// </summary>
/// <remarks>
/// The underlying implementation remains internal — callers compose through this
/// factory and the <see cref="G2ArithmeticBackend"/> bundle. The arithmetic is
/// correctness-first BigInteger over the Fp2 twist; it is not constant-time and not
/// hardware-accelerated.
/// </remarks>
public static class Bls12Curve381ManagedG2Backend
{
    /// <summary>
    /// Builds the BLS12-381 G2 backend bundle: add, negate, scalar-multiply, and the
    /// on-curve and prime-order-subgroup predicates, from the BigInteger reference.
    /// </summary>
    public static G2ArithmeticBackend Create()
    {
        return new G2ArithmeticBackend(
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381BigIntegerG2Reference.GetAdd(),
            Bls12Curve381BigIntegerG2Reference.GetNegate(),
            Bls12Curve381BigIntegerG2Reference.GetScalarMultiply(),
            Bls12Curve381BigIntegerG2Reference.GetIsOnCurve(),
            Bls12Curve381BigIntegerG2Reference.GetIsInPrimeOrderSubgroup());
    }
}
