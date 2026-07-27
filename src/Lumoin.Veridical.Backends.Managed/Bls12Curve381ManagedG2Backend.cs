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
/// factory and the <see cref="G2ArithmeticBackend"/> bundle. Scalar multiplication —
/// the one G2 operation that takes a secret scalar at the BBS key-generation seam —
/// runs through the constant-time ladder; the remaining operations take only public
/// inputs and stay on the correctness-first BigInteger reference over the Fp2 twist,
/// which is not constant-time. Nothing is hardware-accelerated.
/// </remarks>
public static class Bls12Curve381ManagedG2Backend
{
    /// <summary>
    /// Builds the BLS12-381 G2 backend bundle: add and negate from the BigInteger
    /// reference, scalar-multiply from the constant-time ladder (byte-identical to
    /// the reference, agreement-gated), and the on-curve and prime-order-subgroup
    /// predicates.
    /// </summary>
    public static G2ArithmeticBackend Create()
    {
        return new G2ArithmeticBackend(
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381BigIntegerG2Reference.GetAdd(),
            Bls12Curve381BigIntegerG2Reference.GetNegate(),
            Bls12Curve381ConstantTimeG2Backend.GetScalarMultiply(),
            Bls12Curve381BigIntegerG2Reference.GetIsOnCurve(),
            Bls12Curve381BigIntegerG2Reference.GetIsInPrimeOrderSubgroup());
    }
}
