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
/// factory and the <see cref="G1ArithmeticBackend"/> bundle. Scalar multiplication —
/// the one group operation that may take a secret prover-side scalar — runs through
/// the constant-time ladder; the remaining operations (add, negate, multi-scalar
/// multiplication, the predicates) stay on the correctness-first BigInteger
/// reference and the Pippenger bucket method, which are not constant-time. Nothing
/// is hardware-accelerated. BN254 ships a single hash-to-curve, exposed as
/// <see cref="GetHashToCurve"/>.
/// </remarks>
public static class Bn254ManagedG1Backend
{
    /// <summary>
    /// Builds the BN254 G1 backend bundle: add and negate from the BigInteger
    /// reference, scalar-multiply from the constant-time ladder (byte-identical to
    /// the reference, agreement-gated), multi-scalar multiplication from the caching
    /// Pippenger backend, and the on-curve and prime-order-subgroup predicates.
    /// </summary>
    public static G1ArithmeticBackend Create()
    {
        return new G1ArithmeticBackend(
            CurveParameterSet.Bn254,
            Bn254BigIntegerG1Reference.GetAdd(),
            Bn254BigIntegerG1Reference.GetNegate(),
            Bn254ConstantTimeG1Backend.GetScalarMultiply(),
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
