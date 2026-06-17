using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The public composition root for NIST P-256 (secp256r1) scalar-field (signature
/// field, mod <c>n</c>) arithmetic — the counterpart of
/// <see cref="Bls12Curve381ManagedScalarBackend"/> and
/// <see cref="Bn254ManagedScalarBackend"/>. P-256 has no SIMD scalar backend, so every
/// operation is the portable BigInteger reference and
/// <see cref="ScalarArithmeticBackend.IsHardwareAccelerated"/> is always
/// <see langword="false"/>.
/// </summary>
/// <remarks>
/// P-256 has no baked-in hash-to-scalar expand-message function (its reference takes
/// one as a parameter), so the bundle's <see cref="ScalarArithmeticBackend.HashToScalar"/>
/// is <see langword="null"/>; a caller needing hash-to-scalar wires it explicitly. This
/// supplies the scalar arithmetic that the group-only <see cref="P256ManagedG1Backend"/>
/// does not, completing the P-256 surface an external ECDSA / SECDSA consumer needs.
/// </remarks>
public static class P256ManagedScalarBackend
{
    /// <summary>Builds the P-256 scalar backend bundle entirely from the BigInteger reference (add, subtract, multiply, negate, invert, reduce, random, and the batch forms).</summary>
    public static ScalarArithmeticBackend Create()
    {
        return new ScalarArithmeticBackend(
            CurveParameterSet.P256,
            P256BigIntegerScalarReference.GetReduce(),
            P256BigIntegerScalarReference.GetAdd(),
            P256BigIntegerScalarReference.GetSubtract(),
            P256BigIntegerScalarReference.GetMultiply(),
            P256BigIntegerScalarReference.GetNegate(),
            P256BigIntegerScalarReference.GetInvert(),
            P256BigIntegerScalarReference.GetRandom(),
            P256BigIntegerScalarReference.GetBatchAdd(),
            P256BigIntegerScalarReference.GetBatchSubtract(),
            P256BigIntegerScalarReference.GetBatchMultiply(),
            hashToScalar: null,
            isHardwareAccelerated: false);
    }
}
