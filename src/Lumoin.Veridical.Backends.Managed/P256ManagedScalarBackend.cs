using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The public composition root for NIST P-256 (secp256r1) scalar-field (signature
/// field, mod <c>n</c>) arithmetic — the counterpart of
/// <see cref="Bls12Curve381ManagedScalarBackend"/> and
/// <see cref="Bn254ManagedScalarBackend"/>. The secret-sensitive operations come from
/// the constant-time managed <see cref="P256ScalarMontgomeryBackend"/> (closing the
/// SECDSA/ECDSA timing leak the variable-time <c>BigInteger.ModPow</c> inversion and
/// branchy <see cref="BigInteger"/> arithmetic carried); this is portable managed code,
/// not SIMD, so <see cref="ScalarArithmeticBackend.IsHardwareAccelerated"/> stays
/// <see langword="false"/>.
/// </summary>
/// <remarks>
/// Only <c>Random</c> stays on the <see cref="P256BigIntegerScalarReference"/> path — it
/// is CSPRNG rejection sampling over the public order, not arithmetic over a secret, so
/// its branchiness leaks nothing. The constant-time backend is byte-identical to the
/// reference on every operation (agreement-gated), so the rewire is observationally
/// transparent. P-256 has no baked-in hash-to-scalar expand-message function (its
/// reference takes one as a parameter), so the bundle's
/// <see cref="ScalarArithmeticBackend.HashToScalar"/> is <see langword="null"/>; a caller
/// needing hash-to-scalar wires it explicitly. This supplies the scalar arithmetic that
/// the group-only <see cref="P256ManagedG1Backend"/> does not, completing the P-256
/// surface an external ECDSA / SECDSA consumer needs.
/// </remarks>
public static class P256ManagedScalarBackend
{
    /// <summary>
    /// Builds the P-256 scalar backend bundle: the secret-sensitive operations (reduce, add, subtract,
    /// multiply, negate, invert, and the batch forms) from the constant-time
    /// <see cref="P256ScalarMontgomeryBackend"/>, and random sampling from the BigInteger reference.
    /// </summary>
    public static ScalarArithmeticBackend Create()
    {
        return new ScalarArithmeticBackend(
            CurveParameterSet.P256,
            P256ScalarMontgomeryBackend.GetReduce(),
            P256ScalarMontgomeryBackend.GetAdd(),
            P256ScalarMontgomeryBackend.GetSubtract(),
            P256ScalarMontgomeryBackend.GetMultiply(),
            P256ScalarMontgomeryBackend.GetNegate(),
            P256ScalarMontgomeryBackend.GetInvert(),
            P256BigIntegerScalarReference.GetRandom(),
            P256ScalarMontgomeryBackend.GetBatchAdd(),
            P256ScalarMontgomeryBackend.GetBatchSubtract(),
            P256ScalarMontgomeryBackend.GetBatchMultiply(),
            hashToScalar: null,
            isHardwareAccelerated: false);
    }
}
