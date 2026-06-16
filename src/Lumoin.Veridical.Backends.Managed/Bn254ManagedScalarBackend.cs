using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Algebraic;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The public composition root for BN254 scalar-field arithmetic, the symmetric
/// counterpart of <see cref="Bls12Curve381ManagedScalarBackend"/>. When the host
/// supports any SIMD instruction set the dispatch facade covers, the field
/// operations (add, subtract, multiply, negate, invert, and the batch forms) come
/// from SIMD and <see cref="ScalarArithmeticBackend.IsHardwareAccelerated"/> is
/// <see langword="true"/>; otherwise every operation is the portable BigInteger
/// reference. Reduce, random, and hash-to-scalar have no SIMD form.
/// </summary>
/// <remarks>
/// BN254 has no baked-in hash-to-scalar expand-message function (its reference takes
/// one as a parameter), so the bundle's <see cref="ScalarArithmeticBackend.HashToScalar"/>
/// is <see langword="null"/>; a caller needing hash-to-scalar wires it explicitly.
/// </remarks>
public static class Bn254ManagedScalarBackend
{
    /// <summary>Builds the BN254 scalar backend bundle: SIMD field operations when supported, BigInteger reference otherwise and for reduce/random/hash.</summary>
    public static ScalarArithmeticBackend Create()
    {
        bool simd = Bn254SimdScalarBackend.IsSupported;

        ScalarAddDelegate add = simd
            ? Bn254SimdScalarBackend.GetAdd()
            : Bn254BigIntegerScalarReference.GetAdd();
        ScalarSubtractDelegate subtract = simd
            ? Bn254SimdScalarBackend.GetSubtract()
            : Bn254BigIntegerScalarReference.GetSubtract();
        ScalarMultiplyDelegate multiply = simd
            ? Bn254SimdScalarBackend.GetMultiply()
            : Bn254BigIntegerScalarReference.GetMultiply();
        ScalarNegateDelegate negate = simd
            ? Bn254SimdScalarBackend.GetNegate()
            : Bn254BigIntegerScalarReference.GetNegate();
        ScalarInvertDelegate invert = simd
            ? Bn254SimdScalarBackend.GetInvert()
            : Bn254BigIntegerScalarReference.GetInvert();
        ScalarBatchAddDelegate batchAdd = simd
            ? Bn254SimdScalarBackend.GetBatchAdd()
            : Bn254BigIntegerScalarReference.GetBatchAdd();
        ScalarBatchSubtractDelegate batchSubtract = simd
            ? Bn254SimdScalarBackend.GetBatchSubtract()
            : Bn254BigIntegerScalarReference.GetBatchSubtract();
        ScalarBatchMultiplyDelegate batchMultiply = simd
            ? Bn254SimdScalarBackend.GetBatchMultiply()
            : Bn254BigIntegerScalarReference.GetBatchMultiply();

        return new ScalarArithmeticBackend(
            CurveParameterSet.Bn254,
            Bn254BigIntegerScalarReference.GetReduce(),
            add,
            subtract,
            multiply,
            negate,
            invert,
            Bn254BigIntegerScalarReference.GetRandom(),
            batchAdd,
            batchSubtract,
            batchMultiply,
            hashToScalar: null,
            isHardwareAccelerated: simd);
    }
}
