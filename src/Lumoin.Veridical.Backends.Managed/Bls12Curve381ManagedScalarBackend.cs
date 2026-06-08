using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Algebraic;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The public composition root for BLS12-381 scalar-field arithmetic: assembles a
/// <see cref="ScalarArithmeticBackend"/> that uses the per-ISA SIMD backends for
/// every field operation they implement (add, subtract, multiply, negate, invert,
/// and the batch forms) when the host supports SIMD, and the portable BigInteger
/// reference for the rest (reduce, random, hash-to-scalar). An application calls
/// <see cref="Create"/> once and passes the bundle's delegates into the protocol
/// code.
/// </summary>
/// <remarks>
/// <para>
/// The per-ISA backends and the dispatch facade remain internal implementation
/// detail — callers compose through this factory and the
/// <see cref="ScalarArithmeticBackend"/> bundle rather than naming a specific
/// instruction set. The factory is the seam's purpose made concrete: heterogeneous
/// composition, mixing the SIMD field arithmetic with a portable reduce/random/hash
/// that have no SIMD form.
/// </para>
/// <para>
/// Reduce stays on the reference deliberately: it takes a wide (double-width) input
/// and a general reduction is a Barrett-class computation, not the single
/// conditional subtraction the SIMD add/subtract/multiply use on already-bounded
/// operands.
/// </para>
/// <para>
/// WASM PackedSimd is a deliberate non-goal for scalar arithmetic: there is no
/// PackedSimd scalar backend (only the BLAKE3 hash path uses it), and adding one
/// would only inflate surface that cannot execute under the standard test host.
/// </para>
/// </remarks>
public static class Bls12Curve381ManagedScalarBackend
{
    /// <summary>
    /// Builds the BLS12-381 scalar backend bundle. When the host supports any SIMD
    /// instruction set the dispatch facade covers, the field operations (add,
    /// subtract, multiply, negate, invert, and the batch forms) come from SIMD and
    /// <see cref="ScalarArithmeticBackend.IsHardwareAccelerated"/> is
    /// <see langword="true"/>; otherwise every operation is the BigInteger reference.
    /// Reduce, random, and hash-to-scalar are always the BigInteger reference (they
    /// have no SIMD form).
    /// </summary>
    public static ScalarArithmeticBackend Create()
    {
        bool simd = Bls12Curve381SimdScalarBackend.IsSupported;

        ScalarAddDelegate add = simd
            ? Bls12Curve381SimdScalarBackend.GetAdd()
            : Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarSubtractDelegate subtract = simd
            ? Bls12Curve381SimdScalarBackend.GetSubtract()
            : Bls12Curve381BigIntegerScalarReference.GetSubtract();
        ScalarMultiplyDelegate multiply = simd
            ? Bls12Curve381SimdScalarBackend.GetMultiply()
            : Bls12Curve381BigIntegerScalarReference.GetMultiply();
        ScalarNegateDelegate negate = simd
            ? Bls12Curve381SimdScalarBackend.GetNegate()
            : Bls12Curve381BigIntegerScalarReference.GetNegate();
        ScalarInvertDelegate invert = simd
            ? Bls12Curve381SimdScalarBackend.GetInvert()
            : Bls12Curve381BigIntegerScalarReference.GetInvert();
        ScalarBatchAddDelegate batchAdd = simd
            ? Bls12Curve381SimdScalarBackend.GetBatchAdd()
            : Bls12Curve381BigIntegerScalarReference.GetBatchAdd();
        ScalarBatchSubtractDelegate batchSubtract = simd
            ? Bls12Curve381SimdScalarBackend.GetBatchSubtract()
            : Bls12Curve381BigIntegerScalarReference.GetBatchSubtract();
        ScalarBatchMultiplyDelegate batchMultiply = simd
            ? Bls12Curve381SimdScalarBackend.GetBatchMultiply()
            : Bls12Curve381BigIntegerScalarReference.GetBatchMultiply();

        return new ScalarArithmeticBackend(
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            add,
            subtract,
            multiply,
            negate,
            invert,
            Bls12Curve381BigIntegerScalarReference.GetRandom(),
            batchAdd,
            batchSubtract,
            batchMultiply,
            Bls12Curve381BigIntegerScalarReference.GetHashToScalar(),
            isHardwareAccelerated: simd);
    }
}
