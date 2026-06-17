using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Runtime selection of the lane-parallel Fp256 Montgomery batch-multiply backend for the signature-circuit
/// batch consumers (the Reed–Solomon encode and the <c>bind_quad</c> reduction). The single place the
/// <c>GetBatchMultiplyMontgomery</c> seam is wired into the Montgomery sig drivers, so the backend choice is
/// centralized.
/// </summary>
internal static class Fp256SimdBackend
{
    /// <summary>
    /// The batched Montgomery-domain multiply the sig-circuit RS <c>Interpolate</c> and the constraint builder's
    /// <c>bind_quad</c> route their scalar-times-vector / per-term reductions through: the AVX-512 octet backend
    /// when the host supports AVX-512, else the AVX2 quartet backend when the host supports AVX2, else
    /// <see langword="null"/> so the caller falls back to the scalar multiply. Both SIMD backends are byte-identical
    /// to the scalar <c>MultiplyMontgomery</c> oracle by construction (the AVX-512 kernel is the lane-width swap of
    /// the AVX2 one). AVX2 is runtime-validated on this hardware by the agreement gate; AVX-512 is HW-GATED (it only
    /// activates on an AVX-512 host) and its agreement gate reports Inconclusive off AVX-512 hardware, so its
    /// runtime byte-identity is pinned when it first runs on AVX-512 HW or an AVX-512 CI runner — the wiring is
    /// preferred-when-supported, validated-on-HW.
    /// </summary>
    public static ScalarBatchMultiplyDelegate? BatchMultiplyMontgomery() =>
        P256BaseFieldMontgomeryBatchBackendAvx512.IsSupported ? P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery()
        : Avx2.IsSupported ? P256BaseFieldMontgomeryBatchBackendAvx2.GetBatchMultiplyMontgomery()
        : null;
}
