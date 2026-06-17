using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.Wasm;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Dispatch facade over the per-ISA BN254 SIMD scalar backends, the BN254 mirror of
/// <see cref="Bls12Curve381SimdScalarBackend"/>. Picks the highest-capability backend
/// available on the host CPU and exposes a stable surface for callers that do not
/// care which instruction set is underneath.
/// </summary>
/// <remarks>
/// <para>
/// Capability ordering (highest to lowest): AVX-512F (8-wide), AVX2 (4-wide),
/// AArch64 NEON (2-wide), WebAssembly PackedSimd (2-wide; mutually exclusive
/// with the others in practice). <see cref="IsSupported"/> is the inclusive OR over the
/// backends' capability checks; when none are supported callers fall back to
/// <see cref="Bn254BigIntegerScalarReference"/>, which has no SIMD requirement.
/// </para>
/// <para>
/// Add, subtract, and the batch forms are dispatched here; multiply, negate, and
/// invert are added when the BN254 Montgomery path lands.
/// </para>
/// </remarks>
internal static class Bn254SimdScalarBackend
{
    /// <summary>True when at least one of the per-ISA SIMD backends is supported on the host CPU.</summary>
    public static bool IsSupported =>
        Bn254Avx512ScalarBackend.IsSupported
        || Bn254Avx2ScalarBackend.IsSupported
        || Bn254NeonScalarBackend.IsSupported
        || Bn254WasmScalarBackend.IsSupported;


    /// <summary>Returns the scalar-add delegate from the highest-capability supported backend.</summary>
    /// <exception cref="PlatformNotSupportedException">When no SIMD backend is supported on the host CPU.</exception>
    public static ScalarAddDelegate GetAdd()
    {
        if(Avx512F.IsSupported)
        {
            return Bn254Avx512ScalarBackend.GetAdd();
        }

        if(Avx2.IsSupported)
        {
            return Bn254Avx2ScalarBackend.GetAdd();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bn254NeonScalarBackend.GetAdd();
        }

        if(PackedSimd.IsSupported)
        {
            return Bn254WasmScalarBackend.GetAdd();
        }

        throw NoBackendAvailable();
    }


    /// <summary>Returns the scalar-subtract delegate from the highest-capability supported backend.</summary>
    /// <exception cref="PlatformNotSupportedException">When no SIMD backend is supported on the host CPU.</exception>
    public static ScalarSubtractDelegate GetSubtract()
    {
        if(Avx512F.IsSupported)
        {
            return Bn254Avx512ScalarBackend.GetSubtract();
        }

        if(Avx2.IsSupported)
        {
            return Bn254Avx2ScalarBackend.GetSubtract();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bn254NeonScalarBackend.GetSubtract();
        }

        if(PackedSimd.IsSupported)
        {
            return Bn254WasmScalarBackend.GetSubtract();
        }

        throw NoBackendAvailable();
    }


    /// <summary>Returns the batched scalar-add delegate from the highest-capability supported backend.</summary>
    /// <exception cref="PlatformNotSupportedException">When no SIMD backend is supported on the host CPU.</exception>
    public static ScalarBatchAddDelegate GetBatchAdd()
    {
        if(Avx512F.IsSupported)
        {
            return Bn254Avx512ScalarBackend.GetBatchAdd();
        }

        if(Avx2.IsSupported)
        {
            return Bn254Avx2ScalarBackend.GetBatchAdd();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bn254NeonScalarBackend.GetBatchAdd();
        }

        if(PackedSimd.IsSupported)
        {
            return Bn254WasmScalarBackend.GetBatchAdd();
        }

        throw NoBackendAvailable();
    }


    /// <summary>Returns the batched scalar-subtract delegate from the highest-capability supported backend.</summary>
    /// <exception cref="PlatformNotSupportedException">When no SIMD backend is supported on the host CPU.</exception>
    public static ScalarBatchSubtractDelegate GetBatchSubtract()
    {
        if(Avx512F.IsSupported)
        {
            return Bn254Avx512ScalarBackend.GetBatchSubtract();
        }

        if(Avx2.IsSupported)
        {
            return Bn254Avx2ScalarBackend.GetBatchSubtract();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bn254NeonScalarBackend.GetBatchSubtract();
        }

        if(PackedSimd.IsSupported)
        {
            return Bn254WasmScalarBackend.GetBatchSubtract();
        }

        throw NoBackendAvailable();
    }


    /// <summary>Returns the scalar-multiply delegate from the highest-capability supported backend.</summary>
    /// <exception cref="PlatformNotSupportedException">When no SIMD backend is supported on the host CPU.</exception>
    public static ScalarMultiplyDelegate GetMultiply()
    {
        if(Avx512F.IsSupported)
        {
            return Bn254Avx512ScalarBackend.GetMultiply();
        }

        if(Avx2.IsSupported)
        {
            return Bn254Avx2ScalarBackend.GetMultiply();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bn254NeonScalarBackend.GetMultiply();
        }

        if(PackedSimd.IsSupported)
        {
            return Bn254WasmScalarBackend.GetMultiply();
        }

        throw NoBackendAvailable();
    }


    /// <summary>Returns the scalar-negate delegate from the highest-capability supported backend.</summary>
    /// <exception cref="PlatformNotSupportedException">When no SIMD backend is supported on the host CPU.</exception>
    public static ScalarNegateDelegate GetNegate()
    {
        if(Avx512F.IsSupported)
        {
            return Bn254Avx512ScalarBackend.GetNegate();
        }

        if(Avx2.IsSupported)
        {
            return Bn254Avx2ScalarBackend.GetNegate();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bn254NeonScalarBackend.GetNegate();
        }

        if(PackedSimd.IsSupported)
        {
            return Bn254WasmScalarBackend.GetNegate();
        }

        throw NoBackendAvailable();
    }


    /// <summary>Returns the scalar-invert delegate from the highest-capability supported backend.</summary>
    /// <exception cref="PlatformNotSupportedException">When no SIMD backend is supported on the host CPU.</exception>
    public static ScalarInvertDelegate GetInvert()
    {
        if(Avx512F.IsSupported)
        {
            return Bn254Avx512ScalarBackend.GetInvert();
        }

        if(Avx2.IsSupported)
        {
            return Bn254Avx2ScalarBackend.GetInvert();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bn254NeonScalarBackend.GetInvert();
        }

        if(PackedSimd.IsSupported)
        {
            return Bn254WasmScalarBackend.GetInvert();
        }

        throw NoBackendAvailable();
    }


    /// <summary>
    /// Returns the batched scalar-multiply delegate from the highest-capability
    /// supported backend: the lane-interleaved 32-bit-limb CIOS kernel on AVX-512 or
    /// AVX2, else the serial loop of the shared single-element CIOS multiply.
    /// </summary>
    public static ScalarBatchMultiplyDelegate GetBatchMultiply()
    {
        if(Avx512F.IsSupported)
        {
            return Bn254Avx512ScalarBackend.GetBatchMultiply();
        }

        if(Avx2.IsSupported)
        {
            return Bn254Avx2ScalarBackend.GetBatchMultiply();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bn254NeonScalarBackend.GetBatchMultiply();
        }

        if(PackedSimd.IsSupported)
        {
            return Bn254WasmScalarBackend.GetBatchMultiply();
        }

        return BatchMultiply;
    }


    private static void BatchMultiply(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.ScalarBatchMultiply, curve, count);

        int stride = Scalar.SizeBytes;
        if(leftOperandsConcatenated.Length != count * stride
            || rightOperandsConcatenated.Length != count * stride
            || resultsConcatenated.Length != count * stride)
        {
            throw new ArgumentException(
                $"Batched scalar buffers must each be exactly {count} * {stride} bytes for count = {count}.");
        }

        for(int i = 0; i < count; i++)
        {
            int offset = i * stride;
            Bn254MontgomeryArithmetic.Multiply(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    private static PlatformNotSupportedException NoBackendAvailable() => new(
        "No SIMD scalar backend is supported on this host. AVX-512F, AVX2 (Intel/AMD x64), AArch64 NEON (ARM 64-bit), and WebAssembly PackedSimd are the supported sets. Check Bn254SimdScalarBackend.IsSupported before requesting a delegate.");
}
