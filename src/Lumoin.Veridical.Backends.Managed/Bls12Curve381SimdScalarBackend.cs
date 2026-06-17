using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.Wasm;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Dispatch facade over the per-ISA SIMD scalar backends. Picks the
/// fastest available implementation on the host CPU and exposes a stable
/// public surface (<see cref="IsSupported"/>, <see cref="GetAdd"/>, and so
/// on) for callers that do not care which specific instruction set is
/// underneath.
/// </summary>
/// <remarks>
/// <para>
/// Picking happens once per <c>Get*</c> call: each returns the delegate
/// instance from the highest-capability backend available. After that
/// the delegate is just a method-group reference; subsequent invocations
/// do not re-check capabilities.
/// </para>
/// <para>
/// Capability ordering (highest to lowest):
/// </para>
/// <list type="number">
///   <item><description>AVX-512F — 8-wide lane-interleaved batching via <see cref="Bls12Curve381Avx512ScalarBackend"/>.</description></item>
///   <item><description>AVX2 — 4-wide lane-interleaved batching via <see cref="Bls12Curve381Avx2ScalarBackend"/>.</description></item>
///   <item><description>AArch64 NEON — 2-wide lane-interleaved batching via <see cref="Bls12Curve381NeonScalarBackend"/>.</description></item>
///   <item><description>WebAssembly PackedSimd — 2-wide lane-interleaved batching via <see cref="Bls12Curve381WasmScalarBackend"/> (mutually exclusive with the others in practice; a WASM host has no AVX or NEON).</description></item>
/// </list>
/// <para>
/// <see cref="IsSupported"/> is the inclusive OR over every backend's own
/// capability check. When none of them are supported, callers should fall
/// back to <see cref="Bls12Curve381BigIntegerScalarReference"/>, which has
/// no SIMD requirement.
/// </para>
/// </remarks>
internal static class Bls12Curve381SimdScalarBackend
{
    /// <summary>True when at least one of the per-ISA SIMD backends is supported on the host CPU.</summary>
    public static bool IsSupported =>
        Bls12Curve381Avx512ScalarBackend.IsSupported
        || Bls12Curve381Avx2ScalarBackend.IsSupported
        || Bls12Curve381NeonScalarBackend.IsSupported
        || Bls12Curve381WasmScalarBackend.IsSupported;


    /// <summary>Returns the scalar-add delegate from the highest-capability supported backend.</summary>
    /// <exception cref="PlatformNotSupportedException">When no SIMD backend is supported on the host CPU.</exception>
    public static ScalarAddDelegate GetAdd()
    {
        if(Avx512F.IsSupported)
        {
            return Bls12Curve381Avx512ScalarBackend.GetAdd();
        }

        if(Avx2.IsSupported)
        {
            return Bls12Curve381Avx2ScalarBackend.GetAdd();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bls12Curve381NeonScalarBackend.GetAdd();
        }

        if(PackedSimd.IsSupported)
        {
            return Bls12Curve381WasmScalarBackend.GetAdd();
        }

        throw NoBackendAvailable();
    }


    /// <summary>Returns the scalar-subtract delegate from the highest-capability supported backend.</summary>
    /// <exception cref="PlatformNotSupportedException">When no SIMD backend is supported on the host CPU.</exception>
    public static ScalarSubtractDelegate GetSubtract()
    {
        if(Avx512F.IsSupported)
        {
            return Bls12Curve381Avx512ScalarBackend.GetSubtract();
        }

        if(Avx2.IsSupported)
        {
            return Bls12Curve381Avx2ScalarBackend.GetSubtract();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bls12Curve381NeonScalarBackend.GetSubtract();
        }

        if(PackedSimd.IsSupported)
        {
            return Bls12Curve381WasmScalarBackend.GetSubtract();
        }

        throw NoBackendAvailable();
    }


    /// <summary>Returns the batched scalar-add delegate from the highest-capability supported backend.</summary>
    /// <exception cref="PlatformNotSupportedException">When no SIMD backend is supported on the host CPU.</exception>
    public static ScalarBatchAddDelegate GetBatchAdd()
    {
        if(Avx512F.IsSupported)
        {
            return Bls12Curve381Avx512ScalarBackend.GetBatchAdd();
        }

        if(Avx2.IsSupported)
        {
            return Bls12Curve381Avx2ScalarBackend.GetBatchAdd();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bls12Curve381NeonScalarBackend.GetBatchAdd();
        }

        if(PackedSimd.IsSupported)
        {
            return Bls12Curve381WasmScalarBackend.GetBatchAdd();
        }

        throw NoBackendAvailable();
    }


    /// <summary>Returns the batched scalar-subtract delegate from the highest-capability supported backend.</summary>
    /// <exception cref="PlatformNotSupportedException">When no SIMD backend is supported on the host CPU.</exception>
    public static ScalarBatchSubtractDelegate GetBatchSubtract()
    {
        if(Avx512F.IsSupported)
        {
            return Bls12Curve381Avx512ScalarBackend.GetBatchSubtract();
        }

        if(Avx2.IsSupported)
        {
            return Bls12Curve381Avx2ScalarBackend.GetBatchSubtract();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bls12Curve381NeonScalarBackend.GetBatchSubtract();
        }

        if(PackedSimd.IsSupported)
        {
            return Bls12Curve381WasmScalarBackend.GetBatchSubtract();
        }

        throw NoBackendAvailable();
    }


    /// <summary>Returns the scalar-multiply delegate from the highest-capability supported backend.</summary>
    /// <exception cref="PlatformNotSupportedException">When no SIMD backend is supported on the host CPU.</exception>
    public static ScalarMultiplyDelegate GetMultiply()
    {
        if(Avx512F.IsSupported)
        {
            return Bls12Curve381Avx512ScalarBackend.GetMultiply();
        }

        if(Avx2.IsSupported)
        {
            return Bls12Curve381Avx2ScalarBackend.GetMultiply();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bls12Curve381NeonScalarBackend.GetMultiply();
        }

        if(PackedSimd.IsSupported)
        {
            return Bls12Curve381WasmScalarBackend.GetMultiply();
        }

        throw NoBackendAvailable();
    }


    /// <summary>Returns the scalar-negate delegate from the highest-capability supported backend.</summary>
    /// <exception cref="PlatformNotSupportedException">When no SIMD backend is supported on the host CPU.</exception>
    public static ScalarNegateDelegate GetNegate()
    {
        if(Avx512F.IsSupported)
        {
            return Bls12Curve381Avx512ScalarBackend.GetNegate();
        }

        if(Avx2.IsSupported)
        {
            return Bls12Curve381Avx2ScalarBackend.GetNegate();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bls12Curve381NeonScalarBackend.GetNegate();
        }

        if(PackedSimd.IsSupported)
        {
            return Bls12Curve381WasmScalarBackend.GetNegate();
        }

        throw NoBackendAvailable();
    }


    /// <summary>Returns the scalar-invert delegate from the highest-capability supported backend.</summary>
    /// <exception cref="PlatformNotSupportedException">When no SIMD backend is supported on the host CPU.</exception>
    public static ScalarInvertDelegate GetInvert()
    {
        if(Avx512F.IsSupported)
        {
            return Bls12Curve381Avx512ScalarBackend.GetInvert();
        }

        if(Avx2.IsSupported)
        {
            return Bls12Curve381Avx2ScalarBackend.GetInvert();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bls12Curve381NeonScalarBackend.GetInvert();
        }

        if(PackedSimd.IsSupported)
        {
            return Bls12Curve381WasmScalarBackend.GetInvert();
        }

        throw NoBackendAvailable();
    }


    /// <summary>
    /// Returns the batched scalar-multiply delegate from the highest-capability
    /// supported backend. AVX2 (and AVX-512 hosts, which also satisfy AVX2) run the
    /// lane-interleaved 32-bit-limb CIOS kernel that does four independent Montgomery
    /// multiplies per SIMD register; hosts without AVX2 fall back to the serial loop
    /// of the shared single-element CIOS multiply (allocation-free, but one at a time).
    /// </summary>
    public static ScalarBatchMultiplyDelegate GetBatchMultiply()
    {
        if(Avx512F.IsSupported)
        {
            return Bls12Curve381Avx512ScalarBackend.GetBatchMultiply();
        }

        if(Avx2.IsSupported)
        {
            return Bls12Curve381Avx2ScalarBackend.GetBatchMultiply();
        }

        if(AdvSimd.Arm64.IsSupported)
        {
            return Bls12Curve381NeonScalarBackend.GetBatchMultiply();
        }

        if(PackedSimd.IsSupported)
        {
            return Bls12Curve381WasmScalarBackend.GetBatchMultiply();
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
            Bls12Curve381MontgomeryArithmetic.Multiply(
                leftOperandsConcatenated.Slice(offset, stride),
                rightOperandsConcatenated.Slice(offset, stride),
                resultsConcatenated.Slice(offset, stride));
        }
    }


    private static PlatformNotSupportedException NoBackendAvailable() => new(
        "No SIMD scalar backend is supported on this host. AVX-512F, AVX2 (Intel/AMD x64), AArch64 NEON (ARM 64-bit), and WebAssembly PackedSimd are the supported sets. Check Bls12Curve381SimdScalarBackend.IsSupported before requesting a delegate.");
}