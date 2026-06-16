using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core;

/// <summary>
/// Identifies which compute backend executes algebraic operations on
/// cryptographic material.
/// </summary>
/// <remarks>
/// <para>
/// The backend is the interchangeable layer beneath the leaf algebraic types.
/// A leaf type such as <c>Scalar</c> carries pool-backed bytes in the
/// canonical big-endian layout; the operations on those bytes — addition,
/// multiplication, multi-scalar multiplication, FFT, pairing — are dispatched
/// through delegates that a backend supplies. The same delegate signature is
/// satisfied by a managed implementation, a native FFI implementation, a
/// WebGPU compute-shader implementation, or a hardware-accelerator
/// implementation.
/// </para>
/// <para>
/// Predefined backends include <see cref="Managed"/> (pure .NET, browser-safe),
/// <see cref="Native"/> (P/Invoke to blst, arkworks, or similar), <see cref="WebGpu"/>
/// (browser GPU compute), and <see cref="Fpga"/> (custom hardware accelerator).
/// </para>
/// <para>
/// Use <see cref="Create"/> with codes above 1000 to register application-specific
/// backends (a particular accelerator product, a custom FFI library, a
/// vendor-specific GPU compute path).
/// </para>
/// </remarks>
[DebuggerDisplay("{BackendNames.GetName(this),nq}")]
public readonly struct Backend: IEquatable<Backend>
{
    /// <summary>Gets the numeric code for this backend.</summary>
    public int Code { get; }


    private Backend(int code) { Code = code; }


    /// <summary>No specific backend selected.</summary>
    public static Backend None { get; } = new(0);

    /// <summary>
    /// Pure managed .NET implementation. Uses <see cref="System.Numerics.BigInteger"/>,
    /// portable <c>Vector&lt;T&gt;</c> intrinsics where available, and no
    /// platform-specific APIs. Runs unchanged in the browser via WebAssembly,
    /// on x64, on ARM64, and under AOT compilation.
    /// </summary>
    public static Backend Managed { get; } = new(1);

    /// <summary>
    /// Native FFI backend. P/Invokes into a native cryptographic library such
    /// as blst, arkworks, or a comparable accelerated implementation for
    /// server-side prover throughput. Not available in the browser.
    /// </summary>
    public static Backend Native { get; } = new(2);

    /// <summary>
    /// WebGPU compute-shader backend. Dispatches multi-scalar multiplication,
    /// number-theoretic transforms, and similar data-parallel workloads to GPU
    /// compute shaders via WebGPU. Available in browsers that support WebGPU
    /// and on .NET hosts via a WebGPU binding.
    /// </summary>
    public static Backend WebGpu { get; } = new(3);

    /// <summary>
    /// FPGA accelerator backend. Dispatches algebraic operations to a custom
    /// hardware accelerator. Application-specific in practice; this code is a
    /// well-known marker for the category.
    /// </summary>
    public static Backend Fpga { get; } = new(4);


    private static readonly List<Backend> backends = [None, Managed, Native, WebGpu, Fpga];


    /// <summary>Gets all registered backend values.</summary>
    public static IReadOnlyList<Backend> Backends => backends.AsReadOnly();


    /// <summary>
    /// Creates a new backend value for application-specific extensions.
    /// </summary>
    /// <param name="code">The unique numeric code for this backend.</param>
    /// <returns>The newly created backend.</returns>
    /// <exception cref="ArgumentException">Thrown when the code already exists.</exception>
    /// <remarks>
    /// Use code values above 1000 to avoid collisions with future library
    /// additions. This method is not thread-safe; call it only during
    /// application startup before concurrent access begins.
    /// </remarks>
    public static Backend Create(int code)
    {
        for(int i = 0; i < backends.Count; ++i)
        {
            if(backends[i].Code == code)
            {
                throw new ArgumentException($"Backend code {code} already exists.");
            }
        }

        var created = new Backend(code);
        backends.Add(created);

        return created;
    }


    /// <inheritdoc/>
    public override string ToString() => BackendNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(Backend other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is Backend other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;

    /// <inheritdoc/>
    public static bool operator ==(Backend left, Backend right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(Backend left, Backend right) => !left.Equals(right);
}


/// <summary>Provides human-readable names for <see cref="Backend"/> values.</summary>
public static class BackendNames
{
    /// <summary>Gets the name for the specified backend.</summary>
    public static string GetName(Backend backend) => GetName(backend.Code);

    /// <summary>Gets the name for the specified backend code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == Backend.None.Code => nameof(Backend.None),
        var c when c == Backend.Managed.Code => nameof(Backend.Managed),
        var c when c == Backend.Native.Code => nameof(Backend.Native),
        var c when c == Backend.WebGpu.Code => nameof(Backend.WebGpu),
        var c when c == Backend.Fpga.Code => nameof(Backend.Fpga),
        _ => $"Custom ({code})"
    };
}