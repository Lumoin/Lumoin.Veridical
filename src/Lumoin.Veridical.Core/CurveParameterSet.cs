using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core;

/// <summary>
/// Identifies the elliptic curve and parameter set a leaf algebraic type
/// lives over.
/// </summary>
/// <remarks>
/// <para>
/// Every leaf algebraic type — <c>Scalar</c>, <c>G1Point</c>,
/// <c>Fp12Element</c>, and so on — is curve-broad and carries a
/// <see cref="CurveParameterSet"/> value in its tag (surfaced as a
/// <c>Curve</c> property). The library uses this value to dispatch arithmetic
/// to the correct backend delegate set: a <c>ScalarAdd</c> call on a
/// BLS12-381 scalar reaches the BLS12-381-specific add implementation, never
/// the BN254 one.
/// </para>
/// <para>
/// The wire-format string identifier for each curve lives in
/// <see cref="WellKnownCurves"/>; this enum is the runtime routing key. The
/// two refer to the same set of curves and stay in sync. Identifiers in this
/// type use a no-underscore form (<c>Bls12Curve381</c>) so they satisfy the
/// .NET naming convention; the canonical hyphenated wire-format name
/// (<c>"BLS12-381"</c>) lives in <see cref="WellKnownCurves"/> as a string
/// constant.
/// </para>
/// <para>
/// Use <see cref="Create"/> with codes above 1000 to register
/// application-specific curves (a custom-domain BLS curve, a research-stage
/// pairing-friendly construction).
/// </para>
/// </remarks>
[DebuggerDisplay("{CurveParameterSetNames.GetName(this),nq}")]
public readonly struct CurveParameterSet: IEquatable<CurveParameterSet>
{
    /// <summary>Gets the numeric code for this curve.</summary>
    public int Code { get; }


    private CurveParameterSet(int code) { Code = code; }


    /// <summary>No specific curve selected.</summary>
    public static CurveParameterSet None { get; } = new(0);

    /// <summary>BLS12-381. Pairing-friendly curve with a 381-bit base field; used by BBS+, BLS signatures, KZG-based proof systems, and Ethereum 2.0.</summary>
    public static CurveParameterSet Bls12Curve381 { get; } = new(1);

    /// <summary>BN254 (alt_bn128). Pairing-friendly curve with a 254-bit base field; used by Ethereum precompiles and earlier SNARK deployments.</summary>
    public static CurveParameterSet Bn254 { get; } = new(2);

    /// <summary>Pallas. Non-pairing curve forming a 2-cycle with Vesta; used by Halo2 for pairing-free recursion.</summary>
    public static CurveParameterSet Pallas { get; } = new(3);

    /// <summary>Vesta. Non-pairing curve forming a 2-cycle with Pallas.</summary>
    public static CurveParameterSet Vesta { get; } = new(4);

    /// <summary>Grumpkin. Non-pairing curve in a 2-cycle with BN254 used for pairing-free recursion.</summary>
    public static CurveParameterSet Grumpkin { get; } = new(5);

    /// <summary>secp256k1. Used by Bitcoin, Ethereum signing, and many decentralised identity schemes.</summary>
    public static CurveParameterSet Secp256k1 { get; } = new(6);

    /// <summary>Ed25519. Edwards curve over the 25519 prime; used by EdDSA signatures.</summary>
    public static CurveParameterSet Ed25519 { get; } = new(7);

    /// <summary>NIST P-256 (secp256r1, prime256v1).</summary>
    public static CurveParameterSet P256 { get; } = new(8);

    /// <summary>NIST P-384 (secp384r1).</summary>
    public static CurveParameterSet P384 { get; } = new(9);

    /// <summary>NIST P-521 (secp521r1).</summary>
    public static CurveParameterSet P521 { get; } = new(10);


    private static readonly List<CurveParameterSet> parameterSets =
        [None, Bls12Curve381, Bn254, Pallas, Vesta, Grumpkin, Secp256k1, Ed25519, P256, P384, P521];


    /// <summary>Gets all registered curve parameter set values.</summary>
    public static IReadOnlyList<CurveParameterSet> ParameterSets => parameterSets.AsReadOnly();


    /// <summary>
    /// Creates a new curve parameter set value for application-specific extensions.
    /// </summary>
    /// <param name="code">The unique numeric code for this curve.</param>
    /// <returns>The newly created curve parameter set.</returns>
    /// <exception cref="ArgumentException">Thrown when the code already exists.</exception>
    /// <remarks>
    /// Use code values above 1000 to avoid collisions with future library
    /// additions. This method is not thread-safe; call it only during
    /// application startup before concurrent access begins.
    /// </remarks>
    public static CurveParameterSet Create(int code)
    {
        for(int i = 0; i < parameterSets.Count; ++i)
        {
            if(parameterSets[i].Code == code)
            {
                throw new ArgumentException($"Curve parameter set code {code} already exists.");
            }
        }

        var created = new CurveParameterSet(code);
        parameterSets.Add(created);

        return created;
    }


    /// <inheritdoc/>
    public override string ToString() => CurveParameterSetNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(CurveParameterSet other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is CurveParameterSet other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;

    /// <inheritdoc/>
    public static bool operator ==(CurveParameterSet left, CurveParameterSet right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(CurveParameterSet left, CurveParameterSet right) => !left.Equals(right);
}


/// <summary>Provides human-readable names for <see cref="CurveParameterSet"/> values.</summary>
public static class CurveParameterSetNames
{
    /// <summary>Gets the name for the specified curve parameter set.</summary>
    public static string GetName(CurveParameterSet parameterSet) => GetName(parameterSet.Code);

    /// <summary>Gets the name for the specified curve parameter set code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == CurveParameterSet.None.Code => nameof(CurveParameterSet.None),
        var c when c == CurveParameterSet.Bls12Curve381.Code => nameof(CurveParameterSet.Bls12Curve381),
        var c when c == CurveParameterSet.Bn254.Code => nameof(CurveParameterSet.Bn254),
        var c when c == CurveParameterSet.Pallas.Code => nameof(CurveParameterSet.Pallas),
        var c when c == CurveParameterSet.Vesta.Code => nameof(CurveParameterSet.Vesta),
        var c when c == CurveParameterSet.Grumpkin.Code => nameof(CurveParameterSet.Grumpkin),
        var c when c == CurveParameterSet.Secp256k1.Code => nameof(CurveParameterSet.Secp256k1),
        var c when c == CurveParameterSet.Ed25519.Code => nameof(CurveParameterSet.Ed25519),
        var c when c == CurveParameterSet.P256.Code => nameof(CurveParameterSet.P256),
        var c when c == CurveParameterSet.P384.Code => nameof(CurveParameterSet.P384),
        var c when c == CurveParameterSet.P521.Code => nameof(CurveParameterSet.P521),
        _ => $"Custom ({code})"
    };
}