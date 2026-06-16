using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core;

/// <summary>
/// Identifies which lookup-argument family a circuit uses to prove that a
/// committed witness vector lies in a public table.
/// </summary>
/// <remarks>
/// <para>
/// Lookup arguments are how modern proof systems express expensive non-linear
/// operations — range checks, byte-decompositions, S-boxes — without paying
/// for them inside the arithmetic constraint system. They turn an in-circuit
/// computation into an out-of-circuit table reference plus a small
/// commit-and-check protocol.
/// </para>
/// <para>
/// Predefined arguments cover the families this library plans to support:
/// <see cref="Lasso"/> and <see cref="Jolt"/> for sublinear sumcheck-based
/// lookups, <see cref="Plookup"/> for the Plonk-era polynomial-commitment
/// approach, <see cref="Halo2Lookup"/> for Halo2's permutation-flavoured
/// variant, and <see cref="CaulkPlus"/> for sublinear lookups in the KZG
/// setting.
/// </para>
/// <para>
/// Use <see cref="Create"/> with codes above 1000 to register application-specific
/// or research-stage lookup arguments.
/// </para>
/// </remarks>
[DebuggerDisplay("{LookupArgumentNames.GetName(this),nq}")]
public readonly struct LookupArgument: IEquatable<LookupArgument>
{
    /// <summary>Gets the numeric code for this lookup argument.</summary>
    public int Code { get; }


    private LookupArgument(int code) { Code = code; }


    /// <summary>No specific lookup argument selected.</summary>
    public static LookupArgument None { get; } = new(0);

    /// <summary>
    /// Lasso. Sumcheck-based lookup whose prover work is sublinear in the
    /// table size when the table is structured.
    /// </summary>
    public static LookupArgument Lasso { get; } = new(1);

    /// <summary>
    /// Jolt. zkVM-oriented application of the Lasso family that decomposes
    /// instruction execution into table lookups.
    /// </summary>
    public static LookupArgument Jolt { get; } = new(2);

    /// <summary>
    /// Plookup. Polynomial-commitment lookup argument designed for Plonk-style
    /// systems, with prover work linear in the table size.
    /// </summary>
    public static LookupArgument Plookup { get; } = new(3);

    /// <summary>
    /// Halo2 lookup. The permutation-flavoured lookup argument bundled with
    /// the Halo2 proof system.
    /// </summary>
    public static LookupArgument Halo2Lookup { get; } = new(4);

    /// <summary>
    /// Caulk+. Sublinear lookup argument in the KZG commitment setting,
    /// suitable for very large public tables.
    /// </summary>
    public static LookupArgument CaulkPlus { get; } = new(5);


    private static readonly List<LookupArgument> lookupArguments =
        [None, Lasso, Jolt, Plookup, Halo2Lookup, CaulkPlus];


    /// <summary>Gets all registered lookup argument values.</summary>
    public static IReadOnlyList<LookupArgument> LookupArguments => lookupArguments.AsReadOnly();


    /// <summary>
    /// Creates a new lookup argument value for application-specific extensions.
    /// </summary>
    /// <param name="code">The unique numeric code for this lookup argument.</param>
    /// <returns>The newly created lookup argument.</returns>
    /// <exception cref="ArgumentException">Thrown when the code already exists.</exception>
    /// <remarks>
    /// Use code values above 1000 to avoid collisions with future library
    /// additions. This method is not thread-safe; call it only during
    /// application startup before concurrent access begins.
    /// </remarks>
    public static LookupArgument Create(int code)
    {
        for(int i = 0; i < lookupArguments.Count; ++i)
        {
            if(lookupArguments[i].Code == code)
            {
                throw new ArgumentException($"Lookup argument code {code} already exists.");
            }
        }

        var created = new LookupArgument(code);
        lookupArguments.Add(created);

        return created;
    }


    /// <inheritdoc/>
    public override string ToString() => LookupArgumentNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(LookupArgument other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is LookupArgument other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;

    /// <inheritdoc/>
    public static bool operator ==(LookupArgument left, LookupArgument right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(LookupArgument left, LookupArgument right) => !left.Equals(right);
}


/// <summary>Provides human-readable names for <see cref="LookupArgument"/> values.</summary>
public static class LookupArgumentNames
{
    /// <summary>Gets the name for the specified lookup argument.</summary>
    public static string GetName(LookupArgument argument) => GetName(argument.Code);

    /// <summary>Gets the name for the specified lookup argument code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == LookupArgument.None.Code => nameof(LookupArgument.None),
        var c when c == LookupArgument.Lasso.Code => nameof(LookupArgument.Lasso),
        var c when c == LookupArgument.Jolt.Code => nameof(LookupArgument.Jolt),
        var c when c == LookupArgument.Plookup.Code => nameof(LookupArgument.Plookup),
        var c when c == LookupArgument.Halo2Lookup.Code => nameof(LookupArgument.Halo2Lookup),
        var c when c == LookupArgument.CaulkPlus.Code => nameof(LookupArgument.CaulkPlus),
        _ => $"Custom ({code})"
    };
}