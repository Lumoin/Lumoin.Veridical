using System;

namespace Lumoin.Veridical.Core;

/// <summary>
/// Well-known lookup argument identifiers and predicates.
/// </summary>
/// <remarks>
/// <para>
/// Lookup arguments prove that a value (or a vector of values) is contained in a
/// committed table. Modern lookup arguments such as Lasso and Jolt make the
/// per-lookup cost sub-linear in the table size, which is the property that
/// makes table-based authorization predicates affordable inside a circuit.
/// </para>
/// <para>
/// Lookup arguments compose with folding schemes at the fold-step level: each
/// folded step may carry its own lookup proofs for its in-step predicates while
/// the accumulator covers the cross-step state transition.
/// </para>
/// </remarks>
public static class WellKnownLookupArguments
{
    /// <summary>
    /// Lasso lookup argument (Setty, Thaler, Wahby, 2023). Reduces a lookup
    /// against a structured table to a sum-check argument with cost sub-linear
    /// in the table size.
    /// </summary>
    public const string Lasso = "Lasso";

    /// <summary>
    /// Jolt zkVM lookup argument (Arun, Setty, Thaler, 2023). Builds on Lasso
    /// to express instruction execution as table lookups, giving a lookup-centric
    /// virtual machine model.
    /// </summary>
    public const string Jolt = "Jolt";

    /// <summary>
    /// Plookup (Gabizon, Williamson, 2020). Earlier lookup argument with cost
    /// linear in the table size; a baseline for comparison rather than a
    /// production target for this library.
    /// </summary>
    public const string Plookup = "Plookup";

    /// <summary>
    /// Halo2 lookup argument. The lookup primitive built into the Halo2 proof
    /// system, used in PLONK-family circuits for table membership checks.
    /// </summary>
    public const string Halo2Lookup = "Halo2Lookup";

    /// <summary>
    /// Caulk+ lookup argument (Posen, Kattis, 2022). Cached quotients lookup
    /// argument optimised for static tables with many lookups.
    /// </summary>
    public const string CaulkPlus = "CaulkPlus";


    /// <summary>Determines whether the specified value identifies the Lasso lookup argument.</summary>
    public static bool IsLasso(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Lasso, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies the Jolt lookup argument.</summary>
    public static bool IsJolt(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Jolt, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies the Plookup lookup argument.</summary>
    public static bool IsPlookup(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Plookup, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies the Halo2 lookup argument.</summary>
    public static bool IsHalo2Lookup(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Halo2Lookup, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies the Caulk+ lookup argument.</summary>
    public static bool IsCaulkPlus(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, CaulkPlus, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Determines whether the specified lookup argument is sub-linear in the
    /// table size. Lasso, Jolt, and Caulk+ are sub-linear; Plookup and the
    /// Halo2 lookup argument are linear.
    /// </summary>
    public static bool IsSublinear(string? value) =>
        IsLasso(value) || IsJolt(value) || IsCaulkPlus(value);
}