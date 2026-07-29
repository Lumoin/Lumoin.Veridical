using System;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>The direction of a supply-chain threshold claim: the measured quantity must be at least, or at most, the public bound.</summary>
public enum SupplyChainDirection
{
    /// <summary>The measured quantity must be greater than or equal to the public bound — a floor, such as recycled content or minimum durability.</summary>
    AtLeast,

    /// <summary>The measured quantity must be less than or equal to the public bound — a ceiling, such as a carbon footprint or a hazardous-substance limit.</summary>
    AtMost,
}


/// <summary>
/// One named numeric claim in a supply-chain bundle: a caller-declared measured
/// witness variable, the public bound it is compared against
/// (<see cref="FixedPointBound"/> — a baked constant or a public-input variable,
/// carrying its own domain), and the comparison direction. A claim is data — a
/// bundle of these drives
/// <see cref="R1csCircuitBuilderSupplyChainPredicates.AssertBatteryPassport"/> and
/// its matching witness bindings — so naming a claim does not multiply the
/// predicate surface.
/// </summary>
/// <remarks>
/// The measured value is a witness the <em>caller</em> declares (through
/// <c>DeclareWitnessVariable</c>), not one the bundle auto-declares, so the same
/// variable can later be tied to a commitment — a signed credential digest, a
/// Poseidon-Merkle leaf — that binds the proven quantity to its source.
/// <see cref="Name"/> is both the claim's identity within a bundle and the prefix
/// of its auxiliary witness names, and (in a bundle) the declared name of the
/// measured variable.
/// </remarks>
public readonly record struct SupplyChainClaim
{
    /// <summary>The claim's name: unique within a bundle, the prefix under which its auxiliary witnesses are declared and bound, and the declared name of the measured variable.</summary>
    public string Name { get; }

    /// <summary>The caller-declared witness variable holding the measured quantity, encoded at <see cref="Bound"/>'s domain scale.</summary>
    public R1csVariableIndex Measured { get; }

    /// <summary>The public bound — a regulatory floor or ceiling — as a baked constant or a public-input variable, carrying the domain the comparison happens in.</summary>
    public FixedPointBound Bound { get; }

    /// <summary>Whether the measured value must be at least, or at most, the bound.</summary>
    public SupplyChainDirection Direction { get; }


    private SupplyChainClaim(string name, R1csVariableIndex measured, FixedPointBound bound, SupplyChainDirection direction)
    {
        Name = name;
        Measured = measured;
        Bound = bound;
        Direction = direction;
    }


    /// <summary>A claim that <paramref name="measured"/> is at least <paramref name="threshold"/> — a floor, such as recycled content at or above a regulatory minimum.</summary>
    /// <exception cref="ArgumentException">When <paramref name="name"/> is null or empty.</exception>
    public static SupplyChainClaim AtLeast(string name, R1csVariableIndex measured, FixedPointBound threshold)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        return new SupplyChainClaim(name, measured, threshold, SupplyChainDirection.AtLeast);
    }


    /// <summary>A claim that <paramref name="measured"/> is at most <paramref name="cap"/> — a ceiling, such as a carbon footprint at or below a regulatory cap.</summary>
    /// <exception cref="ArgumentException">When <paramref name="name"/> is null or empty.</exception>
    public static SupplyChainClaim AtMost(string name, R1csVariableIndex measured, FixedPointBound cap)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        return new SupplyChainClaim(name, measured, cap, SupplyChainDirection.AtMost);
    }
}
