using Lumoin.Veridical.Core.Commitments;
using System;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// A running fold accumulator: a satisfied relaxed R1CS
/// instance–witness pair together with the opening witness of its
/// error-vector commitment. This is exactly the triple a Nova-style
/// fold step (<see cref="RelaxedR1csFold.Fold"/>) consumes and
/// produces, and the triple the unified Spartan prover compresses.
/// </summary>
/// <remarks>
/// <para>
/// The bundle owns the disposal of all three members. A fold chain
/// (<c>FoldChain</c>) replaces its accumulator each step and disposes
/// the superseded one, so a consumer that reads
/// <see cref="Instance"/> for verification must not dispose it
/// independently — the owning chain does.
/// </para>
/// </remarks>
public sealed class RelaxedR1csAccumulator: IDisposable
{
    /// <summary>The relaxed instance (matrices, public inputs, <c>u</c>, error commitment).</summary>
    public RelaxedR1csInstance Instance { get; }

    /// <summary>The relaxed witness (witness scalars plus the explicit error vector <c>E</c>).</summary>
    public RelaxedR1csWitness Witness { get; }

    /// <summary>The commitment blind (per-row blinding) of the instance's error commitment.</summary>
    public PolynomialCommitmentBlind ErrorOpeningWitness { get; }


    /// <summary>
    /// Bundles a satisfied relaxed instance, its witness, and the
    /// opening witness of its error commitment. Ownership of all three
    /// transfers to this accumulator.
    /// </summary>
    /// <param name="instance">The relaxed instance.</param>
    /// <param name="witness">The relaxed witness.</param>
    /// <param name="errorOpeningWitness">The error-commitment opening witness.</param>
    /// <exception cref="ArgumentNullException">When any argument is <see langword="null"/>.</exception>
    public RelaxedR1csAccumulator(
        RelaxedR1csInstance instance,
        RelaxedR1csWitness witness,
        PolynomialCommitmentBlind errorOpeningWitness)
    {
        ArgumentNullException.ThrowIfNull(instance);
        ArgumentNullException.ThrowIfNull(witness);
        ArgumentNullException.ThrowIfNull(errorOpeningWitness);

        Instance = instance;
        Witness = witness;
        ErrorOpeningWitness = errorOpeningWitness;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        Instance.Dispose();
        Witness.Dispose();
        ErrorOpeningWitness.Dispose();
    }
}