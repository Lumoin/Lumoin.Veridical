using System;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Structural transformations over a built <see cref="R1csCircuit"/>, shaped to
/// compose through <see cref="R1csBuilder{TResult, TState, TBuilder}.With"/>:
/// each is a <c>Func&lt;R1csCircuit, R1csCircuitBuilder, R1csBuildState, R1csCircuit&gt;</c>.
/// Future passes (deduplication, common-subexpression elimination, constant
/// folding) land here as further static methods; the composition surface is
/// ready for them.
/// </summary>
public static class R1csCircuitTransformations
{
    /// <summary>The reserved name prefix of the witness columns padding introduces. The witness binding for each is zero.</summary>
    public const string PaddingWitnessNamePrefix = "__pad_witness_";


    /// <summary>
    /// Pads the circuit to power-of-two dimensions on both axes — the form
    /// Spartan's sumcheck requires — with a floor of 2 per axis (Spartan needs
    /// at least one sumcheck round, so a single power-of-two of 1 is not usable;
    /// see <c>NextPowerOfTwo</c>). The constraint (row) count rounds up to that
    /// power of two by appending <c>0 · 0 = 0</c> constraints; the variable
    /// (column) count rounds up by appending dummy intermediate witness
    /// variables named <c>{PaddingWitnessNamePrefix}{n}</c>. Real constraints
    /// and variables keep their positions; the public-input block is untouched
    /// (padding grows only the witness side, at the end). A circuit already
    /// power-of-two on both axes is returned unchanged, so the transformation is
    /// idempotent.
    /// </summary>
    /// <remarks>
    /// Compose it through the builder: <c>builder.With(R1csCircuitTransformations.PowerOfTwoPadding)</c>.
    /// The caller must bind the padding witnesses to zero at compile time;
    /// <see cref="R1csPredicateWitness.AddPowerOfTwoPaddingBindings"/> derives
    /// those bindings.
    /// </remarks>
    /// <param name="circuit">The circuit to pad — the accumulated fold result.</param>
    /// <param name="builder">Unused; present to match the transformation delegate shape.</param>
    /// <param name="state">Unused; present to match the transformation delegate shape.</param>
    /// <returns>The padded circuit, or <paramref name="circuit"/> unchanged when already power-of-two on both axes.</returns>
    [SuppressMessage("Style", "IDE0060:Remove unused parameter", Justification = "builder and state are present to match the R1csBuilder transformation delegate shape (Func<R1csCircuit, R1csCircuitBuilder, R1csBuildState, R1csCircuit>); padding consults only the circuit.")]
    public static R1csCircuit PowerOfTwoPadding(R1csCircuit circuit, R1csCircuitBuilder builder, R1csBuildState state)
    {
        ArgumentNullException.ThrowIfNull(circuit);

        int currentRows = 0;
        foreach(IR1csOp op in circuit.Operations)
        {
            if(op is AddConstraintOp)
            {
                currentRows++;
            }
        }

        int currentColumns = circuit.VariableCount;
        int targetRows = NextPowerOfTwo(currentRows);
        int targetColumns = NextPowerOfTwo(currentColumns);

        if(targetRows == currentRows && targetColumns == currentColumns)
        {
            return circuit;
        }

        ImmutableArray<IR1csOp>.Builder operations = circuit.Operations.ToBuilder();
        ImmutableArray<R1csVariableMetadata>.Builder variables = circuit.Variables.ToBuilder();

        int paddingColumns = targetColumns - currentColumns;
        for(int i = 0; i < paddingColumns; i++)
        {
            var index = new R1csVariableIndex(currentColumns + i);
            string name = $"{PaddingWitnessNamePrefix}{i}";
            operations.Add(new DeclareIntermediateVariableOp(index, name));
            variables.Add(new R1csVariableMetadata(index, name, R1csVariableKind.Intermediate));
        }

        int paddingRows = targetRows - currentRows;
        for(int i = 0; i < paddingRows; i++)
        {
            operations.Add(new AddConstraintOp(
                R1csLinearCombination.Zero,
                R1csLinearCombination.Zero,
                R1csLinearCombination.Zero));
        }

        return new R1csCircuit(
            circuit.Curve,
            operations.ToImmutable(),
            variables.ToImmutable(),
            circuit.PublicInputCount,
            circuit.WitnessVariableCount + paddingColumns);
    }


    private static int NextPowerOfTwo(int value)
    {
        //Spartan's sumcheck needs at least one round per axis, so the smallest
        //usable power-of-two dimension is 2: 2^0 = 1 yields a zero-round,
        //degenerate sumcheck the prover cannot evaluate (it rents a zero-length
        //buffer for the row/column challenges and throws). Floor at 2.
        if(value <= 2)
        {
            return 2;
        }

        return (int)BitOperations.RoundUpToPowerOf2((uint)value);
    }
}
