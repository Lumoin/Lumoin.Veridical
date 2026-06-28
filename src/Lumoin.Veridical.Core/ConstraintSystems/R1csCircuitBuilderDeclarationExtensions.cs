using System;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// The fluent declaration and constraint surface of
/// <see cref="R1csCircuitBuilder"/>. Each method validates eagerly (so errors
/// surface at the call site), computes any variable index eagerly (so the
/// caller can reference it immediately), and appends a transformation via
/// <see cref="Common.R1csBuilder{TResult, TState, TBuilder}.With"/> that writes the
/// corresponding operation into the accumulating circuit when the builder
/// folds.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class R1csCircuitBuilderDeclarationExtensions
{
    extension(R1csCircuitBuilder builder)
    {
        /// <summary>
        /// Declares a public input and returns its variable index. Public
        /// inputs must all be declared before the first witness variable or
        /// constraint.
        /// </summary>
        /// <exception cref="InvalidOperationException">When a witness variable or constraint has already been added (the contiguity rule).</exception>
        /// <exception cref="ArgumentException">When the name is null, empty, or already used.</exception>
        public R1csVariableIndex DeclarePublicInput(string name)
        {
            ValidateNewName(builder, name);

            if(builder.PublicInputsLocked)
            {
                throw new InvalidOperationException(
                    $"Cannot declare public input '{name}': all public inputs must be declared before the first witness variable or constraint. Public inputs occupy a contiguous block immediately after the constant-one wire (the R1csVariableIndex layout convention).");
            }

            return Declare(builder, name, R1csVariableKind.PublicInput);
        }


        /// <summary>Declares a private witness variable and returns its index. Locks the public-input phase.</summary>
        /// <exception cref="ArgumentException">When the name is null, empty, or already used.</exception>
        public R1csVariableIndex DeclareWitnessVariable(string name)
        {
            ValidateNewName(builder, name);
            builder.PublicInputsLocked = true;

            return Declare(builder, name, R1csVariableKind.WitnessVariable);
        }


        /// <summary>
        /// Declares an auxiliary (intermediate) witness variable and returns
        /// its index. Semantically a witness variable; the distinct kind marks
        /// it as generator-introduced. Locks the public-input phase.
        /// </summary>
        /// <exception cref="ArgumentException">When the name is null, empty, or already used.</exception>
        public R1csVariableIndex DeclareIntermediateVariable(string name)
        {
            ValidateNewName(builder, name);
            builder.PublicInputsLocked = true;

            return Declare(builder, name, R1csVariableKind.Intermediate);
        }


        /// <summary>
        /// Adds the constraint <c>(left) · (middle) = (right)</c> and returns
        /// the builder for chaining. Locks the public-input phase.
        /// </summary>
        /// <exception cref="ArgumentException">When any operand references a variable index that has not been declared.</exception>
        public R1csCircuitBuilder AddConstraint(
            R1csLinearCombination left,
            R1csLinearCombination middle,
            R1csLinearCombination right)
        {
            ArgumentNullException.ThrowIfNull(left);
            ArgumentNullException.ThrowIfNull(middle);
            ArgumentNullException.ThrowIfNull(right);

            ValidateReferences(builder, left, nameof(left));
            ValidateReferences(builder, middle, nameof(middle));
            ValidateReferences(builder, right, nameof(right));

            builder.PublicInputsLocked = true;

            var op = new AddConstraintOp(left, middle, right);

            return builder.With((circuit, _, _) => AppendConstraint(circuit, op));
        }


        /// <summary>Looks up a previously-declared variable's index by name.</summary>
        /// <exception cref="ArgumentException">When no variable with that name has been declared.</exception>
        public R1csVariableIndex VariableByName(string name)
        {
            ArgumentNullException.ThrowIfNull(name);

            if(!builder.State.NamedVariables.TryGetValue(name, out R1csVariableIndex index))
            {
                throw new ArgumentException($"No variable named '{name}' has been declared.", nameof(name));
            }

            return index;
        }
    }


    private static R1csVariableIndex Declare(R1csCircuitBuilder builder, string name, R1csVariableKind kind)
    {
        var index = new R1csVariableIndex(builder.NextVariableIndex);
        builder.NextVariableIndex++;
        builder.State = builder.State.WithVariable(name, index);

        IR1csOp op = kind switch
        {
            R1csVariableKind.PublicInput => new DeclarePublicInputOp(index, name),
            R1csVariableKind.WitnessVariable => new DeclareWitnessVariableOp(index, name),
            R1csVariableKind.Intermediate => new DeclareIntermediateVariableOp(index, name),
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unsupported declaration kind.")
        };

        var metadata = new R1csVariableMetadata(index, name, kind);
        _ = builder.With((circuit, _, _) => AppendDeclaration(circuit, op, metadata, kind));

        return index;
    }


    private static R1csCircuit AppendDeclaration(R1csCircuit circuit, IR1csOp op, R1csVariableMetadata metadata, R1csVariableKind kind)
    {
        int publicInputCount = circuit.PublicInputCount + (kind == R1csVariableKind.PublicInput ? 1 : 0);
        int witnessVariableCount = circuit.WitnessVariableCount + (kind is R1csVariableKind.WitnessVariable or R1csVariableKind.Intermediate ? 1 : 0);

        return new R1csCircuit(
            circuit.Curve,
            circuit.Operations.Add(op),
            circuit.Variables.Add(metadata),
            publicInputCount,
            witnessVariableCount);
    }


    private static R1csCircuit AppendConstraint(R1csCircuit circuit, AddConstraintOp op)
    {
        return new R1csCircuit(
            circuit.Curve,
            circuit.Operations.Add(op),
            circuit.Variables,
            circuit.PublicInputCount,
            circuit.WitnessVariableCount);
    }


    private static void ValidateNewName(R1csCircuitBuilder builder, string name)
    {
        if(string.IsNullOrEmpty(name))
        {
            throw new ArgumentException("Variable name must be non-empty.", nameof(name));
        }

        if(builder.State.NamedVariables.ContainsKey(name))
        {
            throw new ArgumentException($"A variable named '{name}' is already declared; names are unique within a circuit.", nameof(name));
        }
    }


    private static void ValidateReferences(R1csCircuitBuilder builder, R1csLinearCombination combination, string paramName)
    {
        int variableCount = builder.NextVariableIndex;
        foreach((R1csVariableIndex Variable, BigInteger Coefficient) term in combination.Terms)
        {
            int value = term.Variable.Value;
            if(value < 0 || value >= variableCount)
            {
                throw new ArgumentException(
                    $"Constraint references variable index {value}, which has not been declared (the circuit has {variableCount} variables).",
                    paramName);
            }
        }
    }
}
