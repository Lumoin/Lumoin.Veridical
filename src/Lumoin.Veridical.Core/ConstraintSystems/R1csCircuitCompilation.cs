using Lumoin.Veridical.Core.Memory;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Compiles an <see cref="R1csCircuit"/> against input bindings into a
/// satisfying <see cref="RawR1csInstance"/> / <see cref="RawR1csWitness"/>
/// pair ready for the Spartan prover.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class R1csCircuitCompilation
{
    extension(R1csCircuit circuit)
    {
        /// <summary>
        /// Evaluates the circuit's operations against <paramref name="inputs"/>
        /// and produces the public instance and the private witness.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Two passes: first every declared variable is bound to its input
        /// value (the constant one is fixed to 1; a missing binding throws),
        /// then the constraint operations are turned into the three sparse
        /// matrices, reducing each arbitrary-precision coefficient modulo the
        /// curve's scalar field order.
        /// </para>
        /// <para>
        /// Before building the matrices the assignment is checked against the
        /// constraints in arbitrary-precision arithmetic modulo the field
        /// order; a non-satisfying assignment throws
        /// <see cref="R1csCircuitCompilationException"/> naming the first
        /// failing constraint. This is the equivalent of
        /// <see cref="RawR1csInstanceExtensions"/>'s <c>CheckSatisfiedBy</c>,
        /// performed inline so the compiler stays self-contained — that method
        /// takes injected scalar-arithmetic delegates that the builder API
        /// deliberately does not, and the compiler already holds every value
        /// as a <see cref="BigInteger"/>, so the in-field check needs no
        /// backend.
        /// </para>
        /// </remarks>
        /// <param name="inputs">The name→value bindings for every declared public, witness, and intermediate variable.</param>
        /// <param name="pool">The pool the instance, witness, and matrices rent their buffers from.</param>
        /// <returns>The public instance and the satisfying witness.</returns>
        /// <exception cref="ArgumentNullException">When <paramref name="inputs"/> or <paramref name="pool"/> is null.</exception>
        /// <exception cref="R1csCircuitCompilationException">When an input is missing, the circuit has no constraints or witness variables, or the assignment does not satisfy the constraints.</exception>
        public (RawR1csInstance Instance, RawR1csWitness Witness) Compile(
            R1csCircuitInputs inputs,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(circuit);
            ArgumentNullException.ThrowIfNull(inputs);
            ArgumentNullException.ThrowIfNull(pool);

            CurveParameterSet curve = circuit.Curve;
            WellKnownCurves.ThrowIfCurveNotWired(curve);
            BigInteger fieldOrder = WellKnownCurves.GetScalarFieldOrder(curve);
            int scalarSize = R1csMatrix.GetValueByteSize(curve);

            BigInteger[] assignment = BindVariables(circuit, inputs, fieldOrder);

            var constraints = new List<AddConstraintOp>();
            foreach(IR1csOp op in circuit.Operations)
            {
                if(op is AddConstraintOp constraint)
                {
                    constraints.Add(constraint);
                }
            }

            if(constraints.Count == 0)
            {
                throw new R1csCircuitCompilationException(
                    "Circuit has no constraints; at least one constraint is required to compile an instance.");
            }

            if(circuit.WitnessVariableCount == 0)
            {
                throw new R1csCircuitCompilationException(
                    "Circuit has no witness variables; a provable instance needs at least one private variable.");
            }

            VerifySatisfaction(constraints, assignment, fieldOrder);

            int columnCount = circuit.VariableCount;
            R1csMatrix a = BuildMatrix(constraints, static c => c.Left, columnCount, fieldOrder, scalarSize, curve, pool);
            R1csMatrix b;
            R1csMatrix c;
            try
            {
                b = BuildMatrix(constraints, static op => op.Middle, columnCount, fieldOrder, scalarSize, curve, pool);
            }
            catch
            {
                a.Dispose();
                throw;
            }

            try
            {
                c = BuildMatrix(constraints, static op => op.Right, columnCount, fieldOrder, scalarSize, curve, pool);
            }
            catch
            {
                a.Dispose();
                b.Dispose();
                throw;
            }

            RawR1csInstance instance;
            try
            {
                instance = BuildInstance(circuit, assignment, a, b, c, scalarSize, pool);
            }
            catch
            {
                a.Dispose();
                b.Dispose();
                c.Dispose();
                throw;
            }

            try
            {
                RawR1csWitness witness = BuildWitness(circuit, assignment, scalarSize, curve, pool);
                return (instance, witness);
            }
            catch
            {
                instance.Dispose();
                throw;
            }
        }


        /// <summary>
        /// Builds the public <see cref="RawR1csInstance"/> — the three coefficient
        /// matrices and the public inputs — from the circuit's structure alone,
        /// with no witness. This is the verifier's counterpart to <c>Compile</c>: a
        /// counterparty checking a proof holds the public statement (the circuit,
        /// rebuilt from a trusted descriptor, and the revealed public inputs) but
        /// not the private assignment, so it cannot use <c>Compile</c>, which binds
        /// every variable and checks satisfaction.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <c>A</c>, <c>B</c>, and <c>C</c> matrices are a pure function of the
        /// circuit's constraint operations — they do not depend on any variable's
        /// value — so they are identical to the matrices <c>Compile</c> produces for
        /// the same circuit. Only the public inputs carry values, and they arrive
        /// here already encoded (canonical big-endian scalars, in public-input
        /// declaration order), the same bytes the prover's instance exposes through
        /// <see cref="RawR1csInstance.GetPublicInputsBytes"/>.
        /// </para>
        /// <para>
        /// No satisfaction check is performed and no witness is built: the proof,
        /// not this instance, is the evidence that a satisfying witness exists.
        /// </para>
        /// </remarks>
        /// <param name="publicInputs">The canonical big-endian bytes of the public-input scalars, in declaration order; length must be <c>PublicInputCount × scalarSize</c>.</param>
        /// <param name="pool">The pool the matrices and instance rent their buffers from.</param>
        /// <returns>The public instance a verifier checks a proof against.</returns>
        /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is null.</exception>
        /// <exception cref="R1csCircuitCompilationException">When the circuit has no constraints.</exception>
        /// <exception cref="ArgumentException">When <paramref name="publicInputs"/> does not match the circuit's public-input count, or a public input is not a canonical scalar.</exception>
        public RawR1csInstance CompileInstance(ReadOnlySpan<byte> publicInputs, BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(circuit);
            ArgumentNullException.ThrowIfNull(pool);

            CurveParameterSet curve = circuit.Curve;
            WellKnownCurves.ThrowIfCurveNotWired(curve);
            BigInteger fieldOrder = WellKnownCurves.GetScalarFieldOrder(curve);
            int scalarSize = R1csMatrix.GetValueByteSize(curve);

            var constraints = new List<AddConstraintOp>();
            foreach(IR1csOp op in circuit.Operations)
            {
                if(op is AddConstraintOp constraint)
                {
                    constraints.Add(constraint);
                }
            }

            if(constraints.Count == 0)
            {
                throw new R1csCircuitCompilationException(
                    "Circuit has no constraints; at least one constraint is required to compile an instance.");
            }

            if(publicInputs.Length != circuit.PublicInputCount * scalarSize)
            {
                throw new ArgumentException(
                    $"Public-input byte length {publicInputs.Length} does not match the circuit's {circuit.PublicInputCount} public input(s) at {scalarSize} bytes each.",
                    nameof(publicInputs));
            }

            int columnCount = circuit.VariableCount;
            R1csMatrix a = BuildMatrix(constraints, static op => op.Left, columnCount, fieldOrder, scalarSize, curve, pool);
            R1csMatrix b;
            R1csMatrix c;
            try
            {
                b = BuildMatrix(constraints, static op => op.Middle, columnCount, fieldOrder, scalarSize, curve, pool);
            }
            catch
            {
                a.Dispose();
                throw;
            }

            try
            {
                c = BuildMatrix(constraints, static op => op.Right, columnCount, fieldOrder, scalarSize, curve, pool);
            }
            catch
            {
                a.Dispose();
                b.Dispose();
                throw;
            }

            //RawR1csInstance.Create takes ownership of the matrices on success and
            //validates the public-input bytes (length + canonical); on a validation
            //throw it has not taken ownership, so the matrices are disposed here.
            try
            {
                return RawR1csInstance.Create(a, b, c, publicInputs, pool);
            }
            catch
            {
                a.Dispose();
                b.Dispose();
                c.Dispose();
                throw;
            }
        }
    }


    private static BigInteger[] BindVariables(R1csCircuit circuit, R1csCircuitInputs inputs, BigInteger fieldOrder)
    {
        var assignment = new BigInteger[circuit.VariableCount];
        foreach(R1csVariableMetadata variable in circuit.Variables)
        {
            if(variable.Kind == R1csVariableKind.ConstantOne)
            {
                assignment[variable.Index.Value] = BigInteger.One;
                continue;
            }

            if(!inputs.TryGetValue(variable.Name, out BigInteger value))
            {
                throw new R1csCircuitCompilationException(
                    $"No input value bound for variable '{variable.Name}' (index {variable.Index.Value}, {variable.Kind}).");
            }

            assignment[variable.Index.Value] = Reduce(value, fieldOrder);
        }

        return assignment;
    }


    private static void VerifySatisfaction(IReadOnlyList<AddConstraintOp> constraints, BigInteger[] assignment, BigInteger fieldOrder)
    {
        for(int row = 0; row < constraints.Count; row++)
        {
            AddConstraintOp constraint = constraints[row];
            BigInteger az = Evaluate(constraint.Left, assignment, fieldOrder);
            BigInteger bz = Evaluate(constraint.Middle, assignment, fieldOrder);
            BigInteger cz = Evaluate(constraint.Right, assignment, fieldOrder);

            if(Reduce(az * bz - cz, fieldOrder) != BigInteger.Zero)
            {
                throw new R1csCircuitCompilationException(
                    $"Assignment does not satisfy constraint {row}: (A·z)·(B·z) = {Reduce(az * bz, fieldOrder)} but (C·z) = {cz} (mod r). The predicate that emitted this constraint and the supplied auxiliary values disagree.");
            }
        }
    }


    private static BigInteger Evaluate(R1csLinearCombination combination, BigInteger[] assignment, BigInteger fieldOrder)
    {
        BigInteger accumulator = combination.Constant;
        foreach((R1csVariableIndex Variable, BigInteger Coefficient) term in combination.Terms)
        {
            accumulator += term.Coefficient * assignment[term.Variable.Value];
        }

        return Reduce(accumulator, fieldOrder);
    }


    private static R1csMatrix BuildMatrix(
        IReadOnlyList<AddConstraintOp> constraints,
        Func<AddConstraintOp, R1csLinearCombination> select,
        int columnCount,
        BigInteger fieldOrder,
        int scalarSize,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        var rows = new List<int>();
        var columns = new List<int>();
        var values = new List<BigInteger>();

        for(int row = 0; row < constraints.Count; row++)
        {
            R1csLinearCombination combination = select(constraints[row]);

            //Sum coefficients per column (the constant term lands on the
            //constant-one column 0, where it may meet an explicit term), then
            //emit in ascending column order so the triples stay sorted.
            var perColumn = new SortedDictionary<int, BigInteger>();
            foreach((R1csVariableIndex Variable, BigInteger Coefficient) term in combination.Terms)
            {
                Accumulate(perColumn, term.Variable.Value, term.Coefficient);
            }

            if(!combination.Constant.IsZero)
            {
                Accumulate(perColumn, 0, combination.Constant);
            }

            foreach(KeyValuePair<int, BigInteger> entry in perColumn)
            {
                BigInteger reduced = Reduce(entry.Value, fieldOrder);
                if(!reduced.IsZero)
                {
                    rows.Add(row);
                    columns.Add(entry.Key);
                    values.Add(reduced);
                }
            }
        }

        if(rows.Count == 0)
        {
            //A genuinely all-zero matrix has no COO encoding; synthesise a
            //single zero entry at (0, 0), which does not change satisfaction.
            Span<int> singleRow = stackalloc int[] { 0 };
            Span<int> singleColumn = stackalloc int[] { 0 };
            Span<byte> zeroValue = stackalloc byte[scalarSize];
            zeroValue.Clear();
            return R1csMatrix.FromSortedTriples(singleRow, singleColumn, zeroValue, constraints.Count, columnCount, curve, pool);
        }

        int nonzeroCount = rows.Count;
        byte[] valueBytes = new byte[nonzeroCount * scalarSize];
        for(int i = 0; i < nonzeroCount; i++)
        {
            WriteCanonical(values[i], valueBytes.AsSpan(i * scalarSize, scalarSize));
        }

        return R1csMatrix.FromSortedTriples(
            CollectionsMarshal.AsSpan(rows),
            CollectionsMarshal.AsSpan(columns),
            valueBytes,
            constraints.Count,
            columnCount,
            curve,
            pool);
    }


    private static RawR1csInstance BuildInstance(
        R1csCircuit circuit,
        BigInteger[] assignment,
        R1csMatrix a,
        R1csMatrix b,
        R1csMatrix c,
        int scalarSize,
        BaseMemoryPool pool)
    {
        //Public inputs occupy indices 1..1+PublicInputCount by the builder's
        //contiguity guarantee.
        int publicInputCount = circuit.PublicInputCount;
        byte[] publicInputBytes = new byte[publicInputCount * scalarSize];
        for(int i = 0; i < publicInputCount; i++)
        {
            WriteCanonical(assignment[1 + i], publicInputBytes.AsSpan(i * scalarSize, scalarSize));
        }

        return RawR1csInstance.Create(a, b, c, publicInputBytes, pool);
    }


    private static RawR1csWitness BuildWitness(
        R1csCircuit circuit,
        BigInteger[] assignment,
        int scalarSize,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        //Witness variables occupy the positions after the public-input block.
        int witnessCount = circuit.WitnessVariableCount;
        int witnessStart = 1 + circuit.PublicInputCount;
        byte[] witnessBytes = new byte[witnessCount * scalarSize];
        for(int i = 0; i < witnessCount; i++)
        {
            WriteCanonical(assignment[witnessStart + i], witnessBytes.AsSpan(i * scalarSize, scalarSize));
        }

        return RawR1csWitness.FromCanonical(witnessBytes, curve, pool);
    }


    private static void Accumulate(SortedDictionary<int, BigInteger> perColumn, int column, BigInteger coefficient)
    {
        perColumn[column] = perColumn.TryGetValue(column, out BigInteger existing)
            ? existing + coefficient
            : coefficient;
    }


    private static BigInteger Reduce(BigInteger value, BigInteger fieldOrder)
    {
        BigInteger remainder = value % fieldOrder;
        return remainder.Sign < 0 ? remainder + fieldOrder : remainder;
    }


    private static void WriteCanonical(BigInteger reducedValue, Span<byte> destination)
    {
        //reducedValue is already in [0, r); write it big-endian, right-aligned.
        destination.Clear();
        if(!reducedValue.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new R1csCircuitCompilationException(
                $"Reduced scalar did not fit in the {destination.Length}-byte canonical field-element span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
