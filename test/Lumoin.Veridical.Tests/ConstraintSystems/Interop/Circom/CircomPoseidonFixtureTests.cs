using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.Circom;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.IO;
using System.IO.Pipelines;
using System.Threading;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.Circom;

/// <summary>
/// Real-world fixture gate: a two-input Poseidon R1CS instance and its
/// matching witness, one fixture per curve target, parse through both
/// adapters into a well-formed <see cref="RawR1csInstance"/> and
/// <see cref="RawR1csWitness"/> and satisfy <c>A·z ∘ B·z = C·z</c> in the
/// curve's scalar arithmetic.
/// </summary>
/// <remarks>
/// The satisfaction check is the load-bearing assertion: it exercises every
/// coefficient in all three matrices against the parsed witness, so a single
/// LE/BE byte-order mistake, section-payload slicing error, or row/column
/// transposition surfaces here as a non-satisfaction. Multiplier2 already
/// proved the parser end-to-end through Spartan; this proves it scales to a
/// non-trivial circuit (a few hundred constraints) whose constraint section
/// precedes its header section in file order, exercising the reader's
/// variable section-order handling. The exact constraint and wire counts
/// are specific to how the circuit was compiled, so the structural
/// assertions check consistency and scale, not frozen numbers. Poseidon's
/// shape is not a power of two, so it does not feed the Spartan prover.
/// </remarks>
[TestClass]
internal sealed class CircomPoseidonFixtureTests
{
    /// <summary>The fixture directory, relative to the test output, holding the per-curve Circom Poseidon fixture files.</summary>
    private const string FixtureDirectoryRelative = "ConstraintSystems/Interop/Circom/Fixtures";

    /// <summary>The minimum constraint row count a compiled two-input Poseidon circuit must have to count as a non-trivial fixture.</summary>
    private const int PoseidonConstraintLowerBound = 200;


    /// <summary>Verifies that the BLS12-381 Poseidon(2) fixture parses and satisfies its constraints under the curve's scalar arithmetic.</summary>
    [TestMethod]
    public void Bls12Curve381PoseidonFixtureParsesAndSatisfies()
    {
        ExercisePoseidonFixture(
            "bls12_381",
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381BigIntegerScalarReference.GetAdd(),
            Bls12Curve381BigIntegerScalarReference.GetMultiply());
    }


    /// <summary>Verifies that the BN254 Poseidon(2) fixture parses and satisfies its constraints under the curve's scalar arithmetic.</summary>
    [TestMethod]
    public void Bn254PoseidonFixtureParsesAndSatisfies()
    {
        ExercisePoseidonFixture(
            "bn254",
            CurveParameterSet.Bn254,
            Bn254BigIntegerScalarReference.GetAdd(),
            Bn254BigIntegerScalarReference.GetMultiply());
    }


    /// <summary>Loads <paramref name="curveDirectory"/>'s Poseidon fixture, parses its instance and witness, and asserts structural consistency and constraint satisfaction.</summary>
    /// <param name="curveDirectory">The fixture subdirectory naming the curve, matching the committed fixture layout.</param>
    /// <param name="curve">The curve the fixture bytes are declared under.</param>
    /// <param name="add">The reference scalar addition used to check satisfaction.</param>
    /// <param name="multiply">The reference scalar multiplication used to check satisfaction.</param>
    private static void ExercisePoseidonFixture(
        string curveDirectory,
        CurveParameterSet curve,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply)
    {
        (byte[] r1csBytes, byte[] wtnsBytes) = LoadFixtureBytes(curveDirectory);

        using RawR1csInstance instance = ParseR1cs(r1csBytes, curve);
        using RawR1csWitness witness = ParseWtns(wtnsBytes, curve);

        //Structural consistency across the three matrices, the scale that
        //distinguishes a real Poseidon circuit from the trivial multiplier2, the
        //Circom public-input convention, and the witness/wire relationship.
        Assert.AreEqual(instance.A.RowCount, instance.B.RowCount, "A/B row counts");
        Assert.AreEqual(instance.A.RowCount, instance.C.RowCount, "A/C row counts");
        Assert.AreEqual(instance.A.ColumnCount, instance.B.ColumnCount, "A/B column counts");
        Assert.AreEqual(instance.A.ColumnCount, instance.C.ColumnCount, "A/C column counts");
        Assert.IsGreaterThan(
            PoseidonConstraintLowerBound,
            instance.A.RowCount,
            $"Poseidon(2) should compile to more than {PoseidonConstraintLowerBound} constraints; got {instance.A.RowCount}.");
        Assert.AreEqual(0, instance.PublicInputCount, "PublicInputCount (Circom convention routes all wires but z[0] into the witness)");
        Assert.AreEqual(instance.A.ColumnCount - 1, witness.WitnessVariableCount, "WitnessVariableCount = wires - 1 (z[0]=1 dropped)");
        Assert.AreEqual(curve.Code, instance.Curve.Code, "parsed instance curve");

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(
            witness, add, multiply, BaseMemoryPool.Shared);

        if(satisfaction is R1csSatisfaction.Violated violated)
        {
            Assert.Fail(
                $"Poseidon fixture ({curveDirectory}) satisfaction check failed at constraint {violated.ConstraintIndex.Value}; " +
                $"A·z ∘ B·z computed one value, C·z expected another. " +
                $"Involved variables: {string.Join(", ", violated.InvolvedVariables)}.");
        }

        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction);
    }


    /// <summary>Reads the Poseidon <c>.r1cs</c> and <c>.wtns</c> fixture bytes for <paramref name="curveDirectory"/>.</summary>
    /// <param name="curveDirectory">The fixture subdirectory naming the curve.</param>
    private static (byte[] R1csBytes, byte[] WtnsBytes) LoadFixtureBytes(string curveDirectory)
    {
        string directory = Path.Combine(AppContext.BaseDirectory, FixtureDirectoryRelative, curveDirectory);
        if(!Directory.Exists(directory))
        {
            //Fall back to repo-relative when the test host does not copy
            //AppContext.BaseDirectory's parallel test folders (some MTP configs).
            directory = Path.Combine(FixtureDirectoryRelative, curveDirectory);
        }

        string r1csPath = Path.Combine(directory, "poseidon2.r1cs");
        string wtnsPath = Path.Combine(directory, "poseidon2.wtns");

        if(!File.Exists(r1csPath))
        {
            Assert.Inconclusive(
                $"Fixture file not found: {r1csPath}. Restore the committed fixture bytes.");
        }

        if(!File.Exists(wtnsPath))
        {
            Assert.Inconclusive(
                $"Fixture file not found: {wtnsPath}. Restore the committed fixture bytes.");
        }

        return (File.ReadAllBytes(r1csPath), File.ReadAllBytes(wtnsPath));
    }


    /// <summary>Parses the R1CS instance from raw Circom <c>.r1cs</c> bytes, with no intake ceiling.</summary>
    /// <param name="bytes">The complete <c>.r1cs</c> file bytes.</param>
    /// <param name="curve">The curve the instance is declared under.</param>
    private static RawR1csInstance ParseR1cs(byte[] bytes, CurveParameterSet curve)
    {
        var stream = new MemoryStream(bytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);

        return CircomR1csReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomBinary,
            curve,
            BaseMemoryPool.Shared,
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);
    }


    /// <summary>Parses the R1CS witness from raw Circom <c>.wtns</c> bytes, with no intake ceiling.</summary>
    /// <param name="bytes">The complete <c>.wtns</c> file bytes.</param>
    /// <param name="curve">The curve the witness is declared under.</param>
    private static RawR1csWitness ParseWtns(byte[] bytes, CurveParameterSet curve)
    {
        var stream = new MemoryStream(bytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);

        return CircomWitnessReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomWitness,
            curve,
            BaseMemoryPool.Shared,
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);
    }
}
