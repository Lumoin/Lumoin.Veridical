using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Tests the witness-assembly sink directly by driving its push API. The
/// payoff assertion combines both builders: a multiplier2 instance (public
/// output <c>c</c>, private <c>a, b</c>) and the witness assembled from the
/// header's instance value plus the witness message's private values must
/// satisfy <c>A·z ∘ B·z = C·z</c>, because the scatter must reconstruct the
/// full <c>z[1..]</c> that the PublicInputCount = 0 convention expects.
/// </summary>
/// <remarks>
/// Satisfaction cannot reveal a witness whose values collapsed to zero, because multiplier2 is satisfied by
/// <c>z = (1, 0, 0, 0)</c>, so the assembly tests push distinct, full-width values and read every witness byte
/// back. Several construction, intake and build guards share an exception type, so each rejection test drives
/// exactly one guard and asserts what only that guard produces.
/// </remarks>
[TestClass]
internal sealed class ZkInterfaceWitnessBuilderTests
{
    /// <summary>
    /// The four-column variable space <c>z = (1, c, a, b)</c> of multiplier2, declared as <c>free_variable_id</c>.
    /// </summary>
    private const int VariableCount = 4;

    /// <summary>The witness width of a four-column variable space: every variable but the constant one.</summary>
    private const int WitnessVariableCount = 3;

    /// <summary>
    /// The widest column ceiling. These tests drive the assembly logic directly, not the source-size
    /// amplification guard, so they pass a ceiling no column count exceeds; <see cref="ZkInterfaceBuilderBoundaryTests"/>
    /// pins that guard.
    /// </summary>
    private const int UnboundedColumnCeiling = int.MaxValue;

    /// <summary>The constructor parameter a null-pool rejection names.</summary>
    private const string PoolParameterName = "pool";

    /// <summary>The constructor parameter a negative-ceiling rejection names.</summary>
    private const string MaxColumnCountParameterName = "maxColumnCount";

    /// <summary>A column ceiling below zero, which no source byte length can produce.</summary>
    private const int NegativeColumnCeiling = -1;

    /// <summary>The variable ID of the constant one, which the witness excludes from <c>z[1..]</c>.</summary>
    private const ulong ConstantVariableId = 0;

    /// <summary>The constant variable's value one, written as the single little-endian byte a truncating producer emits.</summary>
    private const byte ConstantOneValue = 1;

    /// <summary>The first variable after the constant; multiplier2 places its public output <c>c</c> here.</summary>
    private const ulong FirstVariableId = 1;

    /// <summary>The second variable after the constant; multiplier2 places its factor <c>a</c> here.</summary>
    private const ulong SecondVariableId = 2;

    /// <summary>The third variable after the constant; multiplier2 places its factor <c>b</c> here.</summary>
    private const ulong ThirdVariableId = 3;

    /// <summary>
    /// The witness slot of <see cref="FirstVariableId"/>: <c>z[1..]</c> omits the constant column, so each variable
    /// sits one slot below its ID.
    /// </summary>
    private const int FirstVariableSlot = 0;

    /// <summary>The witness slot of <see cref="SecondVariableId"/>.</summary>
    private const int SecondVariableSlot = 1;

    /// <summary>The witness slot of <see cref="ThirdVariableId"/>.</summary>
    private const int ThirdVariableSlot = 2;

    /// <summary>The variable space of a witness with one variable beyond the constant, declared as <c>free_variable_id</c>.</summary>
    private const int SingleVariableColumnCount = 2;

    /// <summary>The witness width of <see cref="SingleVariableColumnCount"/> columns.</summary>
    private const int SingleWitnessVariableCount = 1;

    /// <summary>Selects a reproducible stream of distinct, non-zero, full-width canonical witness values.</summary>
    private const int WitnessValueFillSalt = 43;

    /// <summary>The BN254 scalar field modulus as the lowercase big-endian hex a field rejection reports.</summary>
    private const string Bn254ScalarFieldModulusHex = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

    /// <summary>The text only the repeated-declaration guard on <c>field_maximum</c> produces.</summary>
    private const string RepeatedFieldMaximumMessage = "more than one CircuitHeader field_maximum";

    /// <summary>The text only the empty-witness guard produces.</summary>
    private const string NoVariablesMessage = "has no variables beyond the constant one";


    /// <summary>
    /// Builds the multiplier2 instance and witness over BLS12-381 and checks the witness width and that the pair
    /// satisfies the instance.
    /// </summary>
    [TestMethod]
    public void Bls12Curve381InstanceAndWitnessSatisfy()
    {
        ExerciseMultiplier2(
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381BigIntegerScalarReference.GetAdd(),
            Bls12Curve381BigIntegerScalarReference.GetMultiply());
    }


    /// <summary>
    /// Builds the multiplier2 instance and witness over BN254 and checks the witness width and that the pair
    /// satisfies the instance.
    /// </summary>
    [TestMethod]
    public void Bn254InstanceAndWitnessSatisfy()
    {
        ExerciseMultiplier2(
            CurveParameterSet.Bn254,
            Bn254BigIntegerScalarReference.GetAdd(),
            Bn254BigIntegerScalarReference.GetMultiply());
    }


    /// <summary>
    /// Pins that a witness stream that never declares <c>field_maximum</c> is rejected at
    /// <see cref="ZkInterfaceWitnessBuilder.Build"/> with <see cref="R1csUnsupportedFieldException"/>, because an
    /// undeclared field cannot be validated against the curve.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsAbsentField()
    {
        var builder = new ZkInterfaceWitnessBuilder(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, UnboundedColumnCeiling);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(VariableCount);
        PushAssignment(sink, witness: false, variableId: 1, value: 33);

        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() => builder.Build());
    }


    /// <summary>
    /// Pins that the constructor rejects a null pool with an <see cref="ArgumentNullException"/> naming
    /// <c>pool</c>. The curve is wired and the ceiling is non-negative, so no other constructor check can throw,
    /// and nothing else in the constructor reads the pool, so only the null check can answer at construction;
    /// without it the failure would surface later, at the first rent in
    /// <see cref="ZkInterfaceWitnessBuilder.Build"/>.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsNullPool()
    {
        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => new ZkInterfaceWitnessBuilder(CurveParameterSet.Bls12Curve381, null!, UnboundedColumnCeiling),
            "A null pool must be rejected.");

        Assert.AreEqual(PoolParameterName, exception.ParamName, "The rejection must name the pool parameter.");
    }


    /// <summary>
    /// Pins that the constructor rejects a negative column ceiling with an
    /// <see cref="ArgumentOutOfRangeException"/> naming <c>maxColumnCount</c>. The pool is present and the curve is
    /// wired, so only the sign check can answer; without it the builder would construct, every column count
    /// would exceed the negative ceiling, and each build that reached the source ceiling would fail there with a
    /// plain <see cref="ArgumentException"/>.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsNegativeColumnCeiling()
    {
        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new ZkInterfaceWitnessBuilder(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, NegativeColumnCeiling),
            "A negative column ceiling must be rejected.");

        Assert.AreEqual(MaxColumnCountParameterName, exception.ParamName, "The rejection must name the column-ceiling parameter.");
    }


    /// <summary>
    /// Pins that a second <c>field_maximum</c> declaration is rejected even when both declarations match the
    /// curve. The repeated value is the curve's own, so the field reconciliation after the repetition check
    /// cannot throw, and the repeated-declaration guard is the only one that can answer; its message is asserted
    /// because the exception type alone does not identify it.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsSecondFieldMaximum()
    {
        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, UnboundedColumnCeiling);
        IZkInterfaceMessageSink sink = builder;
        DeclareFieldMaximum(sink, CurveParameterSet.Bls12Curve381);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => DeclareFieldMaximum(sink, CurveParameterSet.Bls12Curve381),
            "A repeated field_maximum must be rejected.");

        Assert.Contains(RepeatedFieldMaximumMessage, exception.Message, StringComparison.Ordinal, "The repeated-declaration guard must be what rejects the stream.");
    }


    /// <summary>
    /// Pins that a BLS12-381 witness builder rejects a declared BN254 field at the declaration itself with
    /// <see cref="R1csUnsupportedFieldException"/> reporting the declared modulus. It is the first declaration, so
    /// the repeated-declaration guard cannot answer, and the field reconciliation is the only intake check that
    /// throws this type; without it the foreign field would be accepted silently.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsFieldThatDoesNotMatchTheCurve()
    {
        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, UnboundedColumnCeiling);
        IZkInterfaceMessageSink sink = builder;

        R1csUnsupportedFieldException exception = Assert.ThrowsExactly<R1csUnsupportedFieldException>(
            () => DeclareFieldMaximum(sink, CurveParameterSet.Bn254),
            "A field that does not match the curve must be rejected.");

        Assert.AreEqual(Bn254ScalarFieldModulusHex, exception.FoundModulusHex, "The rejection must report the declared BN254 modulus.");
    }


    /// <summary>
    /// Pins that a stream which declares its field but neither a <c>free_variable_id</c> nor any assignment is
    /// rejected at <see cref="ZkInterfaceWitnessBuilder.Build"/>, because a witness needs at least one variable
    /// beyond the constant. The field matches, and a zero-column space passes both the source ceiling and the
    /// dense-buffer limit, so only the empty-witness guard can answer. The exact type and the message are both
    /// asserted, because without the guard the negative buffer size reaches the pool, which throws the derived
    /// <see cref="ArgumentOutOfRangeException"/>. A resolution that gave this empty stream two columns would
    /// build a one-variable witness instead of throwing.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsWitnessWithNoVariableBeyondTheConstant()
    {
        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, UnboundedColumnCeiling);
        IZkInterfaceMessageSink sink = builder;
        DeclareFieldMaximum(sink, CurveParameterSet.Bls12Curve381);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => builder.Build().Dispose(),
            "A witness without a variable beyond the constant must be rejected.");

        Assert.Contains(NoVariablesMessage, exception.Message, StringComparison.Ordinal, "The empty-witness guard must be what rejects the stream.");
    }


    /// <summary>
    /// Pins that a declared <c>free_variable_id</c> above every assigned ID sizes the witness, and that the
    /// declared columns no message assigns read as zero. Only the first variable is assigned, which alone needs
    /// two columns, so the four-column width can come only from the declaration: a builder that loses the
    /// declared value, skips it, or keeps the narrower of the declared and assigned widths builds a one-variable
    /// witness instead.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderZeroFillsDeclaredColumnsThatNoMessageAssigns()
    {
        Span<byte> expected = stackalloc byte[WitnessVariableCount * ZkInterfaceTestFields.FieldElementSizeBytes];
        expected.Clear();
        FillWitnessValues(WitnessSlot(expected, FirstVariableSlot));

        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, UnboundedColumnCeiling);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(VariableCount);
        DeclareFieldMaximum(sink, CurveParameterSet.Bls12Curve381);
        PushCanonicalAssignment(sink, witness: false, variableId: FirstVariableId, canonicalBigEndian: WitnessSlot(expected, FirstVariableSlot));

        using RawR1csWitness witness = builder.Build();

        Assert.AreEqual(WitnessVariableCount, witness.WitnessVariableCount, "The declared free_variable_id must size the witness beyond the assigned IDs.");
        Assert.IsTrue(expected.SequenceEqual(witness.GetWitnessBytes()), "The assigned value must fill its own slot and the unassigned declared slots must be zero.");
    }


    /// <summary>
    /// Pins that a stream assigning the constant variable and one other builds a one-variable witness that holds
    /// only the other value. One variable beyond the constant is the smallest witness the builder accepts, so a
    /// size check that also refuses it rejects this stream. The constant's assignment, and only that one, must be
    /// skipped: <c>z[1..]</c> has no slot for column 0, so scattering it addresses the slot before the buffer and
    /// throws, while skipping the other column leaves the witness value unwritten.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderSkipsTheConstantColumnInASingleVariableWitness()
    {
        Span<byte> expected = stackalloc byte[SingleWitnessVariableCount * ZkInterfaceTestFields.FieldElementSizeBytes];
        FillWitnessValues(expected);

        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, UnboundedColumnCeiling);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(SingleVariableColumnCount);
        DeclareFieldMaximum(sink, CurveParameterSet.Bls12Curve381);
        PushAssignment(sink, witness: false, variableId: ConstantVariableId, value: ConstantOneValue);
        PushCanonicalAssignment(sink, witness: true, variableId: FirstVariableId, canonicalBigEndian: WitnessSlot(expected, FirstVariableSlot));

        using RawR1csWitness witness = builder.Build();

        Assert.AreEqual(SingleWitnessVariableCount, witness.WitnessVariableCount, "One variable beyond the constant must give a one-variable witness.");
        Assert.IsTrue(expected.SequenceEqual(witness.GetWitnessBytes()), "The witness must hold only the value of the first variable.");
    }


    /// <summary>
    /// Pins that, with no <c>free_variable_id</c> declared, the highest assigned ID alone sizes the witness, and
    /// that each value lands in its own ID's slot as canonical big-endian, whatever order the assignments arrive
    /// in and whichever message carries them. The values are distinct, non-zero, full-width scalars, so a value
    /// that is dropped, left unconverted, misplaced or never copied changes a witness byte; satisfaction alone
    /// cannot show this, because multiplier2 is satisfied by the all-zero witness. With nothing declared, a
    /// resolution that ignores the assigned IDs, stops tracking the highest one, or counts short of it either
    /// rejects the stream or has no slot for the highest ID.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderSizesAndScattersFromAssignedIdsWithoutFreeVariableId()
    {
        Span<byte> expected = stackalloc byte[WitnessVariableCount * ZkInterfaceTestFields.FieldElementSizeBytes];
        FillWitnessValues(expected);

        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, UnboundedColumnCeiling);
        IZkInterfaceMessageSink sink = builder;
        DeclareFieldMaximum(sink, CurveParameterSet.Bls12Curve381);

        //The highest ID arrives first and the public value between the private ones, so neither arrival order nor message kind can stand in for the ID.
        PushCanonicalAssignment(sink, witness: true, variableId: ThirdVariableId, canonicalBigEndian: WitnessSlot(expected, ThirdVariableSlot));
        PushCanonicalAssignment(sink, witness: false, variableId: FirstVariableId, canonicalBigEndian: WitnessSlot(expected, FirstVariableSlot));
        PushCanonicalAssignment(sink, witness: true, variableId: SecondVariableId, canonicalBigEndian: WitnessSlot(expected, SecondVariableSlot));

        using RawR1csWitness witness = builder.Build();

        Assert.AreEqual(WitnessVariableCount, witness.WitnessVariableCount, "The highest assigned ID must size the witness.");
        Assert.IsTrue(expected.SequenceEqual(witness.GetWitnessBytes()), "Each value must land in its own ID's slot as canonical big-endian.");
    }


    /// <summary>
    /// Builds the multiplier2 instance and witness over <paramref name="curve"/> and asserts the witness width and
    /// that the pair satisfies the instance.
    /// </summary>
    /// <param name="curve">The curve the instance and the witness are built over.</param>
    /// <param name="add">The reference scalar addition for <paramref name="curve"/>.</param>
    /// <param name="multiply">The reference scalar multiplication for <paramref name="curve"/>.</param>
    private static void ExerciseMultiplier2(CurveParameterSet curve, ScalarAddDelegate add, ScalarMultiplyDelegate multiply)
    {
        using RawR1csInstance instance = BuildMultiplier2Instance(curve);
        using RawR1csWitness witness = BuildMultiplier2Witness(curve);

        Assert.AreEqual(WitnessVariableCount, witness.WitnessVariableCount, "WitnessVariableCount = columns - 1");

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, add, multiply, BaseMemoryPool.Shared);

        if(satisfaction is R1csSatisfaction.Violated violated)
        {
            Assert.Fail($"multiplier2 instance+witness satisfaction failed at constraint {violated.ConstraintIndex.Value}.");
        }

        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction);
    }


    /// <summary>
    /// Pushes the multiplier2 assignment through the sink interface, the public output as an instance variable
    /// and the factors as witness variables, and builds the witness <c>z[1..] = (33, 3, 11)</c>.
    /// </summary>
    /// <param name="curve">The curve whose field the stream declares.</param>
    /// <returns>The witness, owned by the caller.</returns>
    private static RawR1csWitness BuildMultiplier2Witness(CurveParameterSet curve)
    {
        //z = (1, c, a, b) with c public (instance variable), a and b private
        //(witness). The witness reader scatters both into z[1..] = (33, 3, 11).
        var builder = new ZkInterfaceWitnessBuilder(curve, BaseMemoryPool.Shared, UnboundedColumnCeiling);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(VariableCount);

        Span<byte> fieldMaximum = stackalloc byte[ZkInterfaceTestFields.FieldElementSizeBytes];
        ZkInterfaceTestFields.WriteFieldMaximumLittleEndian(curve, fieldMaximum);
        sink.OnFieldMaximum(fieldMaximum);

        PushAssignment(sink, witness: false, variableId: 1, value: 33);  //c (public)
        PushAssignment(sink, witness: true, variableId: 2, value: 3);    //a (private)
        PushAssignment(sink, witness: true, variableId: 3, value: 11);   //b (private)

        return builder.Build();
    }


    /// <summary>Reports one assignment whose value fits in the single little-endian byte a truncating producer emits.</summary>
    /// <param name="sink">The sink receiving the assignment.</param>
    /// <param name="witness"><see langword="true"/> to report a private witness variable; <see langword="false"/> to report a public instance variable.</param>
    /// <param name="variableId">The variable the value is assigned to.</param>
    /// <param name="value">The value.</param>
    private static void PushAssignment(IZkInterfaceMessageSink sink, bool witness, ulong variableId, byte value)
    {
        Span<byte> littleEndian = stackalloc byte[] { value };
        PushLittleEndianAssignment(sink, witness, variableId, littleEndian);
    }


    /// <summary>
    /// Reports one assignment whose value is <paramref name="canonicalBigEndian"/> re-encoded little-endian, the
    /// byte order ZkInterface stores field elements in.
    /// </summary>
    /// <param name="sink">The sink receiving the assignment.</param>
    /// <param name="witness"><see langword="true"/> to report a private witness variable; <see langword="false"/> to report a public instance variable.</param>
    /// <param name="variableId">The variable the value is assigned to.</param>
    /// <param name="canonicalBigEndian">The full-width value in canonical big-endian order; it is not modified.</param>
    private static void PushCanonicalAssignment(IZkInterfaceMessageSink sink, bool witness, ulong variableId, ReadOnlySpan<byte> canonicalBigEndian)
    {
        Span<byte> littleEndian = stackalloc byte[ZkInterfaceTestFields.FieldElementSizeBytes];
        canonicalBigEndian.CopyTo(littleEndian);
        littleEndian.Reverse();
        PushLittleEndianAssignment(sink, witness, variableId, littleEndian);
    }


    /// <summary>Reports one little-endian assignment through the message that carries its kind of variable.</summary>
    /// <param name="sink">The sink receiving the assignment.</param>
    /// <param name="witness"><see langword="true"/> to report a private witness variable; <see langword="false"/> to report a public instance variable.</param>
    /// <param name="variableId">The variable the value is assigned to.</param>
    /// <param name="valueLittleEndian">The value in ZkInterface's little-endian byte order.</param>
    private static void PushLittleEndianAssignment(IZkInterfaceMessageSink sink, bool witness, ulong variableId, ReadOnlySpan<byte> valueLittleEndian)
    {
        if(witness)
        {
            sink.OnWitnessVariable(variableId, valueLittleEndian);
        }
        else
        {
            sink.OnInstanceVariable(variableId, valueLittleEndian);
        }
    }


    /// <summary>Pushes the padded multiplier2 circuit through the sink interface and builds the instance.</summary>
    /// <param name="curve">The curve whose field the circuit declares.</param>
    /// <returns>The instance, owned by the caller.</returns>
    private static RawR1csInstance BuildMultiplier2Instance(CurveParameterSet curve)
    {
        var builder = new ZkInterfaceR1csInstanceBuilder(curve, BaseMemoryPool.Shared);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(VariableCount);

        Span<byte> fieldMaximum = stackalloc byte[ZkInterfaceTestFields.FieldElementSizeBytes];
        ZkInterfaceTestFields.WriteFieldMaximumLittleEndian(curve, fieldMaximum);
        sink.OnFieldMaximum(fieldMaximum);

        Span<byte> one = stackalloc byte[] { 1 };

        //C0: a · b = c → A{2:1}, B{3:1}, C{1:1}.
        sink.BeginConstraint();
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.A, 2, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.B, 3, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.C, 1, one);
        sink.EndConstraint();

        //C1: 1 · 1 = 1 padding → A{0:1}, B{0:1}, C{0:1}.
        sink.BeginConstraint();
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.A, 0, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.B, 0, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.C, 0, one);
        sink.EndConstraint();

        return builder.Build();
    }


    /// <summary>Declares the field maximum of <paramref name="curve"/>, which every accepted stream carries.</summary>
    /// <param name="sink">The sink receiving the declaration.</param>
    /// <param name="curve">The curve whose scalar field is declared.</param>
    private static void DeclareFieldMaximum(IZkInterfaceMessageSink sink, CurveParameterSet curve)
    {
        Span<byte> fieldMaximum = stackalloc byte[ZkInterfaceTestFields.FieldElementSizeBytes];
        ZkInterfaceTestFields.WriteFieldMaximumLittleEndian(curve, fieldMaximum);
        sink.OnFieldMaximum(fieldMaximum);
    }


    /// <summary>
    /// Fills <paramref name="destination"/> with distinct, non-zero, full-width canonical BLS12-381 scalars, one per
    /// witness slot.
    /// </summary>
    /// <param name="destination">Whole scalars laid end to end.</param>
    private static void FillWitnessValues(Span<byte> destination)
    {
        DeterministicScalarFill.FillCanonical(
            destination,
            WitnessValueFillSalt,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bls12Curve381);
    }


    /// <summary>Returns one scalar-width slot from a run of whole witness scalars.</summary>
    /// <param name="witnessBytes">Whole scalars laid end to end in <c>z[1..]</c> order.</param>
    /// <param name="slot">The zero-based slot to return.</param>
    /// <returns>The scalar-width slice holding that slot.</returns>
    private static Span<byte> WitnessSlot(Span<byte> witnessBytes, int slot)
    {
        return witnessBytes.Slice(slot * ZkInterfaceTestFields.FieldElementSizeBytes, ZkInterfaceTestFields.FieldElementSizeBytes);
    }
}
