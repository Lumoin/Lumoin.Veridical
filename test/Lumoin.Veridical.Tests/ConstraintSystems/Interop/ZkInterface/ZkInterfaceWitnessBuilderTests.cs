using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Tests the witness-assembly sink directly by driving its push API. The
/// payoff assertion combines both builders: a multiplier2 instance (public
/// output <c>c</c>, private <c>a, b</c>) and the witness assembled from the
/// header's instance value plus the witness message's private values must
/// satisfy <c>A·z ∘ B·z = C·z</c> — proving the scatter reconstructs the
/// full <c>z[1..]</c> that the PublicInputCount = 0 convention expects.
/// </summary>
[TestClass]
internal sealed class ZkInterfaceWitnessBuilderTests
{
    private const int VariableCount = 4;
    private const int WitnessVariableCount = 3;

    //These tests drive the assembly logic directly, not the source-size
    //amplification guard, so they pass an unbounded column ceiling; the guard is
    //pinned separately in ZkInterfaceBuilderBoundaryTests.
    private const int UnboundedColumnCeiling = int.MaxValue;


    [TestMethod]
    public void Bls12Curve381InstanceAndWitnessSatisfy()
    {
        ExerciseMultiplier2(
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381BigIntegerScalarReference.GetAdd(),
            Bls12Curve381BigIntegerScalarReference.GetMultiply());
    }


    [TestMethod]
    public void Bn254InstanceAndWitnessSatisfy()
    {
        ExerciseMultiplier2(
            CurveParameterSet.Bn254,
            Bn254BigIntegerScalarReference.GetAdd(),
            Bn254BigIntegerScalarReference.GetMultiply());
    }


    [TestMethod]
    public void WitnessBuilderRejectsAbsentField()
    {
        var builder = new ZkInterfaceWitnessBuilder(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, UnboundedColumnCeiling);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(VariableCount);
        PushAssignment(sink, witness: false, variableId: 1, value: 33);

        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() => builder.Build());
    }


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


    private static void PushAssignment(IZkInterfaceMessageSink sink, bool witness, ulong variableId, byte value)
    {
        Span<byte> littleEndian = stackalloc byte[1];
        littleEndian[0] = value;
        if(witness)
        {
            sink.OnWitnessVariable(variableId, littleEndian);
        }
        else
        {
            sink.OnInstanceVariable(variableId, littleEndian);
        }
    }


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
}
