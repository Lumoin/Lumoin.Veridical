using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Tests the matrix-assembly sink directly by driving its push API — the
/// architecture's payoff: the assembler is exercised over a real curve
/// without needing a hand-encoded FlatBuffers fixture (owned BLS/BN254
/// <c>.zkif</c> files arrive in W.4 for the full pipe path). The circuit
/// is the padded multiplier2 (<c>a·b = c</c> plus a <c>1·1 = 1</c> row so
/// the shape is a power of two): variables <c>z = (1, c, a, b)</c>,
/// satisfied by <c>(1, 33, 3, 11)</c>. The satisfaction check is the
/// load-bearing assertion — it runs every coefficient against the witness,
/// so an LE/BE, column, or zero-pad mistake surfaces as a non-satisfaction.
/// </summary>
[TestClass]
internal sealed class ZkInterfaceR1csInstanceBuilderTests
{
    private const int VariableCount = 4;
    private const int ConstraintCount = 2;


    [TestMethod]
    public void Bls12Curve381Multiplier2BuildsAndSatisfies()
    {
        ExerciseMultiplier2(
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381BigIntegerScalarReference.GetAdd(),
            Bls12Curve381BigIntegerScalarReference.GetMultiply());
    }


    [TestMethod]
    public void Bn254Multiplier2BuildsAndSatisfies()
    {
        ExerciseMultiplier2(
            CurveParameterSet.Bn254,
            Bn254BigIntegerScalarReference.GetAdd(),
            Bn254BigIntegerScalarReference.GetMultiply());
    }


    [TestMethod]
    public void BuilderRejectsFieldThatDoesNotMatchTheCurve()
    {
        var builder = new ZkInterfaceR1csInstanceBuilder(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        //Declaring BN254's field while asking for a BLS12-381 instance.
        byte[] bn254FieldMaximum = ZkInterfaceTestFields.FieldMaximumLittleEndian(CurveParameterSet.Bn254);
        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() => builder.OnFieldMaximum(bn254FieldMaximum));
    }


    [TestMethod]
    public void BuilderRejectsAbsentField()
    {
        //A full circuit but with no field_maximum ever declared: the field
        //cannot be validated against the curve, so Build rejects it.
        var builder = new ZkInterfaceR1csInstanceBuilder(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(VariableCount);
        PushPaddingConstraint(sink);

        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() => builder.Build());
    }


    private static void ExerciseMultiplier2(CurveParameterSet curve, ScalarAddDelegate add, ScalarMultiplyDelegate multiply)
    {
        using RawR1csInstance instance = BuildMultiplier2(curve);

        Assert.AreEqual(ConstraintCount, instance.A.RowCount, "A.RowCount");
        Assert.AreEqual(VariableCount, instance.A.ColumnCount, "A.ColumnCount");
        Assert.AreEqual(0, instance.PublicInputCount, "PublicInputCount");
        Assert.AreEqual(2, instance.A.NonzeroCount, "A.NonzeroCount");
        Assert.AreEqual(2, instance.B.NonzeroCount, "B.NonzeroCount");
        Assert.AreEqual(2, instance.C.NonzeroCount, "C.NonzeroCount");
        Assert.AreEqual(curve.Code, instance.Curve.Code, "parsed instance curve");

        using RawR1csWitness witness = BuildMultiplier2Witness(curve);
        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, add, multiply, SensitiveMemoryPool<byte>.Shared);

        if(satisfaction is R1csSatisfaction.Violated violated)
        {
            Assert.Fail($"multiplier2 satisfaction failed at constraint {violated.ConstraintIndex.Value}.");
        }

        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction);
    }


    private static RawR1csInstance BuildMultiplier2(CurveParameterSet curve)
    {
        var builder = new ZkInterfaceR1csInstanceBuilder(curve, SensitiveMemoryPool<byte>.Shared);
        //Drive the push API through the sink interface, exactly as a decoder would.
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(VariableCount);

        Span<byte> fieldMaximum = stackalloc byte[ZkInterfaceTestFields.FieldElementSizeBytes];
        ZkInterfaceTestFields.WriteFieldMaximumLittleEndian(curve, fieldMaximum);
        sink.OnFieldMaximum(fieldMaximum);

        Span<byte> one = stackalloc byte[] { 1 };

        //C0: a · b = c with z = (one, c, a, b) → A{2:1}, B{3:1}, C{1:1}.
        sink.BeginConstraint();
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.A, 2, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.B, 3, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.C, 1, one);
        sink.EndConstraint();

        //C1: 1 · 1 = 1 padding → A{0:1}, B{0:1}, C{0:1}.
        PushPaddingConstraint(sink);

        return builder.Build();
    }


    private static void PushPaddingConstraint(IZkInterfaceMessageSink sink)
    {
        Span<byte> one = stackalloc byte[] { 1 };
        sink.BeginConstraint();
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.A, 0, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.B, 0, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.C, 0, one);
        sink.EndConstraint();
    }


    private static RawR1csWitness BuildMultiplier2Witness(CurveParameterSet curve)
    {
        //z[1..] = (c, a, b) = (33, 3, 11); satisfies a · b = c with a = 3, b = 11.
        int scalarSize = R1csMatrix.GetValueByteSize(curve);
        Span<byte> witnessBytes = stackalloc byte[3 * ZkInterfaceTestFields.FieldElementSizeBytes];
        witnessBytes = witnessBytes[..(3 * scalarSize)];
        WriteCanonicalBigEndian(new BigInteger(33), witnessBytes.Slice(0 * scalarSize, scalarSize));
        WriteCanonicalBigEndian(new BigInteger(3), witnessBytes.Slice(1 * scalarSize, scalarSize));
        WriteCanonicalBigEndian(new BigInteger(11), witnessBytes.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, curve, SensitiveMemoryPool<byte>.Shared);
    }


    private static void WriteCanonicalBigEndian(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Witness value did not fit the canonical span.");
        }

        //TryWriteBytes packs the value at the start; right-align it so the
        //scalar is canonical big-endian (high-order zero padding on the left).
        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
