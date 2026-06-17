using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Tests for the <c>Prepare()</c> adapters that lift raw R1CS
/// instances and witnesses to relaxed form (u = 1, zero error
/// vector, identity-G1 error commitment) for the unified prover.
/// </summary>
[TestClass]
internal sealed class PrepareTests
{
    private static readonly ScalarAddDelegate Add = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static readonly ScalarMultiplyDelegate Multiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();


    [TestMethod]
    public void PreparedInstanceHasURelaxationScalarEqualToOne()
    {
        using RawR1csInstance raw = R1csTestCircuits.BuildMultiplyCircuit();
        using RelaxedR1csInstance prepared = raw.Prepare(BaseMemoryPool.Shared);

        int scalarSize = Scalar.SizeBytes;
        ReadOnlySpan<byte> u = prepared.GetUBytes();
        Assert.AreEqual(scalarSize, u.Length);

        //u = 1 in canonical big-endian: 31 zero bytes then 0x01.
        var uValue = new BigInteger(u, isUnsigned: true, isBigEndian: true);
        Assert.AreEqual(BigInteger.One, uValue);
    }


    [TestMethod]
    public void PreparedInstanceErrorCommitmentRowsAreIdentityG1()
    {
        using RawR1csInstance raw = R1csTestCircuits.BuildMultiplyCircuit();
        using RelaxedR1csInstance prepared = raw.Prepare(BaseMemoryPool.Shared);

        //The generic error commitment carries the same canonical bytes a Hyrax
        //commitment exposes; rebuild the Hyrax view (the matrix shape derives from
        //the error MLE's row-variable count) to read per-row commitments.
        int g1Size = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;
        int rowVariableCount = BitOperations.Log2((uint)raw.A.RowCount);
        HyraxCommitmentDimensions dimensions = HyraxCommitmentDimensions.ForVariableCount(rowVariableCount);
        using HyraxCommitment errorCommitment = HyraxCommitment.FromBytes(
            prepared.ErrorCommitment.AsReadOnlySpan(),
            dimensions.RowCount, dimensions.ColumnCount, rowVariableCount,
            CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        for(int row = 0; row < errorCommitment.RowCount; row++)
        {
            ReadOnlySpan<byte> rowBytes = errorCommitment.GetRowCommitment(row);
            //Compressed G1 identity: high byte 0xc0 (compression +
            //infinity flags), remaining 47 bytes zero.
            Assert.AreEqual(0xc0, rowBytes[0]);
            for(int i = 1; i < g1Size; i++)
            {
                Assert.AreEqual(0, rowBytes[i], $"Identity G1 byte {i} of row {row} must be zero.");
            }
        }
    }


    [TestMethod]
    public void PreparedInstanceCarriesMatricesAndPublicInputsThrough()
    {
        using RawR1csInstance raw = R1csTestCircuits.BuildMultiplyCircuit();
        using RelaxedR1csInstance prepared = raw.Prepare(BaseMemoryPool.Shared);

        Assert.AreEqual(raw.A.RowCount, prepared.A.RowCount);
        Assert.AreEqual(raw.A.ColumnCount, prepared.A.ColumnCount);
        Assert.AreEqual(raw.PublicInputCount, prepared.PublicInputCount);
        Assert.IsTrue(raw.A.GetValuesBytes().SequenceEqual(prepared.A.GetValuesBytes()));
        Assert.IsTrue(raw.B.GetValuesBytes().SequenceEqual(prepared.B.GetValuesBytes()));
        Assert.IsTrue(raw.C.GetValuesBytes().SequenceEqual(prepared.C.GetValuesBytes()));
        Assert.IsTrue(raw.GetPublicInputsBytes().SequenceEqual(prepared.GetPublicInputsBytes()));
    }


    [TestMethod]
    public void PreparedPairSatisfiesTheRelaxedIdentity()
    {
        using RawR1csInstance raw = R1csTestCircuits.BuildMultiplyCircuit();
        using RawR1csWitness rawWitness = R1csTestCircuits.BuildMultiplyWitness(x: 3, y: 4);

        using RelaxedR1csInstance prepared = raw.Prepare(BaseMemoryPool.Shared);
        using RelaxedR1csWitness preparedWitness = rawWitness.Prepare(
            errorLength: raw.A.RowCount, BaseMemoryPool.Shared);

        using R1csSatisfaction satisfaction = prepared.CheckSatisfiedBy(
            preparedWitness, Add, Multiply, BaseMemoryPool.Shared);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction);
    }


    [TestMethod]
    public void PreparedWitnessHasZeroErrorVector()
    {
        using RawR1csWitness rawWitness = R1csTestCircuits.BuildMultiplyWitness(x: 3, y: 4);
        using RelaxedR1csWitness prepared = rawWitness.Prepare(
            errorLength: 1, BaseMemoryPool.Shared);

        Assert.AreEqual(1, prepared.ErrorLength);
        ReadOnlySpan<byte> error = prepared.GetErrorBytes();
        foreach(byte b in error)
        {
            Assert.AreEqual(0, b, "Prepared witness error vector must be all-zero.");
        }
    }
}