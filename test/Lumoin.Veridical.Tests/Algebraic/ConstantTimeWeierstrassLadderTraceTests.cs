using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Deterministic constant-time evidence for the shared
/// <see cref="ConstantTimeWeierstrassLadder"/>: the sequence of field operations the ladder
/// issues is recorded through wrapped delegates and must be identical across secret-scalar
/// classes, and its totals must equal the closed forms fixed by the ladder shape alone.
/// This is the delegate-trace pattern the NTT encoder's witness-independence gate
/// established, applied to the secret-scalar region of the BLS12-381 and BN254
/// constant-time G1 backends; the wall-clock dudect pair in the Analysis suite is the
/// complementary <c>[Slow]</c> check.
/// </summary>
[TestClass]
internal sealed class ConstantTimeWeierstrassLadderTraceTests
{
    /// <summary>
    /// The ladder walks every bit of the full 32-byte scalar span.
    /// </summary>
    private const int ScalarBitCount = 256;

    /// <summary>
    /// The multiplication count of one complete Renes-Costello-Batina doubling (Algorithm 3) as
    /// transcribed in ConstantTimeWeierstrassLadder: 16 (11 generic, 3 by the curve coefficient a,
    /// 2 by 3·b). Every ladder bit runs exactly one doubling and one addition.
    /// </summary>
    private const int MultiplicationsPerDoubling = 16;

    /// <summary>The doubling's addition count.</summary>
    private const int AdditionsPerDoubling = 12;

    /// <summary>The doubling's subtraction count.</summary>
    private const int SubtractionsPerDoubling = 3;

    /// <summary>
    /// The multiplication count of one complete addition (Algorithm 1): 17 (12 generic, 3 by a,
    /// 2 by 3·b).
    /// </summary>
    private const int MultiplicationsPerAddition = 17;

    /// <summary>The addition's addition count.</summary>
    private const int AdditionsPerAddition = 17;

    /// <summary>The addition's subtraction count.</summary>
    private const int SubtractionsPerAddition = 6;

    /// <summary>
    /// Arbitrary but fixed salt for the BLS12-381 G1 trace, distinct per group and from the streams
    /// other suites draw from DeterministicScalarFill. Each test consumes salt + 1 and salt + 2, so
    /// the bases are spaced more than two apart to keep every consumed stream disjoint.
    /// </summary>
    private const int Bls12Curve381ScalarSalt = 0xC381;

    /// <summary>The BN254 G1 trace salt.</summary>
    private const int Bn254ScalarSalt = 0xC254;

    /// <summary>The BLS12-381 G2 trace salt.</summary>
    private const int Bls12Curve381G2ScalarSalt = 0xC584;


    [TestMethod]
    public void TheLadderOperationTraceIsScalarIndependentOnBls12Curve381()
    {
        Span<byte> baseX = stackalloc byte[Bls12Curve381BaseFieldMontgomeryBackend.ElementSize];
        Span<byte> baseY = stackalloc byte[Bls12Curve381BaseFieldMontgomeryBackend.ElementSize];
        Bls12Curve381BigIntegerG1Reference.AffinePoint generator = Bls12Curve381BigIntegerG1Reference.Decode(
            WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.Bls12Curve381));
        WriteCanonical(generator.X, baseX);
        WriteCanonical(generator.Y, baseY);

        ConstantTimeLadderField realField = Bls12Curve381ConstantTimeG1Backend.CreateLadderField();
        AssertScalarIndependentTrace(
            "BLS12-381 G1",
            realField,
            baseX,
            baseY,
            Bls12Curve381ScalarSalt,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bls12Curve381);
    }


    [TestMethod]
    public void TheLadderOperationTraceIsScalarIndependentOnBn254()
    {
        Span<byte> baseX = stackalloc byte[Bn254BaseFieldMontgomeryBackend.ElementSize];
        Span<byte> baseY = stackalloc byte[Bn254BaseFieldMontgomeryBackend.ElementSize];
        Bn254BigIntegerG1Reference.AffinePoint generator = Bn254BigIntegerG1Reference.Decode(
            WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.Bn254));
        WriteCanonical(generator.X, baseX);
        WriteCanonical(generator.Y, baseY);

        ConstantTimeLadderField realField = Bn254ConstantTimeG1Backend.CreateLadderField();
        AssertScalarIndependentTrace(
            "BN254 G1",
            realField,
            baseX,
            baseY,
            Bn254ScalarSalt,
            Bn254BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bn254);
    }


    [TestMethod]
    public void TheLadderOperationTraceIsScalarIndependentOnBls12Curve381G2()
    {
        //The G2 ladder runs the identical shape over Fp2 delegates, so the closed forms hold with
        //"field operation" meaning one Fp2 operation; inside one Fp2 operation the constant-time
        //backend's own fixed component sequence applies.
        Span<byte> baseX = stackalloc byte[Bls12Curve381ConstantTimeFp2Backend.ElementSize];
        Span<byte> baseY = stackalloc byte[Bls12Curve381ConstantTimeFp2Backend.ElementSize];
        Bls12Curve381BigIntegerG2Reference.AffinePoint generator = Bls12Curve381BigIntegerG2Reference.Decode(
            WellKnownCurves.GetG2GeneratorCompressed(CurveParameterSet.Bls12Curve381));
        WriteCanonicalFp2(generator.X, baseX);
        WriteCanonicalFp2(generator.Y, baseY);

        ConstantTimeLadderField realField = Bls12Curve381ConstantTimeG2Backend.CreateLadderField();
        AssertScalarIndependentTrace(
            "BLS12-381 G2",
            realField,
            baseX,
            baseY,
            Bls12Curve381G2ScalarSalt,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bls12Curve381);
    }


    /// <summary>
    /// A deterministic obliviousness gate with no wall-clock involvement: the sequence of field
    /// operations the ladder issues is recorded through wrapped delegates and must be identical for
    /// different scalar values — two independent pseudorandom scalars and the all-zero scalar, so a
    /// skip-on-zero shortcut cannot pass — and its totals must equal the closed forms fixed by the
    /// ladder shape alone. The trace sees delegate granularity — operation kind, count and order;
    /// indexing is loop-counter-derived by construction and inside a single field operation the
    /// backend's own discipline applies. The traced region is the ladder — the secret-scalar-touching
    /// code; the surrounding decode/encode operate on public points and the final normalize is a
    /// fixed-public-exponent Fermat ladder.
    /// </summary>
    private static void AssertScalarIndependentTrace(
        string prefix,
        in ConstantTimeLadderField realField,
        ReadOnlySpan<byte> baseX,
        ReadOnlySpan<byte> baseY,
        int scalarSalt,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve)
    {
        var trace = new List<char>();
        ScalarAddDelegate add = realField.Add;
        ScalarSubtractDelegate subtract = realField.Subtract;
        ScalarMultiplyDelegate multiply = realField.Multiply;
        ScalarAddDelegate tracedAdd = (a, b, result, c) =>
        {
            trace.Add('a');
            add(a, b, result, c);
        };
        ScalarSubtractDelegate tracedSubtract = (a, b, result, c) =>
        {
            trace.Add('s');
            subtract(a, b, result, c);
        };
        ScalarMultiplyDelegate tracedMultiply = (a, b, result, c) =>
        {
            trace.Add('m');
            multiply(a, b, result, c);
        };

        ConstantTimeLadderField tracedField = new(
            tracedAdd,
            tracedSubtract,
            tracedMultiply,
            realField.CurveA,
            realField.CurveBTimes3,
            realField.One);

        Span<byte> scalar = stackalloc byte[Scalar.SizeBytes];
        DeterministicScalarFill.FillCanonical(scalar, scalarSalt + 1, reduce, curve);
        char[] firstTrace = RunTracedLadder(tracedField, trace, baseX, baseY, scalar);

        DeterministicScalarFill.FillCanonical(scalar, scalarSalt + 2, reduce, curve);
        char[] secondTrace = RunTracedLadder(tracedField, trace, baseX, baseY, scalar);

        scalar.Clear();
        char[] zeroTrace = RunTracedLadder(tracedField, trace, baseX, baseY, scalar);

        Assert.IsTrue(firstTrace.AsSpan().SequenceEqual(secondTrace), $"The ladder operation trace must not depend on the scalar value for {prefix}.");
        //The all-zero scalar pins that no skip-on-zero shortcut can creep in.
        Assert.IsTrue(firstTrace.AsSpan().SequenceEqual(zeroTrace), $"The ladder operation trace must not depend on zero scalar bits for {prefix}.");

        int multiplications = 0;
        int additions = 0;
        int subtractions = 0;
        foreach(char operation in firstTrace)
        {
            if(operation == 'm')
            {
                multiplications++;
            }
            else if(operation == 'a')
            {
                additions++;
            }
            else
            {
                subtractions++;
            }
        }

        Assert.AreEqual(ScalarBitCount * (MultiplicationsPerDoubling + MultiplicationsPerAddition), multiplications, $"The multiplication count must be fixed by the ladder shape for {prefix}.");
        Assert.AreEqual(ScalarBitCount * (AdditionsPerDoubling + AdditionsPerAddition), additions, $"The addition count must be fixed by the ladder shape for {prefix}.");
        Assert.AreEqual(ScalarBitCount * (SubtractionsPerDoubling + SubtractionsPerAddition), subtractions, $"The subtraction count must be fixed by the ladder shape for {prefix}.");
    }


    private static char[] RunTracedLadder(
        in ConstantTimeLadderField tracedField,
        List<char> trace,
        ReadOnlySpan<byte> baseX,
        ReadOnlySpan<byte> baseY,
        ReadOnlySpan<byte> scalar)
    {
        int elementSize = tracedField.ElementSize;
        Span<byte> accumulatorX = stackalloc byte[elementSize];
        Span<byte> accumulatorY = stackalloc byte[elementSize];
        Span<byte> accumulatorZ = stackalloc byte[elementSize];

        trace.Clear();
        ConstantTimeWeierstrassLadder.ScalarMultiply(tracedField, baseX, baseY, scalar, accumulatorX, accumulatorY, accumulatorZ);
        char[] snapshot = [.. trace];

        return snapshot;
    }


    /// <summary>
    /// Writes an Fp2 value into the ladder-internal [c0 : 48 BE][c1 : 48 BE] layout.
    /// </summary>
    private static void WriteCanonicalFp2(Bls12Curve381BigIntegerG2Reference.Fp2Value value, Span<byte> destination)
    {
        int componentSize = destination.Length / 2;
        WriteCanonical(value.C0, destination[..componentSize]);
        WriteCanonical(value.C1, destination[componentSize..]);
    }


    /// <summary>
    /// Writes value as a right-aligned canonical big-endian field element.
    /// </summary>
    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("A base-field element did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
