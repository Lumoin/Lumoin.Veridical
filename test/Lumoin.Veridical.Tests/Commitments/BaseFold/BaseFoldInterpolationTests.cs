using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// Tests for the BaseFold evals→coefficients interpolation (AB.4): the
/// multilinear Möbius transform that turns a <see cref="MultilinearExtension"/>'s
/// dense hypercube evaluations into the monomial coefficient vector
/// <see cref="FoldableCodeExtensions.Encode"/> commits to. A hand-computed case
/// pins the convention; a Möbius↔zeta round-trip confirms losslessness on random
/// inputs. The full ordering tie to Encode/Fold is exercised by the end-to-end
/// evaluation-protocol tests.
/// </summary>
[TestClass]
internal sealed class BaseFoldInterpolationTests
{
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

    private const int ScalarSize = 32;
    private const int IterationCount = 50;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void TwoVariableCoefficientsMatchTheHandComputedMonomialForm()
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        //A 2-variable MLE with small integer evaluations on the hypercube,
        //indexed (b1 + 2·b2): f(0,0)=3, f(1,0)=5, f(0,1)=8, f(1,1)=13.
        //Monomial form f = c00 + c10·X1 + c01·X2 + c11·X1X2 with
        //  c00 = f(0,0)              = 3
        //  c10 = f(1,0) − f(0,0)     = 2
        //  c01 = f(0,1) − f(0,0)     = 5
        //  c11 = f(1,1) − f(1,0) − f(0,1) + f(0,0) = 13 − 5 − 8 + 3 = 3
        //Coefficient index k carries the monomial in the variables whose bit is
        //set in k, matching the evaluation index order.
        using IMemoryOwner<byte> evalOwner = pool.Rent(4 * ScalarSize);
        Span<byte> evals = evalOwner.Memory.Span[..(4 * ScalarSize)];
        WriteSmall(evals, 0, 3);
        WriteSmall(evals, 1, 5);
        WriteSmall(evals, 2, 8);
        WriteSmall(evals, 3, 13);

        using MultilinearExtension mle = MultilinearExtension.FromEvaluations(evals, 2, Curve, pool);

        using IMemoryOwner<byte> coeffOwner = pool.Rent(4 * ScalarSize);
        Span<byte> coeffs = coeffOwner.Memory.Span[..(4 * ScalarSize)];
        mle.InterpolateToCoefficients(coeffs, Subtract);

        AssertSmall(coeffs, 0, 3, "c00");
        AssertSmall(coeffs, 1, 2, "c10");
        AssertSmall(coeffs, 2, 5, "c01");
        AssertSmall(coeffs, 3, 3, "c11");
    }


    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    [DataRow(5)]
    public void ZetaTransformOfCoefficientsRecoversEvaluations(int variableCount)
    {
        Gen.Byte.Array[(1 << variableCount) * ScalarSize]
            .Sample(rawBytes =>
            {
                SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
                int evaluationCount = 1 << variableCount;

                using IMemoryOwner<byte> evalOwner = pool.Rent(evaluationCount * ScalarSize);
                Span<byte> evals = evalOwner.Memory.Span[..(evaluationCount * ScalarSize)];
                for(int i = 0; i < evaluationCount; i++)
                {
                    Reduce(rawBytes.AsSpan(i * ScalarSize, ScalarSize), evals.Slice(i * ScalarSize, ScalarSize), Curve);
                }

                using MultilinearExtension mle = MultilinearExtension.FromEvaluations(evals, variableCount, Curve, pool);

                using IMemoryOwner<byte> coeffOwner = pool.Rent(evaluationCount * ScalarSize);
                Span<byte> coeffs = coeffOwner.Memory.Span[..(evaluationCount * ScalarSize)];
                mle.InterpolateToCoefficients(coeffs, Subtract);

                //The forward zeta transform — the same butterfly structure with
                //addition instead of subtraction — inverts the Möbius transform,
                //so it must reproduce the original evaluations exactly.
                ZetaInPlace(coeffs, variableCount);

                return coeffs.SequenceEqual(evals);
            }, iter: IterationCount);
    }


    //Forward zeta: f(b) = Σ_{S ⊆ supp(b)} coeff[S]. The inverse of the Möbius
    //butterfly — for each variable bit, the high entry gains the low entry.
    private static void ZetaInPlace(Span<byte> values, int variableCount)
    {
        int count = 1 << variableCount;
        for(int bit = 0; bit < variableCount; bit++)
        {
            int stride = 1 << bit;
            int blockSpan = stride << 1;
            for(int blockStart = 0; blockStart < count; blockStart += blockSpan)
            {
                for(int offset = 0; offset < stride; offset++)
                {
                    int lowIndex = blockStart + offset;
                    int highIndex = lowIndex + stride;
                    ReadOnlySpan<byte> low = values.Slice(lowIndex * ScalarSize, ScalarSize);
                    Span<byte> high = values.Slice(highIndex * ScalarSize, ScalarSize);
                    Add(high, low, high, Curve);
                }
            }
        }
    }


    private static void WriteSmall(Span<byte> buffer, int index, int value)
    {
        Span<byte> slot = buffer.Slice(index * ScalarSize, ScalarSize);
        slot.Clear();
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(slot[^4..], value);
    }


    private static void AssertSmall(ReadOnlySpan<byte> buffer, int index, int expected, string name)
    {
        Span<byte> expectedSlot = stackalloc byte[ScalarSize];
        expectedSlot.Clear();
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(expectedSlot[^4..], expected);
        Assert.IsTrue(
            buffer.Slice(index * ScalarSize, ScalarSize).SequenceEqual(expectedSlot),
            $"Coefficient {name} (index {index}) must equal {expected}.");
    }
}
