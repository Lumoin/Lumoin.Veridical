using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Text;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Pins the variable-order convention between Spartan's sumchecks and the
/// statistical mask kernel (SM.7b): Spartan binds variables LOW-first (round
/// <c>i</c> binds <c>x_{i+1}</c>, the low eval-table bit) while
/// <see cref="MonomialBasisMask"/> binds HIGH-first (the BaseFold fold order),
/// so the masked drivers relabel — Spartan round <c>i</c> blends at kernel
/// variable <c>d − i</c>, and the kernel's terminal evaluation point is the
/// REVERSED challenge vector. This test is an independent executable statement
/// of that convention over the public kernel API alone: a low-first masked
/// chain with a zero base polynomial must close exactly at
/// <c>ρ · s(reversed challenges)</c> — and must NOT close at the unreversed
/// point, proving the reversal is load-bearing. If a kernel or driver refactor
/// breaks the symmetry, this test names the cause where the masked roundtrips
/// would only show a distant mismatch.
/// </summary>
[TestClass]
internal sealed class MaskedSpartanMaskOrderConventionTests
{
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

    private const int ScalarSize = 32;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;
    private static readonly byte[] MaskSeed = Encoding.UTF8.GetBytes("veridical.spartan.mask-order-convention.test.v1");


    [TestMethod]
    [DataRow(2, 2)]
    [DataRow(3, 2)]
    [DataRow(4, 2)]
    [DataRow(2, 3)]
    [DataRow(3, 3)]
    [DataRow(4, 3)]
    public void LowFirstChainClosesAtTheReversedPoint(int variableCount, int perVariableDegree)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarRandomDelegate random = new DeterministicScalarRandom(MaskSeed).AsDelegate();

        MonomialBasis basis = MonomialBasis.SumOfUnivariatesWithPad(variableCount, padPairCount: 0, perVariableDegree);
        using MonomialBasisMask mask = MonomialBasisMask.Sample(basis, random, Curve, pool);

        using Scalar rho = MakeScalar(7, pool);
        using Scalar sigma = mask.ComputeSigma(Add, Multiply, pool);

        //The running claim starts at ρ·σ — the mask-only blended chain (the
        //base polynomial is zero throughout, isolating the mask's algebra).
        Span<byte> claim = stackalloc byte[ScalarSize];
        Multiply(rho.AsReadOnlySpan(), sigma.AsReadOnlySpan(), claim, Curve);

        //One-based kernel registry plus the challenges in Spartan ROUND order.
        var registry = new Scalar[variableCount + 1];
        var challengesInRoundOrder = new Scalar[variableCount];

        try
        {
            Span<byte> c0 = stackalloc byte[ScalarSize];
            Span<byte> c2 = stackalloc byte[ScalarSize];
            Span<byte> c3 = stackalloc byte[ScalarSize];
            Span<byte> c1 = stackalloc byte[ScalarSize];
            Span<byte> term = stackalloc byte[ScalarSize];

            for(int round = 0; round < variableCount; round++)
            {
                //THE CONVENTION, half 1: Spartan round i (low-first) blends at
                //kernel variable d − i (high-first).
                int boundVariable = variableCount - round;

                c0.Clear();
                c2.Clear();
                c3.Clear();
                if(perVariableDegree >= 3)
                {
                    mask.AddRoundBlend(boundVariable, registry, rho.AsReadOnlySpan(), c0, c2, c3, Add, Multiply);
                }
                else
                {
                    mask.AddRoundBlend(boundVariable, registry, rho.AsReadOnlySpan(), c0, c2, Add, Multiply);
                }

                //Reconstruct the chain-elided linear coefficient from
                //h(0) + h(1) = claim: c1 = claim − 2·c0 − c2 − c3.
                claim.CopyTo(c1);
                Subtract(c1, c0, c1, Curve);
                Subtract(c1, c0, c1, Curve);
                Subtract(c1, c2, c1, Curve);
                Subtract(c1, c3, c1, Curve);

                //Deterministic small challenge, distinct per round so the
                //reversal is observable.
                Scalar challenge = MakeScalar((round * 13) + 5, pool);
                challengesInRoundOrder[round] = challenge;
                registry[boundVariable] = challenge;

                //claim ← h(r) = c0 + r·(c1 + r·(c2 + r·c3)), Horner.
                ReadOnlySpan<byte> r = challenge.AsReadOnlySpan();
                term.Clear();
                Add(term, c3, term, Curve);
                Multiply(term, r, term, Curve);
                Add(term, c2, term, Curve);
                Multiply(term, r, term, Curve);
                Add(term, c1, term, Curve);
                Multiply(term, r, term, Curve);
                Add(c0, term, claim, Curve);
            }

            //THE CONVENTION, half 2: the kernel's terminal point is the
            //REVERSED challenge vector (kernel X_j ≡ Spartan x_{d+1−j}),
            //restated here inline and independently of the production helper.
            var reversedPoint = new Scalar[variableCount];
            for(int i = 0; i < variableCount; i++)
            {
                reversedPoint[i] = challengesInRoundOrder[variableCount - 1 - i];
            }

            using Scalar terminalAtReversed = mask.EvaluateAt(reversedPoint, Add, Multiply, pool);
            Span<byte> expected = stackalloc byte[ScalarSize];
            Multiply(rho.AsReadOnlySpan(), terminalAtReversed.AsReadOnlySpan(), expected, Curve);

            Assert.IsTrue(
                claim.SequenceEqual(expected),
                $"The low-first masked chain must close at ρ·s(reversed challenges) for d = {variableCount}, degree = {perVariableDegree}.");

            //The reversal is load-bearing: the unreversed (round-order) point
            //must NOT close the chain. Deterministic inputs make this a stable
            //pin rather than a probabilistic one; the challenges are distinct
            //per round, so the two points differ for every d ≥ 2.
            using Scalar terminalAtRoundOrder = mask.EvaluateAt(challengesInRoundOrder, Add, Multiply, pool);
            Span<byte> unreversed = stackalloc byte[ScalarSize];
            Multiply(rho.AsReadOnlySpan(), terminalAtRoundOrder.AsReadOnlySpan(), unreversed, Curve);

            Assert.IsFalse(
                claim.SequenceEqual(unreversed),
                $"The chain must NOT close at the unreversed point for d = {variableCount}, degree = {perVariableDegree} — if it does, the convention pin has gone vacuous.");
        }
        finally
        {
            foreach(Scalar challenge in challengesInRoundOrder)
            {
                challenge?.Dispose();
            }
        }
    }


    private static Scalar MakeScalar(int value, BaseMemoryPool pool)
    {
        Span<byte> wide = stackalloc byte[ScalarSize];
        wide.Clear();
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], value);
        Span<byte> canonical = stackalloc byte[ScalarSize];
        Reduce(wide, canonical, Curve);

        return Scalar.FromCanonical(canonical, Curve, pool);
    }
}
