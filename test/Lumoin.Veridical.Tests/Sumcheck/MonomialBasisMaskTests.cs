using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.Spartan;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Text;

namespace Lumoin.Veridical.Tests.Sumcheck;

/// <summary>
/// SM.2b — the monomial-basis sumcheck mask (<see cref="MonomialBasisMask"/>
/// over a <see cref="MonomialBasis"/>; Libra ePrint 2019/317 §4.1 generalised
/// per <c>ZK-STATMASK-DESIGN.md</c> §2 v2): pins the generic
/// closed-form <c>σ</c>, the per-round blend, and the terminal
/// <c>s(r)</c>/weight pairing against a naive dense reference that evaluates
/// the mask monomial by monomial and brute-forces the round partial sums. The
/// chain property <c>p_k(0) + p_k(1) = claim</c> from <c>σ</c> down to
/// <c>s(r)</c> ties every closed form to every other, exercised over both
/// production basis shapes: the padded sum-of-univariates (large <c>d</c>) and
/// the full degree-≤2 basis (small <c>d</c>). Real BLS12-381 arithmetic.
/// </summary>
[TestClass]
internal sealed class MonomialBasisMaskTests
{
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

    private const int ScalarSize = 32;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;
    private static readonly byte[] MaskSeed = Encoding.UTF8.GetBytes("veridical.sumcheck.monomialmask.kernel.test.v1");


    [TestMethod]
    [DataRow(5, 4)]
    [DataRow(5, 8)]
    [DataRow(6, 8)]
    public void PaddedSumOfUnivariatesChainsFromSigmaToTerminal(int variableCount, int padPairCount)
    {
        MonomialBasis basis = MonomialBasis.SumOfUnivariatesWithPad(variableCount, padPairCount);
        Assert.AreEqual((2 * variableCount) + 1 + (2 * padPairCount), basis.Count, "The padded basis count must be 2d + 1 + 2P.");

        AssertChainsFromSigmaToTerminal(basis, salt: 23);
    }


    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    public void FullBasisChainsFromSigmaToTerminal(int variableCount)
    {
        MonomialBasis basis = MonomialBasis.Full(variableCount);
        int expectedCount = 1;
        for(int j = 0; j < variableCount; j++)
        {
            expectedCount *= 3;
        }

        Assert.AreEqual(expectedCount, basis.Count, "The full basis count must be 3^d.");

        AssertChainsFromSigmaToTerminal(basis, salt: 29);
    }


    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public void WeightVectorInnerProductEqualsEvaluation(bool padded)
    {
        //⟨coefficients, w(r)⟩ = s(r), including over a padded destination whose
        //tail weights are zero — the exact pairing the weighted opening of the
        //committed coefficient multilinear relies on.
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        ScalarRandomDelegate random = new DeterministicScalarRandom(MaskSeed).AsDelegate();
        MonomialBasis basis = padded
            ? MonomialBasis.SumOfUnivariatesWithPad(variableCount: 5, padPairCount: 6)
            : MonomialBasis.Full(variableCount: 3);

        using MonomialBasisMask mask = MonomialBasisMask.Sample(basis, random, Curve, pool);
        Scalar[] registry = BuildChallengeRegistry(basis.VariableCount, salt: 31, pool);

        try
        {
            Scalar[] point = PointFromRegistry(registry, basis.VariableCount);

            //Round up to the next power of two, as the committed multilinear is.
            int paddedCount = (int)System.Numerics.BitOperations.RoundUpToPowerOf2((uint)basis.Count);
            using IMemoryOwner<byte> coefficientsOwner = pool.Rent(paddedCount * ScalarSize);
            Span<byte> coefficients = coefficientsOwner.Memory.Span[..(paddedCount * ScalarSize)];
            mask.CopyCoefficientsTo(coefficients);

            using IMemoryOwner<byte> weightsOwner = pool.Rent(paddedCount * ScalarSize);
            Span<byte> weights = weightsOwner.Memory.Span[..(paddedCount * ScalarSize)];
            MonomialBasisMask.BuildWeightVector(basis, point, weights, Multiply, Curve);

            Span<byte> innerProduct = stackalloc byte[ScalarSize];
            innerProduct.Clear();
            Span<byte> product = stackalloc byte[ScalarSize];
            for(int i = 0; i < paddedCount; i++)
            {
                Multiply(coefficients.Slice(i * ScalarSize, ScalarSize), weights.Slice(i * ScalarSize, ScalarSize), product, Curve);
                Add(innerProduct, product, innerProduct, Curve);
            }

            using Scalar expected = mask.EvaluateAt(point, Add, Multiply, pool);
            Assert.IsTrue(
                innerProduct.SequenceEqual(expected.AsReadOnlySpan()),
                $"The coefficient/weight inner product must equal s(r) (padded = {padded}).");
        }
        finally
        {
            DisposeRegistry(registry);
        }
    }


    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public void SigmaMatchesDenseHypercubeSum(bool padded)
    {
        //σ against the literal Σ_b s(b) over all 2^d boolean points.
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        ScalarRandomDelegate random = new DeterministicScalarRandom(MaskSeed).AsDelegate();
        MonomialBasis basis = padded
            ? MonomialBasis.SumOfUnivariatesWithPad(variableCount: 5, padPairCount: 5)
            : MonomialBasis.Full(variableCount: 4);
        int d = basis.VariableCount;

        using MonomialBasisMask mask = MonomialBasisMask.Sample(basis, random, Curve, pool);
        using IMemoryOwner<byte> coefficientsOwner = pool.Rent(basis.Count * ScalarSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..(basis.Count * ScalarSize)];
        mask.CopyCoefficientsTo(coefficients);

        //Boolean coordinates as canonical scalars, reused across assignments.
        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[ScalarSize - 1] = 0x01;

        Span<byte> denseSum = stackalloc byte[ScalarSize];
        denseSum.Clear();
        Span<byte> value = stackalloc byte[ScalarSize];
        Span<byte> coordinates = stackalloc byte[d * ScalarSize];
        for(int b = 0; b < (1 << d); b++)
        {
            for(int j = 0; j < d; j++)
            {
                ReadOnlySpan<byte> bit = ((b >> j) & 1) != 0 ? one : zero;
                bit.CopyTo(coordinates.Slice(j * ScalarSize, ScalarSize));
            }

            EvaluateMaskReference(basis, coefficients, coordinates, value);
            Add(denseSum, value, denseSum, Curve);
        }

        using Scalar sigma = mask.ComputeSigma(Add, Multiply, pool);
        Assert.IsTrue(
            sigma.AsReadOnlySpan().SequenceEqual(denseSum),
            $"The closed-form σ must equal the dense hypercube sum (padded = {padded}).");
    }


    [TestMethod]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    public void CubicSumOfUnivariatesChainsFromSigmaToTerminal(int variableCount)
    {
        //The degree-3 shape (the Spartan outer sumcheck's round format): per
        //round the kernel blends c_0, c_2, AND c_3; the reference samples the
        //brute-forced round polynomial at t ∈ {0, 1, 2, 3} and checks the
        //finite-difference identities division-free — the third difference
        //p(3) − 3p(2) + 3p(1) − p(0) = 6·c_3 and the second difference
        //p(2) − 2p(1) + p(0) = 2·c_2 + 6·c_3 — then chains the claim through
        //the cubic down to s(r).
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        ScalarRandomDelegate random = new DeterministicScalarRandom(MaskSeed).AsDelegate();
        MonomialBasis basis = MonomialBasis.SumOfUnivariatesWithPad(variableCount, padPairCount: 2, perVariableDegree: 3);
        Assert.AreEqual((3 * variableCount) + 1 + 4, basis.Count, "The cubic padded basis count must be 3d + 1 + 2P.");

        using MonomialBasisMask mask = MonomialBasisMask.Sample(basis, random, Curve, pool);
        using IMemoryOwner<byte> coefficientsOwner = pool.Rent(basis.Count * ScalarSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..(basis.Count * ScalarSize)];
        mask.CopyCoefficientsTo(coefficients);
        Scalar[] challengesForVariable = BuildChallengeRegistry(variableCount, salt: 41, pool);

        try
        {
            using Scalar sigma = mask.ComputeSigma(Add, Multiply, pool);
            Span<byte> claim = stackalloc byte[ScalarSize];
            sigma.AsReadOnlySpan().CopyTo(claim);

            Span<byte> rho = stackalloc byte[ScalarSize];
            WriteSmallScalar(1, rho);

            Span<byte> c0 = stackalloc byte[ScalarSize];
            Span<byte> c2 = stackalloc byte[ScalarSize];
            Span<byte> c3 = stackalloc byte[ScalarSize];
            Span<byte> p0 = stackalloc byte[ScalarSize];
            Span<byte> p1 = stackalloc byte[ScalarSize];
            Span<byte> p2 = stackalloc byte[ScalarSize];
            Span<byte> p3 = stackalloc byte[ScalarSize];
            Span<byte> left = stackalloc byte[ScalarSize];
            Span<byte> right = stackalloc byte[ScalarSize];
            Span<byte> scratch = stackalloc byte[ScalarSize];
            Span<byte> chained = stackalloc byte[ScalarSize];
            Span<byte> nextClaim = stackalloc byte[ScalarSize];

            for(int k = variableCount; k >= 1; k--)
            {
                c0.Clear();
                c2.Clear();
                c3.Clear();
                mask.AddRoundBlend(k, challengesForVariable, rho, c0, c2, c3, Add, Multiply);

                ReferenceRoundPolynomial(basis, coefficients, k, challengesForVariable, 0, p0);
                ReferenceRoundPolynomial(basis, coefficients, k, challengesForVariable, 1, p1);
                ReferenceRoundPolynomial(basis, coefficients, k, challengesForVariable, 2, p2);
                ReferenceRoundPolynomial(basis, coefficients, k, challengesForVariable, 3, p3);

                //Constant share: c_0 = p(0).
                Assert.IsTrue(c0.SequenceEqual(p0), $"The round-{k} constant share must equal p(0) for d = {variableCount}.");

                //Cubic share: p(3) − 3p(2) + 3p(1) − p(0) = 6·c_3.
                Subtract(p3, p2, left, Curve);
                Subtract(left, p2, left, Curve);
                Subtract(left, p2, left, Curve);
                Add(left, p1, left, Curve);
                Add(left, p1, left, Curve);
                Add(left, p1, left, Curve);
                Subtract(left, p0, left, Curve);
                MultiplyBySix(c3, right);
                Assert.IsTrue(left.SequenceEqual(right), $"The round-{k} cubic share must match the third difference for d = {variableCount}.");

                //Quadratic share: p(2) − 2p(1) + p(0) = 2·c_2 + 6·c_3.
                Subtract(p2, p1, left, Curve);
                Subtract(left, p1, left, Curve);
                Add(left, p0, left, Curve);
                Add(c2, c2, right, Curve);
                MultiplyBySix(c3, scratch);
                Add(right, scratch, right, Curve);
                Assert.IsTrue(left.SequenceEqual(right), $"The round-{k} quadratic share must match the second difference for d = {variableCount}.");

                //Chain: p(0) + p(1) = claim.
                Add(p0, p1, chained, Curve);
                Assert.IsTrue(chained.SequenceEqual(claim), $"p_{k}(0) + p_{k}(1) must chain from the running claim for d = {variableCount}.");

                //claim ← p_k(r_k) through the cubic.
                EvaluateCubicFromSamples(p0, p1, p2, p3, challengesForVariable[k].AsReadOnlySpan(), nextClaim);
                nextClaim.CopyTo(claim);
            }

            Scalar[] point = PointFromRegistry(challengesForVariable, variableCount);
            using Scalar terminal = mask.EvaluateAt(point, Add, Multiply, pool);
            Assert.IsTrue(
                terminal.AsReadOnlySpan().SequenceEqual(claim),
                $"The chained terminal claim must equal s(r) for d = {variableCount}.");
        }
        finally
        {
            DisposeRegistry(challengesForVariable);
        }
    }


    [TestMethod]
    public void QuadraticBlendOverloadRejectsCubicBases()
    {
        //A cubic basis routed through the quadratic overload would silently drop
        //the cubic share; the kernel must refuse loudly instead.
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        ScalarRandomDelegate random = new DeterministicScalarRandom(MaskSeed).AsDelegate();
        MonomialBasis basis = MonomialBasis.SumOfUnivariatesWithPad(variableCount: 3, padPairCount: 0, perVariableDegree: 3);

        using MonomialBasisMask mask = MonomialBasisMask.Sample(basis, random, Curve, pool);
        Scalar[] registry = BuildChallengeRegistry(3, salt: 43, pool);

        try
        {
            byte[] rho = new byte[ScalarSize];
            rho[ScalarSize - 1] = 0x01;
            byte[] c0 = new byte[ScalarSize];
            byte[] c2 = new byte[ScalarSize];

            _ = Assert.ThrowsExactly<InvalidOperationException>(
                () => mask.AddRoundBlend(3, registry, rho, c0, c2, Add, Multiply),
                "The quadratic overload must reject a basis with cubic round shares.");
        }
        finally
        {
            DisposeRegistry(registry);
        }
    }


    [TestMethod]
    public void PadPairCapacityIsEnforced()
    {
        //The padded shape offers exactly 2^{d−1} multilinear pad monomials over
        //x_2…x_d; requesting more must refuse loudly (small d uses Full instead).
        const int VariableCount = 3;
        const int Capacity = 1 << (VariableCount - 1);

        MonomialBasis atCapacity = MonomialBasis.SumOfUnivariatesWithPad(VariableCount, Capacity);
        Assert.AreEqual((2 * VariableCount) + 1 + (2 * Capacity), atCapacity.Count);

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = MonomialBasis.SumOfUnivariatesWithPad(VariableCount, Capacity + 1),
            "A pad request beyond the multilinear-monomial capacity must be refused.");
    }


    [TestMethod]
    public void TwoSampledMasksDiffer()
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        ScalarRandomDelegate random = new DeterministicScalarRandom(MaskSeed).AsDelegate();
        MonomialBasis basis = MonomialBasis.SumOfUnivariatesWithPad(variableCount: 4, padPairCount: 3);

        using MonomialBasisMask first = MonomialBasisMask.Sample(basis, random, Curve, pool);
        using MonomialBasisMask second = MonomialBasisMask.Sample(basis, random, Curve, pool);

        Assert.AreEqual(basis.Count, first.CoefficientCount, "The mask must carry one coefficient per basis monomial.");
        Assert.IsFalse(
            first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()),
            "Two draws from the sampler must produce different masks.");
    }


    //The strongest property: starting the claim at σ, every round's blend must
    //agree with the brute-forced partial sum p_k at t ∈ {0, 1, 2}, the chain
    //p_k(0) + p_k(1) = claim must hold per round, and the final claim p_1(r_1)
    //must equal EvaluateAt(r) — one pass exercising ComputeSigma, AddRoundBlend
    //(both blended coefficients), and EvaluateAt against each other.
    private static void AssertChainsFromSigmaToTerminal(MonomialBasis basis, int salt)
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        ScalarRandomDelegate random = new DeterministicScalarRandom(MaskSeed).AsDelegate();
        int d = basis.VariableCount;

        using MonomialBasisMask mask = MonomialBasisMask.Sample(basis, random, Curve, pool);
        using IMemoryOwner<byte> coefficientsOwner = pool.Rent(basis.Count * ScalarSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..(basis.Count * ScalarSize)];
        mask.CopyCoefficientsTo(coefficients);
        Scalar[] challengesForVariable = BuildChallengeRegistry(d, salt, pool);

        try
        {
            using Scalar sigma = mask.ComputeSigma(Add, Multiply, pool);
            Span<byte> claim = stackalloc byte[ScalarSize];
            sigma.AsReadOnlySpan().CopyTo(claim);

            Span<byte> rho = stackalloc byte[ScalarSize];
            rho.Clear();
            rho[ScalarSize - 1] = 0x01;

            //Scratch for the per-round comparisons, hoisted out of the loop;
            //every buffer is fully overwritten by its producer each iteration.
            Span<byte> c0 = stackalloc byte[ScalarSize];
            Span<byte> c2 = stackalloc byte[ScalarSize];
            Span<byte> p0 = stackalloc byte[ScalarSize];
            Span<byte> p1 = stackalloc byte[ScalarSize];
            Span<byte> p2 = stackalloc byte[ScalarSize];
            Span<byte> left = stackalloc byte[ScalarSize];
            Span<byte> right = stackalloc byte[ScalarSize];
            Span<byte> chained = stackalloc byte[ScalarSize];
            Span<byte> nextClaim = stackalloc byte[ScalarSize];

            for(int k = d; k >= 1; k--)
            {
                //Kernel blends into zeroed coefficients with ρ = 1, exposing the
                //raw constant and quadratic shares.
                c0.Clear();
                c2.Clear();
                mask.AddRoundBlend(k, challengesForVariable, rho, c0, c2, Add, Multiply);

                //Reference round polynomial at t = 0, 1, 2 by brute force.
                ReferenceRoundPolynomial(basis, coefficients, k, challengesForVariable, 0, p0);
                ReferenceRoundPolynomial(basis, coefficients, k, challengesForVariable, 1, p1);
                ReferenceRoundPolynomial(basis, coefficients, k, challengesForVariable, 2, p2);

                //Constant share: the blended c_0 must equal p_k(0).
                Assert.IsTrue(c0.SequenceEqual(p0), $"The round-{k} constant share must equal the brute-forced p(0) for d = {d}.");

                //Quadratic share: p(0) − 2·p(1) + p(2) = 2·c_2 — division-free.
                Subtract(p0, p1, left, Curve);
                Subtract(left, p1, left, Curve);
                Add(left, p2, left, Curve);
                Add(c2, c2, right, Curve);
                Assert.IsTrue(left.SequenceEqual(right), $"The round-{k} quadratic share must equal the brute-forced one for d = {d}.");

                //Chain: p_k(0) + p_k(1) must equal the running claim.
                Add(p0, p1, chained, Curve);
                Assert.IsTrue(chained.SequenceEqual(claim), $"p_{k}(0) + p_{k}(1) must chain from the running claim for d = {d}.");

                //claim ← p_k(r_k).
                EvaluateQuadraticFromSamples(p0, p1, p2, challengesForVariable[k].AsReadOnlySpan(), nextClaim);
                nextClaim.CopyTo(claim);
            }

            //The terminal claim must be s(r).
            Scalar[] point = PointFromRegistry(challengesForVariable, d);
            using Scalar terminal = mask.EvaluateAt(point, Add, Multiply, pool);
            Assert.IsTrue(
                terminal.AsReadOnlySpan().SequenceEqual(claim),
                $"The chained terminal claim must equal s(r) for d = {d}.");
        }
        finally
        {
            DisposeRegistry(challengesForVariable);
        }
    }


    //The brute-forced round polynomial p_k(t): the partial sum of the mask over
    //the k−1 free boolean variables with X_k = t and the higher variables bound
    //to their challenges.
    private static void ReferenceRoundPolynomial(
        MonomialBasis basis,
        ReadOnlySpan<byte> coefficients,
        int k,
        Scalar[] challengesForVariable,
        int t,
        Span<byte> result)
    {
        int d = basis.VariableCount;
        result.Clear();
        Span<byte> value = stackalloc byte[ScalarSize];
        Span<byte> coordinates = stackalloc byte[d * ScalarSize];

        //Fixed coordinate sections: X_k = t and the bound challenges above it.
        WriteSmallScalar(t, coordinates.Slice((k - 1) * ScalarSize, ScalarSize));
        for(int j = k + 1; j <= d; j++)
        {
            challengesForVariable[j].AsReadOnlySpan().CopyTo(coordinates.Slice((j - 1) * ScalarSize, ScalarSize));
        }

        for(int assignment = 0; assignment < (1 << (k - 1)); assignment++)
        {
            for(int j = 1; j < k; j++)
            {
                WriteSmallScalar((assignment >> (j - 1)) & 1, coordinates.Slice((j - 1) * ScalarSize, ScalarSize));
            }

            EvaluateMaskReference(basis, coefficients, coordinates, value);
            Add(result, value, result, Curve);
        }
    }


    //The naive mask evaluation Σ_e c_e·Π x_j^{e_j} at the given coordinates.
    private static void EvaluateMaskReference(
        MonomialBasis basis,
        ReadOnlySpan<byte> coefficients,
        ReadOnlySpan<byte> coordinates,
        Span<byte> result)
    {
        result.Clear();
        Span<byte> monomial = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        for(int i = 0; i < basis.Count; i++)
        {
            ReadOnlySpan<byte> exponents = basis.ExponentsAt(i);
            monomial.Clear();
            monomial[ScalarSize - 1] = 0x01;
            for(int j = 0; j < exponents.Length; j++)
            {
                for(int e = 0; e < exponents[j]; e++)
                {
                    Multiply(monomial, coordinates.Slice(j * ScalarSize, ScalarSize), monomial, Curve);
                }
            }

            Multiply(coefficients.Slice(i * ScalarSize, ScalarSize), monomial, term, Curve);
            Add(result, term, result, Curve);
        }
    }


    //Evaluates the quadratic through (0, p0), (1, p1), (2, p2) at r without
    //field division until the end: c0 = p0, 2c2 = p0 − 2p1 + p2,
    //2c1 = 2(p1 − p0) − 2c2, then q(r) = (2·p0 + 2c1·r + 2c2·r²)·inv(2).
    private static void EvaluateQuadraticFromSamples(
        ReadOnlySpan<byte> p0,
        ReadOnlySpan<byte> p1,
        ReadOnlySpan<byte> p2,
        ReadOnlySpan<byte> r,
        Span<byte> result)
    {
        Span<byte> twoC2 = stackalloc byte[ScalarSize];
        Subtract(p0, p1, twoC2, Curve);
        Subtract(twoC2, p1, twoC2, Curve);
        Add(twoC2, p2, twoC2, Curve);

        Span<byte> twoC1 = stackalloc byte[ScalarSize];
        Subtract(p1, p0, twoC1, Curve);
        Add(twoC1, twoC1, twoC1, Curve);
        Subtract(twoC1, twoC2, twoC1, Curve);

        Span<byte> doubled = stackalloc byte[ScalarSize];
        Add(p0, p0, doubled, Curve);
        Span<byte> term = stackalloc byte[ScalarSize];
        Multiply(twoC1, r, term, Curve);
        Add(doubled, term, doubled, Curve);
        Multiply(r, r, term, Curve);
        Multiply(twoC2, term, term, Curve);
        Add(doubled, term, doubled, Curve);

        Multiply(doubled, InverseOfTwo, result, Curve);
    }


    //The inverse of two in the BLS12-381 scalar field: (p + 1) / 2 where p is
    //the field order — computed once from the reference field order.
    private static byte[] InverseOfTwo { get; } = ComputeInverse(2);

    //The inverse of six, for recovering a cubic's value from its four samples
    //after the division-free coefficient identities.
    private static byte[] InverseOfSix { get; } = ComputeInverse(6);

    private static byte[] ComputeInverse(int value)
    {
        System.Numerics.BigInteger p = Bls12Curve381BigIntegerScalarReference.FieldOrder;
        System.Numerics.BigInteger inverse = System.Numerics.BigInteger.ModPow(value, p - 2, p);
        byte[] result = new byte[ScalarSize];
        byte[] raw = inverse.ToByteArray(isUnsigned: true, isBigEndian: true);
        raw.CopyTo(result.AsSpan(ScalarSize - raw.Length));

        return result;
    }


    //result = 6·value by field doubling and adding.
    private static void MultiplyBySix(ReadOnlySpan<byte> value, Span<byte> result)
    {
        Span<byte> twice = stackalloc byte[ScalarSize];
        Add(value, value, twice, Curve);
        Add(twice, twice, result, Curve);
        Add(result, twice, result, Curve);
    }


    //Evaluates the cubic through (0, p0) … (3, p3) at r, division-free until a
    //single final multiply by inv(6): with T = 6c₃ (the third difference),
    //S = 2c₂ + T (the second difference), and 6c₁ = 6(p1 − p0) − 3(S − T) − T,
    //6·q(r) = 6p0 + (6c₁)r + 3(S − T)r² + T·r³.
    private static void EvaluateCubicFromSamples(
        ReadOnlySpan<byte> p0,
        ReadOnlySpan<byte> p1,
        ReadOnlySpan<byte> p2,
        ReadOnlySpan<byte> p3,
        ReadOnlySpan<byte> r,
        Span<byte> result)
    {
        //T = p3 − 3p2 + 3p1 − p0.
        Span<byte> t = stackalloc byte[ScalarSize];
        Subtract(p3, p2, t, Curve);
        Subtract(t, p2, t, Curve);
        Subtract(t, p2, t, Curve);
        Add(t, p1, t, Curve);
        Add(t, p1, t, Curve);
        Add(t, p1, t, Curve);
        Subtract(t, p0, t, Curve);

        //S = p2 − 2p1 + p0; twoC2 = S − T; threeTwoC2 = 3·(2c₂).
        Span<byte> twoC2 = stackalloc byte[ScalarSize];
        Subtract(p2, p1, twoC2, Curve);
        Subtract(twoC2, p1, twoC2, Curve);
        Add(twoC2, p0, twoC2, Curve);
        Subtract(twoC2, t, twoC2, Curve);
        Span<byte> threeTwoC2 = stackalloc byte[ScalarSize];
        Add(twoC2, twoC2, threeTwoC2, Curve);
        Add(threeTwoC2, twoC2, threeTwoC2, Curve);

        //6c₁ = 6(p1 − p0) − 3·(2c₂) − T.
        Span<byte> sixC1 = stackalloc byte[ScalarSize];
        Subtract(p1, p0, sixC1, Curve);
        MultiplyBySix(sixC1, sixC1);
        Subtract(sixC1, threeTwoC2, sixC1, Curve);
        Subtract(sixC1, t, sixC1, Curve);

        //6·q(r) by Horner over (6p0, 6c₁, 3·2c₂, T), then halve six-fold.
        Span<byte> accumulator = stackalloc byte[ScalarSize];
        t.CopyTo(accumulator);
        Multiply(accumulator, r, accumulator, Curve);
        Add(accumulator, threeTwoC2, accumulator, Curve);
        Multiply(accumulator, r, accumulator, Curve);
        Add(accumulator, sixC1, accumulator, Curve);
        Multiply(accumulator, r, accumulator, Curve);
        Span<byte> sixP0 = stackalloc byte[ScalarSize];
        MultiplyBySix(p0, sixP0);
        Add(accumulator, sixP0, accumulator, Curve);

        Multiply(accumulator, InverseOfSix, result, Curve);
    }


    //One-based challenge registry: registry[j] = r_j; index 0 is an unused
    //placeholder scalar so the indexing matches the X_j naming.
    private static Scalar[] BuildChallengeRegistry(int variableCount, int salt, SensitiveMemoryPool<byte> pool)
    {
        var registry = new Scalar[variableCount + 1];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int j = 0; j <= variableCount; j++)
        {
            wide.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 61) + (j * 37) + 11);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 17) + (j * 53) + 7);
            IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
            Reduce(wide, owner.Memory.Span[..ScalarSize], Curve);
            registry[j] = new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
        }

        return registry;
    }


    //The evaluation point r in MLE storage order from the one-based registry.
    private static Scalar[] PointFromRegistry(Scalar[] registry, int variableCount)
    {
        var point = new Scalar[variableCount];
        for(int j = 1; j <= variableCount; j++)
        {
            point[j - 1] = registry[j];
        }

        return point;
    }


    private static void WriteSmallScalar(int value, Span<byte> destination)
    {
        destination.Clear();
        destination[ScalarSize - 1] = (byte)value;
    }


    private static void DisposeRegistry(Scalar[] registry)
    {
        foreach(Scalar challenge in registry)
        {
            challenge.Dispose();
        }
    }
}
