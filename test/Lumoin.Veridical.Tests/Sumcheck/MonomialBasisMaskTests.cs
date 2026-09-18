using Lumoin.Veridical.Backends.Managed;
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
/// The monomial-basis sumcheck mask (<see cref="MonomialBasisMask"/>
/// over a <see cref="MonomialBasis"/>; Libra ePrint 2019/317 §4.1 generalised
/// to an arbitrary monomial basis) pins the generic
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
    /// <summary>The real BLS12-381 scalar addition delegate every test in this file computes over.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The real BLS12-381 scalar subtraction delegate every test in this file computes over.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The real BLS12-381 scalar multiplication delegate every test in this file computes over.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The delegate that reduces a wide byte buffer to a canonical BLS12-381 scalar, used to build deterministic challenges.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The byte width of one BLS12-381 scalar.</summary>
    private const int ScalarSize = 32;

    /// <summary>The BLS12-381 curve tag every delegate call in this file routes over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;

    /// <summary>The fixed seed for every deterministic mask sampler this file constructs.</summary>
    private static byte[] MaskSeed { get; } = Encoding.UTF8.GetBytes("veridical.sumcheck.monomialmask.kernel.test.v1");


    /// <summary>Both factory shapes release storage idempotently and reject all exponent access after disposal.</summary>
    /// <param name="padded">Whether to use the padded univariate basis.</param>
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public void BasisDisposalIsIdempotentAndInvalidatesAccess(bool padded)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        //A single variable exercises both factory shapes without unnecessary storage.
        const int VariableCount = 1;
        using MonomialBasis basis = padded
            ? MonomialBasis.SumOfUnivariatesWithPad(VariableCount, padPairCount: 0, pool)
            : MonomialBasis.Full(VariableCount, pool);
        Assert.HasCount(VariableCount, basis.ExponentsAt(0));

        basis.Dispose();
        basis.Dispose();

        ObjectDisposedException exception = Assert.ThrowsExactly<ObjectDisposedException>(() => basis.ExponentsAt(0));
        Assert.AreEqual(nameof(MonomialBasis), exception.ObjectName);
        Assert.ThrowsExactly<ObjectDisposedException>(() => basis.ExponentsAt(-1));
        Assert.ThrowsExactly<ObjectDisposedException>(() => basis.ExponentsAt(basis.Count));
    }


    /// <summary>Checks the padded univariate mask chain from its hypercube sum to the terminal evaluation.</summary>
    [TestMethod]
    [DataRow(5, 4)]
    [DataRow(5, 8)]
    [DataRow(6, 8)]
    public void PaddedSumOfUnivariatesChainsFromSigmaToTerminal(int variableCount, int padPairCount)
    {
        using MonomialBasis basis = MonomialBasis.SumOfUnivariatesWithPad(variableCount, padPairCount, BaseMemoryPool.Shared);
        Assert.AreEqual((2 * variableCount) + 1 + (2 * padPairCount), basis.Count, "The padded basis count must be 2d + 1 + 2P.");

        AssertChainsFromSigmaToTerminal(basis, salt: 23);
    }


    /// <summary>Checks the full basis mask chain from its hypercube sum to the terminal evaluation.</summary>
    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    public void FullBasisChainsFromSigmaToTerminal(int variableCount)
    {
        using MonomialBasis basis = MonomialBasis.Full(variableCount, BaseMemoryPool.Shared);
        int expectedCount = 1;
        for(int j = 0; j < variableCount; j++)
        {
            expectedCount *= 3;
        }

        Assert.AreEqual(expectedCount, basis.Count, "The full basis count must be 3^d.");

        AssertChainsFromSigmaToTerminal(basis, salt: 29);
    }


    /// <summary>Checks that the public weights and mask coefficients reproduce the mask evaluation.</summary>
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public void WeightVectorInnerProductEqualsEvaluation(bool padded)
    {
        //⟨coefficients, w(r)⟩ = s(r), including over a padded destination whose
        //tail weights are zero — the exact pairing the weighted opening of the
        //committed coefficient multilinear relies on.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarRandomDelegate random = new DeterministicScalarRandom(MaskSeed).AsDelegate();
        using MonomialBasis basis = padded
            ? MonomialBasis.SumOfUnivariatesWithPad(variableCount: 5, padPairCount: 6, pool)
            : MonomialBasis.Full(variableCount: 3, pool);

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


    /// <summary>Verifies that Sample throws <see cref="InvalidOperationException"/> for a sampler that always returns zero bytes, since blending nothing would silently void the mask's statistical zero-knowledge.</summary>
    [TestMethod]
    public void SampleWithZeroEntropyThrows()
    {
        //A sampler that returns identically-zero bytes models the RNG wiring
        //failure that silently voids the statistical zero-knowledge: the mask
        //blends nothing, yet every proof still verifies. Sample must reject it
        //at generation with InvalidOperationException.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using MonomialBasis basis = MonomialBasis.SumOfUnivariatesWithPad(variableCount: 4, padPairCount: 0, pool);

        Assert.ThrowsExactly<InvalidOperationException>(() =>
            MonomialBasisMask.Sample(basis, ZeroScalarRandom, Curve, pool).Dispose());
    }


    /// <summary>
    /// An entropy delegate with the production sampler signature that always returns zero bytes,
    /// modelling an RNG wiring failure.
    /// </summary>
    private static Tag ZeroScalarRandom(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
    {
        destination.Clear();

        return inboundTag;
    }


    /// <summary>Verifies that the mask's closed-form σ equals the literal sum of its evaluations over every point of the Boolean hypercube.</summary>
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public void SigmaMatchesDenseHypercubeSum(bool padded)
    {
        //σ against the literal Σ_b s(b) over all 2^d boolean points.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarRandomDelegate random = new DeterministicScalarRandom(MaskSeed).AsDelegate();
        using MonomialBasis basis = padded
            ? MonomialBasis.SumOfUnivariatesWithPad(variableCount: 5, padPairCount: 5, pool)
            : MonomialBasis.Full(variableCount: 4, pool);
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


    /// <summary>Checks the cubic mask chain from its hypercube sum to the terminal evaluation.</summary>
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarRandomDelegate random = new DeterministicScalarRandom(MaskSeed).AsDelegate();
        using MonomialBasis basis = MonomialBasis.SumOfUnivariatesWithPad(variableCount, padPairCount: 2, pool, perVariableDegree: 3);
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


    /// <summary>Verifies that routing a cubic-degree basis through the quadratic round-blend overload throws, rather than silently dropping the cubic share.</summary>
    [TestMethod]
    public void QuadraticBlendOverloadRejectsCubicBases()
    {
        //A cubic basis routed through the quadratic overload would silently drop
        //the cubic share; the kernel must refuse loudly instead.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarRandomDelegate random = new DeterministicScalarRandom(MaskSeed).AsDelegate();
        using MonomialBasis basis = MonomialBasis.SumOfUnivariatesWithPad(variableCount: 3, padPairCount: 0, pool, perVariableDegree: 3);

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


    /// <summary>Checks that the basis factory rejects pad pairs beyond its capacity.</summary>
    [TestMethod]
    public void PadPairCapacityIsEnforced()
    {
        //The padded shape offers exactly 2^{d−1} multilinear pad monomials over
        //x_2…x_d; requesting more must refuse loudly (small d uses Full instead).
        const int VariableCount = 3;
        const int Capacity = 1 << (VariableCount - 1);

        using MonomialBasis atCapacity = MonomialBasis.SumOfUnivariatesWithPad(VariableCount, Capacity, BaseMemoryPool.Shared);
        Assert.AreEqual((2 * VariableCount) + 1 + (2 * Capacity), atCapacity.Count);

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => MonomialBasis.SumOfUnivariatesWithPad(VariableCount, Capacity + 1, BaseMemoryPool.Shared).Dispose(),
            "A pad request beyond the multilinear-monomial capacity must be refused.");
    }


    /// <summary>Checks that separately sampled masks have different coefficients.</summary>
    [TestMethod]
    public void TwoSampledMasksDiffer()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarRandomDelegate random = new DeterministicScalarRandom(MaskSeed).AsDelegate();
        using MonomialBasis basis = MonomialBasis.SumOfUnivariatesWithPad(variableCount: 4, padPairCount: 3, pool);

        using MonomialBasisMask first = MonomialBasisMask.Sample(basis, random, Curve, pool);
        using MonomialBasisMask second = MonomialBasisMask.Sample(basis, random, Curve, pool);

        Assert.AreEqual(basis.Count, first.CoefficientCount, "The mask must carry one coefficient per basis monomial.");
        Assert.IsFalse(
            first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()),
            "Two draws from the sampler must produce different masks.");
    }


    /// <summary>
    /// Asserts the strongest chain property for a quadratic-shaped basis: starting the claim at σ,
    /// every round's blend agrees with the brute-forced partial sum p_k at t ∈ {0, 1, 2}, the chain
    /// p_k(0) + p_k(1) = claim holds per round, and the final claim p_1(r_1) equals EvaluateAt(r) —
    /// one pass exercising ComputeSigma, AddRoundBlend and EvaluateAt against each other.
    /// </summary>
    private static void AssertChainsFromSigmaToTerminal(MonomialBasis basis, int salt)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
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


    /// <summary>
    /// Computes the brute-forced round polynomial p_k(t): the partial sum of the mask over the
    /// k-1 free Boolean variables with X_k = t and the higher variables bound to their challenges.
    /// </summary>
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


    /// <summary>Computes the naive mask evaluation Σ_e c_e·Π x_j^{e_j} at the given coordinates.</summary>
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


    /// <summary>
    /// Evaluates the quadratic through (0, p0), (1, p1), (2, p2) at r without field division until
    /// the end: c0 = p0, 2c2 = p0 − 2p1 + p2, 2c1 = 2(p1 − p0) − 2c2, then
    /// q(r) = (2·p0 + 2c1·r + 2c2·r²)·inv(2).
    /// </summary>
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


    /// <summary>
    /// The inverse of two in the BLS12-381 scalar field, equal to (p + 1) / 2 where p is the field
    /// order, computed once from the reference field order.
    /// </summary>
    private static byte[] InverseOfTwo { get; } = ComputeInverse(2);

    /// <summary>
    /// The inverse of six in the BLS12-381 scalar field, used to recover a cubic's value from its
    /// four samples after the division-free coefficient identities.
    /// </summary>
    private static byte[] InverseOfSix { get; } = ComputeInverse(6);

    /// <summary>Computes the modular inverse of the given small integer in the BLS12-381 scalar field by Fermat's little theorem.</summary>
    private static byte[] ComputeInverse(int value)
    {
        System.Numerics.BigInteger p = Bls12Curve381BigIntegerScalarReference.FieldOrder;
        System.Numerics.BigInteger inverse = System.Numerics.BigInteger.ModPow(value, p - 2, p);
        byte[] result = new byte[ScalarSize];
        byte[] raw = inverse.ToByteArray(isUnsigned: true, isBigEndian: true);
        raw.CopyTo(result.AsSpan(ScalarSize - raw.Length));

        return result;
    }


    /// <summary>Computes result = 6·value by field doubling and adding.</summary>
    private static void MultiplyBySix(ReadOnlySpan<byte> value, Span<byte> result)
    {
        Span<byte> twice = stackalloc byte[ScalarSize];
        Add(value, value, twice, Curve);
        Add(twice, twice, result, Curve);
        Add(result, twice, result, Curve);
    }


    /// <summary>
    /// Evaluates the cubic through (0, p0) … (3, p3) at r, division-free until a single final
    /// multiply by inv(6): with T = 6c₃ (the third difference), S = 2c₂ + T (the second
    /// difference), and 6c₁ = 6(p1 − p0) − 3(S − T) − T, 6·q(r) = 6p0 + (6c₁)r + 3(S − T)r² + T·r³.
    /// </summary>
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


    /// <summary>
    /// Builds a one-based challenge registry where registry[j] = r_j; index 0 is an unused
    /// placeholder scalar so the indexing matches the X_j naming.
    /// </summary>
    private static Scalar[] BuildChallengeRegistry(int variableCount, int salt, BaseMemoryPool pool)
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


    /// <summary>Builds the evaluation point r in MLE storage order from the one-based registry.</summary>
    private static Scalar[] PointFromRegistry(Scalar[] registry, int variableCount)
    {
        var point = new Scalar[variableCount];
        for(int j = 1; j <= variableCount; j++)
        {
            point[j - 1] = registry[j];
        }

        return point;
    }


    /// <summary>Writes a small non-negative integer as a canonical scalar in its last byte, the rest zeroed.</summary>
    private static void WriteSmallScalar(int value, Span<byte> destination)
    {
        destination.Clear();
        destination[ScalarSize - 1] = (byte)value;
    }


    /// <summary>Disposes every challenge scalar a registry holds.</summary>
    private static void DisposeRegistry(Scalar[] registry)
    {
        foreach(Scalar challenge in registry)
        {
            challenge.Dispose();
        }
    }
}
