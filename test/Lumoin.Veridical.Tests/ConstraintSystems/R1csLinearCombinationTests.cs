using CsCheck;
using Lumoin.Veridical.Core.ConstraintSystems;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Property and unit tests for <see cref="R1csLinearCombination"/>: the
/// affine-algebra laws (commutativity, associativity, identity, inverse,
/// distributivity) and the normalisation invariant (sorted, deduplicated,
/// zero-free terms) that makes structural equality meaningful.
/// </summary>
[TestClass]
internal sealed class R1csLinearCombinationTests
{
    private const int IterationCount = 1000;
    private const int MaxVariableIndex = 8;
    private const long CoefficientBound = 1000;
    private const int MaxTerms = 6;


    private static readonly Gen<BigInteger> GenCoefficient =
        Gen.Long[-CoefficientBound, CoefficientBound].Select(v => new BigInteger(v));

    private static readonly Gen<(R1csVariableIndex, BigInteger)> GenTerm =
        Gen.Select(Gen.Int[0, MaxVariableIndex].Select(i => new R1csVariableIndex(i)), GenCoefficient);

    private static readonly Gen<R1csLinearCombination> GenCombination =
        Gen.Select(
            GenTerm.Array[0, MaxTerms],
            GenCoefficient,
            (terms, constant) => R1csLinearCombination.Create(terms, constant));


    [TestMethod]
    public void AdditionIsCommutative()
    {
        Gen.Select(GenCombination, GenCombination)
            .Sample(pair => (pair.Item1 + pair.Item2) == (pair.Item2 + pair.Item1), iter: IterationCount);
    }


    [TestMethod]
    public void AdditionIsAssociative()
    {
        Gen.Select(GenCombination, GenCombination, GenCombination)
            .Sample(
                t => ((t.Item1 + t.Item2) + t.Item3) == (t.Item1 + (t.Item2 + t.Item3)),
                iter: IterationCount);
    }


    [TestMethod]
    public void ZeroIsTheAdditiveIdentity()
    {
        GenCombination.Sample(a => (a + R1csLinearCombination.Zero) == a, iter: IterationCount);
    }


    [TestMethod]
    public void NegationIsTheAdditiveInverse()
    {
        GenCombination.Sample(a => (a + (-a)) == R1csLinearCombination.Zero, iter: IterationCount);
    }


    [TestMethod]
    public void ScalarMultiplicationDistributesOverAddition()
    {
        Gen.Select(GenCoefficient, GenCombination, GenCombination)
            .Sample(
                t => (t.Item1 * (t.Item2 + t.Item3)) == ((t.Item1 * t.Item2) + (t.Item1 * t.Item3)),
                iter: IterationCount);
    }


    [TestMethod]
    public void SubtractionIsAdditionOfTheNegation()
    {
        Gen.Select(GenCombination, GenCombination)
            .Sample(pair => (pair.Item1 - pair.Item2) == (pair.Item1 + (-pair.Item2)), iter: IterationCount);
    }


    [TestMethod]
    public void DuplicateVariableTermsAreSummed()
    {
        var x = new R1csVariableIndex(3);
        R1csLinearCombination combination = R1csLinearCombination.Create(
            [(x, new BigInteger(2)), (x, new BigInteger(5))],
            BigInteger.Zero);

        Assert.HasCount(1, combination.Terms, "duplicate variable terms collapse to one");
        Assert.AreEqual(new BigInteger(7), combination.Terms[0].Coefficient, "coefficients sum");
    }


    [TestMethod]
    public void ZeroCoefficientTermsAreDropped()
    {
        var x = new R1csVariableIndex(1);
        var y = new R1csVariableIndex(2);
        R1csLinearCombination combination = R1csLinearCombination.Create(
            [(x, new BigInteger(4)), (y, BigInteger.Zero)],
            BigInteger.Zero);

        Assert.HasCount(1, combination.Terms, "zero-coefficient term is dropped");
        Assert.AreEqual(x, combination.Terms[0].Variable, "only the non-zero term survives");
    }


    [TestMethod]
    public void TermsAreSortedByVariableIndex()
    {
        R1csLinearCombination combination = R1csLinearCombination.Create(
            [(new R1csVariableIndex(5), BigInteger.One), (new R1csVariableIndex(2), BigInteger.One)],
            BigInteger.Zero);

        Assert.AreEqual(2, combination.Terms[0].Variable.Value, "lowest index first");
        Assert.AreEqual(5, combination.Terms[1].Variable.Value, "highest index last");
    }


    [TestMethod]
    public void StructurallyEqualCombinationsHaveEqualHashCodes()
    {
        var x = new R1csVariableIndex(1);
        R1csLinearCombination a = (BigInteger.One * R1csLinearCombination.From(x)) + R1csLinearCombination.FromConstant(new BigInteger(3));
        R1csLinearCombination b = R1csLinearCombination.Create([(x, BigInteger.One)], new BigInteger(3));

        Assert.AreEqual(a, b, "structurally equal");
        Assert.AreEqual(a.GetHashCode(), b.GetHashCode(), "equal objects hash equally");
    }
}
