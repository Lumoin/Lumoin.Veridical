using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Tests for the predicate library. Each predicate has a positive case
/// (the assignment satisfies, so the circuit compiles and
/// <c>CheckSatisfiedBy</c> agrees), a negative case (a non-satisfying
/// assignment is rejected at compile time), and a boundary case. A final
/// composite test applies several predicates to one variable. Compilation's
/// own satisfaction check is the rejection mechanism, so "rejected" means
/// <see cref="R1csCircuitCompilationException"/>.
/// </summary>
[TestClass]
internal sealed class R1csCircuitBuilderPredicatesTests
{
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;
    private static CurveParameterSet Curve => CurveParameterSet.Bls12Curve381;
    private static BigInteger Order => WellKnownCurves.GetScalarFieldOrder(Curve);
    private static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();


    //==== AssertEqual ====

    [TestMethod]
    public void AssertEqualAcceptsEqualValues()
    {
        AssertSatisfied(b =>
        {
            R1csVariableIndex x = b.DeclareWitnessVariable("x");
            R1csVariableIndex y = b.DeclareWitnessVariable("y");
            b.AssertEqual(x, y);
        }, ("x", 7), ("y", 7));
    }


    [TestMethod]
    public void AssertEqualRejectsUnequalValues()
    {
        AssertRejected(b =>
        {
            R1csVariableIndex x = b.DeclareWitnessVariable("x");
            R1csVariableIndex y = b.DeclareWitnessVariable("y");
            b.AssertEqual(x, y);
        }, ("x", 7), ("y", 8));
    }


    [TestMethod]
    public void AssertEqualAcceptsZeroBoundary()
    {
        AssertSatisfied(b =>
        {
            R1csVariableIndex x = b.DeclareWitnessVariable("x");
            R1csVariableIndex y = b.DeclareWitnessVariable("y");
            b.AssertEqual(x, y);
        }, ("x", 0), ("y", 0));
    }


    //==== AssertNotEqual ====

    [TestMethod]
    public void AssertNotEqualAcceptsDistinctValuesWithInverse()
    {
        AssertSatisfied(b =>
        {
            R1csVariableIndex x = b.DeclareWitnessVariable("x");
            R1csVariableIndex y = b.DeclareWitnessVariable("y");
            b.AssertNotEqual(x, y, "xy");
        }, ("x", 7), ("y", 3), ("xy_inverse", Inverse(7 - 3)));
    }


    [TestMethod]
    public void AssertNotEqualRejectsEqualValues()
    {
        //a == b => a - b = 0, which has no inverse; any supplied value fails.
        AssertRejected(b =>
        {
            R1csVariableIndex x = b.DeclareWitnessVariable("x");
            R1csVariableIndex y = b.DeclareWitnessVariable("y");
            b.AssertNotEqual(x, y, "xy");
        }, ("x", 5), ("y", 5), ("xy_inverse", 0));
    }


    [TestMethod]
    public void AssertNotEqualRejectsWrongInverse()
    {
        //Distinct values but a bogus inverse: (a-b)·inv must equal 1.
        AssertRejected(b =>
        {
            R1csVariableIndex x = b.DeclareWitnessVariable("x");
            R1csVariableIndex y = b.DeclareWitnessVariable("y");
            b.AssertNotEqual(x, y, "xy");
        }, ("x", 7), ("y", 3), ("xy_inverse", 999));
    }


    //==== AssertBoolean ====

    [TestMethod]
    public void AssertBooleanAcceptsZero()
    {
        AssertSatisfied(b => b.AssertBoolean(b.DeclareWitnessVariable("x")), ("x", 0));
    }


    [TestMethod]
    public void AssertBooleanAcceptsOne()
    {
        AssertSatisfied(b => b.AssertBoolean(b.DeclareWitnessVariable("x")), ("x", 1));
    }


    [TestMethod]
    public void AssertBooleanRejectsTwo()
    {
        AssertRejected(b => b.AssertBoolean(b.DeclareWitnessVariable("x")), ("x", 2));
    }


    //==== AssertRangeCheck ====

    [TestMethod]
    public void AssertRangeCheckAcceptsValueInRange()
    {
        const int bits = 8;
        const long value = 200;
        AssertSatisfied(
            b => b.AssertRangeCheck(b.DeclareWitnessVariable("v"), bits, "v"),
            WithBits("v", value, bits, ("v", value)));
    }


    [TestMethod]
    public void AssertRangeCheckAcceptsZeroBoundary()
    {
        const int bits = 8;
        AssertSatisfied(
            b => b.AssertRangeCheck(b.DeclareWitnessVariable("v"), bits, "v"),
            WithBits("v", 0, bits, ("v", 0)));
    }


    [TestMethod]
    public void AssertRangeCheckAcceptsMaximumBoundary()
    {
        const int bits = 8;
        const long value = 255; //2^8 - 1
        AssertSatisfied(
            b => b.AssertRangeCheck(b.DeclareWitnessVariable("v"), bits, "v"),
            WithBits("v", value, bits, ("v", value)));
    }


    [TestMethod]
    public void AssertRangeCheckRejectsValueOutOfRange()
    {
        const int bits = 4;
        const long value = 16; //2^4 — the low 4 bits sum to 0, not 16.
        AssertRejected(
            b => b.AssertRangeCheck(b.DeclareWitnessVariable("v"), bits, "v"),
            WithBits("v", value, bits, ("v", value)));
    }


    //==== AssertLessThanOrEqual / AssertGreaterThanOrEqual ====

    [TestMethod]
    public void AssertLessThanOrEqualAcceptsLess()
    {
        const int bits = 8;
        long difference = 50 - 10;
        AssertSatisfied(
            b =>
            {
                R1csVariableIndex a = b.DeclareWitnessVariable("a");
                R1csVariableIndex c = b.DeclareWitnessVariable("c");
                b.AssertLessThanOrEqual(a, c, bits, "le");
            },
            WithBits("le", difference, bits, ("a", 10), ("c", 50)));
    }


    [TestMethod]
    public void AssertLessThanOrEqualAcceptsEqualBoundary()
    {
        const int bits = 8;
        AssertSatisfied(
            b =>
            {
                R1csVariableIndex a = b.DeclareWitnessVariable("a");
                R1csVariableIndex c = b.DeclareWitnessVariable("c");
                b.AssertLessThanOrEqual(a, c, bits, "le");
            },
            WithBits("le", 0, bits, ("a", 42), ("c", 42)));
    }


    [TestMethod]
    public void AssertLessThanOrEqualRejectsGreater()
    {
        //a > c: the true difference c - a is negative, so its low `bits` bits
        //cannot sum to the (huge, mod-r) value of c - a.
        const int bits = 8;
        long difference = 10 - 50; //negative
        AssertRejected(
            b =>
            {
                R1csVariableIndex a = b.DeclareWitnessVariable("a");
                R1csVariableIndex c = b.DeclareWitnessVariable("c");
                b.AssertLessThanOrEqual(a, c, bits, "le");
            },
            WithBits("le", difference, bits, ("a", 50), ("c", 10)));
    }


    [TestMethod]
    public void AssertGreaterThanOrEqualAcceptsGreater()
    {
        const int bits = 8;
        long difference = 90 - 30;
        AssertSatisfied(
            b =>
            {
                R1csVariableIndex a = b.DeclareWitnessVariable("a");
                R1csVariableIndex c = b.DeclareWitnessVariable("c");
                b.AssertGreaterThanOrEqual(a, c, bits, "ge");
            },
            WithBits("ge", difference, bits, ("a", 90), ("c", 30)));
    }


    [TestMethod]
    public void AssertGreaterThanOrEqualRejectsLess()
    {
        const int bits = 8;
        long difference = 30 - 90; //negative
        AssertRejected(
            b =>
            {
                R1csVariableIndex a = b.DeclareWitnessVariable("a");
                R1csVariableIndex c = b.DeclareWitnessVariable("c");
                b.AssertGreaterThanOrEqual(a, c, bits, "ge");
            },
            WithBits("ge", difference, bits, ("a", 30), ("c", 90)));
    }


    //==== AssertInSet ====

    [TestMethod]
    public void AssertInSetAcceptsMember()
    {
        BigInteger[] set = [5, 17, 42];
        AssertSatisfied(
            b => b.AssertInSet(b.DeclareWitnessVariable("x"), set, "x"),
            WithSetProducts("x", 42, set, ("x", 42)));
    }


    [TestMethod]
    public void AssertInSetRejectsNonMember()
    {
        BigInteger[] set = [5, 17, 42];
        AssertRejected(
            b => b.AssertInSet(b.DeclareWitnessVariable("x"), set, "x"),
            WithSetProducts("x", 100, set, ("x", 100)));
    }


    [TestMethod]
    public void AssertInSetAcceptsSingleElementSet()
    {
        BigInteger[] set = [99];
        AssertSatisfied(
            b => b.AssertInSet(b.DeclareWitnessVariable("x"), set, "x"),
            ("x", 99));
    }


    [TestMethod]
    public void AssertInSetRejectsEmptySetAtBuild()
    {
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex x = builder.DeclareWitnessVariable("x");
        Assert.ThrowsExactly<ArgumentException>(() => builder.AssertInSet(x, ReadOnlySpan<BigInteger>.Empty, "x"));
    }


    //==== Composite ====

    [TestMethod]
    public void CompositePredicatesComposeOnOneVariable()
    {
        //Prove x is in [0, 127] (7-bit range) AND x is in {5, 17, 42}, with x = 42.
        const int bits = 7;
        BigInteger[] set = [5, 17, 42];
        const long x = 42;

        var inputs = new List<(string, BigInteger)> { ("x", x) };
        inputs.AddRange(BitBindings("range", x, bits));
        inputs.AddRange(SetProductBindings("member", x, set));

        AssertSatisfied(
            b =>
            {
                R1csVariableIndex xv = b.DeclareWitnessVariable("x");
                b.AssertRangeCheck(xv, bits, "range");
                b.AssertInSet(xv, set, "member");
            },
            [.. inputs]);
    }


    //==== Helpers ====

    private static void AssertSatisfied(Action<R1csCircuitBuilder> configure, params (string Name, BigInteger Value)[] inputs)
    {
        var builder = new R1csCircuitBuilder(Curve);
        configure(builder);
        R1csCircuit circuit = builder.Build();

        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(InputsOf(inputs), Pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, Add, Multiply, Pool);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction, "the compiled predicate circuit is satisfied by its witness");
    }


    private static void AssertRejected(Action<R1csCircuitBuilder> configure, params (string Name, BigInteger Value)[] inputs)
    {
        var builder = new R1csCircuitBuilder(Curve);
        configure(builder);
        R1csCircuit circuit = builder.Build();

        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => circuit.Compile(InputsOf(inputs), Pool));
    }


    private static R1csCircuitInputs InputsOf((string Name, BigInteger Value)[] inputs)
    {
        var dictionary = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        foreach((string Name, BigInteger Value) input in inputs)
        {
            dictionary[input.Name] = input.Value;
        }

        return new R1csCircuitInputs(dictionary);
    }


    /// <summary>Combines explicit bindings with the bit decomposition of <paramref name="value"/> under <paramref name="name"/>.</summary>
    private static (string, BigInteger)[] WithBits(string name, long value, int bits, params (string, BigInteger)[] extra)
    {
        var list = new List<(string, BigInteger)>(extra);
        list.AddRange(BitBindings(name, value, bits));
        return [.. list];
    }


    private static IEnumerable<(string, BigInteger)> BitBindings(string name, long value, int bits)
    {
        for(int i = 0; i < bits; i++)
        {
            //Reduce the (possibly negative) value mod r first, then read bit i.
            BigInteger reduced = Reduce(value);
            yield return ($"{name}_bit_{i}", (reduced >> i) & BigInteger.One);
        }
    }


    /// <summary>Combines explicit bindings with the set-membership partial products under <paramref name="name"/>.</summary>
    private static (string, BigInteger)[] WithSetProducts(string name, long value, BigInteger[] set, params (string, BigInteger)[] extra)
    {
        var list = new List<(string, BigInteger)>(extra);
        list.AddRange(SetProductBindings(name, value, set));
        return [.. list];
    }


    private static IEnumerable<(string, BigInteger)> SetProductBindings(string name, long value, BigInteger[] set)
    {
        //{name}_product_k = Π_{j=0}^{k} (value - set[j]) for k = 1 .. set.Length - 2.
        BigInteger accumulator = Reduce(value - set[0]);
        for(int i = 1; i < set.Length - 1; i++)
        {
            accumulator = Reduce(accumulator * Reduce(value - set[i]));
            yield return ($"{name}_product_{i}", accumulator);
        }
    }


    private static BigInteger Inverse(long difference)
    {
        BigInteger reduced = Reduce(difference);
        return BigInteger.ModPow(reduced, Order - 2, Order);
    }


    private static BigInteger Reduce(BigInteger value)
    {
        BigInteger remainder = value % Order;
        return remainder.Sign < 0 ? remainder + Order : remainder;
    }
}
