using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Lookup;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Lookup;

/// <summary>
/// Tests for the LogUp security-level ledger terms, the lookup-argument
/// registry additions, and the column-construction helpers (multiplicity
/// counting and the hard-failing batch inversion).
/// </summary>
[TestClass]
internal sealed class LogUpLedgerAndRegistryTests
{
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    private const int ScalarSize = Scalar.SizeBytes;

    //The BLS12-381 scalar field's conservative size floor used by every ledger
    //term: BitLength(r) − 1.
    private const int Bls12ScalarFloorBits = 254;

    //A production-shaped ledger point: 2^16 rows, one witness column.
    private const int LedgerVariableCount = 16;
    private const int LedgerWitnessColumnCount = 1;

    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void SumcheckTermMatchesHandComputation()
    {
        double bits = WellKnownSecurityLevels.LogUpSumcheckSoundnessBits(Curve, LedgerVariableCount, LedgerWitnessColumnCount);

        //n·(M+3)/r with n = 16, M = 1: weight 64, so floor − 6 bits.
        Assert.AreEqual(Bls12ScalarFloorBits - 6.0, bits, 1e-9, "The sumcheck term must be log2(r) − log2(n·(M+3)).");
    }


    [TestMethod]
    public void FieldTermIsDominatedByTheLogDerivativeIdentity()
    {
        double bits = WellKnownSecurityLevels.LogUpFieldTermBits(Curve, LedgerVariableCount, LedgerWitnessColumnCount);

        //(M+1)·2^n = 2^17 dominates; the kernel/folding addend of n+1 = 17
        //moves the weight imperceptibly, so the term sits just under
        //floor − 17.
        Assert.IsLessThan(Bls12ScalarFloorBits - 17.0, bits, "The field term must charge the (M+1)·2^n identity weight.");
        Assert.IsGreaterThan(Bls12ScalarFloorBits - 17.1, bits, "The kernel and folding events must stay sub-bit at this shape.");
    }


    [TestMethod]
    public void LigeroLedgerChargesTheOpeningUnionBound()
    {
        //The CLI's production Ligero shape: rate 1/16 with its derived 64
        //queries. The LogUp path runs M + 2 = 3 openings and forging any one
        //suffices, so the ledger must report the single-opening figure minus
        //log2(3) — and proximity must still be the bottleneck term.
        const int ProductionInverseRate = 16;
        const int ProductionQueryCount = 64;

        SecurityLevelLedger ledger = WellKnownSecurityLevels.ComputeLogUpOverLigero(
            Curve, LedgerVariableCount, LedgerWitnessColumnCount, ProductionInverseRate, ProductionQueryCount);

        double singleOpeningBits = WellKnownSecurityLevels.LigeroProximitySoundnessBits(
            LedgerVariableCount, ProductionInverseRate, ProductionQueryCount);
        Assert.AreEqual(singleOpeningBits - Math.Log2(3.0), ledger.ProximityBits, 1e-9, "The proximity term must charge the union bound over the three openings.");
        Assert.AreEqual(ledger.ProximityBits, ledger.EffectiveBits, 1e-9, "Proximity must be the bottleneck term at the production shape.");
        Assert.AreEqual(HidingKind.None, ledger.Hiding, "Unmasked LogUp openings disclose the opened values; the ledger must never claim hiding.");
    }


    [TestMethod]
    public void BaseFoldLedgerComputesAllThreeTerms()
    {
        SecurityLevelLedger ledger = WellKnownSecurityLevels.ComputeLogUpOverBaseFold(
            Curve, LedgerVariableCount, LedgerWitnessColumnCount, WellKnownBaseFoldIoppParameters.ClassicalSecurityDefaultQueryCount);

        Assert.IsGreaterThan(0.0, ledger.ProximityBits);
        Assert.IsGreaterThan(0.0, ledger.SumcheckBits);
        Assert.IsGreaterThan(0.0, ledger.FieldTermBits);
        Assert.AreEqual(CommitmentScheme.BaseFold, ledger.Scheme);
    }


    [TestMethod]
    public void GkrSoundnessTermMatchesHandComputation()
    {
        double bits = WellKnownSecurityLevels.LogUpGkrSoundnessBits(Curve, LedgerVariableCount, LedgerWitnessColumnCount);

        //One witness column adds one selector variable: ν = 17, so the
        //Proposition-1 cascade weight is 17·52/2 = 442.
        Assert.AreEqual(Bls12ScalarFloorBits - Math.Log2(442.0), bits, 1e-9, "The GKR term must be log2(r) − log2(ν·(3ν+1)/2).");
    }


    [TestMethod]
    public void GkrLigeroLedgerChargesTheSmallerOpeningUnionBound()
    {
        //The CLI's production Ligero shape: rate 1/16 with its derived 64
        //queries, matching the plain variant's union-bound test above.
        const int ProductionInverseRate = 16;
        const int ProductionQueryCount = 64;

        SecurityLevelLedger ledger = WellKnownSecurityLevels.ComputeLogUpGkrOverLigero(
            Curve, LedgerVariableCount, LedgerWitnessColumnCount, ProductionInverseRate, ProductionQueryCount);

        //The GKR variant opens M + 1 = 2 columns (no helper), so its union
        //bound costs one bit — half a bit less than the plain variant's
        //three-opening charge.
        double singleOpeningBits = WellKnownSecurityLevels.LigeroProximitySoundnessBits(
            LedgerVariableCount, ProductionInverseRate, ProductionQueryCount);
        Assert.AreEqual(singleOpeningBits - 1.0, ledger.ProximityBits, 1e-9, "The proximity term must charge the union bound over the two openings.");
        Assert.AreEqual(ledger.ProximityBits, ledger.EffectiveBits, 1e-9, "Proximity must be the bottleneck term at the production shape.");
        Assert.AreEqual(HidingKind.None, ledger.Hiding, "Unmasked LogUp-GKR openings disclose the opened values.");
    }


    [TestMethod]
    public void LogUpIsRegisteredInBothIdentifierSurfaces()
    {
        Assert.AreEqual(6, LookupArgument.LogUp.Code, "LogUp takes the next predefined registry code.");
        Assert.Contains(LookupArgument.LogUp, LookupArgument.LookupArguments);
        Assert.AreEqual(nameof(LookupArgument.LogUp), LookupArgumentNames.GetName(LookupArgument.LogUp));
        Assert.IsTrue(WellKnownLookupArguments.IsLogUp(WellKnownLookupArguments.LogUp));
        Assert.IsFalse(WellKnownLookupArguments.IsSublinear(WellKnownLookupArguments.LogUp), "LogUp is linear in the table size.");
    }


    [TestMethod]
    public void MultiplicityCountsAggregateOnFirstDuplicate()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //Two variables → four rows. Table = (v0, v0, v1, v2); the witness hits
        //v0 three times and v1 once, so the counts must land as (3, 0, 1, 0):
        //all v0 weight on its first position, zero on the duplicate.
        const int VariableCount = 2;
        const int Size = 1 << VariableCount;
        using IMemoryOwner<byte> materialOwner = pool.Rent(2 * Size * ScalarSize);
        Span<byte> material = materialOwner.Memory.Span[..(2 * Size * ScalarSize)];
        Span<byte> table = material[..(Size * ScalarSize)];
        Span<byte> witness = material.Slice(Size * ScalarSize, Size * ScalarSize);
        DeterministicScalarFill.FillCanonical(table, salt: 907, Reduce, Curve);
        table[..ScalarSize].CopyTo(table.Slice(ScalarSize, ScalarSize));

        table[..ScalarSize].CopyTo(witness[..ScalarSize]);
        table[..ScalarSize].CopyTo(witness.Slice(ScalarSize, ScalarSize));
        table[..ScalarSize].CopyTo(witness.Slice(2 * ScalarSize, ScalarSize));
        table.Slice(2 * ScalarSize, ScalarSize).CopyTo(witness.Slice(3 * ScalarSize, ScalarSize));

        using IMemoryOwner<byte> multiplicityOwner = LogUpColumns.BuildMultiplicities(table, witness, VariableCount, witnessColumnCount: 1, pool);
        ReadOnlySpan<byte> multiplicities = multiplicityOwner.Memory.Span[..(Size * ScalarSize)];

        Assert.AreEqual(3, multiplicities[(1 * ScalarSize) - 1], "Three hits on the duplicated value aggregate on its first table position.");
        Assert.AreEqual(0, multiplicities[(2 * ScalarSize) - 1], "The duplicate's second position carries zero weight.");
        Assert.AreEqual(1, multiplicities[(3 * ScalarSize) - 1], "The singly-hit value counts once.");
        Assert.AreEqual(0, multiplicities[(4 * ScalarSize) - 1], "An unreferenced table value counts zero.");
    }


    [TestMethod]
    public void BatchInversionInvertsEveryElement()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //Five elements exercises the forward/backward passes past the
        //endpoints.
        const int Count = 5;
        using IMemoryOwner<byte> elementsOwner = pool.Rent(Count * ScalarSize);
        Span<byte> elements = elementsOwner.Memory.Span[..(Count * ScalarSize)];
        DeterministicScalarFill.FillCanonical(elements, salt: 911, Reduce, Curve);
        using IMemoryOwner<byte> originalsOwner = pool.Rent(Count * ScalarSize);
        Span<byte> originals = originalsOwner.Memory.Span[..(Count * ScalarSize)];
        elements.CopyTo(originals);

        LogUpColumns.InvertInPlace(elements, Count, Multiply, Invert, Curve, pool);

        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> one = stackalloc byte[ScalarSize];
        one[ScalarSize - 1] = 1;
        for(int i = 0; i < Count; i++)
        {
            Multiply(originals.Slice(i * ScalarSize, ScalarSize), elements.Slice(i * ScalarSize, ScalarSize), product, Curve);
            Assert.IsTrue(product.SequenceEqual(one), $"Element {i} times its batch inverse must be one.");
        }
    }


    [TestMethod]
    public void BatchInversionRejectsAZeroElement()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        const int Count = 3;
        using IMemoryOwner<byte> elementsOwner = pool.Rent(Count * ScalarSize);
        Memory<byte> elementsMemory = elementsOwner.Memory[..(Count * ScalarSize)];
        DeterministicScalarFill.FillCanonical(elementsMemory.Span, salt: 919, Reduce, Curve);
        elementsMemory.Span.Slice(ScalarSize, ScalarSize).Clear();

        Assert.ThrowsExactly<ArgumentException>(
            () => LogUpColumns.InvertInPlace(elementsMemory.Span, Count, Multiply, Invert, Curve, pool),
            "A zero element must abort the batch loudly, never map to zero silently.");
    }
}
