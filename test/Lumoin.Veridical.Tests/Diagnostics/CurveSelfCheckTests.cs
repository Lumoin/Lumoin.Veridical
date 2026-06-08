using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Diagnostics;
using Lumoin.Veridical.Tests.Algebraic;

namespace Lumoin.Veridical.Tests.Diagnostics;

/// <summary>
/// Behavioural tests for the BLS12-381 <see cref="CurveSelfCheck"/>
/// aggregator. Verify that each witness reports the expected outcome on
/// the declared-canonical constants and on a synthetic failure backend,
/// and that the witness names are stable across runs.
/// </summary>
/// <remarks>
/// <para>
/// The witness-name constants are part of the public surface — tests in
/// other projects and external tooling key on them — so a renaming change
/// must be deliberate. <see cref="WitnessNamesAreStable"/> pins them.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CurveSelfCheckTests
{
    [TestMethod]
    public void WithoutSubgroupDelegateAllStructuralWitnessesPass()
    {
        CurveSelfCheckResult result = CurveSelfCheck.RunBls12Curve381();

        Assert.IsTrue(result.AllPassed, "AllPassed should be true: every structural witness should accept the declared canonical constants.");
        Assert.HasCount(4, result.Witnesses);

        AssertWitnessOutcome(result, CurveSelfCheck.BaseFieldPrimalityWitnessName, CurveSelfCheckOutcome.Passed);
        AssertWitnessOutcome(result, CurveSelfCheck.ScalarFieldPrimalityWitnessName, CurveSelfCheckOutcome.Passed);
        AssertWitnessOutcome(result, CurveSelfCheck.GeneratorWeierstrassWitnessName, CurveSelfCheckOutcome.Passed);
        AssertWitnessOutcome(result, CurveSelfCheck.GeneratorSubgroupWitnessName, CurveSelfCheckOutcome.Skipped);
    }


    [TestMethod]
    public void WithReferenceSubgroupDelegateAllFourWitnessesPass()
    {
        G1IsInPrimeOrderSubgroupDelegate referenceSubgroupCheck =
            Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();

        CurveSelfCheckResult result = CurveSelfCheck.RunBls12Curve381(referenceSubgroupCheck);

        Assert.IsTrue(result.AllPassed, "AllPassed should be true with a correct subgroup-check delegate.");
        AssertWitnessOutcome(result, CurveSelfCheck.GeneratorSubgroupWitnessName, CurveSelfCheckOutcome.Passed);
    }


    [TestMethod]
    public void WithFaultySubgroupDelegateSubgroupWitnessFails()
    {
        // The witness is meant to surface a backend that rejects the canonical
        // generator. Stub a delegate that always returns false to confirm the
        // aggregator routes a rejection into a Failed outcome rather than
        // throwing or swallowing.
        bool AlwaysReject(System.ReadOnlySpan<byte> point, Lumoin.Veridical.Core.CurveParameterSet curve) => false;

        CurveSelfCheckResult result = CurveSelfCheck.RunBls12Curve381(AlwaysReject);

        Assert.IsFalse(result.AllPassed, "AllPassed should be false when a witness fails.");
        AssertWitnessOutcome(result, CurveSelfCheck.GeneratorSubgroupWitnessName, CurveSelfCheckOutcome.Failed);
    }


    [TestMethod]
    public void WitnessNamesAreStable()
    {
        // The witness names are public API — external tooling keys on them.
        // Compare the literals against the names embedded in a runtime
        // result so the test actually pins runtime behaviour rather than a
        // pair of compile-time-inlined constants. A rename of the
        // implementation's witness name (without updating the const) would
        // surface here as a mismatch.
        CurveSelfCheckResult result = CurveSelfCheck.RunBls12Curve381();

        Assert.AreEqual("BaseFieldPrime.IsLikelyPrime", result.Find(CurveSelfCheck.BaseFieldPrimalityWitnessName)?.Name);
        Assert.AreEqual("ScalarFieldPrime.IsLikelyPrime", result.Find(CurveSelfCheck.ScalarFieldPrimalityWitnessName)?.Name);
        Assert.AreEqual("G1Generator.SatisfiesShortWeierstrass", result.Find(CurveSelfCheck.GeneratorWeierstrassWitnessName)?.Name);
        Assert.AreEqual("G1Generator.IsInPrimeOrderSubgroup", result.Find(CurveSelfCheck.GeneratorSubgroupWitnessName)?.Name);
    }


    [TestMethod]
    public void FindReturnsNullForUnknownWitnessName()
    {
        CurveSelfCheckResult result = CurveSelfCheck.RunBls12Curve381();

        Assert.IsNull(result.Find("Nonexistent.Witness"), "Find should return null for a name not in the result.");
    }


    private static void AssertWitnessOutcome(
        CurveSelfCheckResult result,
        string witnessName,
        CurveSelfCheckOutcome expected)
    {
        CurveSelfCheckWitness? witness = result.Find(witnessName);
        Assert.IsNotNull(witness, $"Witness '{witnessName}' was not present in the result.");
        Assert.AreEqual(
            expected,
            witness.Outcome,
            $"Witness '{witnessName}' had outcome {witness.Outcome}; expected {expected}. Message: {witness.Message}");
    }
}