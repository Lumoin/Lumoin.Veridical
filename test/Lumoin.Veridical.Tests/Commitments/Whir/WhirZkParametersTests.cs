using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Whir;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Tests for the zero-knowledge parameter extension (4.2 phase C1): the
/// per-oracle randomness budgets must equal the query counts of the rounds
/// that consume each oracle, the mask spot-check count must carry the
/// schedule's security target plus the mask-oracle union bits, the mask code
/// shapes must follow the smallest-power-of-two domain rule, and every floor
/// and fit guard must reject loudly — an admitted shape that silently
/// degraded hiding would be a privacy defect, not a soundness one.
/// </summary>
[TestClass]
internal sealed class WhirZkParametersTests
{
    /// <summary>
    /// The reference shape's variable count: a 2^8-coefficient message with
    /// the default k = 4 gives two iterations, so both the intermediate and
    /// final budget expressions are exercised.
    /// </summary>
    private const int VariableCount = 8;

    /// <summary>The reference shape's initial inverse-rate exponent: rate 1/4.</summary>
    private const int InitialRateLog2 = 2;

    /// <summary>
    /// The reference per-round target: the largest whole level the shape can
    /// place on distinct query cosets, matching the IOPP tests' fast shape.
    /// </summary>
    private const int SecurityLevelBits = 24;

    /// <summary>
    /// The slack-violation shape's initial inverse-rate exponent: at rate 1/2
    /// an oracle's spare codeword rows equal its message rows, so a query
    /// count above that slack still fits the query domain but cannot hide.
    /// </summary>
    private const int TightRateLog2 = 1;

    /// <summary>
    /// The slack-violation shape's per-round target: prices 20 queries on the
    /// initial oracle at rate 1/2 — above its 16 spare rows, below its 32
    /// query cosets, so the plain schedule admits the shape and only the
    /// hiding extension must refuse it.
    /// </summary>
    private const int TightSecurityLevelBits = 8;

    /// <summary>
    /// A mask rate pushing the sumcheck mask domain past the BLS12-381
    /// two-adicity of 32: the domain exponent lands at roughly the rate plus
    /// five bits for the mask coefficients.
    /// </summary>
    private const int OversizedMaskRateLog2 = 30;

    /// <summary>The BLS12-381 scalar backend bundle.</summary>
    private static ScalarArithmeticBackend Bls { get; } = TestScalarBackends.Bls12Curve381;


    [TestMethod]
    public void RandomnessBudgetsEqualTheConsumingRoundsQueryCounts()
    {
        WhirParameterSchedule schedule = ReferenceSchedule();

        WhirZkParameters zk = WhirZkParameters.Create(schedule);

        Assert.HasCount(schedule.IterationCount, zk.OracleRandomnessCounts, "One budget per committed oracle.");
        for(int oracle = 0; oracle < schedule.IterationCount; oracle++)
        {
            Assert.AreEqual(
                schedule.Rounds[oracle].QueryCount,
                zk.OracleRandomnessCounts[oracle],
                $"Oracle {oracle}'s budget must equal the query count opened against it.");
            Assert.AreEqual(
                schedule.Rounds[oracle].QueryCount << schedule.FoldingParameter,
                zk.OracleRandomnessElementCount(oracle),
                $"Oracle {oracle}'s element count must be the per-limb budget across every limb.");
        }
    }


    [TestMethod]
    public void MaskQueryCountCarriesTheUnionBoundOverAllMaskOracles()
    {
        WhirParameterSchedule schedule = ReferenceSchedule();

        WhirZkParameters zk = WhirZkParameters.Create(schedule);

        int expectedUnion = BitOperations.Log2(BitOperations.RoundUpToPowerOf2((uint)((2 * schedule.IterationCount) + 2)));
        int expectedQueries = WellKnownWhirParameters.ComputeQueryCount(
            schedule.SecurityLevelBits + expectedUnion,
            WhirZkParameters.DefaultMaskRateLog2,
            schedule.Regime,
            schedule.JohnsonProximityParameter);

        Assert.AreEqual(expectedUnion, zk.MaskOracleUnionLog2, "The union bits must cover 2M + 2 mask oracles.");
        Assert.AreEqual(expectedQueries, zk.MaskQueryCount, "The mask spot checks must price the full target plus the union bits.");
    }


    [TestMethod]
    public void MaskCodeShapesFollowTheSmallestPowerOfTwoDomainRule()
    {
        WhirParameterSchedule schedule = ReferenceSchedule();

        WhirZkParameters zk = WhirZkParameters.Create(schedule);

        int sumcheckCoefficients = WhirZkParameters.DefaultMaskMessageLength + zk.MaskQueryCount;
        int expectedSumcheckDomainLog2 =
            BitOperations.Log2(BitOperations.RoundUpToPowerOf2((uint)sumcheckCoefficients)) + WhirZkParameters.DefaultMaskRateLog2;

        Assert.AreEqual(WhirZkParameters.DefaultMaskMessageLength, zk.SumcheckMaskShape.MessageLength, "The sumcheck mask message length is ℓ_zk.");
        Assert.AreEqual(zk.MaskQueryCount, zk.SumcheckMaskShape.RandomnessLength, "The mask spot-check count doubles as the mask randomness length.");
        Assert.AreEqual(expectedSumcheckDomainLog2, zk.SumcheckMaskShape.DomainSizeLog2, "The mask domain is the smallest power of two at the mask rate.");

        Assert.HasCount(schedule.IterationCount - 1, zk.SwitchMaskShapes, "One code-switch mask per main-loop iteration.");
        for(int iteration = 1; iteration < schedule.IterationCount; iteration++)
        {
            Assert.AreEqual(
                zk.OracleRandomnessCounts[iteration - 1] + WhirZkParameters.OutOfDomainSamplesPerIteration,
                zk.SwitchMaskShapes[iteration - 1].MessageLength,
                $"Switch mask {iteration - 1} commits the consumed oracle's folded randomness plus the out-of-domain pad.");
        }
    }


    [TestMethod]
    public void MaskMessageLengthUnderTheLemmaFloorIsRejected()
    {
        WhirParameterSchedule schedule = ReferenceSchedule();

        Assert.Throws<ArgumentOutOfRangeException>(
            () => WhirZkParameters.Create(schedule, maskMessageLength: WhirZkParameters.MinimumMaskMessageLength - 1));
    }


    [TestMethod]
    public void RateOneMaskCodeIsRejected()
    {
        WhirParameterSchedule schedule = ReferenceSchedule();

        Assert.Throws<ArgumentOutOfRangeException>(() => WhirZkParameters.Create(schedule, maskRateLog2: 0));
    }


    [TestMethod]
    public void RandomnessBudgetExceedingTheCodewordSlackIsRejected()
    {
        //The plain schedule admits this shape — 20 queries fit the 2^5 query
        //cosets — but the initial oracle's limbs have only 16 spare
        //coefficient rows, so the hiding extension must refuse it.
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Bls.Curve,
            VariableCount,
            TightRateLog2,
            securityLevelBits: TightSecurityLevelBits);

        Assert.Throws<ArgumentException>(() => WhirZkParameters.Create(schedule));
    }


    [TestMethod]
    public void MaskDomainPastTheTwoAdicityIsRejected()
    {
        WhirParameterSchedule schedule = ReferenceSchedule();

        Assert.Throws<ArgumentException>(() => WhirZkParameters.Create(schedule, maskRateLog2: OversizedMaskRateLog2));
    }


    /// <summary>
    /// The reference schedule the derivation tests extend.
    /// </summary>
    private static WhirParameterSchedule ReferenceSchedule()
    {
        return WhirParameterSchedule.Create(
            Bls.Curve,
            VariableCount,
            InitialRateLog2,
            securityLevelBits: SecurityLevelBits);
    }
}
