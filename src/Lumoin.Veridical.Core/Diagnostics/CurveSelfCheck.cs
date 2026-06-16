using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Aggregates the structural-invariant witnesses a caller can run against
/// a curve's declared canonical constants. Surfaces transcription errors
/// fast and with clear cause.
/// </summary>
/// <remarks>
/// <para>
/// Every BLS12-381 deployment depends on the same handful of canonical
/// constants — base field prime, scalar field order, generator coordinates,
/// curve parameter <c>b</c>. A typo in any one of them silently breaks
/// dozens of downstream algebraic invariants and surfaces only as a
/// hard-to-diagnose decode or arithmetic failure many layers away. The
/// self-check runs four independent witnesses against those constants:
/// </para>
/// <list type="number">
///   <item><description><c>BaseFieldPrime.IsLikelyPrime</c> — Miller-Rabin against the declared base field prime.</description></item>
///   <item><description><c>ScalarFieldPrime.IsLikelyPrime</c> — Miller-Rabin against the declared scalar field order.</description></item>
///   <item><description><c>G1Generator.SatisfiesShortWeierstrass</c> — the declared generator <c>(x, y)</c> satisfies <c>y^2 ≡ x^3 + 4 (mod p)</c>.</description></item>
///   <item><description><c>G1Generator.IsInPrimeOrderSubgroup</c> — optional witness that consumes a caller-supplied subgroup-check delegate.</description></item>
/// </list>
/// <para>
/// The witnesses take different mathematical routes to the same canonical
/// values, so a single transcription error tends to surface against one
/// witness but not the others. That is the diagnostic signal — a failing
/// witness says "the suspect is this specific constant" rather than
/// "decode failed five layers later for an unrelated-looking reason".
/// </para>
/// <para>
/// The aggregator is a read-only verb: it does not mutate library state.
/// Failures surface in <see cref="CurveSelfCheckWitness.Message"/>, never
/// as exceptions, so a caller can present every witness's verdict to a
/// human reviewer in one pass.
/// </para>
/// </remarks>
public static class CurveSelfCheck
{
    /// <summary>Stable identifier for the base field primality witness.</summary>
    public const string BaseFieldPrimalityWitnessName = "BaseFieldPrime.IsLikelyPrime";

    /// <summary>Stable identifier for the scalar field primality witness.</summary>
    public const string ScalarFieldPrimalityWitnessName = "ScalarFieldPrime.IsLikelyPrime";

    /// <summary>Stable identifier for the generator-on-curve witness.</summary>
    public const string GeneratorWeierstrassWitnessName = "G1Generator.SatisfiesShortWeierstrass";

    /// <summary>Stable identifier for the generator-subgroup-membership witness.</summary>
    public const string GeneratorSubgroupWitnessName = "G1Generator.IsInPrimeOrderSubgroup";


    // Canonical BLS12-381 constants per RFC 9380 §4.2.1 and EIP-2537. These
    // are the values every witness is asserting against; a typo here would
    // self-defeat the self-check, so the literals are duplicated from the
    // reference backend on purpose to keep this surface independent of any
    // single backend's transcription.
    private const string BaseFieldPrimeHex =
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    private const string ScalarFieldOrderHex =
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

    private const string GeneratorXHex =
        "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

    private const string GeneratorYHex =
        "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";


    private static readonly BigInteger Bls12Curve381BaseFieldPrime = BigInteger.Parse(
        BaseFieldPrimeHex,
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    private static readonly BigInteger Bls12Curve381ScalarFieldOrder = BigInteger.Parse(
        ScalarFieldOrderHex,
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    private static readonly BigInteger Bls12Curve381GeneratorX = BigInteger.Parse(
        GeneratorXHex,
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    private static readonly BigInteger Bls12Curve381GeneratorY = BigInteger.Parse(
        GeneratorYHex,
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    /// <summary>
    /// Runs the BLS12-381 canonical-constant witnesses and returns the
    /// aggregated outcome.
    /// </summary>
    /// <param name="isInPrimeOrderSubgroup">An optional subgroup-check delegate from a backend. When supplied, the declared generator is checked for prime-order subgroup membership through this delegate. When omitted, the subgroup witness is reported as <see cref="CurveSelfCheckOutcome.Skipped"/>.</param>
    /// <param name="pool">An optional pool from which to rent the generator buffer for the subgroup check. Defaults to <see cref="BaseMemoryPool.Shared"/>.</param>
    /// <returns>The aggregated result with one entry per witness, in declaration order.</returns>
    public static CurveSelfCheckResult RunBls12Curve381(
        G1IsInPrimeOrderSubgroupDelegate? isInPrimeOrderSubgroup = null,
        BaseMemoryPool? pool = null)
    {
        var witnesses = new List<CurveSelfCheckWitness>(4)
        {
            EvaluatePrimality(BaseFieldPrimalityWitnessName, Bls12Curve381BaseFieldPrime, "base field prime p"),
            EvaluatePrimality(ScalarFieldPrimalityWitnessName, Bls12Curve381ScalarFieldOrder, "scalar field order r"),
            EvaluateWeierstrass(),
            EvaluateSubgroup(isInPrimeOrderSubgroup, pool ?? BaseMemoryPool.Shared)
        };

        return new CurveSelfCheckResult(witnesses);
    }


    private static CurveSelfCheckWitness EvaluatePrimality(string witnessName, BigInteger value, string roleDescription)
    {
        bool passed = PrimalityDiagnostics.IsLikelyPrime(value);

        return passed
            ? new CurveSelfCheckWitness(
                witnessName,
                CurveSelfCheckOutcome.Passed,
                $"Miller-Rabin accepted the declared {roleDescription} as prime.")
            : new CurveSelfCheckWitness(
                witnessName,
                CurveSelfCheckOutcome.Failed,
                $"Miller-Rabin found a witness proving the declared {roleDescription} composite. Likely cause: a typo in the constant.");
    }


    private static CurveSelfCheckWitness EvaluateWeierstrass()
    {
        bool passed = WeierstrassDiagnostics.SatisfiesShortWeierstrass(
            Bls12Curve381GeneratorX,
            Bls12Curve381GeneratorY,
            a: BigInteger.Zero,
            b: new BigInteger(4),
            p: Bls12Curve381BaseFieldPrime);

        return passed
            ? new CurveSelfCheckWitness(
                GeneratorWeierstrassWitnessName,
                CurveSelfCheckOutcome.Passed,
                "Declared generator coordinates satisfy y^2 ≡ x^3 + 4 (mod p).")
            : new CurveSelfCheckWitness(
                GeneratorWeierstrassWitnessName,
                CurveSelfCheckOutcome.Failed,
                "Declared generator coordinates do not satisfy y^2 ≡ x^3 + 4 (mod p). Likely cause: a typo in x_gen, y_gen, or p.");
    }


    private static CurveSelfCheckWitness EvaluateSubgroup(
        G1IsInPrimeOrderSubgroupDelegate? isInPrimeOrderSubgroup,
        BaseMemoryPool pool)
    {
        if(isInPrimeOrderSubgroup is null)
        {
            return new CurveSelfCheckWitness(
                GeneratorSubgroupWitnessName,
                CurveSelfCheckOutcome.Skipped,
                "No subgroup-check delegate was supplied. Compose a backend and pass its G1IsInPrimeOrderSubgroupDelegate to verify the declared generator lies in the prime-order subgroup.");
        }

        using G1Point generator = G1Point.Generator(CurveParameterSet.Bls12Curve381, pool);
        bool passed = isInPrimeOrderSubgroup(generator.AsReadOnlySpan(), CurveParameterSet.Bls12Curve381);

        return passed
            ? new CurveSelfCheckWitness(
                GeneratorSubgroupWitnessName,
                CurveSelfCheckOutcome.Passed,
                "Backend's subgroup-check delegate accepted the declared generator as a prime-order element.")
            : new CurveSelfCheckWitness(
                GeneratorSubgroupWitnessName,
                CurveSelfCheckOutcome.Failed,
                "Backend's subgroup-check delegate rejected the declared generator. Likely cause: the generator bytes carry a typo, or the backend's cofactor / subgroup logic is wrong.");
    }
}


/// <summary>
/// Outcome of a single self-check witness.
/// </summary>
public enum CurveSelfCheckOutcome
{
    /// <summary>The witness was evaluated and accepted the declared constants.</summary>
    Passed,

    /// <summary>The witness was evaluated and rejected the declared constants. The <see cref="CurveSelfCheckWitness.Message"/> names a likely cause.</summary>
    Failed,

    /// <summary>The witness could not be evaluated because a required input was not supplied. Not a failure of the constants themselves.</summary>
    Skipped
}


/// <summary>
/// A single self-check witness result.
/// </summary>
/// <param name="Name">Stable identifier from the witness-name constants on <see cref="CurveSelfCheck"/>. Tests and tooling key on this string.</param>
/// <param name="Outcome">The witness outcome.</param>
/// <param name="Message">A human-readable note on what the witness checked and (on failure) the most likely cause.</param>
public sealed record CurveSelfCheckWitness(string Name, CurveSelfCheckOutcome Outcome, string Message);


/// <summary>
/// Aggregate result of a curve self-check run. Carries one
/// <see cref="CurveSelfCheckWitness"/> per witness, in declaration order.
/// </summary>
/// <param name="Witnesses">The witness results.</param>
public sealed record CurveSelfCheckResult(IReadOnlyList<CurveSelfCheckWitness> Witnesses)
{
    /// <summary>
    /// True when no witness reported <see cref="CurveSelfCheckOutcome.Failed"/>.
    /// A <see cref="CurveSelfCheckOutcome.Skipped"/> witness counts as
    /// "did not fail"; the overall outcome reads as "no failure observed".
    /// </summary>
    public bool AllPassed
    {
        get
        {
            for(int i = 0; i < Witnesses.Count; i++)
            {
                if(Witnesses[i].Outcome == CurveSelfCheckOutcome.Failed)
                {
                    return false;
                }
            }


            return true;
        }
    }


    /// <summary>
    /// Returns the named witness, or <see langword="null"/> when none is
    /// registered under that name. Use the witness-name constants on
    /// <see cref="CurveSelfCheck"/> as the lookup key.
    /// </summary>
    /// <param name="witnessName">The stable witness identifier to look up.</param>
    public CurveSelfCheckWitness? Find(string witnessName)
    {
        for(int i = 0; i < Witnesses.Count; i++)
        {
            if(Witnesses[i].Name == witnessName)
            {
                return Witnesses[i];
            }
        }


        return null;
    }
}