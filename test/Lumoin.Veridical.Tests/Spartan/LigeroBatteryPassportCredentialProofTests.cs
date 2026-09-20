using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// End-to-end gate for the supply-chain predicates: a battery-passport bundle —
/// recycled content at or above a regulatory minimum and carbon footprint at or
/// below a cap — is proven in zero knowledge over the Ligero polynomial
/// commitment (Spartan-over-Ligero) and verified. The measured quantities stay
/// private (witness variables). The regulatory bounds are exercised both baked
/// into the circuit as constants (no public inputs) and carried as public inputs
/// the verifier supplies.
/// </summary>
/// <remarks>
/// <para>
/// This exercises the real consumption path — build a bundle circuit, supply raw
/// decimal measurements through a callback that the witness helper encodes at each
/// claim's fixed-point scale, compile to R1CS, prove and verify — over the same
/// backends as the age-threshold gate.
/// </para>
/// <para>
/// Scope boundary: the proof binds the predicate over a <em>supplied</em>
/// measurement; it does not yet tie that in-circuit measurement to a signed
/// credential or a committed graph. Binding the measured value to its source — an
/// in-circuit Poseidon-Merkle membership or a BBS commitment — is the follow-on
/// work and is deliberately not attempted here.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LigeroBatteryPassportCredentialProofTests
{
    /// <summary>The Fiat–Shamir hash delegate this test's transcripts use, backed by the BLAKE3 reference.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    /// <summary>The Fiat–Shamir squeeze delegate this test's transcripts use, backed by the BLAKE3 reference.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    /// <summary>The BLS12-381 scalar-field canonical-reduction delegate this test proves and verifies over.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    /// <summary>The BLS12-381 scalar-field addition delegate this test proves and verifies over.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    /// <summary>The BLS12-381 scalar-field subtraction delegate this test proves and verifies over.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    /// <summary>The BLS12-381 scalar-field multiplication delegate this test proves and verifies over.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    /// <summary>The BLS12-381 scalar-field inversion delegate this test proves and verifies over.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    /// <summary>The BLS12-381 G1 point-addition delegate this test's commitment scheme uses.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    /// <summary>The BLS12-381 G1 scalar-multiplication delegate this test's commitment scheme uses.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    /// <summary>The BLS12-381 G1 multi-scalar-multiplication delegate this test's commitment scheme uses.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    /// <summary>The multilinear-extension evaluation delegate this test's Spartan prover and verifier use.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    /// <summary>The multilinear-extension folding delegate this test's Spartan prover and verifier use.</summary>
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();
    /// <summary>The Merkle two-to-one hash delegate the Ligero commitment scheme uses, backed by <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The digest width, in bytes, this test's Merkle and transcript hashing use.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    /// <summary>The number of Ligero query columns this test's commitment scheme opens.</summary>
    private const int TestQueryCount = 8;
    /// <summary>The Fiat–Shamir domain-separation label for this test's transcripts.</summary>
    private const string TranscriptDomain = "veridical.supplychain.batterypassport.ligero.test.v1";

    /// <summary>The claim name for the recycled-content-percentage witness variable.</summary>
    private const string Recycled = "recycled_content";
    /// <summary>The claim name for the carbon-footprint witness variable.</summary>
    private const string Carbon = "carbon_footprint";
    /// <summary>The public-input name for the regulatory recycled-content minimum, used by the public-bound circuit.</summary>
    private const string RecycledMinimum = "recycled_minimum";
    /// <summary>The public-input name for the regulatory carbon-footprint cap, used by the public-bound circuit.</summary>
    private const string CarbonMaximum = "carbon_maximum";
    /// <summary>The regulatory minimum recycled-content percentage a compliant battery passport must meet or exceed.</summary>
    private const decimal RecycledThreshold = 30.0m;
    /// <summary>The regulatory carbon-footprint cap a compliant battery passport must not exceed.</summary>
    private const decimal CarbonCap = 12.50m;

    /// <summary>The deterministic seed for this test's prover randomness, so a proof run is reproducible.</summary>
    private static byte[] RandomSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.supplychain.batterypassport.rng.v1");
    /// <summary>The curve this test's circuits, witnesses, and commitment scheme operate over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;
    /// <summary>The fixed-point encoding domain for the recycled-content percentage, one fractional digit wide.</summary>
    private static FixedPointDomain RecycledDomain { get; } = FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(1), 100.0m);
    /// <summary>The fixed-point encoding domain for the carbon-footprint measurement, two fractional digits wide.</summary>
    private static FixedPointDomain CarbonDomain { get; } = FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(2), 100.00m);
    /// <summary>The constant-bound form of the recycled-content minimum, baked into the circuit rather than supplied as a public input.</summary>
    private static FixedPointBound RecycledFloor { get; } = FixedPointBound.Constant(RecycledDomain, RecycledThreshold);
    /// <summary>The constant-bound form of the carbon-footprint cap, baked into the circuit rather than supplied as a public input.</summary>
    private static FixedPointBound CarbonCeiling { get; } = FixedPointBound.Constant(CarbonDomain, CarbonCap);


    /// <summary>Verifies that measurements meeting both the recycled-content minimum and the carbon-footprint cap produce a verifying proof when the bounds are compiled into the circuit as constants.</summary>
    [TestMethod]
    public void CompliantBatteryPassportProvesInZeroKnowledge()
    {
        Assert.IsTrue(
            ProveAndVerifyConstantBounds(Measurements(recycledContent: 32.5m, carbonFootprint: 11.20m)),
            "recycled 32.5% ≥ 30.0% and carbon 11.20 ≤ 12.50 must produce a verifying Ligero-backed Spartan proof.");
    }


    /// <summary>Verifies that a recycled-content measurement below the regulatory minimum cannot produce a verifying proof.</summary>
    [TestMethod]
    public void RecycledContentBelowTheMinimumCannotBeProven()
    {
        Assert.IsFalse(
            ProveAndVerifyConstantBounds(Measurements(recycledContent: 28.0m, carbonFootprint: 11.20m)),
            "recycled 28.0% ≥ 30.0% is false and must not be provable.");
    }


    /// <summary>Verifies that a carbon-footprint measurement above the regulatory cap cannot produce a verifying proof.</summary>
    [TestMethod]
    public void CarbonFootprintAboveTheCapCannotBeProven()
    {
        Assert.IsFalse(
            ProveAndVerifyConstantBounds(Measurements(recycledContent: 32.5m, carbonFootprint: 13.75m)),
            "carbon 13.75 ≤ 12.50 is false and must not be provable.");
    }


    /// <summary>Verifies that measurements exactly at the recycled-content minimum and the carbon-footprint cap still prove, since each bound's difference is zero, which is in range.</summary>
    [TestMethod]
    public void BoundaryMeasurementsAtTheLimitsProve()
    {
        Assert.IsTrue(
            ProveAndVerifyConstantBounds(Measurements(recycledContent: 30.0m, carbonFootprint: 12.50m)),
            "the exact threshold and cap both satisfy — each difference is zero, which is in range.");
    }


    /// <summary>Verifies that the same compliant measurements prove when the regulatory bounds are supplied as public inputs rather than baked into the circuit.</summary>
    [TestMethod]
    public void CompliantBatteryPassportWithPublicInputBoundsProvesInZeroKnowledge()
    {
        Assert.IsTrue(
            ProveAndVerifyPublicBounds(Measurements(recycledContent: 32.5m, carbonFootprint: 11.20m)),
            "the same compliant measurements prove when the regulatory bounds are public inputs.");
    }


    /// <summary>Verifies that a non-compliant measurement is unprovable whether the regulatory bound is a circuit constant or a public input.</summary>
    [TestMethod]
    public void PublicInputBoundsRejectANonCompliantMeasurement()
    {
        Assert.IsFalse(
            ProveAndVerifyPublicBounds(Measurements(recycledContent: 28.0m, carbonFootprint: 11.20m)),
            "a false claim is unprovable whether the bound is a constant or a public input.");
    }


    /// <summary>Verifies that flipping the last proof byte after proving causes verification to fail.</summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "The Spartan prover/verifier own their keys (and the provider) and are disposed via using declarations.")]
    public void TamperedProofIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (R1csCircuit circuit, SupplyChainClaim[] claims) = BuildConstantBoundCircuit();
        R1csCircuitInputs inputs = BuildConstantBoundInputs(circuit, claims, Measurements(recycledContent: 32.5m, carbonFootprint: 11.20m));

        using var prover = new SpartanProver(new SpartanProvingKey(BuildProvider()));
        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(inputs, pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        ScalarRandomDelegate random = new DeterministicScalarRandom(RandomSeed).AsDelegate();
        using CommitmentSpartanProof proof = prover.ProveCommitted(
            instance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, pool);

        MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[^1] ^= 0x01;

        using var verifier = new SpartanVerifier(new SpartanVerifyingKey(BuildProvider()));
        (RawR1csInstance Instance, RawR1csWitness Witness) verifierCompiled = circuit.Compile(inputs, pool);
        using RawR1csInstance verifierInstance = verifierCompiled.Instance;
        using RawR1csWitness spareWitness = verifierCompiled.Witness;
        using FiatShamirTranscript verifierTranscript = FreshTranscript();

        bool verified = verifier.VerifyCommitted(proof, verifierInstance, verifierTranscript, Add, Multiply, Subtract, Reduce, Hash, Squeeze, pool);
        Assert.IsFalse(verified, "A tampered battery-passport proof must be rejected.");
    }


    /// <summary>Builds the constant-bound battery-passport circuit and proves and verifies it over the given measurements.</summary>
    /// <param name="values">The recycled-content and carbon-footprint measurements to prove.</param>
    /// <returns><see langword="true"/> when an honest proof over compliant measurements verified; <see langword="false"/> when the measurements do not satisfy the bounds.</returns>
    private static bool ProveAndVerifyConstantBounds(SupplyChainMeasuredValue values)
    {
        (R1csCircuit circuit, SupplyChainClaim[] claims) = BuildConstantBoundCircuit();

        return RunLigeroProveVerify(circuit, () => BuildConstantBoundInputs(circuit, claims, values));
    }


    /// <summary>Builds the public-bound battery-passport circuit and proves and verifies it over the given measurements.</summary>
    /// <param name="values">The recycled-content and carbon-footprint measurements to prove.</param>
    /// <returns><see langword="true"/> when an honest proof over compliant measurements verified; <see langword="false"/> when the measurements do not satisfy the bounds.</returns>
    private static bool ProveAndVerifyPublicBounds(SupplyChainMeasuredValue values)
    {
        (R1csCircuit circuit, SupplyChainClaim[] claims) = BuildPublicBoundCircuit();

        return RunLigeroProveVerify(circuit, () => BuildPublicBoundInputs(circuit, claims, values));
    }


    /// <summary>
    /// Compiles, proves and verifies over Spartan-over-Ligero. A false statement (rejected at
    /// binding/compile time) returns false. The inputs are built lazily so a binding-time
    /// rejection is caught here too.
    /// </summary>
    /// <param name="circuit">The compiled circuit to prove and verify.</param>
    /// <param name="inputsFactory">Builds the circuit inputs; invoked lazily so a binding rejection is caught here.</param>
    /// <returns><see langword="true"/> when an honest proof verified; <see langword="false"/> when the statement is false.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "Instances, witnesses, prover, verifier and transcripts are disposed via using declarations before the result is returned.")]
    private static bool RunLigeroProveVerify(R1csCircuit circuit, Func<R1csCircuitInputs> inputsFactory)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        R1csCircuitInputs inputs;
        (RawR1csInstance Instance, RawR1csWitness Witness) proverCompiled;
        try
        {
            inputs = inputsFactory();
            proverCompiled = circuit.Compile(inputs, pool);
        }
        catch(R1csCircuitCompilationException)
        {
            //The witness does not satisfy the bundle (a claim is false).
            return false;
        }
        catch(ArgumentException)
        {
            //A measurement did not fit its domain — also an unprovable statement.
            return false;
        }

        using RawR1csInstance instance = proverCompiled.Instance;
        using RawR1csWitness witness = proverCompiled.Witness;

        using var prover = new SpartanProver(new SpartanProvingKey(BuildProvider()));
        using FiatShamirTranscript proverTranscript = FreshTranscript();
        ScalarRandomDelegate random = new DeterministicScalarRandom(RandomSeed).AsDelegate();
        using CommitmentSpartanProof proof = prover.ProveCommitted(
            instance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, pool);

        using var verifier = new SpartanVerifier(new SpartanVerifyingKey(BuildProvider()));
        (RawR1csInstance Instance, RawR1csWitness Witness) verifierCompiled = circuit.Compile(inputs, pool);
        using RawR1csInstance verifierInstance = verifierCompiled.Instance;
        using RawR1csWitness spareWitness = verifierCompiled.Witness;
        using FiatShamirTranscript verifierTranscript = FreshTranscript();

        return verifier.VerifyCommitted(proof, verifierInstance, verifierTranscript, Add, Multiply, Subtract, Reduce, Hash, Squeeze, pool);
    }


    /// <summary>Builds the R1CS circuit that asserts the battery-passport claims with both regulatory bounds compiled in as constants.</summary>
    /// <returns>The compiled circuit and the claims it asserts.</returns>
    private static (R1csCircuit Circuit, SupplyChainClaim[] Claims) BuildConstantBoundCircuit()
    {
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex recycled = builder.DeclareWitnessVariable(Recycled);
        R1csVariableIndex carbon = builder.DeclareWitnessVariable(Carbon);
        SupplyChainClaim[] claims =
        [
            SupplyChainClaim.AtLeast(Recycled, recycled, RecycledFloor),
            SupplyChainClaim.AtMost(Carbon, carbon, CarbonCeiling),
        ];
        builder.AssertBatteryPassport(claims);

        return (builder.With(R1csCircuitTransformations.PowerOfTwoPadding).Build(), claims);
    }


    /// <summary>Builds the witness bindings for the constant-bound circuit from the given measurements.</summary>
    /// <param name="circuit">The compiled constant-bound circuit.</param>
    /// <param name="claims">The claims the circuit asserts.</param>
    /// <param name="values">The recycled-content and carbon-footprint measurements to bind.</param>
    /// <returns>The circuit inputs ready to compile.</returns>
    private static R1csCircuitInputs BuildConstantBoundInputs(R1csCircuit circuit, SupplyChainClaim[] claims, SupplyChainMeasuredValue values)
    {
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        R1csSupplyChainWitness.AddBatteryPassportBindings(bindings, claims, values, Curve);
        R1csPredicateWitness.AddPowerOfTwoPaddingBindings(bindings, circuit);

        return new R1csCircuitInputs(bindings);
    }


    /// <summary>Builds the R1CS circuit that asserts the battery-passport claims with both regulatory bounds supplied as public inputs.</summary>
    /// <returns>The compiled circuit and the claims it asserts.</returns>
    private static (R1csCircuit Circuit, SupplyChainClaim[] Claims) BuildPublicBoundCircuit()
    {
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex recycledMinimum = builder.DeclarePublicInput(RecycledMinimum);
        R1csVariableIndex carbonMaximum = builder.DeclarePublicInput(CarbonMaximum);
        R1csVariableIndex recycled = builder.DeclareWitnessVariable(Recycled);
        R1csVariableIndex carbon = builder.DeclareWitnessVariable(Carbon);
        SupplyChainClaim[] claims =
        [
            SupplyChainClaim.AtLeast(Recycled, recycled, FixedPointBound.PublicInput(RecycledDomain, RecycledThreshold, recycledMinimum)),
            SupplyChainClaim.AtMost(Carbon, carbon, FixedPointBound.PublicInput(CarbonDomain, CarbonCap, carbonMaximum)),
        ];
        builder.AssertBatteryPassport(claims);

        return (builder.With(R1csCircuitTransformations.PowerOfTwoPadding).Build(), claims);
    }


    /// <summary>Builds the witness and public-input bindings for the public-bound circuit from the given measurements and the regulatory constants.</summary>
    /// <param name="circuit">The compiled public-bound circuit.</param>
    /// <param name="claims">The claims the circuit asserts.</param>
    /// <param name="values">The recycled-content and carbon-footprint measurements to bind.</param>
    /// <returns>The circuit inputs ready to compile.</returns>
    private static R1csCircuitInputs BuildPublicBoundInputs(R1csCircuit circuit, SupplyChainClaim[] claims, SupplyChainMeasuredValue values)
    {
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal)
        {
            [RecycledMinimum] = RecycledDomain.Encode(RecycledThreshold),
            [CarbonMaximum] = CarbonDomain.Encode(CarbonCap),
        };
        R1csSupplyChainWitness.AddBatteryPassportBindings(bindings, claims, values, Curve);
        R1csPredicateWitness.AddPowerOfTwoPaddingBindings(bindings, circuit);

        return new R1csCircuitInputs(bindings);
    }


    /// <summary>Creates a measurement lookup that returns the given recycled-content and carbon-footprint values for their respective claim names.</summary>
    /// <param name="recycledContent">The recycled-content percentage to return for the <see cref="Recycled"/> claim.</param>
    /// <param name="carbonFootprint">The carbon-footprint value to return for the <see cref="Carbon"/> claim.</param>
    /// <returns>A delegate mapping a claim name to its measured value.</returns>
    private static SupplyChainMeasuredValue Measurements(decimal recycledContent, decimal carbonFootprint) => name => name switch
    {
        Recycled => recycledContent,
        Carbon => carbonFootprint,
        _ => throw new KeyNotFoundException($"No measurement for claim '{name}'."),
    };


    /// <summary>Builds the Ligero polynomial commitment provider this test's Spartan prover and verifier commit through.</summary>
    /// <returns>A fresh Ligero-backed commitment provider.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "The Ligero provider holds no disposable key; the Spartan key that consumes it disposes it.")]
    private static PolynomialCommitmentProvider BuildProvider()
    {
        return LigeroPolynomialCommitmentScheme.Create(
            Curve, TestQueryCount, Add, Subtract, Multiply, Invert, Reduce, Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3, DigestSizeBytes);
    }


    /// <summary>Creates a fresh Fiat–Shamir transcript for one prove or verify run, seeded with this test's domain label.</summary>
    /// <returns>A newly initialized transcript.</returns>
    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>Computes the BLAKE3 two-to-one Merkle compression of two digests.</summary>
    /// <param name="left">The left digest.</param>
    /// <param name="right">The right digest.</param>
    /// <param name="output">Receives the compressed digest.</param>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
