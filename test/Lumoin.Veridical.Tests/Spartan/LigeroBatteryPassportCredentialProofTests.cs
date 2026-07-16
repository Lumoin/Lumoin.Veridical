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
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int TestQueryCount = 8;
    private const string TranscriptDomain = "veridical.supplychain.batterypassport.ligero.test.v1";

    private const string Recycled = "recycled_content";
    private const string Carbon = "carbon_footprint";
    private const string RecycledMinimum = "recycled_minimum";
    private const string CarbonMaximum = "carbon_maximum";
    private const decimal RecycledThreshold = 30.0m;
    private const decimal CarbonCap = 12.50m;

    private static readonly byte[] RandomSeed = System.Text.Encoding.UTF8.GetBytes("veridical.supplychain.batterypassport.rng.v1");
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;
    private static readonly FixedPointDomain RecycledDomain = FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(1), 100.0m);
    private static readonly FixedPointDomain CarbonDomain = FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(2), 100.00m);
    private static readonly FixedPointBound RecycledFloor = FixedPointBound.Constant(RecycledDomain, RecycledThreshold);
    private static readonly FixedPointBound CarbonCeiling = FixedPointBound.Constant(CarbonDomain, CarbonCap);


    [TestMethod]
    public void CompliantBatteryPassportProvesInZeroKnowledge()
    {
        Assert.IsTrue(
            ProveAndVerifyConstantBounds(Measurements(recycledContent: 32.5m, carbonFootprint: 11.20m)),
            "recycled 32.5% ≥ 30.0% and carbon 11.20 ≤ 12.50 must produce a verifying Ligero-backed Spartan proof.");
    }


    [TestMethod]
    public void RecycledContentBelowTheMinimumCannotBeProven()
    {
        Assert.IsFalse(
            ProveAndVerifyConstantBounds(Measurements(recycledContent: 28.0m, carbonFootprint: 11.20m)),
            "recycled 28.0% ≥ 30.0% is false and must not be provable.");
    }


    [TestMethod]
    public void CarbonFootprintAboveTheCapCannotBeProven()
    {
        Assert.IsFalse(
            ProveAndVerifyConstantBounds(Measurements(recycledContent: 32.5m, carbonFootprint: 13.75m)),
            "carbon 13.75 ≤ 12.50 is false and must not be provable.");
    }


    [TestMethod]
    public void BoundaryMeasurementsAtTheLimitsProve()
    {
        Assert.IsTrue(
            ProveAndVerifyConstantBounds(Measurements(recycledContent: 30.0m, carbonFootprint: 12.50m)),
            "the exact threshold and cap both satisfy — each difference is zero, which is in range.");
    }


    [TestMethod]
    public void CompliantBatteryPassportWithPublicInputBoundsProvesInZeroKnowledge()
    {
        Assert.IsTrue(
            ProveAndVerifyPublicBounds(Measurements(recycledContent: 32.5m, carbonFootprint: 11.20m)),
            "the same compliant measurements prove when the regulatory bounds are public inputs.");
    }


    [TestMethod]
    public void PublicInputBoundsRejectANonCompliantMeasurement()
    {
        Assert.IsFalse(
            ProveAndVerifyPublicBounds(Measurements(recycledContent: 28.0m, carbonFootprint: 11.20m)),
            "a false claim is unprovable whether the bound is a constant or a public input.");
    }


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
        using LigeroSpartanProof proof = prover.ProveLigero(
            instance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, pool);

        MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[^1] ^= 0x01;

        using var verifier = new SpartanVerifier(new SpartanVerifyingKey(BuildProvider()));
        (RawR1csInstance Instance, RawR1csWitness Witness) verifierCompiled = circuit.Compile(inputs, pool);
        using RawR1csInstance verifierInstance = verifierCompiled.Instance;
        using RawR1csWitness spareWitness = verifierCompiled.Witness;
        using FiatShamirTranscript verifierTranscript = FreshTranscript();

        bool verified = verifier.VerifyLigero(proof, verifierInstance, verifierTranscript, Add, Multiply, Subtract, Reduce, Hash, Squeeze, pool);
        Assert.IsFalse(verified, "A tampered battery-passport proof must be rejected.");
    }


    private static bool ProveAndVerifyConstantBounds(SupplyChainMeasuredValue values)
    {
        (R1csCircuit circuit, SupplyChainClaim[] claims) = BuildConstantBoundCircuit();

        return RunLigeroProveVerify(circuit, () => BuildConstantBoundInputs(circuit, claims, values));
    }


    private static bool ProveAndVerifyPublicBounds(SupplyChainMeasuredValue values)
    {
        (R1csCircuit circuit, SupplyChainClaim[] claims) = BuildPublicBoundCircuit();

        return RunLigeroProveVerify(circuit, () => BuildPublicBoundInputs(circuit, claims, values));
    }


    //Compiles, proves and verifies over Spartan-over-Ligero; returns whether an
    //honest proof verified. A false statement (rejected at binding/compile time)
    //returns false. The inputs are built lazily so a binding-time rejection is
    //caught here too.
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
        using LigeroSpartanProof proof = prover.ProveLigero(
            instance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, pool);

        using var verifier = new SpartanVerifier(new SpartanVerifyingKey(BuildProvider()));
        (RawR1csInstance Instance, RawR1csWitness Witness) verifierCompiled = circuit.Compile(inputs, pool);
        using RawR1csInstance verifierInstance = verifierCompiled.Instance;
        using RawR1csWitness spareWitness = verifierCompiled.Witness;
        using FiatShamirTranscript verifierTranscript = FreshTranscript();

        return verifier.VerifyLigero(proof, verifierInstance, verifierTranscript, Add, Multiply, Subtract, Reduce, Hash, Squeeze, pool);
    }


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


    private static R1csCircuitInputs BuildConstantBoundInputs(R1csCircuit circuit, SupplyChainClaim[] claims, SupplyChainMeasuredValue values)
    {
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        R1csSupplyChainWitness.AddBatteryPassportBindings(bindings, claims, values, Curve);
        R1csPredicateWitness.AddPowerOfTwoPaddingBindings(bindings, circuit);

        return new R1csCircuitInputs(bindings);
    }


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


    private static SupplyChainMeasuredValue Measurements(decimal recycledContent, decimal carbonFootprint) => name => name switch
    {
        Recycled => recycledContent,
        Carbon => carbonFootprint,
        _ => throw new KeyNotFoundException($"No measurement for claim '{name}'."),
    };


    [SuppressMessage("Reliability", "CA2000", Justification = "The Ligero provider holds no disposable key; the Spartan key that consumes it disposes it.")]
    private static PolynomialCommitmentProvider BuildProvider()
    {
        return LigeroPolynomialCommitmentScheme.Create(
            Curve, TestQueryCount, Add, Subtract, Multiply, Invert, Reduce, Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3, DigestSizeBytes);
    }


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
