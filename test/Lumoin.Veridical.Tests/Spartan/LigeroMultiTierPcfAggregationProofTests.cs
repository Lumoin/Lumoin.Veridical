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
/// End-to-end gate for multi-tier product-carbon-footprint (PCF) aggregation by
/// sequential composition: a chain of suppliers each proves its cradle-to-gate
/// footprint over Spartan-over-Ligero, and each verified proof's committed output
/// is carried into the next tier's proof, so a final manufacturer proves its whole
/// rolled-up footprint is at or below a regulatory cap without recursion and
/// without any in-circuit hashing.
/// </summary>
/// <remarks>
/// <para>
/// Every tier is one circuit of the same shape. Its cradle-to-gate footprint
/// <c>pcf</c> is a public output; the verified footprints of its direct suppliers
/// enter as public inputs <c>upstream_j</c>; and the tier's <em>own</em>
/// gate-to-gate emissions <c>direct</c> are a witness. The tier range-checks
/// <c>direct</c> into the field-safe width — so the aggregate cannot fall below its
/// upstream inputs by wrapping the field — constrains the cradle-to-gate identity
/// <c>pcf = Σ upstream_j + direct</c>, and proves <c>pcf ≤ cap</c> with the
/// fixed-point <see cref="R1csCircuitBuilderSupplyChainPredicates.AssertQuantityAtMost"/>
/// predicate, whose own range check pins <c>pcf</c> into the field-safe width.
/// </para>
/// <para>
/// The composition is ordinary orchestration, not an in-circuit verifier: each
/// tier is proven and verified on its own, and the field element the verifier
/// re-checks — the transcript-bound public-input scalar read back from the tier's
/// <see cref="RawR1csInstance"/> — is the tier's committed output. That exact scalar
/// is bound into the next tier as an <c>upstream_j</c> public input. Because one
/// fixed-point scale encodes every tier, the field sum is the decimal roll-up
/// exactly, and no honest total can wrap the field.
/// </para>
/// <para>
/// Disclosure boundary: this composition reveals everything. A tier's
/// <em>total</em> footprint <c>pcf</c> is public (the next tier and the verifier
/// consume it) and every carried <c>upstream_j</c> is public, so the tier's own
/// emissions <c>direct = pcf − Σ upstream_j</c> are publicly derivable too — and a
/// leaf tier's <c>pcf</c> is its own emissions outright. <c>direct</c> is carried
/// as a witness rather than a labelled public field — the seam a later hiding
/// upgrade would protect — but it confers no confidentiality here. What the example
/// demonstrates is a verifiable roll-up and cap compliance across independently
/// verified tiers, not per-tier privacy. A fully hiding carry — one where a tier's
/// own figures are bound to its proof yet never revealed — needs a primitive this
/// stack does not carry (an in-circuit commitment opening, or a scalar-field-matched
/// discrete-log-equality argument) and is deliberately out of scope.
/// </para>
/// <para>
/// Trust boundary: each proof binds only its own public inputs, so the cross-tier
/// link is the orchestrator asserting that the value carried into a parent equals
/// the committed output the child's verifier accepted. The
/// <see cref="UnderReportingUpstreamDivergesFromTheVerifiedChildCommitment"/> case
/// makes that boundary explicit.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LigeroMultiTierPcfAggregationProofTests
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
    private const string TranscriptDomain = "veridical.supplychain.pcfaggregation.ligero.test.v1";

    private const string Pcf = "pcf";
    private const string Direct = "direct";
    private const string DirectDomain = "direct_domain";
    private const string UpstreamPrefix = "upstream_";

    private static readonly byte[] RandomSeed = System.Text.Encoding.UTF8.GetBytes("veridical.supplychain.pcfaggregation.rng.v1");
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;

    //One scale for every tier: kilograms of CO2-equivalent to two decimals. A
    //shared scale is what makes the field sum the decimal roll-up exactly; the
    //inclusive maximum leaves ample headroom for a whole chain's total and sits far
    //below the field-safe width, so no honest sum wraps.
    private static readonly FixedPointDomain PcfDomain = FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(2), 100_000.00m);


    [TestMethod]
    public void MultiTierRollUpVerifiesAndTheAggregateIsUnderTheRegulatoryCap()
    {
        //Tier 1: two raw-material suppliers, each a leaf (no upstream).
        TierProof cathodeMaterial = ProveAndVerifyTier(cap: 40.00m, directEmissions: 18.30m);
        TierProof anodeMaterial = ProveAndVerifyTier(cap: 25.00m, directEmissions: 9.75m);
        Assert.IsTrue(cathodeMaterial.Verified, "the cathode-material supplier's own footprint proof must verify.");
        Assert.IsTrue(anodeMaterial.Verified, "the anode-material supplier's own footprint proof must verify.");

        //The committed output the verifier re-checked is the supplier's declared PCF.
        Assert.AreEqual(PcfDomain.Encode(18.30m), cathodeMaterial.CommittedPcf, "the field element carried forward is the verified cathode-material footprint.");
        Assert.AreEqual(PcfDomain.Encode(9.75m), anodeMaterial.CommittedPcf, "the field element carried forward is the verified anode-material footprint.");

        //Tier 2: a cell maker aggregates the two verified upstream footprints and
        //adds its own assembly emissions.
        TierProof cell = ProveAndVerifyTier(cap: 80.00m, directEmissions: 12.40m, cathodeMaterial.CommittedPcf, anodeMaterial.CommittedPcf);
        Assert.IsTrue(cell.Verified, "the cell maker's aggregated footprint proof must verify.");
        Assert.AreEqual(18.30m + 9.75m + 12.40m, cell.Pcf, "the cell's cradle-to-gate footprint is its suppliers' footprints plus its own emissions.");

        //Tier 3: the pack manufacturer aggregates the verified cell footprint and
        //proves the whole rolled-up total is under the regulatory cap.
        TierProof pack = ProveAndVerifyTier(cap: 120.00m, directEmissions: 7.10m, cell.CommittedPcf);
        Assert.IsTrue(pack.Verified, "the final pack footprint must verify at or below the regulatory cap.");
        Assert.AreEqual(18.30m + 9.75m + 12.40m + 7.10m, pack.Pcf, "the cradle-to-gate total is the sum of every tier's direct emissions.");
    }


    [TestMethod]
    public void AnAggregateAtExactlyTheCapVerifies()
    {
        TierProof supplier = ProveAndVerifyTier(cap: 50.00m, directEmissions: 20.00m);
        Assert.IsTrue(supplier.Verified, "the supplier's own footprint proof must verify.");

        //Upstream 20.00 + own 30.00 = 50.00, exactly the manufacturer's cap.
        TierProof manufacturer = ProveAndVerifyTier(cap: 50.00m, directEmissions: 30.00m, supplier.CommittedPcf);
        Assert.IsTrue(manufacturer.Verified, "a total that equals the cap satisfies the at-most predicate — the difference is zero, which is in range.");
    }


    [TestMethod]
    public void AnAggregateThatExceedsTheRegulatoryCapCannotBeProven()
    {
        TierProof supplier = ProveAndVerifyTier(cap: 100.00m, directEmissions: 60.00m);
        Assert.IsTrue(supplier.Verified, "the supplier's own footprint proof must verify.");

        //Upstream 60.00 + own 20.00 = 80.00, above the manufacturer's cap of 70.00.
        TierProof manufacturer = ProveAndVerifyTier(cap: 70.00m, directEmissions: 20.00m, supplier.CommittedPcf);
        Assert.IsFalse(manufacturer.Verified, "80.00 ≤ 70.00 is false, so the rolled-up total cannot be proven under the cap.");
    }


    [TestMethod]
    public void ATierWhoseOwnFootprintExceedsItsCapCannotBeProven()
    {
        TierProof supplier = ProveAndVerifyTier(cap: 30.00m, directEmissions: 45.00m);
        Assert.IsFalse(supplier.Verified, "45.00 ≤ 30.00 is false, so even a leaf tier cannot prove a footprint above its own cap.");
    }


    [TestMethod]
    public void ATierCannotUnderReportBelowItsUpstreamByWrappingItsOwnEmissions()
    {
        //An upstream supplier footprint of 40.00 carried into the tier. The tier
        //tries to claim a cradle-to-gate footprint of 5.00 — below its own verified
        //input — by binding its own emissions to the field element that makes
        //direct + upstream wrap the scalar field down to encode(5.00). The identity
        //pcf = direct + upstream then holds modulo the field, so only the range check
        //on direct stands between the circuit and this under-report.
        BigInteger upstream = PcfDomain.Encode(40.00m);
        BigInteger claimedPcf = PcfDomain.Encode(5.00m);
        BigInteger order = WellKnownCurves.GetScalarFieldOrder(Curve);
        BigInteger wrappedDirect = ((claimedPcf - upstream) % order + order) % order;

        R1csCircuit circuit = BuildTierCircuit(upstreamCount: 1, cap: 100.00m);
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal)
        {
            [$"{UpstreamPrefix}0"] = upstream,
            [Direct] = wrappedDirect,
        };
        R1csPredicateWitness.AddRangeCheckBits(bindings, DirectDomain, wrappedDirect, PcfDomain.Bits, Curve);
        R1csSupplyChainWitness.AddQuantityAtMostBindings(bindings, Pcf, Pcf, FixedPointBound.Constant(PcfDomain, 100.00m), 5.00m, Curve);
        R1csPredicateWitness.AddPowerOfTwoPaddingBindings(bindings, circuit);

        Assert.ThrowsExactly<R1csCircuitCompilationException>(
            () => circuit.Compile(new R1csCircuitInputs(bindings), BaseMemoryPool.Shared),
            "the own-emissions range check must reject a wrapped 'direct' that would prove a footprint below the tier's verified upstream.");
    }


    [TestMethod]
    public void UnderReportingUpstreamDivergesFromTheVerifiedChildCommitment()
    {
        TierProof supplier = ProveAndVerifyTier(cap: 50.00m, directEmissions: 40.00m);
        Assert.IsTrue(supplier.Verified, "the supplier's own footprint proof must verify.");

        //A downstream tier can produce an internally consistent proof over whatever
        //upstream value it is handed: here it is handed 10.00 rather than the 40.00
        //the supplier actually proved.
        BigInteger understatedUpstream = PcfDomain.Encode(10.00m);
        TierProof manufacturer = ProveAndVerifyTier(cap: 60.00m, directEmissions: 5.00m, understatedUpstream);
        Assert.IsTrue(manufacturer.Verified, "each proof binds only its own public inputs, so a parent proof is internally consistent for any upstream it is given.");

        //Soundness of the chain therefore rests on the orchestrator refusing an
        //upstream value that is not the child's committed output — a check that is a
        //plain field-element comparison, which this understated carry fails.
        Assert.AreNotEqual(supplier.CommittedPcf, understatedUpstream, "carrying anything other than the child's verified committed output is detectable by comparing against that output.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "The Spartan prover/verifier own their keys (and the provider) and are disposed via using declarations.")]
    public void TamperedAggregateProofIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        TierProof supplier = ProveAndVerifyTier(cap: 50.00m, directEmissions: 30.00m);
        Assert.IsTrue(supplier.Verified, "the supplier's own footprint proof must verify.");

        R1csCircuit circuit = BuildTierCircuit(upstreamCount: 1, cap: 60.00m);
        R1csCircuitInputs inputs = BuildTierInputs(circuit, cap: 60.00m, directEmissions: 8.00m, [supplier.CommittedPcf]);

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
        Assert.IsFalse(verified, "A tampered aggregation proof must be rejected.");
    }


    //Proves and verifies one tier over Spartan-over-Ligero and returns its
    //committed output. A false statement (a footprint above the cap, rejected at
    //binding/compile time) returns an unverified result. The carried upstream
    //values are the committed outputs of already-verified child tiers.
    [SuppressMessage("Reliability", "CA2000", Justification = "Instances, witnesses, prover, verifier and transcripts are disposed via using declarations before the result is returned.")]
    private static TierProof ProveAndVerifyTier(decimal cap, decimal directEmissions, params BigInteger[] carriedUpstream)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        R1csCircuit circuit = BuildTierCircuit(carriedUpstream.Length, cap);

        R1csCircuitInputs inputs;
        (RawR1csInstance Instance, RawR1csWitness Witness) proverCompiled;
        try
        {
            inputs = BuildTierInputs(circuit, cap, directEmissions, carriedUpstream);
            proverCompiled = circuit.Compile(inputs, pool);
        }
        catch(R1csCircuitCompilationException)
        {
            //The witness does not satisfy the tier (the footprint is above the cap).
            return TierProof.Unproven;
        }
        catch(ArgumentException)
        {
            //A quantity did not fit its domain — also an unprovable statement.
            return TierProof.Unproven;
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

        bool verified = verifier.VerifyLigero(proof, verifierInstance, verifierTranscript, Add, Multiply, Subtract, Reduce, Hash, Squeeze, pool);
        BigInteger committedPcf = ReadCommittedPcf(verifierInstance);

        return new TierProof(verified, PcfDomain.Scale.Decode(committedPcf), committedPcf);
    }


    //One tier circuit: a public footprint output, one public input per direct
    //supplier, and a private own-emissions witness. It constrains the cradle-to-gate
    //identity pcf = Σ upstream_j + direct, range-checks the private own emissions
    //into the field-safe width (so the total cannot wrap below its upstream inputs),
    //and proves pcf ≤ cap.
    private static R1csCircuit BuildTierCircuit(int upstreamCount, decimal cap)
    {
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex pcf = builder.DeclarePublicInput(Pcf);
        var upstream = new R1csVariableIndex[upstreamCount];
        for(int j = 0; j < upstreamCount; j++)
        {
            upstream[j] = builder.DeclarePublicInput($"{UpstreamPrefix}{j}");
        }

        R1csVariableIndex direct = builder.DeclareWitnessVariable(Direct);
        builder.AssertRangeCheck(direct, PcfDomain.Bits, DirectDomain);

        R1csLinearCombination rollUp = R1csLinearCombination.From(direct);
        for(int j = 0; j < upstreamCount; j++)
        {
            rollUp += R1csLinearCombination.From(upstream[j]);
        }

        builder.AssertEqual(pcf, rollUp);
        builder.AssertQuantityAtMost(pcf, FixedPointBound.Constant(PcfDomain, cap), Pcf);

        return builder.With(R1csCircuitTransformations.PowerOfTwoPadding).Build();
    }


    //Binds a tier's inputs: the carried upstream footprints (public), the private
    //own emissions and its domain bits, the public footprint output with the
    //at-most auxiliaries, and the padding columns. The footprint decimal is
    //recovered from the exact field sum, so the bound value and the summation
    //constraint agree.
    private static R1csCircuitInputs BuildTierInputs(R1csCircuit circuit, decimal cap, decimal directEmissions, ReadOnlySpan<BigInteger> carriedUpstream)
    {
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal);

        BigInteger encodedDirect = PcfDomain.Encode(directEmissions);
        BigInteger encodedPcf = encodedDirect;
        for(int j = 0; j < carriedUpstream.Length; j++)
        {
            encodedPcf += carriedUpstream[j];
            bindings[$"{UpstreamPrefix}{j}"] = carriedUpstream[j];
        }

        bindings[Direct] = encodedDirect;
        R1csPredicateWitness.AddRangeCheckBits(bindings, DirectDomain, encodedDirect, PcfDomain.Bits, Curve);

        decimal pcf = PcfDomain.Scale.Decode(encodedPcf);
        R1csSupplyChainWitness.AddQuantityAtMostBindings(bindings, Pcf, Pcf, FixedPointBound.Constant(PcfDomain, cap), pcf, Curve);

        R1csPredicateWitness.AddPowerOfTwoPaddingBindings(bindings, circuit);

        return new R1csCircuitInputs(bindings);
    }


    //Reads the tier's committed footprint: the first public input of the verified
    //instance, in canonical big-endian, is the pcf output the verifier re-checked.
    private static BigInteger ReadCommittedPcf(RawR1csInstance instance)
    {
        ReadOnlySpan<byte> publicInputs = instance.GetPublicInputsBytes();
        int scalarSize = publicInputs.Length / instance.PublicInputCount;

        return new BigInteger(publicInputs[..scalarSize], isUnsigned: true, isBigEndian: true);
    }


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


    //The verified outcome of one tier: whether its proof verified, its decoded
    //cradle-to-gate footprint, and the committed field element the next tier carries.
    private readonly record struct TierProof(bool Verified, decimal Pcf, BigInteger CommittedPcf)
    {
        //An unprovable tier — a false statement rejected before proving.
        public static TierProof Unproven { get; } = new(false, decimal.Zero, BigInteger.Zero);
    }
}
