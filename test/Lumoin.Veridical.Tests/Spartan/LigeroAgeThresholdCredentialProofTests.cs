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
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// End-to-end gate mimicking how a consumer (e.g. Verifiable) drives the stack:
/// a dummy ISO-18013-5-shaped mdoc credential is ECDSA-signed by an issuer and
/// its signature verified out of circuit (the LF.3 P-256 reference), then a
/// caller-supplied value callback feeds the holder's private <c>age</c> into an
/// <c>age ≥ threshold</c> circuit which is proven in zero knowledge through the
/// new Ligero polynomial commitment (Spartan-over-Ligero) and verified.
/// </summary>
/// <remarks>
/// <para>
/// This exercises the real consumption path — build a statement circuit, supply
/// attribute values through a callback, compile to R1CS, prove and verify — over
/// the Ligero PCS, rather than a synthetic <c>x · y = 15</c> fixture. The age
/// stays private (a witness variable); the threshold is public.
/// </para>
/// <para>
/// Scope boundary: the issuer's ECDSA signature is checked <em>out of circuit</em>
/// here, so the proof binds <c>age ≥ threshold</c> for a supplied age but does not
/// yet cryptographically tie that in-circuit age to the signed credential.
/// Verifying the ECDSA signature (and the credential hash) <em>inside</em> the
/// circuit — the elliptic-curve-scalar-multiplication gadget — is the remaining
/// Longfellow LF.5 work and is deliberately not attempted here.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LigeroAgeThresholdCredentialProofTests
{
    //The caller's value-supply callback: given an attribute identifier, return its
    //field value. A consumer extracts these from a verified credential; the tests
    //back it with the credential's signed claims.
    private delegate BigInteger CredentialAttributeValue(string attributeIdentifier);

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
    private const int ScalarSize = 32;

    //An eight-bit difference covers any realistic age − threshold gap (0..255).
    private const int AgeDifferenceBits = 8;
    private const int Threshold = 18;
    private const string TranscriptDomain = "veridical.longfellow.ligero.age.test.v1";

    //A fixed ECDSA nonce in [1, n-1] (deterministic test material; production uses RFC 6979).
    private const string NonceHex = "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60";

    private static readonly byte[] RandomSeed = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.ligero.age.rng.v1");
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void IssuerSignatureBindsTheCredential()
    {
        using ECDsa issuer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        MdocCredential credential = SampleCredential(ageYears: 34);

        Span<byte> publicKey = stackalloc byte[33];
        Span<byte> r = stackalloc byte[ScalarSize];
        Span<byte> s = stackalloc byte[ScalarSize];
        Mint(issuer, credential, publicKey, r, s);

        Assert.IsTrue(VerifyIssuerSignature(credential, publicKey, r, s), "An honestly minted credential's issuer signature must verify.");

        //Flip the age claim: the issuer signature no longer covers it.
        MdocCredential tampered = credential with
        {
            Claims = [new MdocClaim("age", EncodeAge(99)), credential.Claims[1]],
        };
        Assert.IsFalse(VerifyIssuerSignature(tampered, publicKey, r, s), "A tampered claim must break the issuer signature.");
    }


    [TestMethod]
    public void AgeAboveThresholdProvesInZeroKnowledge()
    {
        MdocCredential credential = SampleCredential(ageYears: 34);
        CredentialAttributeValue values = AttributeValuesFrom(credential);

        Assert.IsTrue(ProveAndVerifyAgeThreshold(values), "age = 34 ≥ 18 must produce a verifying Ligero-backed Spartan proof.");
    }


    [TestMethod]
    public void AgeBelowThresholdCannotBeProven()
    {
        MdocCredential credential = SampleCredential(ageYears: 16);
        CredentialAttributeValue values = AttributeValuesFrom(credential);

        //A false statement (16 ≥ 18) must not yield a verifying proof: the
        //compile-time satisfaction check (or the bit-decomposition binding)
        //rejects it before any proof can be produced.
        Assert.IsFalse(ProveAndVerifyAgeThreshold(values), "age = 16 ≥ 18 is false and must not be provable.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "The Spartan prover/verifier own their keys (and the provider) and are disposed via using declarations.")]
    public void TamperedProofIsRejected()
    {
        MdocCredential credential = SampleCredential(ageYears: 34);
        CredentialAttributeValue values = AttributeValuesFrom(credential);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        R1csCircuit circuit = BuildAgeThresholdCircuit();
        R1csCircuitInputs inputs = BuildInputs(circuit, values);

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
        Assert.IsFalse(verified, "A tampered Ligero-backed age proof must be rejected.");
    }


    //Builds the circuit, feeds the caller's values, compiles, and runs the full
    //Spartan-over-Ligero prove/verify; returns whether an honest proof verified.
    //Any rejection at binding/compile time (a false statement) returns false.
    [SuppressMessage("Reliability", "CA2000", Justification = "Instances, witnesses, prover, verifier and transcripts are disposed via using declarations before the result is returned.")]
    private static bool ProveAndVerifyAgeThreshold(CredentialAttributeValue values)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        R1csCircuit circuit = BuildAgeThresholdCircuit();

        R1csCircuitInputs inputs;
        (RawR1csInstance Instance, RawR1csWitness Witness) proverCompiled;
        try
        {
            inputs = BuildInputs(circuit, values);
            proverCompiled = circuit.Compile(inputs, pool);
        }
        catch(R1csCircuitCompilationException)
        {
            //The witness does not satisfy the statement (e.g. age < threshold).
            return false;
        }
        catch(ArgumentException)
        {
            //The difference did not fit the allotted bits — also an unprovable statement.
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


    //age (private witness) ≥ threshold (public input).
    private static R1csCircuit BuildAgeThresholdCircuit()
    {
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex threshold = builder.DeclarePublicInput("threshold");
        R1csVariableIndex age = builder.DeclareWitnessVariable("age");
        builder.AssertGreaterThanOrEqual(age, threshold, AgeDifferenceBits, "ageOver");

        return builder.With(R1csCircuitTransformations.PowerOfTwoPadding).Build();
    }


    private static R1csCircuitInputs BuildInputs(R1csCircuit circuit, CredentialAttributeValue values)
    {
        BigInteger age = values("age");
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal)
        {
            ["threshold"] = Threshold,
            ["age"] = age,
        };
        R1csPredicateWitness.AddGreaterThanOrEqualBits(bindings, "ageOver", age, Threshold, AgeDifferenceBits, Curve);
        R1csPredicateWitness.AddPowerOfTwoPaddingBindings(bindings, circuit);

        return new R1csCircuitInputs(bindings);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The Ligero provider holds no disposable key; the Spartan key that consumes it disposes it.")]
    private static PolynomialCommitmentProvider BuildProvider()
    {
        return LigeroPolynomialCommitmentScheme.Create(
            Curve, TestQueryCount, Add, Subtract, Multiply, Invert, Reduce, Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3, DigestSizeBytes);
    }


    private static CredentialAttributeValue AttributeValuesFrom(MdocCredential credential) => attribute =>
    {
        foreach(MdocClaim claim in credential.Claims)
        {
            if(string.Equals(claim.ElementIdentifier, attribute, StringComparison.Ordinal))
            {
                return new BigInteger(claim.ElementValue.Span, isUnsigned: true, isBigEndian: true);
            }
        }

        throw new KeyNotFoundException($"Credential has no claim '{attribute}'.");
    };


    private static MdocCredential SampleCredential(int ageYears) => new(
        DocType: "org.iso.18013.5.1.mDL",
        Claims:
        [
            new MdocClaim("age", EncodeAge(ageYears)),
            new MdocClaim("doc_number", new byte[] { 0x4D, 0x44, 0x4C, 0x31 }),
        ]);


    private static ReadOnlyMemory<byte> EncodeAge(int ageYears)
    {
        byte[] bytes = new byte[sizeof(uint)];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes, (uint)ageYears);

        return bytes;
    }


    private static void Mint(ECDsa issuer, MdocCredential credential, Span<byte> publicKeyCompressed, Span<byte> r, Span<byte> s)
    {
        ExportPublicKeyCompressed(issuer, publicKeyCompressed);
        ECParameters parameters = issuer.ExportParameters(includePrivateParameters: true);

        Span<byte> privateKey = stackalloc byte[ScalarSize];
        LeftPad(parameters.D, privateKey);

        Span<byte> digest = stackalloc byte[ScalarSize];
        HashCanonical(credential, digest);

        Span<byte> nonce = stackalloc byte[ScalarSize];
        Convert.FromHexString(NonceHex).CopyTo(nonce);

        P256EcdsaReference.Sign(privateKey, digest, nonce, r, s);
    }


    private static bool VerifyIssuerSignature(MdocCredential credential, ReadOnlySpan<byte> publicKeyCompressed, ReadOnlySpan<byte> r, ReadOnlySpan<byte> s)
    {
        Span<byte> digest = stackalloc byte[ScalarSize];
        HashCanonical(credential, digest);

        return P256EcdsaReference.Verify(publicKeyCompressed, digest, r, s);
    }


    private static void HashCanonical(MdocCredential credential, Span<byte> digest)
    {
        Span<byte> canonical = stackalloc byte[512];
        int written = CanonicalSerialize(credential, canonical);
        SHA256.HashData(canonical[..written], digest);
    }


    //A deterministic, claim-sorted, length-prefixed canonical encoding standing in
    //for the real ISO 18013-5 CBOR/COSE serializer.
    private static int CanonicalSerialize(in MdocCredential credential, Span<byte> destination)
    {
        int offset = WriteString(credential.DocType, destination);

        List<MdocClaim> ordered = [.. credential.Claims];
        ordered.Sort(static (left, right) => string.CompareOrdinal(left.ElementIdentifier, right.ElementIdentifier));
        foreach(MdocClaim claim in ordered)
        {
            offset += WriteString(claim.ElementIdentifier, destination[offset..]);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(destination[offset..], (ushort)claim.ElementValue.Length);
            offset += sizeof(ushort);
            claim.ElementValue.Span.CopyTo(destination[offset..]);
            offset += claim.ElementValue.Length;
        }

        return offset;
    }


    private static int WriteString(string value, Span<byte> destination)
    {
        int written = System.Text.Encoding.UTF8.GetBytes(value, destination[sizeof(ushort)..]);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)written);

        return sizeof(ushort) + written;
    }


    private static void ExportPublicKeyCompressed(ECDsa ecdsa, Span<byte> destination)
    {
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        Span<byte> x = stackalloc byte[ScalarSize];
        Span<byte> y = stackalloc byte[ScalarSize];
        LeftPad(parameters.Q.X, x);
        LeftPad(parameters.Q.Y, y);

        destination[0] = (byte)(0x02 | (y[^1] & 0x01));
        x.CopyTo(destination[1..]);
    }


    private static void LeftPad(byte[]? source, Span<byte> destination)
    {
        destination.Clear();
        ArgumentNullException.ThrowIfNull(source);
        source.CopyTo(destination[(destination.Length - source.Length)..]);
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
