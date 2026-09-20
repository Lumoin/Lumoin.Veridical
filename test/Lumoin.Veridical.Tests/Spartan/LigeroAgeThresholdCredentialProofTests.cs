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
/// its signature verified out of circuit against the P-256 reference
/// implementation, then a
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
/// circuit requires an elliptic-curve-scalar-multiplication gadget that this
/// proof does not include, so that binding is deliberately not attempted here.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LigeroAgeThresholdCredentialProofTests
{
    /// <summary>
    /// The caller's value-supply callback: given an attribute identifier, returns its field value. A
    /// consumer extracts these from a verified credential; the tests back it with the credential's own
    /// signed claims.
    /// </summary>
    /// <param name="attributeIdentifier">The claim's element identifier, e.g. <c>"age"</c>.</param>
    /// <returns>The claim's value as a field element.</returns>
    private delegate BigInteger CredentialAttributeValue(string attributeIdentifier);

    /// <summary>The production BLAKE3 Fiat-Shamir hash delegate every transcript in this class is built from.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The production BLAKE3 Fiat-Shamir squeeze delegate every transcript in this class draws challenges through.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The BigInteger reference scalar-reduction delegate for the BLS12-381 scalar field.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The validated BLS12-381 scalar addition delegate the Spartan-over-Ligero prove/verify runs on.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The validated BLS12-381 scalar subtraction delegate the Spartan-over-Ligero prove/verify runs on.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The validated BLS12-381 scalar multiplication delegate the Spartan-over-Ligero prove/verify runs on.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The validated BLS12-381 scalar inversion delegate the Spartan-over-Ligero prove/verify runs on.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BigInteger reference G1 point-addition delegate for BLS12-381.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();

    /// <summary>The BigInteger reference G1 scalar-multiplication delegate for BLS12-381.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>The validated BLS12-381 G1 multi-scalar-multiplication delegate the Spartan commitments run on.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;

    /// <summary>The BigInteger reference multilinear-extension evaluation delegate.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The BigInteger reference multilinear-extension folding delegate.</summary>
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    /// <summary>The two-to-one Merkle hash delegate backing the Ligero provider, implemented with production BLAKE3 through <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The Merkle digest width the Ligero provider and hash delegate use, taken from the library's default Merkle parameters.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The opened-column count the Ligero provider uses; small enough to keep the fixture fast.</summary>
    private const int TestQueryCount = 8;

    /// <summary>The byte width of a P-256/BLS12-381 scalar, shared by the ECDSA signing material and the field arithmetic in this class.</summary>
    private const int ScalarSize = 32;

    /// <summary>The bit width of the age-minus-threshold difference the range gadget binds; eight bits covers any realistic age-versus-threshold gap (0..255).</summary>
    private const int AgeDifferenceBits = 8;

    /// <summary>The public age threshold the circuit proves the holder's private age is at least.</summary>
    private const int Threshold = 18;

    /// <summary>The Fiat-Shamir domain-separation label for this test's transcript, distinguishing it from every other transcript domain in the suite.</summary>
    private const string TranscriptDomain = "veridical.longfellow.ligero.age.test.v1";

    /// <summary>A fixed ECDSA nonce in <c>[1, n-1]</c>: deterministic test material, standing in for the RFC 6979 derivation production signing uses.</summary>
    private const string NonceHex = "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60";

    /// <summary>The seed for the deterministic randomness the Spartan prover draws its masking scalars from.</summary>
    private static byte[] RandomSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.ligero.age.rng.v1");

    /// <summary>The BLS12-381 curve parameter set this test's Spartan-over-Ligero arithmetic runs over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Verifies that a correctly minted credential's issuer signature checks out, and that tampering with the signed age claim breaks it.</summary>
    [TestMethod]
    public void IssuerSignatureBindsTheCredential()
    {
        using ECDsa issuer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        MdocCredential credential = SampleCredential(ageYears: 34);

        Span<byte> publicKey = stackalloc byte[33];
        Span<byte> r = stackalloc byte[ScalarSize];
        Span<byte> s = stackalloc byte[ScalarSize];
        Mint(issuer, credential, publicKey, r, s);

        Assert.IsTrue(VerifyIssuerSignature(credential, publicKey, r, s), "A correctly minted credential's issuer signature must verify.");

        //Flip the age claim: the issuer signature no longer covers it.
        MdocCredential tampered = credential with
        {
            Claims = [new MdocClaim("age", EncodeAge(99)), credential.Claims[1]],
        };
        Assert.IsFalse(VerifyIssuerSignature(tampered, publicKey, r, s), "A tampered claim must break the issuer signature.");
    }


    /// <summary>Verifies that a credential whose private age is above the public threshold produces a verifying Ligero-backed Spartan proof.</summary>
    [TestMethod]
    public void AgeAboveThresholdProvesInZeroKnowledge()
    {
        MdocCredential credential = SampleCredential(ageYears: 34);
        CredentialAttributeValue values = AttributeValuesFrom(credential);

        Assert.IsTrue(ProveAndVerifyAgeThreshold(values), "age = 34 ≥ 18 must produce a verifying Ligero-backed Spartan proof.");
    }


    /// <summary>Verifies that a credential whose private age is below the public threshold cannot be proven, since the age-over-threshold statement is false.</summary>
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


    /// <summary>Verifies that flipping the last byte of an honest age-threshold proof makes verification reject it.</summary>
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
        Assert.IsFalse(verified, "A tampered Ligero-backed age proof must be rejected.");
    }


    /// <summary>
    /// Builds the age-threshold circuit, feeds the caller's values, compiles, and runs the full
    /// Spartan-over-Ligero prove/verify. A rejection at binding or compile time — because the age is not
    /// at least the threshold, or the difference does not fit the allotted bits — is reported as an
    /// unverified proof rather than an exception.
    /// </summary>
    /// <param name="values">The callback supplying the credential's attribute values, keyed by identifier.</param>
    /// <returns><see langword="true"/> when an honest proof was produced and verified; <see langword="false"/> when the statement is false or unprovable.</returns>
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


    /// <summary>Builds the circuit asserting <c>age</c> (a private witness) is at least <c>threshold</c> (a public input).</summary>
    /// <returns>The compiled, power-of-two-padded R1CS circuit.</returns>
    private static R1csCircuit BuildAgeThresholdCircuit()
    {
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex threshold = builder.DeclarePublicInput("threshold");
        R1csVariableIndex age = builder.DeclareWitnessVariable("age");
        builder.AssertGreaterThanOrEqual(age, threshold, AgeDifferenceBits, "ageOver");

        return builder.With(R1csCircuitTransformations.PowerOfTwoPadding).Build();
    }


    /// <summary>Binds the circuit's public threshold, private age, and the range gadget's and padding's derived witness bits.</summary>
    /// <param name="circuit">The compiled age-threshold circuit whose padding bindings are derived.</param>
    /// <param name="values">The callback supplying the credential's age attribute.</param>
    /// <returns>The complete variable bindings ready to compile a witness from.</returns>
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


    /// <summary>Builds the Ligero-backed commitment provider this test's Spartan prover and verifier commit and open through.</summary>
    /// <returns>A new Ligero provider; ownership transfers to whichever Spartan key consumes it.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "The Ligero provider holds no disposable key; the Spartan key that consumes it disposes it.")]
    private static PolynomialCommitmentProvider BuildProvider()
    {
        return LigeroPolynomialCommitmentScheme.Create(
            Curve, TestQueryCount, Add, Subtract, Multiply, Invert, Reduce, Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3, DigestSizeBytes);
    }


    /// <summary>Builds a value-supply callback that reads a credential's own claims, the shape a real consumer's extraction would take.</summary>
    /// <param name="credential">The credential whose claims back the returned callback.</param>
    /// <returns>A callback resolving an attribute identifier to that claim's field value.</returns>
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


    /// <summary>Builds a dummy ISO-18013-5-shaped mdoc credential carrying the given age and a fixed document number claim.</summary>
    /// <param name="ageYears">The age, in years, to encode into the credential's <c>age</c> claim.</param>
    /// <returns>The unsigned sample credential.</returns>
    private static MdocCredential SampleCredential(int ageYears) => new(
        DocType: "org.iso.18013.5.1.mDL",
        Claims:
        [
            new MdocClaim("age", EncodeAge(ageYears)),
            new MdocClaim("doc_number", new byte[] { 0x4D, 0x44, 0x4C, 0x31 }),
        ]);


    /// <summary>Encodes an age in years as a fixed-width big-endian claim value.</summary>
    /// <param name="ageYears">The age, in years, to encode.</param>
    /// <returns>The four-byte big-endian encoding of <paramref name="ageYears"/>.</returns>
    private static ReadOnlyMemory<byte> EncodeAge(int ageYears)
    {
        byte[] bytes = new byte[sizeof(uint)];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes, (uint)ageYears);

        return bytes;
    }


    /// <summary>Signs the credential's canonical digest with the issuer's P-256 key under the fixed test nonce, and exports the issuer's compressed public key.</summary>
    /// <param name="issuer">The issuer keypair to sign with and export the public key from.</param>
    /// <param name="credential">The credential to sign.</param>
    /// <param name="publicKeyCompressed">The buffer receiving the issuer's compressed public key.</param>
    /// <param name="r">The buffer receiving the ECDSA signature's <c>r</c> component.</param>
    /// <param name="s">The buffer receiving the ECDSA signature's <c>s</c> component.</param>
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


    /// <summary>Verifies a credential's canonical digest against an ECDSA signature and the issuer's compressed public key, out of circuit.</summary>
    /// <param name="credential">The credential whose canonical digest is checked.</param>
    /// <param name="publicKeyCompressed">The issuer's compressed public key.</param>
    /// <param name="r">The ECDSA signature's <c>r</c> component.</param>
    /// <param name="s">The ECDSA signature's <c>s</c> component.</param>
    /// <returns><see langword="true"/> when the signature verifies against the credential's canonical digest.</returns>
    private static bool VerifyIssuerSignature(MdocCredential credential, ReadOnlySpan<byte> publicKeyCompressed, ReadOnlySpan<byte> r, ReadOnlySpan<byte> s)
    {
        Span<byte> digest = stackalloc byte[ScalarSize];
        HashCanonical(credential, digest);

        return P256EcdsaReference.Verify(publicKeyCompressed, digest, r, s);
    }


    /// <summary>Computes the SHA-256 digest of a credential's canonical encoding, the digest the issuer signature is over.</summary>
    /// <param name="credential">The credential to encode and hash.</param>
    /// <param name="digest">The buffer receiving the 32-byte digest.</param>
    private static void HashCanonical(MdocCredential credential, Span<byte> digest)
    {
        Span<byte> canonical = stackalloc byte[512];
        int written = CanonicalSerialize(credential, canonical);
        SHA256.HashData(canonical[..written], digest);
    }


    /// <summary>
    /// Serializes a credential into a deterministic, claim-sorted, length-prefixed canonical encoding
    /// standing in for the real ISO 18013-5 CBOR/COSE serializer.
    /// </summary>
    /// <param name="credential">The credential to serialize.</param>
    /// <param name="destination">The buffer receiving the encoding.</param>
    /// <returns>The number of bytes written to <paramref name="destination"/>.</returns>
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


    /// <summary>Writes a length-prefixed UTF-8 string: a two-byte big-endian length followed by the encoded bytes.</summary>
    /// <param name="value">The string to encode.</param>
    /// <param name="destination">The buffer receiving the length prefix and the encoded bytes.</param>
    /// <returns>The total number of bytes written, including the length prefix.</returns>
    private static int WriteString(string value, Span<byte> destination)
    {
        int written = System.Text.Encoding.UTF8.GetBytes(value, destination[sizeof(ushort)..]);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)written);

        return sizeof(ushort) + written;
    }


    /// <summary>Exports an ECDSA key's public point in SEC1 compressed form.</summary>
    /// <param name="ecdsa">The key whose public point is exported.</param>
    /// <param name="destination">The 33-byte buffer receiving the compressed point.</param>
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


    /// <summary>Right-aligns a big-endian byte array into a wider fixed-size buffer, zero-filling the leading bytes.</summary>
    /// <param name="source">The source bytes to right-align; must not be <see langword="null"/>.</param>
    /// <param name="destination">The buffer receiving the zero-padded, right-aligned bytes.</param>
    private static void LeftPad(byte[]? source, Span<byte> destination)
    {
        destination.Clear();
        ArgumentNullException.ThrowIfNull(source);
        source.CopyTo(destination[(destination.Length - source.Length)..]);
    }


    /// <summary>Creates a fresh Fiat-Shamir transcript under this test's domain label, ready to absorb a prove or verify run.</summary>
    /// <returns>A new transcript backed by the shared pool.</returns>
    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>Concatenates two digests and hashes them with production BLAKE3, the two-to-one compression the Ligero provider's Merkle tree uses.</summary>
    /// <param name="left">The left digest, placed first in the concatenation.</param>
    /// <param name="right">The right digest, placed after <paramref name="left"/>.</param>
    /// <param name="output">The buffer receiving the combined digest.</param>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
