using Lumoin.Base;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The crypto behind the <c>prove</c> and <c>verify</c> verbs: it turns a
/// <see cref="PredicateProofRequest"/> (statement parameters plus private measured
/// quantities) into a <see cref="PredicateProofArtifact"/>, and checks such an
/// artifact against the statement it describes. Both surfaces (the CLI subcommands
/// and the MCP tools) forward here through the JSON boundary, so the two never
/// drift, and the operations themselves are serializer-agnostic — they take and
/// return the <see cref="Lumoin.Veridical.Json"/> envelope types and touch no file
/// or network I/O.
/// </summary>
/// <remarks>
/// <para>
/// The statement is the §9 supply-chain predicate bundle: an ordered conjunction of
/// at-least / at-most fixed-point claims, proven over Spartan-over-Ligero
/// (transparent, hash-based, no trusted setup). The measured quantities are private
/// witness inputs and are not included in the artifact; a regulatory bound is either
/// baked into the circuit (a constant) or revealed as a public input.
/// </para>
/// <para>
/// Verification rebuilds the identical statement circuit from the artifact's claim
/// descriptors and reconstructs the public instance from the revealed public inputs
/// with <see cref="R1csCircuitCompilation.CompileInstance"/> — no witness. A proof
/// attests only that the described circuit is satisfiable: a constant bound is baked
/// into the matrices and a public bound is absorbed into the transcript, so tampering
/// with either the description or the public inputs fails verification. The verb
/// reports the described statement so an operator confirms it is the intended
/// compliance claim.
/// </para>
/// <para>
/// The commitment parameters (curve, Ligero query count, digest size) are pinned to
/// one wired set that both surfaces enforce, so an artifact cannot silently downgrade
/// them. These are the wired parameters; the formal per-scheme soundness-bits
/// accounting is tracked separately and is not asserted here.
/// </para>
/// </remarks>
internal static class PredicateProofOperations
{
    /// <summary>The format identifier of a prove request this tool accepts.</summary>
    public const string RequestFormat = "veridical-supply-chain-predicate-request/1";

    /// <summary>The format identifier this tool stamps on a produced proof artifact.</summary>
    public const string ArtifactFormat = "veridical-supply-chain-predicate-proof/1";

    /// <summary>The lowercase curve identifier the wired parameter set proves over.</summary>
    public const string CurveId = "bls12-381";

    /// <summary>The Ligero opened-column query count of the wired parameter set.</summary>
    public const int WiredQueryCount = 32;

    /// <summary>The Merkle digest size in bytes of the wired parameter set.</summary>
    public const int WiredDigestBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;
    private static readonly FiatShamirHashDelegate Hash = Blake3FiatShamirBackend.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = Blake3FiatShamirBackend.GetSqueeze();


    /// <summary>
    /// Deserializes a prove request from JSON, proves it, and serializes the produced
    /// artifact back to JSON — the string-in, string-out boundary both the CLI
    /// subcommand and the MCP tool forward to.
    /// </summary>
    /// <exception cref="ArgumentNullException">When an argument is null.</exception>
    /// <exception cref="JsonException">When <paramref name="requestJson"/> is not well-formed.</exception>
    /// <exception cref="ArgumentException">When the request header, a claim, or a decimal value is malformed.</exception>
    /// <exception cref="R1csCircuitCompilationException">When the statement is false, so no proof exists.</exception>
    public static string ProveToJson(string requestJson, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(requestJson);
        ArgumentNullException.ThrowIfNull(pool);

        PredicateProofRequest request = VeridicalPredicateProofJson.DeserializeRequest(requestJson);
        PredicateProofArtifact artifact = Prove(request, pool);

        return VeridicalPredicateProofJson.Serialize(artifact);
    }


    /// <summary>
    /// Deserializes a proof artifact from JSON and verifies it. Malformed JSON is
    /// reported as <see cref="VerificationStatus.Malformed"/> rather than thrown, so
    /// this boundary never throws on artifact content.
    /// </summary>
    /// <exception cref="ArgumentNullException">When an argument is null.</exception>
    public static VerificationResult VerifyFromJson(string artifactJson, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(artifactJson);
        ArgumentNullException.ThrowIfNull(pool);

        PredicateProofArtifact artifact;
        try
        {
            artifact = VeridicalPredicateProofJson.DeserializeArtifact(artifactJson);
        }
        catch(JsonException error)
        {
            return VerificationResult.Malformed($"The artifact is not valid JSON ({error.Message}).");
        }

        return Verify(artifact, pool);
    }


    /// <summary>
    /// Proves the supply-chain predicate bundle described by <paramref name="request"/>
    /// against its private measured quantities, returning the transferable artifact.
    /// </summary>
    /// <exception cref="ArgumentNullException">When an argument is null.</exception>
    /// <exception cref="ArgumentException">When the request header, a claim, or a decimal value is malformed.</exception>
    /// <exception cref="R1csCircuitCompilationException">When the statement is false (a measured quantity does not satisfy its claim), so no proof exists.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The Spartan proving key owns the commitment provider and disposes it; every other disposable flows through a using declaration.")]
    public static PredicateProofArtifact Prove(PredicateProofRequest request, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(pool);

        ValidateHeader(request.Format, RequestFormat, request.Curve, request.QueryCount, request.DigestBytes);

        ArgumentNullException.ThrowIfNull(request.Claims);
        var descriptors = new List<ClaimDescriptor>(request.Claims.Count);
        var measured = new Dictionary<string, decimal>(StringComparer.Ordinal);
        foreach(PredicateProofRequestClaim claim in request.Claims)
        {
            ClaimDescriptor descriptor = ParseRequestClaim(claim);
            descriptors.Add(descriptor);
            measured[descriptor.Name] = ParseDecimal(claim.Measured, $"claim '{claim.Name}' measured value");
        }

        BuiltStatement statement = BuildStatement(descriptors);

        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        foreach(ClaimDescriptor descriptor in descriptors)
        {
            if(descriptor.IsPublic)
            {
                bindings[PublicInputVariableName(descriptor.Name)] = descriptor.Domain.Encode(descriptor.BoundValue);
            }
        }

        R1csSupplyChainWitness.AddBatteryPassportBindings(bindings, statement.Claims, name => measured[name], Curve);
        R1csPredicateWitness.AddPowerOfTwoPaddingBindings(bindings, statement.Circuit);

        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = statement.Circuit.Compile(new R1csCircuitInputs(bindings), pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using ScalarArithmeticBackend scalar = Bls12Curve381ManagedScalarBackend.Create();
        using G1ArithmeticBackend g1 = Bls12Curve381ManagedG1Backend.Create();
        MleEvaluateDelegate mleEvaluate = ManagedMultilinearExtensionBackend.CreateEvaluate(scalar, pool);
        MleFoldDelegate mleFold = ManagedMultilinearExtensionBackend.CreateFold(scalar, pool);

        using var prover = new SpartanProver(new SpartanProvingKey(BuildProvider(scalar, request.QueryCount, request.DigestBytes)));
        using FiatShamirTranscript transcript = FreshTranscript(request.TranscriptDomain, pool);
        using LigeroSpartanProof proof = prover.ProveLigero(
            instance, witness, transcript,
            Hash, Squeeze, scalar.Reduce, scalar.Add, scalar.Subtract, scalar.Multiply, scalar.Invert, scalar.Random,
            g1.Add, g1.ScalarMultiply, g1.MultiScalarMultiply, mleEvaluate, mleFold, pool);

        return new PredicateProofArtifact
        {
            Format = ArtifactFormat,
            Curve = CurveId,
            TranscriptDomain = request.TranscriptDomain,
            QueryCount = request.QueryCount,
            DigestBytes = request.DigestBytes,
            Claims = BuildArtifactClaims(descriptors),
            PublicInputs = Convert.ToBase64String(instance.GetPublicInputsBytes()),
            Proof = Convert.ToBase64String(proof.AsReadOnlySpan()),
        };
    }


    /// <summary>
    /// Verifies <paramref name="artifact"/> against the statement it describes. Never
    /// throws on artifact content: a well-formed but failing proof returns
    /// <see cref="VerificationStatus.Rejected"/>, and unusable artifact content (bad
    /// encoding, unsupported parameters, mismatched shapes) returns
    /// <see cref="VerificationStatus.Malformed"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException">When an argument is null.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The Spartan verifying key owns the commitment provider and disposes it; every other disposable flows through a using declaration.")]
    public static VerificationResult Verify(PredicateProofArtifact artifact, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        ArgumentNullException.ThrowIfNull(pool);

        if(!TryValidateHeader(artifact.Format, ArtifactFormat, artifact.Curve, artifact.QueryCount, artifact.DigestBytes, out string headerError))
        {
            return VerificationResult.Malformed(headerError);
        }

        List<ClaimDescriptor> descriptors;
        byte[] publicInputs;
        byte[] proofBytes;
        try
        {
            descriptors = ParseArtifactClaims(artifact.Claims);
            publicInputs = DecodeBase64(artifact.PublicInputs, "public inputs");
            proofBytes = DecodeBase64(artifact.Proof, "proof");
        }
        catch(ArgumentException ex)
        {
            return VerificationResult.Malformed(ex.Message);
        }

        try
        {
            BuiltStatement statement = BuildStatement(descriptors);

            using RawR1csInstance instance = statement.Circuit.CompileInstance(publicInputs, pool);
            int outerRoundCount = BitOperations.Log2((uint)instance.A.RowCount);
            int innerRoundCount = BitOperations.Log2((uint)instance.A.ColumnCount);

            using ScalarArithmeticBackend scalar = Bls12Curve381ManagedScalarBackend.Create();
            using LigeroSpartanProof proof = LigeroSpartanProof.FromBytes(proofBytes, outerRoundCount, innerRoundCount, artifact.QueryCount, artifact.DigestBytes, Curve, pool);
            using var verifier = new SpartanVerifier(new SpartanVerifyingKey(BuildProvider(scalar, artifact.QueryCount, artifact.DigestBytes)));
            using FiatShamirTranscript transcript = FreshTranscript(artifact.TranscriptDomain, pool);

            bool verified = verifier.VerifyLigero(proof, instance, transcript, scalar.Add, scalar.Multiply, scalar.Subtract, scalar.Reduce, Hash, Squeeze, pool);
            string statementSummary = DescribeStatement(descriptors, publicInputs);

            return verified ? VerificationResult.Valid(statementSummary) : VerificationResult.Rejected(statementSummary);
        }
        catch(ArgumentException ex)
        {
            return VerificationResult.Malformed(ex.Message);
        }
        catch(R1csCircuitCompilationException ex)
        {
            return VerificationResult.Malformed(ex.Message);
        }
    }


    //Builds the statement circuit deterministically from the claim descriptors so the
    //prover and the verifier compile the identical circuit. Public-input bound
    //variables are declared first (the builder's contiguity rule), in claim order,
    //then the measured witness variables in claim order. For a public bound the
    //FixedPointBound's value is not part of the circuit structure (the predicate
    //references the variable, not the value), so the verifier can supply a placeholder.
    private static BuiltStatement BuildStatement(IReadOnlyList<ClaimDescriptor> claims)
    {
        var builder = new R1csCircuitBuilder(Curve);

        var publicVariables = new Dictionary<string, R1csVariableIndex>(StringComparer.Ordinal);
        foreach(ClaimDescriptor claim in claims)
        {
            if(claim.IsPublic)
            {
                publicVariables[claim.Name] = builder.DeclarePublicInput(PublicInputVariableName(claim.Name));
            }
        }

        var supplyClaims = new SupplyChainClaim[claims.Count];
        for(int i = 0; i < claims.Count; i++)
        {
            ClaimDescriptor claim = claims[i];
            R1csVariableIndex measured = builder.DeclareWitnessVariable(claim.Name);
            FixedPointBound bound = claim.IsPublic
                ? FixedPointBound.PublicInput(claim.Domain, claim.BoundValue, publicVariables[claim.Name])
                : FixedPointBound.Constant(claim.Domain, claim.BoundValue);
            supplyClaims[i] = claim.Direction == SupplyChainDirection.AtLeast
                ? SupplyChainClaim.AtLeast(claim.Name, measured, bound)
                : SupplyChainClaim.AtMost(claim.Name, measured, bound);
        }

        builder.AssertBatteryPassport(supplyClaims);
        R1csCircuit circuit = builder.With(R1csCircuitTransformations.PowerOfTwoPadding).Build();

        return new BuiltStatement(circuit, supplyClaims);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The commitment provider is handed to the Spartan key the caller constructs, which owns and disposes it.")]
    private static PolynomialCommitmentProvider BuildProvider(ScalarArithmeticBackend scalar, int queryCount, int digestBytes)
    {
        return LigeroPolynomialCommitmentScheme.Create(
            Curve, queryCount,
            scalar.Add, scalar.Subtract, scalar.Multiply, scalar.Invert, scalar.Reduce,
            Hash, Squeeze, Hash, HashTwoToOne, WellKnownHashAlgorithms.Blake3, digestBytes);
    }


    private static FiatShamirTranscript FreshTranscript(string transcriptDomain, BaseMemoryPool pool)
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(transcriptDomain),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            pool);
    }


    //The Ligero two-to-one Merkle hash: BLAKE3 over the concatenation of the two
    //child digests, matching the digest width the provider is configured with.
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * WiredDigestBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    private static ClaimDescriptor ParseRequestClaim(PredicateProofRequestClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        SupplyChainDirection direction = ParseDirection(claim.Direction);
        FixedPointDomain domain = BuildDomain(claim.FractionalDigits, claim.InclusiveMaximum, out decimal inclusiveMaximum);
        bool isPublic = ParseBoundKind(claim.Bound);
        decimal boundValue = ParseDecimal(claim.BoundValue, $"claim '{claim.Name}' bound value");

        return new ClaimDescriptor(claim.Name, direction, domain, inclusiveMaximum, isPublic, boundValue);
    }


    private static List<ClaimDescriptor> ParseArtifactClaims(IReadOnlyList<PredicateProofClaim> claims)
    {
        ArgumentNullException.ThrowIfNull(claims);
        var descriptors = new List<ClaimDescriptor>(claims.Count);
        foreach(PredicateProofClaim claim in claims)
        {
            ArgumentNullException.ThrowIfNull(claim);
            SupplyChainDirection direction = ParseDirection(claim.Direction);
            FixedPointDomain domain = BuildDomain(claim.FractionalDigits, claim.InclusiveMaximum, out decimal inclusiveMaximum);
            bool isPublic = ParseBoundKind(claim.Bound);

            //A public bound's value is not part of the circuit structure, so the
            //verifier reconstructs the circuit with a placeholder; the real value
            //travels in the public inputs. A constant bound's value is baked into
            //the circuit and must be present.
            decimal boundValue;
            if(isPublic)
            {
                boundValue = decimal.Zero;
            }
            else if(claim.Value is null)
            {
                throw new ArgumentException($"Claim '{claim.Name}' declares a constant bound but carries no value.");
            }
            else
            {
                boundValue = ParseDecimal(claim.Value, $"claim '{claim.Name}' bound value");
            }

            descriptors.Add(new ClaimDescriptor(claim.Name, direction, domain, inclusiveMaximum, isPublic, boundValue));
        }

        return descriptors;
    }


    private static PredicateProofClaim[] BuildArtifactClaims(IReadOnlyList<ClaimDescriptor> descriptors)
    {
        var claims = new PredicateProofClaim[descriptors.Count];
        for(int i = 0; i < descriptors.Count; i++)
        {
            ClaimDescriptor descriptor = descriptors[i];
            claims[i] = new PredicateProofClaim
            {
                Name = descriptor.Name,
                Direction = DirectionToString(descriptor.Direction),
                FractionalDigits = descriptor.Domain.Scale.FractionalDigits,
                InclusiveMaximum = descriptor.InclusiveMaximum.ToString(CultureInfo.InvariantCulture),
                Bound = descriptor.IsPublic ? "public" : "constant",
                Value = descriptor.IsPublic ? null : descriptor.BoundValue.ToString(CultureInfo.InvariantCulture),
            };
        }

        return claims;
    }


    //A one-line, operator-facing description of the proven statement. Constant bounds
    //are shown from the descriptor; public bounds are decoded from the revealed public
    //inputs, in public-input declaration order.
    private static string DescribeStatement(IReadOnlyList<ClaimDescriptor> claims, ReadOnlySpan<byte> publicInputs)
    {
        int scalarSize = Scalar.SizeBytes;
        int offset = 0;
        var builder = new StringBuilder();
        foreach(ClaimDescriptor claim in claims)
        {
            string comparison = claim.Direction == SupplyChainDirection.AtLeast ? ">=" : "<=";
            string bound;
            if(claim.IsPublic)
            {
                var encoded = new BigInteger(publicInputs.Slice(offset, scalarSize), isUnsigned: true, isBigEndian: true);
                offset += scalarSize;
                bound = claim.Domain.Scale.TryDecode(encoded, out decimal value)
                    ? $"{value.ToString(CultureInfo.InvariantCulture)} (public input)"
                    : $"{encoded.ToString(CultureInfo.InvariantCulture)} encoded (public input)";
            }
            else
            {
                bound = $"{claim.BoundValue.ToString(CultureInfo.InvariantCulture)} (constant)";
            }

            if(builder.Length > 0)
            {
                builder.Append("; ");
            }

            builder.Append(claim.Name).Append(' ').Append(comparison).Append(' ').Append(bound);
        }

        return builder.ToString();
    }


    private static FixedPointDomain BuildDomain(int fractionalDigits, string inclusiveMaximum, out decimal parsedMaximum)
    {
        parsedMaximum = ParseDecimal(inclusiveMaximum, "inclusive maximum");

        return FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(fractionalDigits), parsedMaximum);
    }


    private static SupplyChainDirection ParseDirection(string direction)
    {
        if(string.Equals(direction, "atLeast", StringComparison.OrdinalIgnoreCase))
        {
            return SupplyChainDirection.AtLeast;
        }

        if(string.Equals(direction, "atMost", StringComparison.OrdinalIgnoreCase))
        {
            return SupplyChainDirection.AtMost;
        }

        throw new ArgumentException($"Unknown claim direction '{direction}'; expected 'atLeast' or 'atMost'.");
    }


    private static bool ParseBoundKind(string bound)
    {
        if(string.Equals(bound, "public", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if(string.Equals(bound, "constant", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        throw new ArgumentException($"Unknown bound kind '{bound}'; expected 'constant' or 'public'.");
    }


    private static decimal ParseDecimal(string value, string context)
    {
        if(!decimal.TryParse(value, NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out decimal result))
        {
            throw new ArgumentException($"The {context} '{value}' is not a valid invariant-culture decimal.");
        }

        return result;
    }


    private static byte[] DecodeBase64(string value, string context)
    {
        try
        {
            return Convert.FromBase64String(value);
        }
        catch(FormatException)
        {
            throw new ArgumentException($"The {context} are not valid Base64.");
        }
    }


    private static string DirectionToString(SupplyChainDirection direction)
    {
        return direction == SupplyChainDirection.AtLeast ? "atLeast" : "atMost";
    }


    private static string PublicInputVariableName(string claimName)
    {
        return claimName + "_public_input";
    }


    private static void ValidateHeader(string format, string expectedFormat, string curve, int queryCount, int digestBytes)
    {
        if(!string.Equals(format, expectedFormat, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Unexpected format '{format}'; expected '{expectedFormat}'.");
        }

        if(!string.Equals(curve, CurveId, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Unsupported curve '{curve}'; this tool proves over '{CurveId}'.");
        }

        if(queryCount != WiredQueryCount)
        {
            throw new ArgumentException($"Unsupported query count {queryCount}; the wired parameter set uses {WiredQueryCount}.");
        }

        if(digestBytes != WiredDigestBytes)
        {
            throw new ArgumentException($"Unsupported digest size {digestBytes}; the wired parameter set uses {WiredDigestBytes}.");
        }
    }


    private static bool TryValidateHeader(string format, string expectedFormat, string curve, int queryCount, int digestBytes, out string error)
    {
        try
        {
            ValidateHeader(format, expectedFormat, curve, queryCount, digestBytes);
            error = string.Empty;

            return true;
        }
        catch(ArgumentException ex)
        {
            error = ex.Message;

            return false;
        }
    }


    private readonly record struct ClaimDescriptor(
        string Name,
        SupplyChainDirection Direction,
        FixedPointDomain Domain,
        decimal InclusiveMaximum,
        bool IsPublic,
        decimal BoundValue);


    private readonly record struct BuiltStatement(R1csCircuit Circuit, SupplyChainClaim[] Claims);
}
