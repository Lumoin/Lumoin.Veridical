using Lumoin.Base;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Lookup;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Json;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The crypto behind the <c>prove</c> and <c>verify</c> verbs: it turns a
/// <see cref="PredicateProofRequest"/> (statement parameters plus measured
/// quantities) into a <see cref="PredicateProofArtifact"/>, and checks such an
/// artifact against the statement it describes. Both surfaces (the CLI subcommands
/// and the MCP tools) forward here through the JSON boundary, so the two never
/// drift, and the operations themselves are serializer-agnostic — they take and
/// return the <see cref="Lumoin.Veridical.Json"/> envelope types and touch no file
/// or network I/O.
/// </summary>
/// <remarks>
/// <para>
/// The statement is the supply-chain predicate bundle: an ordered conjunction of
/// <c>range</c> claims (at-least / at-most fixed-point comparisons, proven over
/// Spartan-over-Ligero — transparent, hash-based, no trusted setup) and
/// <c>memberOf</c> claims (set membership in a public allowed-value list, each proven
/// by a standalone LogUp-over-Ligero lookup argument). The measured quantities are
/// witness inputs and are not written into the artifact's JSON fields — but every
/// wired path is sound and binding, NOT witness-hiding: the embedded Ligero openings
/// reveal committed data in cleartext (for the wired circuit sizes the Spartan
/// openings determine the full witness by interpolation, and a lookup witness column
/// is the measured value replicated). The artifact must be treated as disclosing the
/// measured values to its recipient; what the proof adds is integrity, not
/// confidentiality. A regulatory bound is either baked into the circuit (a constant)
/// or revealed as a public input; an allowed-value list is public claim data.
/// </para>
/// <para>
/// Each claim's proof attests only its own claim: claim names are unique within a
/// bundle, and no cross-proof binding between the Spartan witness and any lookup
/// witness is asserted — the conjunction is over independently proven statements.
/// Each lookup proof runs on a fresh transcript under the artifact's domain with the
/// claim's name absorbed first, so sibling claims never share a transcript prefix.
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
/// The commitment parameters (curve, Ligero inverse code rate, query count, digest
/// size) are pinned to one wired set that both surfaces enforce, so an artifact
/// cannot silently downgrade them. The wired rate-1/16, 64-column set realises the
/// 128-bit-classical proximity target under the conservative Johnson list-decoding
/// regime (<see cref="WellKnownSecurityLevels.ComputeSpartanOverLigero"/> computes
/// the per-term ledger), and a clamp guard
/// (<see cref="WellKnownSecurityLevels.ThrowIfLigeroSoundnessClamped"/>) rejects
/// any circuit too small to open the full column count, so the tool never ships an
/// under-target proof silently. The lookup path opens three independently forgeable
/// columns (witness, multiplicity, helper), so its query count carries a union-bound
/// surcharge — <see cref="LookupQueryCount"/>, derived from
/// <see cref="WellKnownLigeroParameters"/> — and its own gate checks the realised
/// <see cref="WellKnownSecurityLevels.ComputeLogUpOverLigero"/> ledger at prove and
/// verify time.
/// </para>
/// </remarks>
internal static class PredicateProofOperations
{
    /// <summary>The format identifier of a prove request this tool accepts. Version 3 introduced the per-claim <c>kind</c> discriminator and the <c>memberOf</c> lookup predicate; earlier versions are rejected.</summary>
    public const string RequestFormat = "veridical-supply-chain-predicate-request/3";

    /// <summary>The format identifier this tool stamps on a produced proof artifact. Version 3 introduced the per-claim <c>kind</c> discriminator and the <c>memberOf</c> lookup predicate; earlier versions are rejected.</summary>
    public const string ArtifactFormat = "veridical-supply-chain-predicate-proof/3";

    /// <summary>The <c>kind</c> discriminator of a fixed-point comparison claim.</summary>
    public const string RangeKindName = "range";

    /// <summary>The <c>kind</c> discriminator of an allowed-value set-membership claim.</summary>
    public const string MemberOfKindName = "memberOf";

    /// <summary>The lowercase curve identifier the wired parameter set proves over.</summary>
    public const string CurveId = "bls12-381";

    /// <summary>
    /// The Ligero inverse code rate of the wired parameter set. Rate 1/16 gives 2 soundness
    /// bits per opened column under the Johnson regime and an extension wide enough for the
    /// small supply-chain circuits to open the full 128-bit column count.
    /// </summary>
    public const int WiredInverseRate = 16;

    /// <summary>
    /// The Ligero opened-column query count of the wired parameter set: derived, not
    /// hardcoded, so it always matches the 128-bit-classical target at
    /// <see cref="WiredInverseRate"/> under the wired Johnson regime (64 at rate 1/16).
    /// </summary>
    public static int WiredQueryCount { get; } =
        WellKnownLigeroParameters.ClassicalSecurityQueryCount(WiredInverseRate, WellKnownLigeroParameters.ClassicalSecurityRegime);

    /// <summary>The Merkle digest size in bytes of the wired parameter set.</summary>
    public const int WiredDigestBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The witness-column count of every wired lookup argument: one column carrying the claim's measured value.</summary>
    public const int LookupWitnessColumnCount = 1;

    /// <summary>
    /// The Ligero opened-column query count of the wired lookup parameter set: derived, not
    /// hardcoded. A lookup argument opens <c>M + 2 = 3</c> columns (witness, multiplicity,
    /// helper) and forging any single one suffices, so the union bound prices the proximity
    /// target at <c>128 + log2(3)</c> bits — <c>⌈(128 + log2 3) / 2⌉ = 65</c> opened columns at
    /// <see cref="WiredInverseRate"/> under the wired Johnson regime, one more than
    /// <see cref="WiredQueryCount"/>, whose 64 columns fall about 0.4 bits short of the lookup
    /// target.
    /// </summary>
    public static int LookupQueryCount { get; } = DeriveLookupQueryCount();

    /// <summary>
    /// The smallest lookup-table hypercube the wired parameters admit: at rate 1/16 the
    /// committed extension is <c>15 · 2^⌊n/2⌋</c> columns wide, and opening the full
    /// <see cref="LookupQueryCount"/> needs <c>⌊n/2⌋ ≥ 3</c>. Shorter allowed-value lists are
    /// padded up to <c>2^6</c> table entries by repeating a member, which leaves the table's
    /// set semantics unchanged.
    /// </summary>
    public const int MinimumLookupTableVariableCount = 6;

    /// <summary>The largest lookup-table hypercube the tool accepts: 12 variables, 4096 entries.</summary>
    public const int MaximumLookupTableVariableCount = 12;

    /// <summary>The largest allowed-value list a <c>memberOf</c> claim may carry. The full padded table is absorbed into the transcript and the witness column matches its size, so the cap keeps a claim at CLI scale.</summary>
    public const int MaximumAllowedValueCount = 1 << MaximumLookupTableVariableCount;

    /// <summary>The transcript label under which each lookup proof absorbs its claim's name before proving, separating sibling <c>memberOf</c> claims within one artifact domain.</summary>
    private const string LookupClaimNameLabel = "predicate.lookup.claim.name";

    /// <summary>The largest number of allowed values a statement description lists verbatim before eliding the rest.</summary>
    private const int DescribedAllowedValueCount = 8;

    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;
    private static FiatShamirHashDelegate Hash { get; } = Blake3FiatShamirBackend.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = Blake3FiatShamirBackend.GetSqueeze();


    /// <summary>
    /// Deserializes a prove request from JSON, proves it, and serializes the produced
    /// artifact back to JSON — the string-in, string-out boundary both the CLI
    /// subcommand and the MCP tool forward to.
    /// </summary>
    /// <exception cref="ArgumentNullException">When an argument is null.</exception>
    /// <exception cref="JsonException">When <paramref name="requestJson"/> is not well-formed.</exception>
    /// <exception cref="ArgumentException">When the request header, a claim, or a decimal value is malformed, a measured value is absent from its <c>memberOf</c> claim's allowed values, or a compiled statement falls below its soundness gate.</exception>
    /// <exception cref="R1csCircuitCompilationException">When a range statement is false, so no proof exists.</exception>
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
    /// against its measured quantities, returning the transferable artifact.
    /// </summary>
    /// <exception cref="ArgumentNullException">When an argument is null.</exception>
    /// <exception cref="ArgumentException">When the request header, a claim, or a decimal value is malformed, a measured value is absent from its <c>memberOf</c> claim's allowed values, or a compiled statement falls below its soundness gate.</exception>
    /// <exception cref="R1csCircuitCompilationException">When a range statement is false (a measured quantity does not satisfy its claim), so no proof exists.</exception>
    public static PredicateProofArtifact Prove(PredicateProofRequest request, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(pool);

        ValidateHeader(request.Format, RequestFormat, request.Curve, request.QueryCount, request.InverseRate, request.DigestBytes, request.LookupQueryCount);

        ArgumentNullException.ThrowIfNull(request.Claims);
        var descriptors = new List<ClaimDescriptor>(request.Claims.Count);
        var measured = new Dictionary<string, decimal>(StringComparer.Ordinal);
        foreach(PredicateProofRequestClaim claim in request.Claims)
        {
            ClaimDescriptor descriptor = ParseRequestClaim(claim);
            if(measured.ContainsKey(descriptor.Name))
            {
                throw new ArgumentException($"Claim name '{descriptor.Name}' appears more than once; names identify claims and must be unique.");
            }

            descriptors.Add(descriptor);
            measured[descriptor.Name] = ParseDecimal(claim.Measured, $"claim '{claim.Name}' measured value");
        }

        if(descriptors.Count == 0)
        {
            throw new ArgumentException("The request carries no claims.");
        }

        List<ClaimDescriptor> rangeClaims = FilterByKind(descriptors, PredicateKind.Range);
        List<ClaimDescriptor> lookupClaims = FilterByKind(descriptors, PredicateKind.MemberOf);

        string publicInputs = string.Empty;
        string rangeProof = string.Empty;
        if(rangeClaims.Count > 0)
        {
            (publicInputs, rangeProof) = ProveRangeBundle(rangeClaims, measured, request, pool);
        }

        string[] lookupProofs = ProveLookupClaims(lookupClaims, measured, request, pool);

        return new PredicateProofArtifact
        {
            Format = ArtifactFormat,
            Curve = CurveId,
            TranscriptDomain = request.TranscriptDomain,
            QueryCount = request.QueryCount,
            LookupQueryCount = request.LookupQueryCount,
            InverseRate = request.InverseRate,
            DigestBytes = request.DigestBytes,
            Claims = BuildArtifactClaims(descriptors),
            PublicInputs = publicInputs,
            Proof = rangeProof,
            LookupProofs = lookupProofs,
        };
    }


    /// <summary>
    /// The Spartan-over-Ligero path over the bundle's range claims, unchanged
    /// from the kind-less format: compile the statement circuit with the
    /// measured witness, gate the soundness clamp, prove, and return the
    /// Base64 public inputs and proof.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The Spartan proving key owns the commitment provider and disposes it; every other disposable flows through a using declaration.")]
    private static (string PublicInputs, string Proof) ProveRangeBundle(
        IReadOnlyList<ClaimDescriptor> rangeClaims,
        Dictionary<string, decimal> measured,
        PredicateProofRequest request,
        BaseMemoryPool pool)
    {
        BuiltStatement statement = BuildStatement(rangeClaims);

        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        foreach(ClaimDescriptor descriptor in rangeClaims)
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

        ThrowIfBelowSoundnessTarget(instance, request.InverseRate, request.QueryCount);

        using ScalarArithmeticBackend scalar = Bls12Curve381ManagedScalarBackend.Create();
        using G1ArithmeticBackend g1 = Bls12Curve381ManagedG1Backend.Create();
        MleEvaluateDelegate mleEvaluate = ManagedMultilinearExtensionBackend.CreateEvaluate(scalar, pool);
        MleFoldDelegate mleFold = ManagedMultilinearExtensionBackend.CreateFold(scalar, pool);

        //The NTT row extender accelerates the prover's Ligero encodes; the
        //codeword bytes are identical to the barycentric path, so artifacts are
        //unchanged. The verifier re-encodes no rows and takes no factory.
        using var rowExtenders = new ScalarNttLigeroRowExtenders(scalar.Add, scalar.Subtract, scalar.Multiply, scalar.Invert, Curve, pool, scalar.BatchMultiply);
        using var prover = new SpartanProver(new SpartanProvingKey(BuildProvider(scalar, request.QueryCount, request.InverseRate, request.DigestBytes, rowExtenders.Create)));
        using FiatShamirTranscript transcript = FreshTranscript(request.TranscriptDomain, pool);
        using LigeroSpartanProof proof = prover.ProveLigero(
            instance, witness, transcript,
            Hash, Squeeze, scalar.Reduce, scalar.Add, scalar.Subtract, scalar.Multiply, scalar.Invert, scalar.Random,
            g1.Add, g1.ScalarMultiply, g1.MultiScalarMultiply, mleEvaluate, mleFold, pool);

        return (Convert.ToBase64String(instance.GetPublicInputsBytes()), Convert.ToBase64String(proof.AsReadOnlySpan()));
    }


    /// <summary>
    /// One standalone LogUp-over-Ligero argument per <c>memberOf</c> claim, in
    /// claim order. Proving a value absent from its allowed set fails fast
    /// inside <see cref="LogUpColumns.BuildMultiplicities"/>, before any
    /// commitment work.
    /// </summary>
    private static string[] ProveLookupClaims(
        IReadOnlyList<ClaimDescriptor> lookupClaims,
        Dictionary<string, decimal> measured,
        PredicateProofRequest request,
        BaseMemoryPool pool)
    {
        var lookupProofs = new string[lookupClaims.Count];
        if(lookupClaims.Count == 0)
        {
            return lookupProofs;
        }

        using ScalarArithmeticBackend scalar = Bls12Curve381ManagedScalarBackend.Create();
        using var rowExtenders = new ScalarNttLigeroRowExtenders(scalar.Add, scalar.Subtract, scalar.Multiply, scalar.Invert, Curve, pool, scalar.BatchMultiply);
        for(int i = 0; i < lookupClaims.Count; i++)
        {
            lookupProofs[i] = ProveLookupClaim(lookupClaims[i], measured[lookupClaims[i].Name], request.TranscriptDomain, request.LookupQueryCount, request.InverseRate, request.DigestBytes, scalar, rowExtenders.Create, pool);
        }

        return lookupProofs;
    }


    /// <summary>
    /// Proves one <c>memberOf</c> claim: builds the padded lookup table and
    /// the replicated witness column, gates the lookup ledger, runs the LogUp
    /// prover on a claim-name-separated transcript, and serializes the proof
    /// to Base64 wire bytes.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The commitment provider is created and disposed here through a using declaration.")]
    private static string ProveLookupClaim(
        ClaimDescriptor claim,
        decimal measuredValue,
        string transcriptDomain,
        int queryCount,
        int inverseRate,
        int digestBytes,
        ScalarArithmeticBackend scalar,
        LigeroRowExtenderFactory rowExtenderFactory,
        BaseMemoryPool pool)
    {
        int variableCount = LookupTableVariableCount(claim.AllowedValues.Count);
        ThrowIfLookupBelowSoundnessTarget(variableCount, inverseRate, queryCount);

        int size = 1 << variableCount;
        int columnBytes = size * Scalar.SizeBytes;
        using IMemoryOwner<byte> tableOwner = pool.Rent(columnBytes);
        Span<byte> table = tableOwner.Memory.Span[..columnBytes];
        BuildLookupTable(claim, table);

        //One witness column carrying the measured value at every hypercube
        //point, so the argument's statement is exactly "the measured value
        //appears in the allowed-value table".
        using IMemoryOwner<byte> witnessOwner = pool.Rent(columnBytes);
        Span<byte> witnessColumn = witnessOwner.Memory.Span[..columnBytes];
        Span<byte> encodedMeasured = stackalloc byte[Scalar.SizeBytes];
        WriteCanonicalScalar(claim.Domain.Encode(measuredValue), encodedMeasured);
        for(int row = 0; row < size; row++)
        {
            encodedMeasured.CopyTo(witnessColumn.Slice(row * Scalar.SizeBytes, Scalar.SizeBytes));
        }

        using PolynomialCommitmentProvider provider = BuildProvider(scalar, queryCount, inverseRate, digestBytes, rowExtenderFactory);
        using FiatShamirTranscript transcript = LookupTranscript(transcriptDomain, claim.Name, pool);
        using LogUpProof proof = LogUpProver.Prove(
            table, witnessColumn, variableCount, LookupWitnessColumnCount,
            provider, transcript, Hash, Squeeze, scalar.Reduce, scalar.Add, scalar.Subtract, scalar.Multiply, scalar.Invert, pool);

        int proofBytes = LogUpLigeroProofSerialization.GetBufferSizeBytes(variableCount, LookupWitnessColumnCount, queryCount, inverseRate, digestBytes, Curve);
        using IMemoryOwner<byte> wireOwner = pool.Rent(proofBytes);
        Span<byte> wire = wireOwner.Memory.Span[..proofBytes];
        LogUpLigeroProofSerialization.Write(proof, queryCount, inverseRate, digestBytes, wire);

        return Convert.ToBase64String(wire);
    }


    /// <summary>
    /// Verifies <paramref name="artifact"/> against the statement it describes. Never
    /// throws on artifact content: a well-formed but failing proof returns
    /// <see cref="VerificationStatus.Rejected"/>, and unusable artifact content (bad
    /// encoding, unsupported parameters, mismatched shapes) returns
    /// <see cref="VerificationStatus.Malformed"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException">When an argument is null.</exception>
    public static VerificationResult Verify(PredicateProofArtifact artifact, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        ArgumentNullException.ThrowIfNull(pool);

        if(!TryValidateHeader(artifact.Format, ArtifactFormat, artifact.Curve, artifact.QueryCount, artifact.InverseRate, artifact.DigestBytes, artifact.LookupQueryCount, out string headerError))
        {
            return VerificationResult.Malformed(headerError);
        }

        List<ClaimDescriptor> descriptors;
        byte[] publicInputs;
        byte[] proofBytes;
        byte[][] lookupProofBytes;
        try
        {
            descriptors = ParseArtifactClaims(artifact.Claims);
            publicInputs = DecodeBase64(artifact.PublicInputs, "public inputs");
            proofBytes = DecodeBase64(artifact.Proof, "proof");
            lookupProofBytes = DecodeLookupProofs(artifact.LookupProofs);
        }
        catch(ArgumentException ex)
        {
            return VerificationResult.Malformed(ex.Message);
        }

        if(descriptors.Count == 0)
        {
            return VerificationResult.Malformed("The artifact carries no claims.");
        }

        List<ClaimDescriptor> rangeClaims = FilterByKind(descriptors, PredicateKind.Range);
        List<ClaimDescriptor> lookupClaims = FilterByKind(descriptors, PredicateKind.MemberOf);

        if(lookupProofBytes.Length != lookupClaims.Count)
        {
            return VerificationResult.Malformed($"The artifact carries {lookupProofBytes.Length} lookup proof(s) for {lookupClaims.Count} memberOf claim(s).");
        }

        if(rangeClaims.Count == 0 && (proofBytes.Length > 0 || publicInputs.Length > 0))
        {
            return VerificationResult.Malformed("The artifact carries no range claims but a non-empty range proof or public inputs.");
        }

        try
        {
            bool verified = true;
            if(rangeClaims.Count > 0)
            {
                verified = VerifyRangeBundle(rangeClaims, publicInputs, proofBytes, artifact, pool);
            }

            if(lookupClaims.Count > 0)
            {
                verified &= VerifyLookupClaims(lookupClaims, lookupProofBytes, artifact, pool);
            }

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


    /// <summary>
    /// The Spartan-over-Ligero verify path over the bundle's range claims,
    /// unchanged from the kind-less format: rebuild the circuit, reconstruct
    /// the instance from the revealed public inputs, gate the soundness clamp,
    /// check.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The Spartan verifying key owns the commitment provider and disposes it; every other disposable flows through a using declaration.")]
    private static bool VerifyRangeBundle(
        IReadOnlyList<ClaimDescriptor> rangeClaims,
        byte[] publicInputs,
        byte[] proofBytes,
        PredicateProofArtifact artifact,
        BaseMemoryPool pool)
    {
        BuiltStatement statement = BuildStatement(rangeClaims);

        using RawR1csInstance instance = statement.Circuit.CompileInstance(publicInputs, pool);
        int outerRoundCount = BitOperations.Log2((uint)instance.A.RowCount);
        int innerRoundCount = BitOperations.Log2((uint)instance.A.ColumnCount);

        ThrowIfBelowSoundnessTarget(instance, artifact.InverseRate, artifact.QueryCount);

        using ScalarArithmeticBackend scalar = Bls12Curve381ManagedScalarBackend.Create();
        using LigeroSpartanProof proof = LigeroSpartanProof.FromBytes(proofBytes, outerRoundCount, innerRoundCount, artifact.QueryCount, artifact.InverseRate, artifact.DigestBytes, Curve, pool);
        using var verifier = new SpartanVerifier(new SpartanVerifyingKey(BuildProvider(scalar, artifact.QueryCount, artifact.InverseRate, artifact.DigestBytes)));
        using FiatShamirTranscript transcript = FreshTranscript(artifact.TranscriptDomain, pool);

        return verifier.VerifyLigero(proof, instance, transcript, scalar.Add, scalar.Multiply, scalar.Subtract, scalar.Reduce, Hash, Squeeze, pool);
    }


    /// <summary>
    /// Every <c>memberOf</c> claim's lookup proof must verify; the claims are
    /// checked in claim order against the proofs in artifact order.
    /// </summary>
    private static bool VerifyLookupClaims(
        IReadOnlyList<ClaimDescriptor> lookupClaims,
        byte[][] lookupProofBytes,
        PredicateProofArtifact artifact,
        BaseMemoryPool pool)
    {
        using ScalarArithmeticBackend scalar = Bls12Curve381ManagedScalarBackend.Create();
        MleEvaluateDelegate mleEvaluate = ManagedMultilinearExtensionBackend.CreateEvaluate(scalar, pool);

        bool verified = true;
        for(int i = 0; i < lookupClaims.Count; i++)
        {
            verified &= VerifyLookupClaim(lookupClaims[i], lookupProofBytes[i], artifact.TranscriptDomain, artifact.LookupQueryCount, artifact.InverseRate, artifact.DigestBytes, scalar, mleEvaluate, pool);
        }

        return verified;
    }


    /// <summary>
    /// Verifies one <c>memberOf</c> claim: rebuilds the padded lookup table
    /// from the claim's own allowed values, gates the lookup ledger,
    /// reconstructs the proof through the canonicity funnel, and checks it on
    /// the claim-name-separated transcript.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The commitment provider is created and disposed here through a using declaration.")]
    private static bool VerifyLookupClaim(
        ClaimDescriptor claim,
        byte[] proofBytes,
        string transcriptDomain,
        int queryCount,
        int inverseRate,
        int digestBytes,
        ScalarArithmeticBackend scalar,
        MleEvaluateDelegate mleEvaluate,
        BaseMemoryPool pool)
    {
        int variableCount = LookupTableVariableCount(claim.AllowedValues.Count);
        ThrowIfLookupBelowSoundnessTarget(variableCount, inverseRate, queryCount);

        int columnBytes = (1 << variableCount) * Scalar.SizeBytes;
        using IMemoryOwner<byte> tableOwner = pool.Rent(columnBytes);
        Span<byte> table = tableOwner.Memory.Span[..columnBytes];
        BuildLookupTable(claim, table);

        using PolynomialCommitmentProvider provider = BuildProvider(scalar, queryCount, inverseRate, digestBytes);
        using LogUpProof proof = LogUpLigeroProofSerialization.FromBytes(proofBytes, variableCount, LookupWitnessColumnCount, queryCount, inverseRate, digestBytes, Curve, pool);
        using FiatShamirTranscript transcript = LookupTranscript(transcriptDomain, claim.Name, pool);

        return LogUpVerifier.Verify(table, proof, provider, transcript, Hash, Squeeze, scalar.Reduce, scalar.Add, scalar.Subtract, scalar.Multiply, scalar.Invert, mleEvaluate, pool);
    }


    /// <summary>
    /// Builds the statement circuit deterministically from the claim
    /// descriptors so the prover and the verifier compile the identical
    /// circuit. Public-input bound variables are declared first (the builder's
    /// contiguity rule), in claim order, then the measured witness variables
    /// in claim order. For a public bound the <see cref="FixedPointBound"/>'s
    /// value is not part of the circuit structure (the predicate references
    /// the variable, not the value), so the verifier can supply a placeholder.
    /// </summary>
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
    private static PolynomialCommitmentProvider BuildProvider(ScalarArithmeticBackend scalar, int queryCount, int inverseRate, int digestBytes, LigeroRowExtenderFactory? rowExtenderFactory = null)
    {
        return LigeroPolynomialCommitmentScheme.Create(
            Curve, queryCount,
            scalar.Add, scalar.Subtract, scalar.Multiply, scalar.Invert, scalar.Reduce,
            Hash, Squeeze, Hash, HashTwoToOne, WellKnownHashAlgorithms.Blake3, digestBytes, inverseRate, rowExtenderFactory);
    }


    /// <summary>
    /// The soundness clamp guard over both embedded openings: the error
    /// opening spans the row variables and the witness opening the column
    /// variables, so each must carry the full opened-column count for the
    /// artifact's parameters to realise their target. Runs at prove AND verify
    /// time; the thrown exception surfaces as a prover error or a Malformed
    /// verdict.
    /// </summary>
    /// <exception cref="ArgumentException">When the extension width clamps an opening below the wired query count.</exception>
    private static void ThrowIfBelowSoundnessTarget(RawR1csInstance instance, int inverseRate, int queryCount)
    {
        int outerVariableCount = BitOperations.Log2((uint)instance.A.RowCount);
        int innerVariableCount = BitOperations.Log2((uint)instance.A.ColumnCount);

        WellKnownSecurityLevels.ThrowIfLigeroSoundnessClamped(outerVariableCount, inverseRate, queryCount);
        WellKnownSecurityLevels.ThrowIfLigeroSoundnessClamped(innerVariableCount, inverseRate, queryCount);
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


    /// <summary>
    /// The Ligero two-to-one Merkle hash: BLAKE3 over the concatenation of the
    /// two child digests, matching the digest width the provider is configured
    /// with.
    /// </summary>
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
        FixedPointDomain domain = BuildDomain(claim.FractionalDigits, claim.InclusiveMaximum, out decimal inclusiveMaximum);

        if(ParseKind(claim.Kind, claim.Name) == PredicateKind.MemberOf)
        {
            return ParseMemberOfDescriptor(claim.Name, domain, inclusiveMaximum, claim.Direction, claim.Bound, claim.BoundValue, claim.AllowedValues);
        }

        ThrowIfNotRangeShaped(claim.Name, claim.Direction, claim.Bound, claim.AllowedValues);
        SupplyChainDirection direction = ParseDirection(claim.Direction!);
        bool isPublic = ParseBoundKind(claim.Bound!);
        if(claim.BoundValue is null)
        {
            throw new ArgumentException($"Range claim '{claim.Name}' carries no bound value.");
        }

        decimal boundValue = ParseDecimal(claim.BoundValue, $"claim '{claim.Name}' bound value");

        return new ClaimDescriptor(claim.Name, PredicateKind.Range, direction, domain, inclusiveMaximum, isPublic, boundValue, []);
    }


    private static List<ClaimDescriptor> ParseArtifactClaims(IReadOnlyList<PredicateProofClaim> claims)
    {
        ArgumentNullException.ThrowIfNull(claims);
        var descriptors = new List<ClaimDescriptor>(claims.Count);
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach(PredicateProofClaim claim in claims)
        {
            ArgumentNullException.ThrowIfNull(claim);
            if(!names.Add(claim.Name))
            {
                throw new ArgumentException($"Claim name '{claim.Name}' appears more than once; names identify claims and must be unique.");
            }

            FixedPointDomain domain = BuildDomain(claim.FractionalDigits, claim.InclusiveMaximum, out decimal inclusiveMaximum);

            if(ParseKind(claim.Kind, claim.Name) == PredicateKind.MemberOf)
            {
                descriptors.Add(ParseMemberOfDescriptor(claim.Name, domain, inclusiveMaximum, claim.Direction, claim.Bound, claim.Value, claim.AllowedValues));

                continue;
            }

            ThrowIfNotRangeShaped(claim.Name, claim.Direction, claim.Bound, claim.AllowedValues);
            SupplyChainDirection direction = ParseDirection(claim.Direction!);
            bool isPublic = ParseBoundKind(claim.Bound!);

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

            descriptors.Add(new ClaimDescriptor(claim.Name, PredicateKind.Range, direction, domain, inclusiveMaximum, isPublic, boundValue, []));
        }

        return descriptors;
    }


    /// <summary>Parses the claim-kind discriminator, rejecting anything but <c>range</c> and <c>memberOf</c>.</summary>
    /// <exception cref="ArgumentException">When the kind is unrecognised.</exception>
    private static PredicateKind ParseKind(string kind, string claimName)
    {
        if(string.Equals(kind, RangeKindName, StringComparison.OrdinalIgnoreCase))
        {
            return PredicateKind.Range;
        }

        if(string.Equals(kind, MemberOfKindName, StringComparison.OrdinalIgnoreCase))
        {
            return PredicateKind.MemberOf;
        }

        throw new ArgumentException($"Unknown predicate kind '{kind}' on claim '{claimName}'; expected '{RangeKindName}' or '{MemberOfKindName}'.");
    }


    /// <summary>
    /// A range claim must carry its comparison fields and no allowed-value
    /// list; the kinds keep disjoint field sets so an artifact cannot smuggle
    /// one predicate's parameters under the other's discriminator.
    /// </summary>
    /// <exception cref="ArgumentException">When the claim's field set does not match the range shape.</exception>
    private static void ThrowIfNotRangeShaped(string claimName, string? direction, string? bound, IReadOnlyList<string>? allowedValues)
    {
        if(direction is null || bound is null)
        {
            throw new ArgumentException($"Range claim '{claimName}' must carry 'direction' and 'bound'.");
        }

        if(allowedValues is not null)
        {
            throw new ArgumentException($"Range claim '{claimName}' must not carry 'allowedValues'.");
        }
    }


    /// <summary>
    /// Parses a <c>memberOf</c> claim's descriptor: the comparison fields must
    /// be absent, the allowed-value list non-empty and within the wired cap,
    /// and every allowed value encodable in the claim's fixed-point domain.
    /// </summary>
    /// <exception cref="ArgumentException">When the claim's field set or an allowed value is malformed.</exception>
    private static ClaimDescriptor ParseMemberOfDescriptor(
        string claimName,
        FixedPointDomain domain,
        decimal inclusiveMaximum,
        string? direction,
        string? bound,
        string? boundValue,
        IReadOnlyList<string>? allowedValues)
    {
        if(direction is not null || bound is not null || boundValue is not null)
        {
            throw new ArgumentException($"MemberOf claim '{claimName}' must not carry 'direction', 'bound' or a bound value.");
        }

        if(allowedValues is null || allowedValues.Count == 0)
        {
            throw new ArgumentException($"MemberOf claim '{claimName}' must carry a non-empty 'allowedValues' list.");
        }

        if(allowedValues.Count > MaximumAllowedValueCount)
        {
            throw new ArgumentException($"MemberOf claim '{claimName}' carries {allowedValues.Count} allowed values; the wired maximum is {MaximumAllowedValueCount}.");
        }

        var parsed = new decimal[allowedValues.Count];
        for(int i = 0; i < allowedValues.Count; i++)
        {
            parsed[i] = ParseDecimal(allowedValues[i], $"claim '{claimName}' allowed value {i}");

            //Encoding validates scale exactness and the domain range up front,
            //so a malformed list fails before any proving work starts.
            _ = domain.Encode(parsed[i]);
        }

        return new ClaimDescriptor(claimName, PredicateKind.MemberOf, SupplyChainDirection.AtLeast, domain, inclusiveMaximum, IsPublic: false, decimal.Zero, parsed);
    }


    /// <summary>Selects the descriptors of one predicate kind, preserving claim order.</summary>
    private static List<ClaimDescriptor> FilterByKind(IReadOnlyList<ClaimDescriptor> descriptors, PredicateKind kind)
    {
        var filtered = new List<ClaimDescriptor>(descriptors.Count);
        foreach(ClaimDescriptor descriptor in descriptors)
        {
            if(descriptor.Kind == kind)
            {
                filtered.Add(descriptor);
            }
        }

        return filtered;
    }


    private static PredicateProofClaim[] BuildArtifactClaims(IReadOnlyList<ClaimDescriptor> descriptors)
    {
        var claims = new PredicateProofClaim[descriptors.Count];
        for(int i = 0; i < descriptors.Count; i++)
        {
            ClaimDescriptor descriptor = descriptors[i];
            if(descriptor.Kind == PredicateKind.MemberOf)
            {
                var allowedValues = new string[descriptor.AllowedValues.Count];
                for(int j = 0; j < allowedValues.Length; j++)
                {
                    allowedValues[j] = descriptor.AllowedValues[j].ToString(CultureInfo.InvariantCulture);
                }

                claims[i] = new PredicateProofClaim
                {
                    Name = descriptor.Name,
                    Kind = MemberOfKindName,
                    FractionalDigits = descriptor.Domain.Scale.FractionalDigits,
                    InclusiveMaximum = descriptor.InclusiveMaximum.ToString(CultureInfo.InvariantCulture),
                    AllowedValues = allowedValues,
                };

                continue;
            }

            claims[i] = new PredicateProofClaim
            {
                Name = descriptor.Name,
                Kind = RangeKindName,
                Direction = DirectionToString(descriptor.Direction),
                FractionalDigits = descriptor.Domain.Scale.FractionalDigits,
                InclusiveMaximum = descriptor.InclusiveMaximum.ToString(CultureInfo.InvariantCulture),
                Bound = descriptor.IsPublic ? "public" : "constant",
                Value = descriptor.IsPublic ? null : descriptor.BoundValue.ToString(CultureInfo.InvariantCulture),
            };
        }

        return claims;
    }


    /// <summary>
    /// A one-line, operator-facing description of the proven statement.
    /// Constant bounds are shown from the descriptor; public bounds are
    /// decoded from the revealed public inputs, in public-input declaration
    /// order; <c>memberOf</c> claims list their allowed values.
    /// </summary>
    private static string DescribeStatement(IReadOnlyList<ClaimDescriptor> claims, ReadOnlySpan<byte> publicInputs)
    {
        int scalarSize = Scalar.SizeBytes;
        int offset = 0;
        var builder = new StringBuilder();
        foreach(ClaimDescriptor claim in claims)
        {
            if(claim.Kind == PredicateKind.MemberOf)
            {
                if(builder.Length > 0)
                {
                    builder.Append("; ");
                }

                AppendMemberOfDescription(builder, claim);

                continue;
            }

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


    /// <summary>
    /// A <c>memberOf</c> claim reads <c>name in {v1, v2, ...}</c>; long lists
    /// are elided after the first few members but always report their full
    /// count.
    /// </summary>
    private static void AppendMemberOfDescription(StringBuilder builder, ClaimDescriptor claim)
    {
        builder.Append(claim.Name).Append(" in {");
        int shown = Math.Min(claim.AllowedValues.Count, DescribedAllowedValueCount);
        for(int i = 0; i < shown; i++)
        {
            if(i > 0)
            {
                builder.Append(", ");
            }

            builder.Append(claim.AllowedValues[i].ToString(CultureInfo.InvariantCulture));
        }

        if(claim.AllowedValues.Count > shown)
        {
            builder.Append(", ...");
        }

        builder.Append("} (")
            .Append(claim.AllowedValues.Count.ToString(CultureInfo.InvariantCulture))
            .Append(" allowed value(s))");
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


    private static void ValidateHeader(string format, string expectedFormat, string curve, int queryCount, int inverseRate, int digestBytes, int lookupQueryCount)
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

        if(inverseRate != WiredInverseRate)
        {
            throw new ArgumentException($"Unsupported inverse rate {inverseRate}; the wired parameter set uses {WiredInverseRate}.");
        }

        if(digestBytes != WiredDigestBytes)
        {
            throw new ArgumentException($"Unsupported digest size {digestBytes}; the wired parameter set uses {WiredDigestBytes}.");
        }

        if(lookupQueryCount != LookupQueryCount)
        {
            throw new ArgumentException($"Unsupported lookup query count {lookupQueryCount}; the wired parameter set uses {LookupQueryCount}.");
        }
    }


    private static bool TryValidateHeader(string format, string expectedFormat, string curve, int queryCount, int inverseRate, int digestBytes, int lookupQueryCount, out string error)
    {
        try
        {
            ValidateHeader(format, expectedFormat, curve, queryCount, inverseRate, digestBytes, lookupQueryCount);
            error = string.Empty;

            return true;
        }
        catch(ArgumentException ex)
        {
            error = ex.Message;

            return false;
        }
    }


    /// <summary>
    /// The union-bound-surcharged opened-column count of the lookup path: the
    /// target is the classical level plus log2 of the independently forgeable
    /// opening count, divided by the per-column soundness of the wired rate
    /// and regime.
    /// </summary>
    private static int DeriveLookupQueryCount()
    {
        double unionBoundBits = Math.Log2(LookupWitnessColumnCount + LogUpProver.AuxiliaryColumnCount);
        double bitsPerColumn = WellKnownLigeroParameters.BitsPerOpenedColumn(WellKnownLigeroParameters.ClassicalSecurityRegime, WiredInverseRate);

        return (int)Math.Ceiling((WellKnownLigeroParameters.ClassicalSecurityLevelBits + unionBoundBits) / bitsPerColumn);
    }


    /// <summary>
    /// The lookup soundness gate — the
    /// <see cref="WellKnownSecurityLevels.ComputeLogUpOverLigero"/> consumer:
    /// the realised bottleneck across the union-bounded proximity, sumcheck
    /// and field terms must cover the classical target. Runs at prove AND
    /// verify time; the thrown exception surfaces as a prover error or a
    /// Malformed verdict.
    /// </summary>
    /// <exception cref="ArgumentException">When the realised bits fall below the classical target.</exception>
    private static void ThrowIfLookupBelowSoundnessTarget(int variableCount, int inverseRate, int queryCount)
    {
        SecurityLevelLedger ledger = WellKnownSecurityLevels.ComputeLogUpOverLigero(Curve, variableCount, LookupWitnessColumnCount, inverseRate, queryCount);
        if(ledger.EffectiveBits < WellKnownLigeroParameters.ClassicalSecurityLevelBits)
        {
            throw new ArgumentException(
                $"The lookup parameters realise {ledger.EffectiveBits.ToString("F2", CultureInfo.InvariantCulture)} soundness bits at {variableCount} table variable(s), below the {WellKnownLigeroParameters.ClassicalSecurityLevelBits}-bit target.");
        }
    }


    /// <summary>
    /// The table hypercube for an allowed-value count: the next power of two,
    /// floored at the wired minimum so the full lookup query count always
    /// opens.
    /// </summary>
    private static int LookupTableVariableCount(int allowedValueCount)
    {
        int paddedCount = (int)BitOperations.RoundUpToPowerOf2((uint)allowedValueCount);

        return Math.Max(MinimumLookupTableVariableCount, BitOperations.Log2((uint)paddedCount));
    }


    /// <summary>
    /// The table is the claim's allowed values padded to the hypercube size by
    /// repeating the first member — duplicate table entries are legal in LogUp
    /// and padding with a member leaves the table's set semantics unchanged.
    /// </summary>
    private static void BuildLookupTable(ClaimDescriptor claim, Span<byte> table)
    {
        Span<byte> encoded = stackalloc byte[Scalar.SizeBytes];
        int count = claim.AllowedValues.Count;
        for(int i = 0; i < count; i++)
        {
            WriteCanonicalScalar(claim.Domain.Encode(claim.AllowedValues[i]), encoded);
            encoded.CopyTo(table.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes));
        }

        WriteCanonicalScalar(claim.Domain.Encode(claim.AllowedValues[0]), encoded);
        int totalEntries = table.Length / Scalar.SizeBytes;
        for(int i = count; i < totalEntries; i++)
        {
            encoded.CopyTo(table.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes));
        }
    }


    /// <summary>
    /// Canonical 32-byte big-endian encoding of a domain-encoded value; every
    /// domain maximum keeps the encoding far below the scalar-field order.
    /// </summary>
    /// <exception cref="ArgumentException">When the value does not fit the destination.</exception>
    private static void WriteCanonicalScalar(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        int byteCount = value.GetByteCount(isUnsigned: true);
        if(byteCount > destination.Length || !value.TryWriteBytes(destination[^byteCount..], out _, isUnsigned: true, isBigEndian: true))
        {
            throw new ArgumentException($"The encoded value needs {byteCount} bytes and does not fit a {destination.Length}-byte scalar.");
        }
    }


    /// <summary>
    /// A fresh transcript per lookup proof under the artifact's shared domain,
    /// with the claim's name absorbed first: sibling <c>memberOf</c> claims in
    /// one artifact never share a transcript prefix even when their tables and
    /// measured values coincide.
    /// </summary>
    private static FiatShamirTranscript LookupTranscript(string transcriptDomain, string claimName, BaseMemoryPool pool)
    {
        FiatShamirTranscript transcript = FreshTranscript(transcriptDomain, pool);
        try
        {
            int nameByteCount = Encoding.UTF8.GetByteCount(claimName);
            using IMemoryOwner<byte> nameOwner = pool.Rent(nameByteCount);
            Span<byte> nameBytes = nameOwner.Memory.Span[..nameByteCount];
            Encoding.UTF8.GetBytes(claimName, nameBytes);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(LookupClaimNameLabel), nameBytes, Hash);

            return transcript;
        }
        catch
        {
            transcript.Dispose();
            throw;
        }
    }


    /// <summary>Decodes the artifact's Base64 lookup proofs, rejecting a missing list or invalid encoding.</summary>
    /// <exception cref="ArgumentException">When the list is absent or an entry is not valid Base64.</exception>
    private static byte[][] DecodeLookupProofs(IReadOnlyList<string> lookupProofs)
    {
        if(lookupProofs is null)
        {
            throw new ArgumentException("The artifact carries no lookup-proof list.");
        }

        var decoded = new byte[lookupProofs.Count][];
        for(int i = 0; i < decoded.Length; i++)
        {
            decoded[i] = DecodeBase64(lookupProofs[i], $"lookup proof {i} bytes");
        }

        return decoded;
    }


    /// <summary>The parsed claim-kind discriminator.</summary>
    private enum PredicateKind
    {
        /// <summary>A fixed-point comparison claim proven in the Spartan R1CS bundle.</summary>
        Range,

        /// <summary>An allowed-value set-membership claim proven by a standalone LogUp argument.</summary>
        MemberOf
    }


    /// <summary>
    /// One parsed claim: the shared fixed-point domain plus either the range
    /// comparison fields (<see cref="Direction"/>, <see cref="IsPublic"/>,
    /// <see cref="BoundValue"/>) or the <c>memberOf</c> allowed-value list —
    /// the unused side holds defaults.
    /// </summary>
    private readonly record struct ClaimDescriptor(
        string Name,
        PredicateKind Kind,
        SupplyChainDirection Direction,
        FixedPointDomain Domain,
        decimal InclusiveMaximum,
        bool IsPublic,
        decimal BoundValue,
        IReadOnlyList<decimal> AllowedValues);


    private readonly record struct BuiltStatement(R1csCircuit Circuit, SupplyChainClaim[] Claims);
}
