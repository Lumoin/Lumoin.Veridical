namespace Lumoin.Veridical.Cli;

/// <summary>The outcome of verifying a predicate-proof artifact.</summary>
internal enum VerificationStatus
{
    /// <summary>The proof is valid for the statement it describes.</summary>
    Valid,

    /// <summary>The artifact was well-formed but the proof did not verify.</summary>
    Rejected,

    /// <summary>The artifact could not be checked: bad encoding, unsupported parameters, or a shape mismatch.</summary>
    Malformed,
}


/// <summary>
/// The result of <see cref="PredicateProofOperations.Verify"/>: a status plus a
/// message — the described statement for a valid or rejected proof, or the reason an
/// artifact could not be checked when malformed.
/// </summary>
internal sealed record VerificationResult
{
    /// <summary>The verification status.</summary>
    public required VerificationStatus Status { get; init; }

    /// <summary>The described statement (valid or rejected), or the malformed-artifact reason.</summary>
    public required string Message { get; init; }

    /// <summary>Whether the proof verified.</summary>
    public bool IsValid => Status == VerificationStatus.Valid;


    /// <summary>A single-line, operator-facing report of this outcome.</summary>
    public string ToReport()
    {
        return Status switch
        {
            VerificationStatus.Valid => $"VALID: proves {Message}",
            VerificationStatus.Rejected => $"REJECTED: the proof did not verify for {Message}",
            VerificationStatus.Malformed => $"MALFORMED: {Message}",
            _ => "UNKNOWN",
        };
    }


    /// <summary>A valid proof of <paramref name="statement"/>.</summary>
    public static VerificationResult Valid(string statement)
    {
        return new VerificationResult { Status = VerificationStatus.Valid, Message = statement };
    }


    /// <summary>A well-formed artifact whose proof did not verify against <paramref name="statement"/>.</summary>
    public static VerificationResult Rejected(string statement)
    {
        return new VerificationResult { Status = VerificationStatus.Rejected, Message = statement };
    }


    /// <summary>An artifact that could not be checked, for the given <paramref name="reason"/>.</summary>
    public static VerificationResult Malformed(string reason)
    {
        return new VerificationResult { Status = VerificationStatus.Malformed, Message = reason };
    }
}
