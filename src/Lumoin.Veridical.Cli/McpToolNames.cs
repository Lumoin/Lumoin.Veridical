namespace Lumoin.Veridical.Cli;

/// <summary>
/// Stable names for the MCP tools the Veridical MCP server exposes. Pinned as
/// constants so the server registration and any test or documentation reference
/// the same identifiers.
/// </summary>
internal static class McpToolNames
{
    /// <summary>Platform and scalar-backend information.</summary>
    public const string Info = "Info";

    /// <summary>BLAKE3-256 hash of a text input.</summary>
    public const string Hash = "Hash";

    /// <summary>Run the known-answer conformance vectors.</summary>
    public const string SelfTest = "SelfTest";

    /// <summary>Prove a supply-chain predicate bundle from local data.</summary>
    public const string Prove = "Prove";

    /// <summary>Verify a supply-chain predicate proof artifact.</summary>
    public const string Verify = "Verify";

    /// <summary>Prove a Longfellow JWT presentation token.</summary>
    public const string LongfellowJwtProve = "LongfellowJwtProve";

    /// <summary>Verify a Longfellow JWT proof.</summary>
    public const string LongfellowJwtVerify = "LongfellowJwtVerify";

    /// <summary>Generate a BBS key pair.</summary>
    public const string BbsKeyGenerate = "BbsKeyGenerate";

    /// <summary>Sign messages with a BBS secret key.</summary>
    public const string BbsSign = "BbsSign";

    /// <summary>Verify a BBS signature.</summary>
    public const string BbsVerify = "BbsVerify";

    /// <summary>Derive a BBS selective-disclosure proof.</summary>
    public const string BbsProofGenerate = "BbsProofGenerate";

    /// <summary>Verify a BBS selective-disclosure proof.</summary>
    public const string BbsProofVerify = "BbsProofVerify";

    /// <summary>The SecdsaSplitSign tool.</summary>
    public const string SecdsaSplitSign = "SecdsaSplitSign";

    /// <summary>The SecdsaPublicKey tool.</summary>
    public const string SecdsaPublicKey = "SecdsaPublicKey";

    /// <summary>The SecdsaVerify tool.</summary>
    public const string SecdsaVerify = "SecdsaVerify";

    /// <summary>The SecdsaRecoverNoncePoint tool.</summary>
    public const string SecdsaRecoverNoncePoint = "SecdsaRecoverNoncePoint";

    /// <summary>The SecdsaVerifyFull tool.</summary>
    public const string SecdsaVerifyFull = "SecdsaVerifyFull";

    /// <summary>The SecdsaDlProve tool.</summary>
    public const string SecdsaDlProve = "SecdsaDlProve";

    /// <summary>The SecdsaDlVerify tool.</summary>
    public const string SecdsaDlVerify = "SecdsaDlVerify";

    /// <summary>The SecdsaBlindingProve tool.</summary>
    public const string SecdsaBlindingProve = "SecdsaBlindingProve";

    /// <summary>The SecdsaBlindingVerify tool.</summary>
    public const string SecdsaBlindingVerify = "SecdsaBlindingVerify";

    /// <summary>The SecdsaControlProve tool.</summary>
    public const string SecdsaControlProve = "SecdsaControlProve";

    /// <summary>The SecdsaControlVerify tool.</summary>
    public const string SecdsaControlVerify = "SecdsaControlVerify";

    /// <summary>The SecdsaEcdhMacDeriveKey tool.</summary>
    public const string SecdsaEcdhMacDeriveKey = "SecdsaEcdhMacDeriveKey";

    /// <summary>The SecdsaEcdhMacSign tool.</summary>
    public const string SecdsaEcdhMacSign = "SecdsaEcdhMacSign";

    /// <summary>The SecdsaEcdhMacVerify tool.</summary>
    public const string SecdsaEcdhMacVerify = "SecdsaEcdhMacVerify";

    /// <summary>The SecdsaEcdhMacSplitSign tool.</summary>
    public const string SecdsaEcdhMacSplitSign = "SecdsaEcdhMacSplitSign";

    /// <summary>The AnalysisBaseFoldLeakage tool.</summary>
    public const string AnalysisBaseFoldLeakage = "AnalysisBaseFoldLeakage";

    /// <summary>The AnalysisWelchT tool.</summary>
    public const string AnalysisWelchT = "AnalysisWelchT";

    /// <summary>The AnalysisKolmogorovSmirnov tool.</summary>
    public const string AnalysisKolmogorovSmirnov = "AnalysisKolmogorovSmirnov";

    /// <summary>The AnalysisChiSquared tool.</summary>
    public const string AnalysisChiSquared = "AnalysisChiSquared";

    /// <summary>All exposed tool names.</summary>
    public static string[] All { get; } =
    [
        Info,
        Hash,
        SelfTest,
        Prove,
        Verify,
        LongfellowJwtProve,
        LongfellowJwtVerify,
        BbsKeyGenerate,
        BbsSign,
        BbsVerify,
        BbsProofGenerate,
        BbsProofVerify,
        SecdsaSplitSign,
        SecdsaPublicKey,
        SecdsaVerify,
        SecdsaRecoverNoncePoint,
        SecdsaVerifyFull,
        SecdsaDlProve,
        SecdsaDlVerify,
        SecdsaBlindingProve,
        SecdsaBlindingVerify,
        SecdsaControlProve,
        SecdsaControlVerify,
        SecdsaEcdhMacDeriveKey,
        SecdsaEcdhMacSign,
        SecdsaEcdhMacVerify,
        SecdsaEcdhMacSplitSign,
        AnalysisBaseFoldLeakage,
        AnalysisWelchT,
        AnalysisKolmogorovSmirnov,
        AnalysisChiSquared
    ];
}
