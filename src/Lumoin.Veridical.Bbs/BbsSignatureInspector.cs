using System;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// Read-only structural inspection of a <see cref="BbsSignature"/>:
/// extracts the component hex strings and the ciphersuite identifier
/// without performing any cryptographic operations.
/// </summary>
public static class BbsSignatureInspector
{
    /// <summary>Inspects <paramref name="signature"/> and returns a bundled report.</summary>
    /// <exception cref="ArgumentNullException">When <paramref name="signature"/> is <see langword="null"/>.</exception>
    public static BbsSignatureInspectionReport Inspect(BbsSignature signature)
    {
        ArgumentNullException.ThrowIfNull(signature);

        return new BbsSignatureInspectionReport(
            ByteLength: signature.AsReadOnlySpan().Length,
            CiphersuiteIdentifier: signature.Ciphersuite.Identifier,
            AHex: Convert.ToHexStringLower(signature.GetABytes()),
            EHex: Convert.ToHexStringLower(signature.GetEBytes()));
    }
}


/// <summary>Bundled facts about a single <see cref="BbsSignature"/>.</summary>
/// <param name="ByteLength">Length in bytes of the canonical encoding (always 80 for well-formed signatures).</param>
/// <param name="CiphersuiteIdentifier">The BBS+ ciphersuite api_id this signature was produced under.</param>
/// <param name="AHex">Lowercase hexadecimal rendering of the 48-byte G1 component <c>A</c>.</param>
/// <param name="EHex">Lowercase hexadecimal rendering of the 32-byte scalar component <c>e</c>.</param>
public sealed record BbsSignatureInspectionReport(
    int ByteLength,
    string CiphersuiteIdentifier,
    string AHex,
    string EHex);