using System;
using System.Collections.Immutable;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// Read-only structural inspection of a <see cref="BbsProof"/>:
/// extracts the component hex strings, byte length, and undisclosed
/// count without performing any cryptographic operations. Mirror of
/// <see cref="BbsSignatureInspector"/> for the proof type.
/// </summary>
public static class BbsProofInspector
{
    /// <summary>Inspects <paramref name="proof"/> and returns a bundled report.</summary>
    /// <exception cref="ArgumentNullException">When <paramref name="proof"/> is <see langword="null"/>.</exception>
    public static BbsProofInspectionReport Inspect(BbsProof proof)
    {
        ArgumentNullException.ThrowIfNull(proof);

        ImmutableArray<string>.Builder commitments = ImmutableArray.CreateBuilder<string>(proof.UndisclosedMessageCount);
        for(int i = 0; i < proof.UndisclosedMessageCount; i++)
        {
            commitments.Add(Convert.ToHexStringLower(proof.GetCommitmentBytes(i)));
        }


        return new BbsProofInspectionReport(
            ByteLength: proof.AsReadOnlySpan().Length,
            UndisclosedMessageCount: proof.UndisclosedMessageCount,
            CiphersuiteIdentifier: proof.Ciphersuite.Identifier,
            ABarHex: Convert.ToHexStringLower(proof.GetABarBytes()),
            BBarHex: Convert.ToHexStringLower(proof.GetBBarBytes()),
            DHex: Convert.ToHexStringLower(proof.GetDBytes()),
            EHatHex: Convert.ToHexStringLower(proof.GetEHatBytes()),
            R1HatHex: Convert.ToHexStringLower(proof.GetR1HatBytes()),
            R3HatHex: Convert.ToHexStringLower(proof.GetR3HatBytes()),
            CommitmentHexValues: commitments.MoveToImmutable(),
            ChallengeHex: Convert.ToHexStringLower(proof.GetChallengeBytes()));
    }
}


/// <summary>Bundled facts about a single <see cref="BbsProof"/>.</summary>
/// <param name="ByteLength">Length in bytes of the canonical encoding (<c>272 + 32 * UndisclosedMessageCount</c>).</param>
/// <param name="UndisclosedMessageCount">Number of undisclosed-message commitment scalars carried in the proof.</param>
/// <param name="CiphersuiteIdentifier">The BBS+ ciphersuite api_id this proof was produced under.</param>
/// <param name="ABarHex">Lowercase hexadecimal rendering of the 48-byte G1 component <c>Abar</c>.</param>
/// <param name="BBarHex">Lowercase hexadecimal rendering of the 48-byte G1 component <c>Bbar</c>.</param>
/// <param name="DHex">Lowercase hexadecimal rendering of the 48-byte G1 component <c>D</c>.</param>
/// <param name="EHatHex">Lowercase hexadecimal rendering of the 32-byte scalar <c>e^</c>.</param>
/// <param name="R1HatHex">Lowercase hexadecimal rendering of the 32-byte scalar <c>r1^</c>.</param>
/// <param name="R3HatHex">Lowercase hexadecimal rendering of the 32-byte scalar <c>r3^</c>.</param>
/// <param name="CommitmentHexValues">Lowercase hexadecimal renderings of the per-undisclosed-message commitment scalars <c>m^_j</c>, in proof byte order.</param>
/// <param name="ChallengeHex">Lowercase hexadecimal rendering of the 32-byte challenge scalar <c>c</c>.</param>
public sealed record BbsProofInspectionReport(
    int ByteLength,
    int UndisclosedMessageCount,
    string CiphersuiteIdentifier,
    string ABarHex,
    string BBarHex,
    string DHex,
    string EHatHex,
    string R1HatHex,
    string R3HatHex,
    ImmutableArray<string> CommitmentHexValues,
    string ChallengeHex);