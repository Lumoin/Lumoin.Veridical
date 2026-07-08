using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Blind;

/// <summary>
/// The IETF draft revision the blind-BBS operations (Commit,
/// CoreCommit, deserialize_and_validate_commit, etc.) target, and the
/// revision the vectors in this directory were actually transcribed
/// from. When the draft rolls, these constants update and the
/// vectors get re-transcribed in the same commit.
/// </summary>
internal static class BlindDraftRevision
{
    /// <summary>The IETF draft identifier the blind-BBS operations target.</summary>
    public const string Identifier = "draft-irtf-cfrg-bbs-blind-signatures-03";

    /// <summary>The month and year the -03 draft was published.</summary>
    public const string Date = "2026-06";

    /// <summary>
    /// -03 Section 10 ships no test vectors verbatim (it reads, in
    /// full: "Test vectors are being revised to include new committed
    /// disclosure functionality."). The commitment and generator
    /// vectors in this directory are transcribed from this earlier
    /// revision's Appendix, Section 9, instead. That transcription
    /// remains valid under -03 because CoreCommit,
    /// calculate_blind_challenge, and the commitment-with-proof
    /// serialization are textually identical between -02 and -03;
    /// only the blind proof interface (framed disclosure, the added
    /// Q_2 domain generator) changed between the two revisions, which
    /// is why -02's blind-signature and blind-proof vectors do NOT
    /// carry over to -03 and are deliberately not transcribed here.
    /// </summary>
    public const string CommitmentVectorSourceRevision = "draft-irtf-cfrg-bbs-blind-signatures-02";
}
