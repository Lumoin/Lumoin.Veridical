using Lumoin.Veridical.Bbs;
namespace Lumoin.Veridical.Tests.Bbs.IetfVectors;

/// <summary>
/// The IETF draft revision every vector in this directory was
/// transcribed from. When the draft rolls, this constant updates
/// and the vectors get re-transcribed in the same commit.
/// </summary>
internal static class IetfDraftRevision
{
    /// <summary>The IETF draft identifier the vectors come from.</summary>
    public const string Identifier = "draft-irtf-cfrg-bbs-signatures-10";

    /// <summary>The month and year the draft was published.</summary>
    public const string Date = "2026-01";
}