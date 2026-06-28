using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Text;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Verbose inspector for <see cref="FiatShamirTranscript"/>. Returns a
/// bundled <see cref="FiatShamirTranscriptReport"/> with the current
/// state, squeeze counter, hash function, domain label, and rendered
/// tag.
/// </summary>
/// <remarks>
/// <para>
/// Same pattern as the consolidation-batch and polynomial-batch
/// inspectors. Pure read-only verb, no backend delegates, no mutation.
/// </para>
/// </remarks>
public static class FiatShamirTranscriptInspector
{
    /// <summary>
    /// Inspects <paramref name="transcript"/> and returns the bundled report.
    /// </summary>
    public static FiatShamirTranscriptReport Inspect(FiatShamirTranscript transcript)
    {
        ArgumentNullException.ThrowIfNull(transcript);

        return new FiatShamirTranscriptReport(
            DomainLabel: transcript.DomainLabel,
            HashFunction: transcript.HashFunction,
            CurrentStateHex: transcript.CurrentStateHex,
            SqueezeCount: transcript.SqueezeCount,
            TagSummary: RenderTagSummary(transcript.Tag));
    }


    private static string RenderTagSummary(Tag tag)
    {
        var builder = new StringBuilder();
        bool first = true;
        foreach(var entry in tag.Entries)
        {
            if(!first)
            {
                builder.Append(", ");
            }

            builder.Append(entry.Key.Name);
            builder.Append('=');
            builder.Append(entry.Value);
            first = false;
        }


        return builder.ToString();
    }
}


/// <summary>
/// Bundled facts about a single <see cref="FiatShamirTranscript"/>.
/// </summary>
/// <param name="DomainLabel">The protocol-identifying label fixed at construction.</param>
/// <param name="HashFunction">The hash function this transcript uses.</param>
/// <param name="CurrentStateHex">Lowercase hex of the current 32-byte state.</param>
/// <param name="SqueezeCount">The number of squeezes performed so far.</param>
/// <param name="TagSummary">A human-readable rendering of the transcript's tag entries.</param>
public sealed record FiatShamirTranscriptReport(
    FiatShamirDomainLabel DomainLabel,
    string HashFunction,
    string CurrentStateHex,
    long SqueezeCount,
    string TagSummary);