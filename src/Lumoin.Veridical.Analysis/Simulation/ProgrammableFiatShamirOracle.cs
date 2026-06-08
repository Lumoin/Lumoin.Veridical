using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Analysis.Simulation;

/// <summary>
/// A programmable Fiat-Shamir random oracle for zero-knowledge simulator
/// experiments: the random-oracle-model capability that an FS-compiled ZK
/// simulator is granted and an honest party is not — answering the
/// verifier's oracle queries with responses the simulator chose.
/// </summary>
/// <remarks>
/// <para>
/// Two phases, two delegates. <see cref="CreateRecordingSqueeze"/> wraps a
/// real XOF backend and records every squeeze (input, output, algorithm) in
/// call order while a simulator drives an honest prover run.
/// <see cref="CreateReplaySqueeze"/> then answers the <c>i</c>-th squeeze
/// with the recorded <c>i</c>-th output <em>regardless of the query
/// input</em> — sequence-keyed lazy programming. This is sound ROM
/// programming: the verifier's query points are distinct (the transcript
/// state chains through every absorb and squeeze), each point receives
/// exactly one response, and the responses are uniform (they are real XOF
/// outputs of the simulator's internal run).
/// </para>
/// <para>
/// The replay is deliberately strict: a squeeze beyond the recorded count,
/// an output-length mismatch, or an algorithm mismatch throws — in a
/// simulator experiment any of these means the verifier's squeeze sequence
/// diverged structurally from the prover's, which is a bug, not a
/// distribution. Not thread-safe; one oracle per protocol run.
/// </para>
/// </remarks>
public sealed class ProgrammableFiatShamirOracle
{
    private readonly List<RecordedSqueeze> recordings = [];
    private int replayPosition;


    /// <summary>The number of squeezes recorded so far.</summary>
    public int RecordedCount => recordings.Count;

    /// <summary>The number of recorded squeezes the replay delegate has consumed.</summary>
    public int ReplayedCount => replayPosition;


    /// <summary>
    /// Returns a squeeze delegate that forwards to <paramref name="inner"/>
    /// and records every call's input, output, and algorithm in call order.
    /// </summary>
    /// <param name="inner">The real XOF backend.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="inner"/> is <see langword="null"/>.</exception>
    public FiatShamirSqueezeDelegate CreateRecordingSqueeze(FiatShamirSqueezeDelegate inner)
    {
        ArgumentNullException.ThrowIfNull(inner);

        return (input, output, hashFunction) =>
        {
            inner(input, output, hashFunction);
            recordings.Add(new RecordedSqueeze(input.ToArray(), output.ToArray(), hashFunction));
        };
    }


    /// <summary>
    /// Returns a squeeze delegate that answers the <c>i</c>-th call with the
    /// recorded <c>i</c>-th output regardless of the query input — the
    /// programmed oracle a verifier of a simulated proof queries.
    /// </summary>
    /// <exception cref="InvalidOperationException">When the verifier squeezes more times than were recorded, or a call's output length or algorithm does not match the recording.</exception>
    public FiatShamirSqueezeDelegate CreateReplaySqueeze()
    {
        return (input, output, hashFunction) =>
        {
            if(replayPosition >= recordings.Count)
            {
                throw new InvalidOperationException($"The verifier squeezed {replayPosition + 1} times but only {recordings.Count} responses are programmed.");
            }

            RecordedSqueeze recorded = recordings[replayPosition];
            if(output.Length != recorded.Output.Length)
            {
                throw new InvalidOperationException($"Squeeze {replayPosition} requested {output.Length} bytes but {recorded.Output.Length} were programmed.");
            }

            if(!string.Equals(hashFunction, recorded.HashFunction, StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"Squeeze {replayPosition} requested algorithm '{hashFunction}' but '{recorded.HashFunction}' was programmed.");
            }

            recorded.Output.CopyTo(output);
            replayPosition++;
        };
    }


    /// <summary>
    /// Returns the recorded query input of squeeze <paramref name="index"/>
    /// (for example locating a labelled challenge: the transcript embeds the
    /// operation label verbatim in the XOF input).
    /// </summary>
    public ReadOnlySpan<byte> GetRecordedInput(int index) => recordings[index].Input;


    /// <summary>Returns the recorded response of squeeze <paramref name="index"/>.</summary>
    public ReadOnlySpan<byte> GetRecordedOutput(int index) => recordings[index].Output;


    /// <summary>Rewinds the replay sequence so another verification can run against the same programming.</summary>
    public void ResetReplay()
    {
        replayPosition = 0;
    }


    private readonly record struct RecordedSqueeze(byte[] Input, byte[] Output, string HashFunction);
}
