using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Threading;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// A pipe reader over complete in-memory file bytes that uncovers a fixed number of further bytes per read and holds
/// its caller to the pipe reader contract. A read issued before the previous buffer was advanced, or after a read
/// has already reported completion, throws <see cref="InvalidOperationException"/> instead of handing back the same
/// buffer again, so a caller that breaks either rule fails at that read rather than reading the same bytes forever.
/// </summary>
/// <param name="fileBytes">The file bytes the pipe yields.</param>
/// <param name="chunkBytes">The number of further bytes each read uncovers.</param>
internal sealed class StrictChunkedPipeReader(ReadOnlyMemory<byte> fileBytes, int chunkBytes): PipeReader
{
    /// <summary>The number of leading file bytes the caller has advanced past as consumed.</summary>
    public int ConsumedBytes { get; private set; }

    /// <summary>Whether any read has been issued against the pipe.</summary>
    public bool HasBeenRead { get; private set; }

    /// <summary>The file bytes the pipe yields.</summary>
    private ReadOnlyMemory<byte> FileBytes { get; } = fileBytes;

    /// <summary>The number of further bytes each read uncovers.</summary>
    private int ChunkBytes { get; } = chunkBytes;

    /// <summary>The number of leading file bytes the reads so far have uncovered.</summary>
    private int UncoveredBytes { get; set; }

    /// <summary>The buffer the latest read returned, against which an advanced position is measured.</summary>
    private ReadOnlySequence<byte> LatestBuffer { get; set; }

    /// <summary>Whether the latest read returned a buffer the caller has not advanced past yet.</summary>
    private bool AwaitingAdvance { get; set; }

    /// <summary>Whether the pipe has nothing more to give, because a read reported completion or the reader was completed.</summary>
    private bool IsFinished { get; set; }


    /// <summary>Records <paramref name="consumed"/> as both the consumed and the examined position.</summary>
    /// <param name="consumed">The position within the latest buffer up to which its bytes were consumed.</param>
    public override void AdvanceTo(SequencePosition consumed) => AdvanceTo(consumed, consumed);


    /// <summary>Records how much of the latest buffer was consumed and permits the next read.</summary>
    /// <param name="consumed">The position within the latest buffer up to which its bytes were consumed.</param>
    /// <param name="examined">The position within the latest buffer up to which its bytes were examined; every read uncovers a further chunk regardless.</param>
    public override void AdvanceTo(SequencePosition consumed, SequencePosition examined)
    {
        ConsumedBytes += (int)LatestBuffer.Slice(LatestBuffer.Start, consumed).Length;
        AwaitingAdvance = false;
    }


    /// <summary>Not supported: the bytes are already in memory, so no read is ever left pending.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override void CancelPendingRead() => throw new NotSupportedException("The in-memory pipe never has a pending read to cancel.");


    /// <summary>Marks the pipe finished, so any further read throws.</summary>
    /// <param name="exception">The error that ended reading, if any; not recorded.</param>
    public override void Complete(Exception? exception = null) => IsFinished = true;


    /// <summary>Uncovers the next chunk and returns the result without waiting.</summary>
    /// <param name="cancellationToken">Not observed; the read never waits.</param>
    /// <returns>An already completed read of every uncovered byte not yet consumed.</returns>
    /// <exception cref="InvalidOperationException">When the previous buffer was not advanced or the pipe is finished.</exception>
    public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default) => ValueTask.FromResult(UncoverNextChunk());


    /// <summary>Uncovers the next chunk and returns the result.</summary>
    /// <param name="result">The read of every uncovered byte not yet consumed.</param>
    /// <returns>Always <see langword="true"/>; a read that breaks the contract throws instead.</returns>
    /// <exception cref="InvalidOperationException">When the previous buffer was not advanced or the pipe is finished.</exception>
    public override bool TryRead(out ReadResult result)
    {
        result = UncoverNextChunk();

        return true;
    }


    /// <summary>
    /// Uncovers up to <see cref="ChunkBytes"/> further file bytes and returns every uncovered byte not yet consumed,
    /// reporting completion once the last file byte is uncovered.
    /// </summary>
    /// <returns>The read result for the caller to advance through.</returns>
    /// <exception cref="InvalidOperationException">When the previous buffer was not advanced or the pipe is finished.</exception>
    private ReadResult UncoverNextChunk()
    {
        if(AwaitingAdvance)
        {
            throw new InvalidOperationException("The previous buffer must be advanced before the pipe is read again.");
        }

        if(IsFinished)
        {
            throw new InvalidOperationException("The pipe has already reported completion.");
        }

        HasBeenRead = true;
        UncoveredBytes = Math.Min(UncoveredBytes + ChunkBytes, FileBytes.Length);
        IsFinished = UncoveredBytes == FileBytes.Length;
        AwaitingAdvance = true;
        LatestBuffer = new ReadOnlySequence<byte>(FileBytes[ConsumedBytes..UncoveredBytes]);

        return new ReadResult(LatestBuffer, isCanceled: false, isCompleted: IsFinished);
    }
}
