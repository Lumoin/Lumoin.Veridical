using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Threading;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop;

/// <summary>
/// The single drain loop shared by every R1CS pipe reader. Reads a <see cref="PipeReader"/> to
/// completion, retaining every examined byte as one contiguous logical sequence, and enforces an
/// intake ceiling against untrusted input.
/// </summary>
internal static class R1csPipeIntake
{
    /// <summary>
    /// Reads <paramref name="pipe"/> until the underlying stream completes, examining but never
    /// consuming each partial read so the whole sequence is available to the caller afterwards.
    /// </summary>
    /// <param name="pipe">The pipe carrying the binary file's bytes.</param>
    /// <param name="maximumIntakeBytes">
    /// The largest buffered length this call admits. The comparison runs against the length reported
    /// by every read, not only once the stream completes, so a stream past the ceiling is rejected as
    /// its bytes accumulate rather than after the whole stream has already arrived.
    /// </param>
    /// <param name="cancellationToken">Cancellation for the read loop.</param>
    /// <returns>The complete buffered sequence, once the pipe reports completion.</returns>
    /// <exception cref="R1csIntakeLimitExceededException">
    /// Thrown as soon as the buffered length exceeds <paramref name="maximumIntakeBytes"/>.
    /// </exception>
    public static ReadOnlySequence<byte> DrainPipe(
        PipeReader pipe,
        long maximumIntakeBytes,
        CancellationToken cancellationToken)
    {
        while(true)
        {
            ReadResult result = pipe.ReadAsync(cancellationToken).AsTask().GetAwaiter().GetResult();

            if(result.IsCanceled)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            if(result.Buffer.Length > maximumIntakeBytes)
            {
                throw new R1csIntakeLimitExceededException(maximumIntakeBytes, result.Buffer.Length);
            }

            if(result.IsCompleted)
            {
                return result.Buffer;
            }

            //Retain every byte until the stream is complete, while marking the current buffer as examined.
            pipe.AdvanceTo(result.Buffer.Start, result.Buffer.End);
        }
    }
}
