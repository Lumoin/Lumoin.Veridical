using System.Buffers;
using System.Threading;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Decodes a ZkInterface message stream and pushes its contents into a
/// sink. This is the swap seam for the FlatBuffers layer: the built-in
/// <see cref="ZkInterfaceCursorDecoder.Decoder"/> hand-parses the wire
/// format, but any implementation — for example one backed by a
/// code-generated FlatBuffers runtime — can be substituted by passing it
/// to <see cref="ZkInterfaceR1csReader.CreateReader"/>.
/// </summary>
/// <remarks>
/// The decoder is synchronous and span-based by design: FlatBuffers
/// resolves offsets in both directions, so a message cannot be decoded
/// before its whole buffer is present, and pushing spans into the sink
/// keeps field elements off the managed heap. The reader drains the pipe
/// and hands the decoder the complete stream as <paramref name="source"/>;
/// the decoder may need contiguous access and can materialise a single
/// buffer from a multi-segment sequence if its implementation requires it.
/// </remarks>
/// <param name="source">The complete ZkInterface stream (a sequence of size-prefixed FlatBuffers messages).</param>
/// <param name="sink">The consumer the decoded fields are pushed into.</param>
/// <param name="cancellationToken">Cancellation, honoured between messages.</param>
public delegate void ZkInterfaceMessageDecoderDelegate(
    ReadOnlySequence<byte> source,
    IZkInterfaceMessageSink sink,
    CancellationToken cancellationToken);
