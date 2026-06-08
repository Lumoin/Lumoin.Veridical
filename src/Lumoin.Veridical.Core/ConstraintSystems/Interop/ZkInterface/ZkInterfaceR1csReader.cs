using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Threading;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Reads ZkInterface v1 R1CS files per the QED-it specification at
/// <c>https://github.com/QED-it/zkinterface/blob/master/zkinterface.fbs</c>.
/// </summary>
/// <remarks>
/// <para>
/// File layout: a ZkInterface stream is a sequence of size-prefixed
/// FlatBuffers <c>Root</c> messages — a 4-byte little-endian length (the
/// message size, excluding the prefix) followed by that many bytes of a
/// self-contained FlatBuffers buffer. Each <c>Root</c> carries a single
/// <c>message</c> union: <c>CircuitHeader</c> (the field and instance
/// variables), one or more <c>ConstraintSystem</c> messages (the
/// constraints), an optional <c>Witness</c>, and <c>Command</c> (ignored).
/// </para>
/// <para>
/// The FlatBuffers wire format is read through a swappable
/// <see cref="ZkInterfaceMessageDecoderDelegate"/> that pushes decoded
/// fields into an <see cref="IZkInterfaceMessageSink"/>; <see cref="Reader"/>
/// uses the built-in <see cref="ZkInterfaceCursorDecoder"/> (hand-parsed,
/// no <c>Google.FlatBuffers</c> dependency), and <see cref="CreateReader"/>
/// binds an alternate decoder. The push/span contract keeps field elements
/// off the managed heap, mirroring the rest of the library's pooled-memory
/// discipline.
/// </para>
/// <para>
/// Field handling: the header's <c>field_maximum</c> (the field order minus
/// one) is reconciled against the requested curve's scalar modulus;
/// a mismatch — or an undeclared field — throws
/// <see cref="R1csUnsupportedFieldException"/>. BLS12-381 and BN254 are wired.
/// </para>
/// </remarks>
public static class ZkInterfaceR1csReader
{
    /// <summary>The ZkInterface R1CS reader using the built-in FlatBuffers decoder, exposed through the public delegate shape.</summary>
    public static R1csPipeReaderDelegate Reader { get; } = CreateReader(ZkInterfaceCursorDecoder.Decoder);


    /// <summary>
    /// Builds an <see cref="R1csPipeReaderDelegate"/> that reads ZkInterface
    /// streams through <paramref name="decoder"/>, letting a caller swap the
    /// FlatBuffers implementation while reusing the R1CS assembly. The
    /// built-in <see cref="Reader"/> is this factory applied to
    /// <see cref="ZkInterfaceCursorDecoder.Decoder"/>.
    /// </summary>
    public static R1csPipeReaderDelegate CreateReader(ZkInterfaceMessageDecoderDelegate decoder)
    {
        ArgumentNullException.ThrowIfNull(decoder);
        return (pipe, format, curve, pool, cancellationToken) =>
            ReadInternal(decoder, pipe, format, curve, pool, cancellationToken);
    }


    private static RawR1csInstance ReadInternal(
        ZkInterfaceMessageDecoderDelegate decoder,
        PipeReader pipe,
        WellKnownR1csFormatLabel format,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        ArgumentNullException.ThrowIfNull(pool);

        if(format != WellKnownR1csFormatLabel.ZkInterface)
        {
            throw new ArgumentException(
                $"ZkInterfaceR1csReader handles only WellKnownR1csFormatLabel.ZkInterface; received '{format.Identifier}'.",
                nameof(format));
        }

        WellKnownCurves.ThrowIfCurveNotWired(curve);

        ReadOnlySequence<byte> buffer = DrainPipe(pipe, cancellationToken);

        try
        {
            var builder = new ZkInterfaceR1csInstanceBuilder(curve, pool);
            decoder(buffer, builder, cancellationToken);
            return builder.Build();
        }
        finally
        {
            //The instance owns its own pooled buffers once built, so the pipe's
            //bytes can be released regardless of outcome.
            pipe.AdvanceTo(buffer.End);
        }
    }


    private static ReadOnlySequence<byte> DrainPipe(PipeReader pipe, CancellationToken cancellationToken)
    {
        while(true)
        {
            ReadResult result = pipe.ReadAsync(cancellationToken).AsTask().GetAwaiter().GetResult();

            if(result.IsCanceled)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            if(result.IsCompleted)
            {
                return result.Buffer;
            }

            //Examine everything, consume nothing, so the pipe keeps buffering
            //until the whole (small) stream has arrived.
            pipe.AdvanceTo(result.Buffer.Start, result.Buffer.End);
        }
    }
}
