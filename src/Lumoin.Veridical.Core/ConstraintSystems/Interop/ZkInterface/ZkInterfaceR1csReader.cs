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
/// off the managed heap, matching how the rest of the library sources its
/// buffers from pools rather than allocating them there.
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
        return (pipe, format, curve, pool, maximumIntakeBytes, cancellationToken) =>
            ReadInternal(decoder, pipe, format, curve, pool, maximumIntakeBytes, cancellationToken);
    }


    /// <summary>Decodes the complete stream with the caller's pool and assembles the owned R1CS result.</summary>
    private static RawR1csInstance ReadInternal(
        ZkInterfaceMessageDecoderDelegate decoder,
        PipeReader pipe,
        WellKnownR1csFormatLabel format,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        long maximumIntakeBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(maximumIntakeBytes);

        if(format != WellKnownR1csFormatLabel.ZkInterface)
        {
            throw new ArgumentException(
                $"ZkInterfaceR1csReader handles only WellKnownR1csFormatLabel.ZkInterface; received '{format.Identifier}'.",
                nameof(format));
        }

        WellKnownCurves.ThrowIfCurveNotWired(curve);

        ReadOnlySequence<byte> buffer = R1csPipeIntake.DrainPipe(pipe, maximumIntakeBytes, cancellationToken);

        try
        {
            var builder = new ZkInterfaceR1csInstanceBuilder(curve, pool);
            decoder(buffer, builder, pool, cancellationToken);

            return builder.Build();
        }
        finally
        {
            //The instance owns its own pooled buffers once built, so the pipe's
            //bytes can be released regardless of outcome.
            pipe.AdvanceTo(buffer.End);
        }
    }
}
