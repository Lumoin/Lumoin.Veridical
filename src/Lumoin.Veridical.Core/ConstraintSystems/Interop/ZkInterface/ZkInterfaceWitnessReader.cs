using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Threading;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Reads a ZkInterface v1 witness into a <see cref="RawR1csWitness"/>,
/// the witness-side counterpart of <see cref="ZkInterfaceR1csReader"/>.
/// </summary>
/// <remarks>
/// <para>
/// The witness vector Veridical expects is the whole <c>z[1..]</c> (every
/// variable but the constant one), matching the reader's
/// PublicInputCount = 0 convention. ZkInterface splits those values
/// between the <c>CircuitHeader.instance_variables</c> (public) and a
/// <c>Witness.assigned_variables</c> (private), so the stream must carry a
/// <c>CircuitHeader</c> — for the field, the variable count, and the
/// instance values — alongside the witness. Both sources are scattered by
/// column = variable ID into the dense witness vector.
/// </para>
/// <para>
/// The FlatBuffers layer is read through the same swappable
/// <see cref="ZkInterfaceMessageDecoderDelegate"/> as the instance reader;
/// <see cref="Reader"/> uses the built-in
/// <see cref="ZkInterfaceCursorDecoder"/>, and <see cref="CreateReader"/>
/// binds an alternate decoder.
/// </para>
/// </remarks>
public static class ZkInterfaceWitnessReader
{
    /// <summary>The ZkInterface witness reader using the built-in FlatBuffers decoder, exposed through the public delegate shape.</summary>
    public static R1csWitnessPipeReaderDelegate Reader { get; } = CreateReader(ZkInterfaceCursorDecoder.Decoder);


    /// <summary>
    /// Builds an <see cref="R1csWitnessPipeReaderDelegate"/> that reads
    /// ZkInterface witnesses through <paramref name="decoder"/>. The
    /// built-in <see cref="Reader"/> is this factory applied to
    /// <see cref="ZkInterfaceCursorDecoder.Decoder"/>.
    /// </summary>
    public static R1csWitnessPipeReaderDelegate CreateReader(ZkInterfaceMessageDecoderDelegate decoder)
    {
        ArgumentNullException.ThrowIfNull(decoder);
        return (pipe, format, curve, pool, cancellationToken) =>
            ReadInternal(decoder, pipe, format, curve, pool, cancellationToken);
    }


    private static RawR1csWitness ReadInternal(
        ZkInterfaceMessageDecoderDelegate decoder,
        PipeReader pipe,
        WellKnownR1csFormatLabel format,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        ArgumentNullException.ThrowIfNull(pool);

        if(format != WellKnownR1csFormatLabel.ZkInterface)
        {
            throw new ArgumentException(
                $"ZkInterfaceWitnessReader handles only WellKnownR1csFormatLabel.ZkInterface; received '{format.Identifier}'.",
                nameof(format));
        }

        WellKnownCurves.ThrowIfCurveNotWired(curve);

        ReadOnlySequence<byte> buffer = DrainPipe(pipe, cancellationToken);

        try
        {
            var builder = new ZkInterfaceWitnessBuilder(curve, pool);
            decoder(buffer, builder, cancellationToken);
            return builder.Build();
        }
        finally
        {
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

            pipe.AdvanceTo(result.Buffer.Start, result.Buffer.End);
        }
    }
}
