using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.IO.Pipelines;
using System.Numerics;
using System.Threading;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.Circom;

/// <summary>
/// Reads Circom-compiled <c>.wtns</c> witness files. The format is
/// the de-facto specification emitted by <c>snarkjs</c> and the
/// <c>circom</c>-generated WebAssembly witness generator; the source
/// of record is the encoder in
/// <c>https://github.com/iden3/snarkjs/blob/master/src/wtns_utils.js</c>.
/// </summary>
/// <remarks>
/// <para>
/// File layout: a 4-byte <c>wtns</c> magic, a 4-byte little-endian
/// version (version 2 is accepted), a 4-byte little-endian section
/// count, then variable-order typed sections in the same shape as
/// the <c>.r1cs</c> format — 4-byte type + 8-byte payload size +
/// payload bytes. Two sections are interpreted: the header (type 1,
/// declaring field size, prime modulus, and witness length) and
/// the witness data (type 2, <c>nWitness</c> field elements stored
/// little-endian).
/// </para>
/// <para>
/// Output: the <c>.wtns</c> file contains the full witness vector
/// <c>z = (1, z[1], z[2], ..., z[nWitness - 1])</c>. The reader
/// drops <c>z[0] = 1</c> (the canonical constant) and returns the
/// remaining elements via <see cref="RawR1csWitness.FromCanonical"/> in
/// Veridical's canonical big-endian byte order. This matches the
/// "PublicInputCount = 0, all wires in the witness" convention the
/// <see cref="CircomR1csReader"/> uses; the two adapters compose
/// end-to-end without re-splitting the witness vector.
/// </para>
/// </remarks>
public static class CircomWitnessReader
{
    private const uint SupportedFileVersion = 2u;
    private const uint HeaderSectionType = 1u;
    private const uint WitnessDataSectionType = 2u;

    private static readonly byte[] FileMagic = [(byte)'w', (byte)'t', (byte)'n', (byte)'s'];

    private static readonly BigInteger Bls12Curve381ScalarFieldModulus = BigInteger.Parse(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    /// <summary>The BN254 (alt_bn128) scalar field order, against which a BN254-declared <c>.wtns</c> prime is validated.</summary>
    private static readonly BigInteger Bn254ScalarFieldModulus = BigInteger.Parse(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    /// <summary>The Circom <c>.wtns</c> reader exposed through the public delegate shape.</summary>
    public static R1csWitnessPipeReaderDelegate Reader { get; } =
        (pipe, format, curve, pool, cancellationToken) =>
            ReadInternal(pipe, format, curve, pool, cancellationToken);


    private static RawR1csWitness ReadInternal(
        PipeReader pipe,
        WellKnownR1csFormatLabel format,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        ArgumentNullException.ThrowIfNull(pool);

        if(format != WellKnownR1csFormatLabel.CircomWitness)
        {
            throw new ArgumentException(
                $"CircomWitnessReader handles only WellKnownR1csFormatLabel.CircomWitness; received '{format.Identifier}'.",
                nameof(format));
        }

        WellKnownCurves.ThrowIfCurveNotWired(curve);

        ReadOnlySequence<byte> buffer = DrainPipe(pipe, cancellationToken);

        try
        {
            return ParseBuffer(buffer, curve, pool);
        }
        finally
        {
            pipe.AdvanceTo(buffer.End);
        }
    }


    private static RawR1csWitness ParseBuffer(
        ReadOnlySequence<byte> buffer,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        var reader = new SequenceReader<byte>(buffer);

        ReadAndValidateMagic(ref reader);
        uint version = ReadUInt32Le(ref reader, "version");
        if(version != SupportedFileVersion)
        {
            throw new ArgumentException(
                $"CircomWitnessReader supports only .wtns file version {SupportedFileVersion}; file declares version {version}.");
        }

        uint sectionCount = ReadUInt32Le(ref reader, "section count");

        uint? witnessLength = null;
        ReadOnlySequence<byte>? witnessData = null;

        for(uint sectionIndex = 0; sectionIndex < sectionCount; sectionIndex++)
        {
            uint sectionType = ReadUInt32Le(ref reader, "section type");
            ulong sectionSize = ReadUInt64Le(ref reader, "section size");

            if(sectionSize > (ulong)reader.Remaining)
            {
                throw new ArgumentException(
                    $"Section {sectionIndex} declares size {sectionSize} bytes but only {reader.Remaining} bytes remain in the file.");
            }

            ReadOnlySequence<byte> sectionPayload = reader.UnreadSequence.Slice(0, (long)sectionSize);
            reader.Advance((long)sectionSize);

            switch(sectionType)
            {
                case HeaderSectionType:
                    witnessLength = ParseHeaderSection(sectionPayload, curve);
                    break;

                case WitnessDataSectionType:
                    witnessData = sectionPayload;
                    break;

                //Any other section type is read past per the same
                //spec-conformance pattern the .r1cs reader follows.
                default:
                    break;
            }
        }

        if(witnessLength is null)
        {
            throw new ArgumentException(".wtns file is missing the header section (type 1).");
        }

        if(witnessData is null)
        {
            throw new ArgumentException(".wtns file is missing the witness data section (type 2).");
        }

        return BuildWitness(witnessData.Value, witnessLength.Value, curve, pool);
    }


    private static void ReadAndValidateMagic(ref SequenceReader<byte> reader)
    {
        Span<byte> magic = stackalloc byte[FileMagic.Length];
        if(!reader.TryCopyTo(magic))
        {
            throw new ArgumentException(".wtns file is shorter than the 4-byte magic.");
        }

        reader.Advance(FileMagic.Length);

        if(!magic.SequenceEqual(FileMagic))
        {
            throw new ArgumentException(
                $".wtns file magic mismatch. Expected ASCII 'wtns' (77 74 6e 73); found {Convert.ToHexString(magic)}.");
        }
    }


    private static uint ReadUInt32Le(ref SequenceReader<byte> reader, string fieldName)
    {
        Span<byte> bytes = stackalloc byte[sizeof(uint)];
        if(!reader.TryCopyTo(bytes))
        {
            throw new ArgumentException(
                $".wtns file truncated while reading {fieldName} ({sizeof(uint)} bytes); only {reader.Remaining} bytes remained.");
        }

        reader.Advance(sizeof(uint));
        return BinaryPrimitives.ReadUInt32LittleEndian(bytes);
    }


    private static ulong ReadUInt64Le(ref SequenceReader<byte> reader, string fieldName)
    {
        Span<byte> bytes = stackalloc byte[sizeof(ulong)];
        if(!reader.TryCopyTo(bytes))
        {
            throw new ArgumentException(
                $".wtns file truncated while reading {fieldName} ({sizeof(ulong)} bytes); only {reader.Remaining} bytes remained.");
        }

        reader.Advance(sizeof(ulong));
        return BinaryPrimitives.ReadUInt64LittleEndian(bytes);
    }


    private static uint ParseHeaderSection(ReadOnlySequence<byte> payload, CurveParameterSet curve)
    {
        var reader = new SequenceReader<byte>(payload);

        uint fieldSize = ReadUInt32Le(ref reader, "header.fieldSize");
        if(fieldSize == 0 || fieldSize > 256 || fieldSize % 8 != 0)
        {
            throw new ArgumentException(
                $".wtns header declares field_size = {fieldSize}; must be a positive multiple of 8 not exceeding 256.");
        }

        int scalarSizeBytes = R1csMatrix.GetValueByteSize(curve);
        if(fieldSize != (uint)scalarSizeBytes)
        {
            throw new ArgumentException(
                $".wtns header declares field_size = {fieldSize} bytes but curve {curve} expects {scalarSizeBytes} bytes per scalar.");
        }

        Span<byte> primeBytes = stackalloc byte[scalarSizeBytes];
        if(!reader.TryCopyTo(primeBytes))
        {
            throw new ArgumentException(
                $".wtns header truncated while reading the prime modulus ({scalarSizeBytes} bytes).");
        }

        reader.Advance(scalarSizeBytes);
        ValidatePrimeModulus(primeBytes, curve);

        uint nWitness = ReadUInt32Le(ref reader, "header.nWitness");
        if(nWitness == 0)
        {
            throw new ArgumentException(".wtns header declares nWitness = 0; witness must have at least the constant.");
        }

        return nWitness;
    }


    private static void ValidatePrimeModulus(ReadOnlySpan<byte> primeLittleEndian, CurveParameterSet curve)
    {
        Span<byte> primeBe = stackalloc byte[primeLittleEndian.Length];
        for(int i = 0; i < primeLittleEndian.Length; i++)
        {
            primeBe[i] = primeLittleEndian[primeLittleEndian.Length - 1 - i];
        }

        BigInteger fileModulus = new(primeBe, isUnsigned: true, isBigEndian: true);
        //Dispatch the expected modulus on the declared curve; the gate above has
        //already restricted curve to Bls12Curve381 or Bn254.
        BigInteger expectedModulus = curve.Code == CurveParameterSet.Bn254.Code
            ? Bn254ScalarFieldModulus
            : Bls12Curve381ScalarFieldModulus;

        if(fileModulus != expectedModulus)
        {
            string expectedHex = expectedModulus.ToString("x", CultureInfo.InvariantCulture);
            string foundHex = fileModulus.ToString("x", CultureInfo.InvariantCulture);
            throw new R1csUnsupportedFieldException(expectedHex, foundHex);
        }
    }


    private static RawR1csWitness BuildWitness(
        ReadOnlySequence<byte> witnessDataLittleEndian,
        uint nWitness,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int scalarSizeBytes = R1csMatrix.GetValueByteSize(curve);
        ulong expectedBytes = (ulong)nWitness * (ulong)scalarSizeBytes;

        if(witnessDataLittleEndian.Length != (long)expectedBytes)
        {
            throw new ArgumentException(
                $".wtns witness section has {witnessDataLittleEndian.Length} bytes but the header declares {nWitness} × {scalarSizeBytes} = {expectedBytes} bytes.");
        }

        //Drop z[0] (the canonical constant 1) and reverse each
        //remaining scalar LE -> BE into the destination buffer.
        if(nWitness < 1)
        {
            throw new ArgumentException(".wtns witness section is empty; expected at least one element (the constant).");
        }

        int privateCount = (int)(nWitness - 1);
        if(privateCount == 0)
        {
            throw new ArgumentException(
                ".wtns witness contains only the constant z[0] = 1; nothing to populate RawR1csWitness with.");
        }

        byte[] destination = new byte[privateCount * scalarSizeBytes];
        var reader = new SequenceReader<byte>(witnessDataLittleEndian);

        //Skip z[0].
        Span<byte> scratch = stackalloc byte[scalarSizeBytes];
        if(!reader.TryCopyTo(scratch))
        {
            throw new ArgumentException(".wtns witness section truncated while skipping z[0].");
        }

        reader.Advance(scalarSizeBytes);

        for(int i = 0; i < privateCount; i++)
        {
            if(!reader.TryCopyTo(scratch))
            {
                throw new ArgumentException(
                    $".wtns witness section truncated while reading element {i + 1} of {nWitness}.");
            }

            reader.Advance(scalarSizeBytes);

            //LE -> BE: write the bytes in reverse order into the
            //destination slot for this element.
            int offset = i * scalarSizeBytes;
            for(int j = 0; j < scalarSizeBytes; j++)
            {
                destination[offset + j] = scratch[scalarSizeBytes - 1 - j];
            }
        }

        return RawR1csWitness.FromCanonical(destination, curve, pool);
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