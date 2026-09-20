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
/// Reads Circom-compiled <c>.wtns</c> witness files. The format has no
/// separate specification document; its layout — described below — is
/// fixed by convention rather than by a written spec. The iden3
/// <c>snarkjs</c> encoder at
/// <c>https://github.com/iden3/snarkjs/blob/master/src/wtns_utils.js</c>
/// is the de-facto definition that convention follows.
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
/// treats the first scalar as the constant <c>z[0]</c>, skips it without
/// checking its value, and returns the
/// remaining elements via <see cref="RawR1csWitness.FromCanonical"/> in
/// Veridical's canonical big-endian byte order. This matches the
/// "PublicInputCount = 0, all wires in the witness" convention the
/// <see cref="CircomR1csReader"/> uses; the two adapters compose
/// end-to-end without re-splitting the witness vector.
/// </para>
/// </remarks>
public static class CircomWitnessReader
{
    /// <summary>The largest admitted field width, 256 bytes, bounding the header shape check before curve validation.</summary>
    private const uint MaximumFieldSizeBytes = 256u;

    /// <summary>The field width alignment required by the reader: a positive multiple of eight bytes.</summary>
    private const uint FieldSizeAlignmentBytes = 8u;

    /// <summary>The one leading wire reserved for the constant in the Circom witness convention.</summary>
    private const int ConstantWireCount = 1;

    /// <summary>The only supported file version: 2 for the Circom witness format.</summary>
    private const uint SupportedFileVersion = 2u;

    /// <summary>The section type code 1, which identifies the field and circuit header in the binary format.</summary>
    private const uint HeaderSectionType = 1u;

    /// <summary>The section type code 2, which identifies the witness scalars in the binary format.</summary>
    private const uint WitnessDataSectionType = 2u;

    /// <summary>The four ASCII bytes that identify a <c>.wtns</c> file.</summary>
    private static byte[] FileMagic { get; } = [(byte)'w', (byte)'t', (byte)'n', (byte)'s'];

    /// <summary>The BLS12-381 scalar field order for validating the prime declared by a BLS12-381 witness file.</summary>
    private static BigInteger Bls12Curve381ScalarFieldModulus { get; } = BigInteger.Parse(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    /// <summary>The BN254 (alt_bn128) scalar field order, against which a BN254-declared <c>.wtns</c> prime is validated.</summary>
    private static BigInteger Bn254ScalarFieldModulus { get; } = BigInteger.Parse(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    /// <summary>The Circom <c>.wtns</c> reader exposed through the public delegate shape.</summary>
    public static R1csWitnessPipeReaderDelegate Reader { get; } =
        (pipe, format, curve, pool, maximumIntakeBytes, cancellationToken) =>
            ReadInternal(pipe, format, curve, pool, maximumIntakeBytes, cancellationToken);


    /// <summary>Validates the reader arguments before draining the pipe, then parses and consumes its complete buffer.</summary>
    private static RawR1csWitness ReadInternal(
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

        if(format != WellKnownR1csFormatLabel.CircomWitness)
        {
            throw new ArgumentException(
                $"CircomWitnessReader handles only WellKnownR1csFormatLabel.CircomWitness; received '{format.Identifier}'.",
                nameof(format));
        }

        WellKnownCurves.ThrowIfCurveNotWired(curve);

        ReadOnlySequence<byte> buffer = R1csPipeIntake.DrainPipe(pipe, maximumIntakeBytes, cancellationToken);

        try
        {
            return ParseBuffer(buffer, curve, pool);
        }
        finally
        {
            pipe.AdvanceTo(buffer.End);
        }
    }


    /// <summary>Validates the file envelope and required sections, then constructs the parsed witness.</summary>
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

            //Only the header and data sections are interpreted; other payloads are skipped.
            if(sectionType is HeaderSectionType)
            {
                witnessLength = ParseHeaderSection(sectionPayload, curve);
            }
            else if(sectionType is WitnessDataSectionType)
            {
                witnessData = sectionPayload;
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


    /// <summary>Consumes the file magic and rejects truncated or unrecognised signatures.</summary>
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


    /// <summary>Reads a four-byte little-endian count or type field and rejects truncation with the field name.</summary>
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


    /// <summary>Reads an eight-byte little-endian section size and rejects truncation with the field name.</summary>
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


    /// <summary>Validates the scalar field and header counts before returning the stored witness length.</summary>
    private static uint ParseHeaderSection(ReadOnlySequence<byte> payload, CurveParameterSet curve)
    {
        var reader = new SequenceReader<byte>(payload);

        uint fieldSize = ReadUInt32Le(ref reader, "header.fieldSize");
        if(fieldSize == 0 || fieldSize > MaximumFieldSizeBytes || fieldSize % FieldSizeAlignmentBytes != 0)
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

        //Only scalars after the constant occupy the returned witness buffer. Reject counts whose dense vector
        //exceeds one array before the byte count is computed with signed 32-bit arithmetic.
        if((long)(nWitness - ConstantWireCount) * scalarSizeBytes > Array.MaxLength)
        {
            throw new ArgumentException(
                $".wtns header declares nWitness = {nWitness}; the witness vector exceeds the maximum addressable size.");
        }

        return nWitness;
    }


    /// <summary>Checks the unsigned little-endian modulus against the declared curve scalar field.</summary>
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


    /// <summary>Checks the section length, skips the first scalar and copies the remaining scalars into canonical big-endian witness storage.</summary>
    /// <remarks>
    /// Canonical scalars are staged in a pooled buffer and copied into the witness's own storage by
    /// <see cref="RawR1csWitness.FromCanonical"/>. The staging rental is disposed when this method exits.
    /// </remarks>
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

        //The first scalar exists because the header rejects an empty witness. Treat it as the constant z[0]
        //without checking its value, and reverse each remaining scalar from LE to BE into the destination buffer.
        int privateCount = (int)(nWitness - ConstantWireCount);
        if(privateCount == 0)
        {
            throw new ArgumentException(
                ".wtns witness contains only the constant z[0] = 1; nothing to populate RawR1csWitness with.");
        }

        int destinationLength = privateCount * scalarSizeBytes;
        using IMemoryOwner<byte> destinationOwner = pool.Rent(destinationLength);
        Span<byte> destination = destinationOwner.Memory.Span[..destinationLength];
        var reader = new SequenceReader<byte>(witnessDataLittleEndian);
        Span<byte> scratch = stackalloc byte[scalarSizeBytes];

        //The section length covers nWitness whole scalars, so every element read below lies inside it.
        //The first element is treated as the constant z[0] and skipped.
        reader.Advance(scalarSizeBytes);

        for(int i = 0; i < privateCount; i++)
        {
            reader.UnreadSequence.Slice(0, scalarSizeBytes).CopyTo(scratch);
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
}
