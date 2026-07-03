using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO.Pipelines;
using System.Numerics;
using System.Threading;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.Circom;

/// <summary>
/// Reads Circom-compiled <c>.r1cs</c> binary files per the iden3
/// specification at
/// <c>https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md</c>.
/// </summary>
/// <remarks>
/// <para>
/// File layout: a 4-byte <c>r1cs</c> magic, a 4-byte little-endian
/// version (only version 1 is accepted), a 4-byte little-endian
/// section count, and then variable-order sections each prefixed by a
/// 4-byte type code and an 8-byte little-endian payload size. Only
/// the header section (type 1) and the constraint section (type 2)
/// are interpreted; other section types are read past per the spec.
/// </para>
/// <para>
/// Field handling: the header declares the prime modulus as a
/// little-endian byte sequence. The reader compares it against
/// the declared curve's scalar field modulus and throws
/// <see cref="R1csUnsupportedFieldException"/> on a mismatch. BLS12-381
/// and BN254 are wired.
/// </para>
/// <para>
/// Public-input convention: the iden3 <c>.r1cs</c> format declares
/// <c>nPubOut</c> and <c>nPubIn</c> in the header but carries no
/// witness values. To produce a complete <see cref="RawR1csInstance"/>,
/// the reader sets <see cref="RawR1csInstance.PublicInputCount"/> to
/// zero and routes every wire (except the constant <c>z[0] = 1</c>)
/// into the corresponding <see cref="RawR1csWitness"/>. Tests that need
/// Circom's pub/priv distinction reconstruct an instance with
/// caller-supplied public values; that pathway lands when
/// <see cref="RawR1csInstance"/> grows a deferred-public-input mode.
/// </para>
/// <para>
/// Byte order: the file stores both length fields and coefficient
/// values little-endian. Veridical's <see cref="R1csMatrix"/> stores
/// scalars in canonical big-endian; the reader reverses each
/// coefficient as it copies it from the file into the matrix value
/// buffer.
/// </para>
/// </remarks>
public static class CircomR1csReader
{
    private const uint SupportedFileVersion = 1u;
    private const uint HeaderSectionType = 1u;
    private const uint ConstraintSectionType = 2u;

    private static readonly byte[] FileMagic = [(byte)'r', (byte)'1', (byte)'c', (byte)'s'];

    /// <summary>
    /// BLS12-381 scalar field modulus
    /// <c>r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001</c>.
    /// Declared locally because Core cannot depend on the
    /// Bls12Curve381BigIntegerScalarReference backend: that type lives in
    /// Lumoin.Veridical.Backends.Managed, which references Core, not the
    /// other way round.
    /// </summary>
    private static readonly BigInteger Bls12Curve381ScalarFieldModulus = BigInteger.Parse(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    /// <summary>The BN254 (alt_bn128) scalar field order, against which a BN254-declared <c>.r1cs</c> prime is validated.</summary>
    private static readonly BigInteger Bn254ScalarFieldModulus = BigInteger.Parse(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    /// <summary>The Circom <c>.r1cs</c> reader exposed through the public delegate shape.</summary>
    public static R1csPipeReaderDelegate Reader { get; } =
        (pipe, format, curve, pool, cancellationToken) =>
            ReadInternal(pipe, format, curve, pool, cancellationToken);


    private static RawR1csInstance ReadInternal(
        PipeReader pipe,
        WellKnownR1csFormatLabel format,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        ArgumentNullException.ThrowIfNull(pool);

        if(format != WellKnownR1csFormatLabel.CircomBinary)
        {
            throw new ArgumentException(
                $"CircomR1csReader handles only WellKnownR1csFormatLabel.CircomBinary; received '{format.Identifier}'.",
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
            //Mark the entire buffer as consumed so the pipe can release
            //its memory; the parsed instance owns its own buffers from
            //'pool' at this point and no longer needs the pipe's bytes.
            pipe.AdvanceTo(buffer.End);
        }
    }


    private static RawR1csInstance ParseBuffer(
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
                $"CircomR1csReader supports only .r1cs file version {SupportedFileVersion}; file declares version {version}.");
        }

        uint sectionCount = ReadUInt32Le(ref reader, "section count");

        CircomR1csHeader? header = null;
        ReadOnlySequence<byte>? constraintSection = null;

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
                    header = ParseHeaderSection(sectionPayload, curve);
                    break;

                case ConstraintSectionType:
                    constraintSection = sectionPayload;
                    break;

                //All other section types (wire-to-label map, custom
                //gates, etc.) are skipped per the spec.
                default:
                    break;
            }
        }

        if(header is null)
        {
            throw new ArgumentException("R1CS file is missing the header section (type 1).");
        }

        if(constraintSection is null)
        {
            throw new ArgumentException("R1CS file is missing the constraint section (type 2).");
        }

        return ParseConstraintsAndBuild(constraintSection.Value, header.Value, curve, pool);
    }


    private static void ReadAndValidateMagic(ref SequenceReader<byte> reader)
    {
        Span<byte> magic = stackalloc byte[FileMagic.Length];
        if(!reader.TryCopyTo(magic))
        {
            throw new ArgumentException("R1CS file is shorter than the 4-byte magic.");
        }

        reader.Advance(FileMagic.Length);

        if(!magic.SequenceEqual(FileMagic))
        {
            throw new ArgumentException(
                $"R1CS file magic mismatch. Expected ASCII 'r1cs' (72 31 63 73); found {Convert.ToHexString(magic)}.");
        }
    }


    /// <summary>
    /// Reads a little-endian <see cref="uint"/> from
    /// <paramref name="reader"/>. The .r1cs format uses uint32 widely
    /// for length and count fields.
    /// </summary>
    private static uint ReadUInt32Le(ref SequenceReader<byte> reader, string fieldName)
    {
        Span<byte> bytes = stackalloc byte[sizeof(uint)];
        if(!reader.TryCopyTo(bytes))
        {
            throw new ArgumentException(
                $"R1CS file truncated while reading {fieldName} ({sizeof(uint)} bytes); only {reader.Remaining} bytes remained.");
        }

        reader.Advance(sizeof(uint));
        return BinaryPrimitives.ReadUInt32LittleEndian(bytes);
    }


    /// <summary>
    /// Reads a little-endian <see cref="ulong"/>. The .r1cs format uses
    /// uint64 for section sizes and the label count.
    /// </summary>
    private static ulong ReadUInt64Le(ref SequenceReader<byte> reader, string fieldName)
    {
        Span<byte> bytes = stackalloc byte[sizeof(ulong)];
        if(!reader.TryCopyTo(bytes))
        {
            throw new ArgumentException(
                $"R1CS file truncated while reading {fieldName} ({sizeof(ulong)} bytes); only {reader.Remaining} bytes remained.");
        }

        reader.Advance(sizeof(ulong));
        return BinaryPrimitives.ReadUInt64LittleEndian(bytes);
    }


    private static CircomR1csHeader ParseHeaderSection(
        ReadOnlySequence<byte> payload,
        CurveParameterSet curve)
    {
        var reader = new SequenceReader<byte>(payload);

        uint fieldSize = ReadUInt32Le(ref reader, "header.fieldSize");
        if(fieldSize == 0 || fieldSize > 256 || fieldSize % 8 != 0)
        {
            throw new ArgumentException(
                $"R1CS header declares field_size = {fieldSize}; must be a positive multiple of 8 not exceeding 256.");
        }

        int scalarSizeBytes = R1csMatrix.GetValueByteSize(curve);
        if(fieldSize != (uint)scalarSizeBytes)
        {
            throw new ArgumentException(
                $"R1CS header declares field_size = {fieldSize} bytes but curve {curve} expects {scalarSizeBytes} bytes per scalar.");
        }

        Span<byte> primeBytes = stackalloc byte[scalarSizeBytes];
        if(!reader.TryCopyTo(primeBytes))
        {
            throw new ArgumentException(
                $"R1CS header truncated while reading the prime modulus ({scalarSizeBytes} bytes).");
        }

        reader.Advance(scalarSizeBytes);
        ValidatePrimeModulus(primeBytes, curve);

        uint nWires = ReadUInt32Le(ref reader, "header.nWires");
        uint nPubOut = ReadUInt32Le(ref reader, "header.nPubOut");
        uint nPubIn = ReadUInt32Le(ref reader, "header.nPubIn");
        uint nPrvIn = ReadUInt32Le(ref reader, "header.nPrvIn");
        ulong nLabels = ReadUInt64Le(ref reader, "header.nLabels");
        uint nConstraints = ReadUInt32Le(ref reader, "header.nConstraints");

        if(nWires == 0)
        {
            throw new ArgumentException("R1CS header declares nWires = 0; circuits must have at least the constant wire.");
        }

        if(nConstraints == 0)
        {
            throw new ArgumentException("R1CS header declares nConstraints = 0; constraint section is mandatory.");
        }

        //The sum is computed in ulong: in uint arithmetic a crafted header
        //(e.g. nPubOut = 0xFFFFFFFF, nPubIn = 1) wraps mod 2^32 and slips
        //past this consistency check.
        if((ulong)nPubOut + nPubIn + nPrvIn + 1 > nWires)
        {
            throw new ArgumentException(
                $"R1CS header inconsistency: nPubOut ({nPubOut}) + nPubIn ({nPubIn}) + nPrvIn ({nPrvIn}) + 1 (constant) exceeds nWires ({nWires}).");
        }

        return new CircomR1csHeader(nWires, nPubOut, nPubIn, nPrvIn, nLabels, nConstraints);
    }


    private static void ValidatePrimeModulus(ReadOnlySpan<byte> primeLittleEndian, CurveParameterSet curve)
    {
        //File stores the prime little-endian; reverse to big-endian to
        //compare against BigInteger.Parse-style hex modulus.
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


    private static RawR1csInstance ParseConstraintsAndBuild(
        ReadOnlySequence<byte> payload,
        CircomR1csHeader header,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int scalarSizeBytes = R1csMatrix.GetValueByteSize(curve);
        int constraintCount = checked((int)header.NConstraints);
        int variableCount = checked((int)header.NWires);

        //Three running triple lists, one per matrix. Constraints are
        //read in ascending row order, but circom does NOT guarantee
        //ascending wire order WITHIN a linear combination (it emits terms
        //in construction order), so each accumulator sorts its triples by
        //(row, column) in Build before feeding R1csMatrix.FromSortedTriples.
        //Duplicate (row, column) pairs from buggy emitters survive the sort
        //as adjacent equal keys and surface as FromSortedTriples's
        //strict-ascending error.
        var aTriples = new TripleAccumulator(scalarSizeBytes);
        var bTriples = new TripleAccumulator(scalarSizeBytes);
        var cTriples = new TripleAccumulator(scalarSizeBytes);

        var reader = new SequenceReader<byte>(payload);

        for(int constraint = 0; constraint < constraintCount; constraint++)
        {
            ReadLinearCombinationInto(ref reader, constraint, scalarSizeBytes, variableCount, aTriples);
            ReadLinearCombinationInto(ref reader, constraint, scalarSizeBytes, variableCount, bTriples);
            ReadLinearCombinationInto(ref reader, constraint, scalarSizeBytes, variableCount, cTriples);
        }

        if(reader.Remaining != 0)
        {
            throw new ArgumentException(
                $"R1CS constraint section has {reader.Remaining} trailing bytes after the declared {constraintCount} constraints.");
        }

        R1csMatrix a = aTriples.Build(constraintCount, variableCount, curve, pool, "A");
        R1csMatrix b;
        R1csMatrix c;

        try
        {
            b = bTriples.Build(constraintCount, variableCount, curve, pool, "B");
        }
        catch
        {
            a.Dispose();
            throw;
        }

        try
        {
            c = cTriples.Build(constraintCount, variableCount, curve, pool, "C");
        }
        catch
        {
            a.Dispose();
            b.Dispose();
            throw;
        }

        try
        {
            //Public-input bytes are empty in this batch — see remarks
            //on the type. PublicInputCount = 0; the entire z[1..] is
            //handled as private witness from Veridical's perspective.
            return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, pool);
        }
        catch
        {
            a.Dispose();
            b.Dispose();
            c.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Reads one linear combination (<c>nTerms</c> followed by
    /// <c>nTerms</c> × (wire_index, coefficient_LE)) into the
    /// <paramref name="accumulator"/>, contributing one triple per
    /// non-zero term.
    /// </summary>
    private static void ReadLinearCombinationInto(
        ref SequenceReader<byte> reader,
        int constraintRow,
        int scalarSizeBytes,
        int variableCount,
        TripleAccumulator accumulator)
    {
        uint nTerms = ReadUInt32Le(ref reader, "linearCombination.nTerms");

        Span<byte> coefficientLe = stackalloc byte[64];
        if(scalarSizeBytes > coefficientLe.Length)
        {
            throw new ArgumentException(
                $"Scalar size {scalarSizeBytes} exceeds the inline buffer width.");
        }

        coefficientLe = coefficientLe[..scalarSizeBytes];

        for(uint t = 0; t < nTerms; t++)
        {
            uint wireIndex = ReadUInt32Le(ref reader, "linearCombination.wireIndex");

            if(wireIndex >= (uint)variableCount)
            {
                throw new ArgumentException(
                    $"Constraint row {constraintRow} references wire {wireIndex} but the circuit has only {variableCount} wires.");
            }

            if(!reader.TryCopyTo(coefficientLe))
            {
                throw new ArgumentException(
                    $"R1CS constraint section truncated while reading coefficient at constraint {constraintRow}, wire {wireIndex}.");
            }

            reader.Advance(scalarSizeBytes);
            accumulator.Add(constraintRow, (int)wireIndex, coefficientLe);
        }
    }


    /// <summary>Header section payload, captured for the constraint-section parse.</summary>
    private readonly record struct CircomR1csHeader(
        uint NWires,
        uint NPubOut,
        uint NPubIn,
        uint NPrvIn,
        ulong NLabels,
        uint NConstraints);


    /// <summary>
    /// Mutable accumulator for one matrix's (row, column, coefficient)
    /// triples. Coefficients arrive little-endian and are reversed
    /// into Veridical's canonical big-endian as they're stored.
    /// </summary>
    private sealed class TripleAccumulator
    {
        private readonly int scalarSizeBytes;
        private readonly List<int> rows = new();
        private readonly List<int> columns = new();
        private readonly List<byte> valueBytes = new();


        public TripleAccumulator(int scalarSizeBytes)
        {
            this.scalarSizeBytes = scalarSizeBytes;
        }


        public int Count => rows.Count;


        public void Add(int row, int column, ReadOnlySpan<byte> coefficientLittleEndian)
        {
            rows.Add(row);
            columns.Add(column);

            //Reverse LE -> BE while appending.
            for(int i = coefficientLittleEndian.Length - 1; i >= 0; i--)
            {
                valueBytes.Add(coefficientLittleEndian[i]);
            }
        }


        public R1csMatrix Build(
            int rowCount,
            int columnCount,
            CurveParameterSet curve,
            BaseMemoryPool pool,
            string matrixName)
        {
            if(rows.Count == 0)
            {
                //R1csMatrix requires at least one non-zero. A genuinely
                //all-zero matrix is uncommon in real Circom output;
                //synthesise a (0, 0) entry with coefficient zero to
                //satisfy the invariant without changing satisfaction
                //semantics.
                int[] singleRow = [0];
                int[] singleColumn = [0];
                byte[] zeroValue = new byte[scalarSizeBytes];
                return R1csMatrix.FromSortedTriples(
                    singleRow, singleColumn, zeroValue,
                    rowCount, columnCount, curve, pool);
            }

            int nnz = rows.Count;
            if(valueBytes.Count != nnz * scalarSizeBytes)
            {
                throw new InvalidOperationException(
                    $"Internal triple accumulator for matrix {matrixName} has {valueBytes.Count} value bytes for {nnz} triples; expected {nnz * scalarSizeBytes}.");
            }

            //Sort triples lexicographically by (row, column). Rows already
            //arrive grouped and ascending (constraints are read in row order);
            //only the columns within a row may be unordered, since circom does
            //not emit linear-combination terms in ascending wire order.
            //FromSortedTriples requires strictly-ascending (row, column) input.
            int[] order = new int[nnz];
            for(int i = 0; i < nnz; i++)
            {
                order[i] = i;
            }

            Array.Sort(order, (x, y) =>
            {
                int byRow = rows[x].CompareTo(rows[y]);
                return byRow != 0 ? byRow : columns[x].CompareTo(columns[y]);
            });

            int[] sortedRows = new int[nnz];
            int[] sortedColumns = new int[nnz];
            byte[] sortedValues = new byte[nnz * scalarSizeBytes];
            byte[] flatValues = valueBytes.ToArray();
            for(int i = 0; i < nnz; i++)
            {
                int source = order[i];
                sortedRows[i] = rows[source];
                sortedColumns[i] = columns[source];
                Array.Copy(flatValues, source * scalarSizeBytes, sortedValues, i * scalarSizeBytes, scalarSizeBytes);
            }

            return R1csMatrix.FromSortedTriples(
                sortedRows,
                sortedColumns,
                sortedValues,
                rowCount, columnCount, curve, pool);
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

            //Tell the pipe we've examined everything but consumed
            //nothing, so it keeps buffering until completion. The full
            //file is small (Poseidon at ~200 constraints is well under
            //100 KiB) so the whole-file-in-memory approach is fine.
            pipe.AdvanceTo(result.Buffer.Start, result.Buffer.End);
        }
    }
}