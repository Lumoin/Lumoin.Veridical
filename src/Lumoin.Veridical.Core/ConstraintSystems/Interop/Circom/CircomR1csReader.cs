using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO.Pipelines;
using System.Numerics;
using System.Runtime.InteropServices;
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
/// into the corresponding <see cref="RawR1csWitness"/>.
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
    /// <summary>The largest admitted field width, 256 bytes, bounding the header shape check before curve validation.</summary>
    private const uint MaximumFieldSizeBytes = 256u;

    /// <summary>The field width alignment required by the reader: a positive multiple of eight bytes.</summary>
    private const uint FieldSizeAlignmentBytes = 8u;

    /// <summary>The one leading wire reserved for the constant in the Circom witness convention.</summary>
    private const int ConstantWireCount = 1;

    /// <summary>The first constraint row, zero, used for the placeholder entry of an empty matrix.</summary>
    private const int EmptyMatrixRow = 0;

    /// <summary>The constant wire column, zero, used for the placeholder entry of an empty matrix.</summary>
    private const int ConstantWireColumn = 0;

    /// <summary>The only supported file version: 1 for the Circom R1CS format.</summary>
    private const uint SupportedFileVersion = 1u;

    /// <summary>The section type code 1, which identifies the field and circuit header in the binary format.</summary>
    private const uint HeaderSectionType = 1u;

    /// <summary>The section type code 2, which identifies the constraint terms in the binary format.</summary>
    private const uint ConstraintSectionType = 2u;

    /// <summary>The four ASCII bytes that identify a <c>.r1cs</c> file.</summary>
    private static byte[] FileMagic { get; } = [(byte)'r', (byte)'1', (byte)'c', (byte)'s'];

    /// <summary>
    /// BLS12-381 scalar field modulus
    /// <c>r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001</c>.
    /// Declared locally because Core cannot depend on the
    /// Bls12Curve381BigIntegerScalarReference backend: that type lives in
    /// Lumoin.Veridical.Backends.Managed, which references Core, not the
    /// other way round.
    /// </summary>
    private static BigInteger Bls12Curve381ScalarFieldModulus { get; } = BigInteger.Parse(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    /// <summary>The BN254 (alt_bn128) scalar field order, against which a BN254-declared <c>.r1cs</c> prime is validated.</summary>
    private static BigInteger Bn254ScalarFieldModulus { get; } = BigInteger.Parse(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    /// <summary>The Circom <c>.r1cs</c> reader exposed through the public delegate shape.</summary>
    public static R1csPipeReaderDelegate Reader { get; } =
        (pipe, format, curve, pool, maximumIntakeBytes, cancellationToken) =>
            ReadInternal(pipe, format, curve, pool, maximumIntakeBytes, cancellationToken);


    /// <summary>Validates the reader arguments before draining the pipe, then parses and consumes its complete buffer.</summary>
    private static RawR1csInstance ReadInternal(
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

        if(format != WellKnownR1csFormatLabel.CircomBinary)
        {
            throw new ArgumentException(
                $"CircomR1csReader handles only WellKnownR1csFormatLabel.CircomBinary; received '{format.Identifier}'.",
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
            //Mark the entire buffer as consumed so the pipe can release
            //its memory; the parsed instance owns its own buffers,
            //copied from 'pool', independent of the pipe's bytes.
            pipe.AdvanceTo(buffer.End);
        }
    }


    /// <summary>Validates the file envelope and required sections, then constructs the parsed instance.</summary>
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

            //Only the header and data sections are interpreted; other payloads are skipped.
            if(sectionType is HeaderSectionType)
            {
                header = ParseHeaderSection(sectionPayload, curve);
            }
            else if(sectionType is ConstraintSectionType)
            {
                constraintSection = sectionPayload;
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


    /// <summary>Consumes the file magic and rejects truncated or unrecognised signatures.</summary>
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


    /// <summary>Validates the scalar field and header counts before returning the circuit dimensions.</summary>
    private static CircomR1csHeader ParseHeaderSection(
        ReadOnlySequence<byte> payload,
        CurveParameterSet curve)
    {
        var reader = new SequenceReader<byte>(payload);

        uint fieldSize = ReadUInt32Le(ref reader, "header.fieldSize");
        if(fieldSize == 0 || fieldSize > MaximumFieldSizeBytes || fieldSize % FieldSizeAlignmentBytes != 0)
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

        //nWires and nConstraints are attacker-controlled uint32 fields that index Int32-based
        //buffers during construction. A header declaring either above Int32.MaxValue must be
        //rejected here as malformed rather than surface later as an OverflowException from the
        //checked (int) casts in ParseConstraintsAndBuild.
        if(nWires > int.MaxValue)
        {
            throw new ArgumentException($"R1CS header declares nWires = {nWires}, exceeding the maximum supported wire count ({int.MaxValue}).");
        }

        if(nConstraints > int.MaxValue)
        {
            throw new ArgumentException($"R1CS header declares nConstraints = {nConstraints}, exceeding the maximum supported constraint count ({int.MaxValue}).");
        }

        //The sum is computed in ulong: in uint arithmetic a crafted header
        //(e.g. nPubOut = 0xFFFFFFFF, nPubIn = 1) wraps mod 2^32 and slips
        //past this consistency check.
        if((ulong)nPubOut + nPubIn + nPrvIn + ConstantWireCount > nWires)
        {
            throw new ArgumentException(
                $"R1CS header inconsistency: nPubOut ({nPubOut}) + nPubIn ({nPubIn}) + nPrvIn ({nPrvIn}) + 1 (constant) exceeds nWires ({nWires}).");
        }

        return new CircomR1csHeader(nWires, nPubOut, nPubIn, nPrvIn, nLabels, nConstraints);
    }


    /// <summary>Checks the unsigned little-endian modulus against the declared curve scalar field.</summary>
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


    /// <summary>Reads every encoded constraint and constructs the three sorted matrices with no public input values.</summary>
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

        R1csMatrix a = aTriples.Build(constraintCount, variableCount, curve, pool);
        R1csMatrix b;
        R1csMatrix c;

        try
        {
            b = bTriples.Build(constraintCount, variableCount, curve, pool);
        }
        catch
        {
            a.Dispose();
            throw;
        }

        try
        {
            c = cTriples.Build(constraintCount, variableCount, curve, pool);
        }
        catch
        {
            a.Dispose();
            b.Dispose();
            throw;
        }

        try
        {
            //Public-input bytes are empty under the PublicInputCount = 0
            //convention described in the type's remarks; the entire
            //z[1..] is handled as private witness from Veridical's
            //perspective.
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
    /// encoded term.
    /// </summary>
    private static void ReadLinearCombinationInto(
        ref SequenceReader<byte> reader,
        int constraintRow,
        int scalarSizeBytes,
        int variableCount,
        TripleAccumulator accumulator)
    {
        uint nTerms = ReadUInt32Le(ref reader, "linearCombination.nTerms");

        //The scalar width comes from the declared curve, never from the file, so the buffer holds exactly one coefficient.
        Span<byte> coefficientLe = stackalloc byte[scalarSizeBytes];

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
    /// <param name="NWires">The total wire count, including the constant.</param>
    /// <param name="NPubOut">The declared number of public output wires.</param>
    /// <param name="NPubIn">The declared number of public input wires.</param>
    /// <param name="NPrvIn">The declared number of private input wires.</param>
    /// <param name="NLabels">The number of labels in the wire-to-label map.</param>
    /// <param name="NConstraints">The number of constraint rows to read.</param>
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
        /// <summary>The canonical byte width of every coefficient stored in this accumulator.</summary>
        private int ScalarSizeBytes { get; }

        /// <summary>The constraint row for each encoded term, in arrival order.</summary>
        private List<int> Rows { get; } = new();

        /// <summary>The wire column for each encoded term, in arrival order.</summary>
        private List<int> Columns { get; } = new();

        /// <summary>The canonical big-endian coefficients, one scalar per encoded term in arrival order.</summary>
        private List<byte> ValueBytes { get; } = new();


        /// <summary>Creates an empty accumulator whose coefficients have the supplied canonical byte width.</summary>
        public TripleAccumulator(int scalarSizeBytes)
        {
            this.ScalarSizeBytes = scalarSizeBytes;
        }


        /// <summary>The number of encoded terms currently held by this accumulator.</summary>
        public int Count => Rows.Count;


        /// <summary>Appends a term and reverses its coefficient from little-endian to canonical big-endian.</summary>
        public void Add(int row, int column, ReadOnlySpan<byte> coefficientLittleEndian)
        {
            Rows.Add(row);
            Columns.Add(column);

            //Reverse LE -> BE while appending.
            for(int i = coefficientLittleEndian.Length - 1; i >= 0; i--)
            {
                ValueBytes.Add(coefficientLittleEndian[i]);
            }
        }


        /// <summary>Sorts terms by row and column and constructs a matrix, supplying one zero entry when no terms are encoded.</summary>
        /// <remarks>
        /// Coefficients are staged in a pooled buffer and copied into the matrix's own storage by
        /// <see cref="R1csMatrix.FromSortedTriples"/>. The staging rental is disposed when this method exits.
        /// </remarks>
        public R1csMatrix Build(
            int rowCount,
            int columnCount,
            CurveParameterSet curve,
            BaseMemoryPool pool)
        {
            if(Rows.Count == 0)
            {
                //R1csMatrix requires at least one stored entry. A zero coefficient at the first row and
                //constant column satisfies that storage invariant without changing which witnesses satisfy it.
                int[] singleRow = [EmptyMatrixRow];
                int[] singleColumn = [ConstantWireColumn];
                using IMemoryOwner<byte> zeroValueOwner = pool.Rent(ScalarSizeBytes);
                Span<byte> zeroValue = zeroValueOwner.Memory.Span[..ScalarSizeBytes];
                //The pool is the caller's and may not zero a fresh rental; clearing sets this placeholder coefficient to exactly zero.
                zeroValue.Clear();

                return R1csMatrix.FromSortedTriples(
                    singleRow, singleColumn, zeroValue,
                    rowCount, columnCount, curve, pool);
            }

            //Every Add appends one row and exactly one scalar's coefficient bytes, so valueBytes holds nnz scalars.
            int nnz = Rows.Count;

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
                int byRow = Rows[x].CompareTo(Rows[y]);

                return byRow != 0 ? byRow : Columns[x].CompareTo(Columns[y]);
            });

            int[] sortedRows = new int[nnz];
            int[] sortedColumns = new int[nnz];
            int sortedValuesLength = nnz * ScalarSizeBytes;
            using IMemoryOwner<byte> sortedValuesOwner = pool.Rent(sortedValuesLength);
            Span<byte> sortedValues = sortedValuesOwner.Memory.Span[..sortedValuesLength];
            ReadOnlySpan<byte> flatValues = CollectionsMarshal.AsSpan(ValueBytes);
            for(int i = 0; i < nnz; i++)
            {
                int source = order[i];
                sortedRows[i] = Rows[source];
                sortedColumns[i] = Columns[source];
                flatValues.Slice(source * ScalarSizeBytes, ScalarSizeBytes)
                    .CopyTo(sortedValues.Slice(i * ScalarSizeBytes, ScalarSizeBytes));
            }

            return R1csMatrix.FromSortedTriples(
                sortedRows,
                sortedColumns,
                sortedValues,
                rowCount, columnCount, curve, pool);
        }
    }
}
