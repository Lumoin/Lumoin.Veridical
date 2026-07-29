using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Core.Lookup;

/// <summary>
/// Prover-side column construction for the LogUp argument: the multiplicity
/// column counted from the witness against the table, and the helper column of
/// batched fractional terms at the denominator challenge.
/// </summary>
/// <remarks>
/// <para>
/// The multiplicity column is always computed here from the witness and table —
/// never caller-supplied — so a caller cannot present multiplicities that were
/// chosen after seeing a transcript challenge. Occurrence counts aggregate onto
/// the first table position (in table order) holding a given value; duplicate
/// table entries later in the column carry multiplicity zero, which the
/// log-derivative identity absorbs harmlessly.
/// </para>
/// <para>
/// Batch inversion uses Montgomery's trick (one field inversion plus three
/// multiplications per element) and throws on a zero input instead of the
/// common silent 0 → 0 convention: a zero denominator means the transcript
/// challenge collided with a table or witness value — a negligible-probability
/// completeness abort that must fail loudly, never emit a garbage column.
/// </para>
/// </remarks>
internal static class LogUpColumns
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Builds the multiplicity column: for every hypercube position, the number
    /// of witness entries (across all columns) equal to that position's table
    /// value, aggregated onto the first table position holding the value.
    /// Throws when any witness entry is absent from the table — the statement
    /// is false and no proof exists.
    /// </summary>
    /// <param name="tableEvaluations">The table column, <c>2^variableCount × 32</c> canonical bytes.</param>
    /// <param name="witnessEvaluations">The witness columns concatenated, <c>witnessColumnCount × 2^variableCount × 32</c> canonical bytes.</param>
    /// <param name="variableCount">The hypercube variable count.</param>
    /// <param name="witnessColumnCount">The number of witness columns.</param>
    /// <param name="pool">The pool to rent the result and scratch from.</param>
    /// <returns>The multiplicity column evaluations, <c>2^variableCount × 32</c> bytes; ownership transfers to the caller.</returns>
    /// <exception cref="ArgumentException">When a witness entry does not appear in the table.</exception>
    public static IMemoryOwner<byte> BuildMultiplicities(
        ReadOnlySpan<byte> tableEvaluations,
        ReadOnlySpan<byte> witnessEvaluations,
        int variableCount,
        int witnessColumnCount,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int size = 1 << variableCount;

        //Sort table indices by value bytes (stable through the index tiebreak),
        //so every run of equal values is contiguous and starts at the smallest
        //table index — the position all multiplicity weight aggregates onto.
        using IMemoryOwner<byte> orderOwner = pool.Rent(size * sizeof(int));
        Span<int> order = MemoryMarshal.Cast<byte, int>(orderOwner.Memory.Span)[..size];
        for(int i = 0; i < size; i++)
        {
            order[i] = i;
        }

        //Sorting needs the table bytes reachable from a capturable Memory.
        IMemoryOwner<byte> tableCopyOwner = pool.Rent(size * ScalarSize);
        Memory<byte> tableCopy = tableCopyOwner.Memory[..(size * ScalarSize)];
        tableEvaluations.CopyTo(tableCopy.Span);
        try
        {
            order.Sort((left, right) =>
            {
                int comparison = tableCopy.Span.Slice(left * ScalarSize, ScalarSize)
                    .SequenceCompareTo(tableCopy.Span.Slice(right * ScalarSize, ScalarSize));

                return comparison != 0 ? comparison : left.CompareTo(right);
            });

            using IMemoryOwner<byte> countOwner = pool.Rent(size * sizeof(long));
            Span<long> counts = MemoryMarshal.Cast<byte, long>(countOwner.Memory.Span)[..size];
            counts.Clear();

            for(int column = 0; column < witnessColumnCount; column++)
            {
                for(int row = 0; row < size; row++)
                {
                    ReadOnlySpan<byte> value = witnessEvaluations.Slice(((column * size) + row) * ScalarSize, ScalarSize);
                    int runStart = FindFirstEqualInOrder(tableCopy.Span, order, value);
                    if(runStart < 0)
                    {
                        throw new ArgumentException(
                            $"Witness column {column}, row {row} holds a value that does not appear in the table; the lookup statement is false.",
                            nameof(witnessEvaluations));
                    }

                    counts[order[runStart]]++;
                }
            }

            IMemoryOwner<byte> multiplicityOwner = pool.Rent(size * ScalarSize);
            Span<byte> multiplicities = multiplicityOwner.Memory.Span[..(size * ScalarSize)];
            multiplicities.Clear();
            for(int i = 0; i < size; i++)
            {
                //Counts are bounded by witnessColumnCount · 2^variableCount, far
                //below the scalar field order, so the big-endian tail encoding is
                //always canonical.
                BinaryPrimitives.WriteUInt64BigEndian(
                    multiplicities.Slice((i * ScalarSize) + (ScalarSize - sizeof(ulong)), sizeof(ulong)),
                    (ulong)counts[i]);
            }

            return multiplicityOwner;
        }
        finally
        {
            tableCopyOwner.Dispose();
        }
    }


    /// <summary>
    /// Builds the helper column
    /// <c>h(y) = m(y)/(x − t(y)) − Σ_i 1/(x − w_i(y))</c> at the denominator
    /// challenge <c>x</c>, using one batched inversion per column.
    /// </summary>
    /// <param name="tableEvaluations">The table column bytes.</param>
    /// <param name="witnessEvaluations">The witness columns concatenated.</param>
    /// <param name="multiplicityEvaluations">The multiplicity column bytes.</param>
    /// <param name="denominatorChallenge">The challenge <c>x</c>, 32 canonical bytes.</param>
    /// <param name="variableCount">The hypercube variable count.</param>
    /// <param name="witnessColumnCount">The number of witness columns.</param>
    /// <param name="add">Scalar-add delegate.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="invert">Scalar-invert delegate.</param>
    /// <param name="curve">The curve whose scalar field the columns live in.</param>
    /// <param name="pool">The pool to rent the result and scratch from.</param>
    /// <returns>The helper column evaluations; ownership transfers to the caller.</returns>
    /// <exception cref="ArgumentException">When the challenge collides with a table or witness value (zero denominator).</exception>
    public static IMemoryOwner<byte> BuildHelperColumn(
        ReadOnlySpan<byte> tableEvaluations,
        ReadOnlySpan<byte> witnessEvaluations,
        ReadOnlySpan<byte> multiplicityEvaluations,
        ReadOnlySpan<byte> denominatorChallenge,
        int variableCount,
        int witnessColumnCount,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);

        int size = 1 << variableCount;

        IMemoryOwner<byte> helperOwner = pool.Rent(size * ScalarSize);
        Span<byte> helper = helperOwner.Memory.Span[..(size * ScalarSize)];
        try
        {
            using IMemoryOwner<byte> denominatorOwner = pool.Rent(size * ScalarSize);
            Span<byte> denominators = denominatorOwner.Memory.Span[..(size * ScalarSize)];
            Span<byte> scratch = stackalloc byte[ScalarSize];

            //Table side first: h = m · (x − t)^-1.
            for(int i = 0; i < size; i++)
            {
                subtract(denominatorChallenge, tableEvaluations.Slice(i * ScalarSize, ScalarSize), denominators.Slice(i * ScalarSize, ScalarSize), curve);
            }

            InvertInPlace(denominators, size, multiply, invert, curve, pool);
            for(int i = 0; i < size; i++)
            {
                multiply(multiplicityEvaluations.Slice(i * ScalarSize, ScalarSize), denominators.Slice(i * ScalarSize, ScalarSize), helper.Slice(i * ScalarSize, ScalarSize), curve);
            }

            //Witness side: subtract each column's (x − w_i)^-1.
            for(int column = 0; column < witnessColumnCount; column++)
            {
                for(int i = 0; i < size; i++)
                {
                    subtract(denominatorChallenge, witnessEvaluations.Slice(((column * size) + i) * ScalarSize, ScalarSize), denominators.Slice(i * ScalarSize, ScalarSize), curve);
                }

                InvertInPlace(denominators, size, multiply, invert, curve, pool);
                for(int i = 0; i < size; i++)
                {
                    Span<byte> destination = helper.Slice(i * ScalarSize, ScalarSize);
                    subtract(destination, denominators.Slice(i * ScalarSize, ScalarSize), scratch, curve);
                    scratch.CopyTo(destination);
                }
            }

            return helperOwner;
        }
        catch
        {
            helperOwner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Montgomery-trick batch inversion in place: one field inversion plus three
    /// multiplications per element. Throws on a zero element — the callers'
    /// denominators are zero exactly when a transcript challenge collided with a
    /// committed value, which must abort loudly rather than emit zeros.
    /// </summary>
    /// <param name="elements">The elements to invert in place, <c>count × 32</c> canonical bytes.</param>
    /// <param name="count">The element count; at least 1.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="invert">Scalar-invert delegate.</param>
    /// <param name="curve">The curve whose scalar field the elements live in.</param>
    /// <param name="pool">The pool to rent the prefix scratch from.</param>
    /// <exception cref="ArgumentException">When an element is zero.</exception>
    public static void InvertInPlace(
        Span<byte> elements,
        int count,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(count, 1);
        if(elements.Length != count * ScalarSize)
        {
            throw new ArgumentException($"Batch inversion over {count} elements needs {count * ScalarSize} bytes; received {elements.Length}.", nameof(elements));
        }

        using IMemoryOwner<byte> prefixOwner = pool.Rent(count * ScalarSize);
        Span<byte> prefixes = prefixOwner.Memory.Span[..(count * ScalarSize)];

        for(int i = 0; i < count; i++)
        {
            ReadOnlySpan<byte> element = elements.Slice(i * ScalarSize, ScalarSize);
            if(!element.ContainsAnyExcept((byte)0))
            {
                throw new ArgumentException($"Batch inversion input {i} is zero; a LogUp denominator vanished, meaning the transcript challenge collided with a committed value.", nameof(elements));
            }

            if(i == 0)
            {
                element.CopyTo(prefixes[..ScalarSize]);
            }
            else
            {
                multiply(prefixes.Slice((i - 1) * ScalarSize, ScalarSize), element, prefixes.Slice(i * ScalarSize, ScalarSize), curve);
            }
        }

        Span<byte> runningInverse = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        invert(prefixes.Slice((count - 1) * ScalarSize, ScalarSize), runningInverse, curve);

        for(int i = count - 1; i >= 1; i--)
        {
            Span<byte> element = elements.Slice(i * ScalarSize, ScalarSize);
            multiply(runningInverse, element, scratch, curve);
            multiply(runningInverse, prefixes.Slice((i - 1) * ScalarSize, ScalarSize), element, curve);
            scratch.CopyTo(runningInverse);
        }

        runningInverse.CopyTo(elements[..ScalarSize]);
    }


    //Binary search over the sorted index order for the first position whose
    //table value equals the probe; −1 when absent.
    private static int FindFirstEqualInOrder(ReadOnlySpan<byte> tableBytes, ReadOnlySpan<int> order, ReadOnlySpan<byte> value)
    {
        int low = 0;
        int high = order.Length - 1;
        int found = -1;
        while(low <= high)
        {
            int middle = low + ((high - low) / 2);
            int comparison = tableBytes.Slice(order[middle] * ScalarSize, ScalarSize).SequenceCompareTo(value);
            if(comparison < 0)
            {
                low = middle + 1;
            }
            else if(comparison > 0)
            {
                high = middle - 1;
            }
            else
            {
                found = middle;
                high = middle - 1;
            }
        }

        return found;
    }
}
