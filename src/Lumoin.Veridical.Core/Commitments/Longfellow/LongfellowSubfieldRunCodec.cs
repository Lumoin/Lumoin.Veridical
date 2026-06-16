using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The field-specific subfield handling the Ligero proof serializer's run-length encoder needs: the
/// <c>in_subfield</c> predicate that bounds each run, the subfield element byte width
/// (<c>Field::kSubFieldBytes</c>), and the <c>to_bytes_subfield</c> / <c>of_bytes_subfield</c> framing.
/// It is the serializer's seam between the two fields without a type hierarchy: the binary hash circuit
/// builds <see cref="ForGf2k128"/> (the GF(2^128) basis solve over a pooled row-echelon reduction), the
/// prime signature circuit builds <see cref="ForFp256"/> (the base field is its own subfield, so every
/// element is in-subfield and the subfield framing equals the full-field framing).
/// </summary>
/// <remarks>
/// <para>
/// The reference's run-length pass (<c>zk_proof.h write_com_proof</c>) alternates full-field and
/// subfield runs, the first run full-field, the boundary being a change of <c>F.in_subfield(req[i])</c>.
/// Over <c>Fp256Base</c> (<c>fp_generic.h</c>: <c>in_subfield ≡ true</c>, line 284) the leading
/// full-field run is empty and one subfield run covers everything; since
/// <c>to_bytes_subfield ≡ to_bytes_field</c> and <c>kSubFieldBytes = kBytes = 32</c> (lines 47, 386–388),
/// each element still writes its 32-byte <c>to_bytes_field</c> bytes. Over <c>f_128</c> the predicate is
/// the GF(2)-basis membership test and the subfield framing compresses an in-subfield element to its
/// <c>subFieldBytes</c> coordinate vector.
/// </para>
/// <para>
/// Disposable: the GF(2^128) codec owns the pooled basis reduction; the Fp256 codec owns nothing.
/// </para>
/// </remarks>
internal sealed class LongfellowSubfieldRunCodec: IDisposable
{
    private readonly Func<ReadOnlySpan<byte>, bool> inSubfield;
    private readonly EncodeSubfieldDelegate toBytesSubfield;
    private readonly DecodeSubfieldDelegate ofBytesSubfield;
    private IDisposable? state;


    //The two subfield framing operations, as span delegates so the GF basis solve and the Fp256 identity
    //reversal share one shape without an interface.
    private delegate void EncodeSubfieldDelegate(ReadOnlySpan<byte> element, Span<byte> destination);

    private delegate bool DecodeSubfieldDelegate(ReadOnlySpan<byte> source, Span<byte> element);


    private LongfellowSubfieldRunCodec(
        int subFieldBytes,
        Func<ReadOnlySpan<byte>, bool> inSubfield,
        EncodeSubfieldDelegate toBytesSubfield,
        DecodeSubfieldDelegate ofBytesSubfield,
        IDisposable? state)
    {
        SubFieldBytes = subFieldBytes;
        this.inSubfield = inSubfield;
        this.toBytesSubfield = toBytesSubfield;
        this.ofBytesSubfield = ofBytesSubfield;
        this.state = state;
    }


    /// <summary>The subfield element byte width (<c>Field::kSubFieldBytes</c>).</summary>
    public int SubFieldBytes { get; }


    /// <summary>
    /// The GF(2^128) codec: the <c>in_subfield</c> basis solve over a pooled row-echelon reduction of the
    /// subfield basis (<c>g^j</c> from <paramref name="fft"/>), with the coordinate-vector framing.
    /// </summary>
    /// <param name="profile">The field profile (validated as the GF(2^128) profile is the serializer's caller; carried for symmetry with <see cref="ForFp256"/>).</param>
    /// <param name="fft">The LCH14 engine over the matching subfield, supplying the basis.</param>
    /// <param name="subFieldBytes">The subfield element byte size (2 for GF(2^16), 4 for GF(2^32)).</param>
    /// <param name="pool">The pool the basis reduction rents from.</param>
    public static LongfellowSubfieldRunCodec ForGf2k128(LongfellowFieldProfile profile, Lch14AdditiveFft fft, int subFieldBytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(fft);
        ArgumentNullException.ThrowIfNull(pool);

        SubfieldBasis basis = SubfieldBasis.Reduce(fft, subFieldBytes, pool);

        return new LongfellowSubfieldRunCodec(
            subFieldBytes,
            basis.InSubfield,
            basis.ToBytesSubfield,
            (source, element) =>
            {
                basis.OfBytesSubfield(source, element);

                return true;
            },
            basis);
    }


    /// <summary>
    /// The P-256 base-field codec: <c>in_subfield ≡ true</c>, <c>kSubFieldBytes = 32</c>, and the subfield
    /// framing IS the full-field framing (<c>to_bytes_subfield ≡ to_bytes_field</c>,
    /// <c>of_bytes_subfield ≡ of_bytes_field</c>), routed through <paramref name="profile"/>. It owns no
    /// pooled state.
    /// </summary>
    /// <param name="profile">The Fp256 field profile, supplying the 32-byte <c>to_bytes_field</c> / <c>of_bytes_field</c> framing.</param>
    public static LongfellowSubfieldRunCodec ForFp256(LongfellowFieldProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        return new LongfellowSubfieldRunCodec(
            profile.ElementBytes,
            static _ => true,
            profile.ToBytesField,
            profile.TryFromBytesField,
            state: null);
    }


    /// <summary>The reference's <c>in_subfield(req[i])</c>: whether the run-length pass should treat the element as a subfield element.</summary>
    /// <param name="element">The canonical scalar to test.</param>
    public bool InSubfield(ReadOnlySpan<byte> element) => inSubfield(element);


    /// <summary>The reference's <c>to_bytes_subfield</c>: writes the element's <see cref="SubFieldBytes"/> subfield bytes.</summary>
    /// <param name="element">The canonical scalar (asserted in-subfield by the caller's run logic).</param>
    /// <param name="destination">Receives <see cref="SubFieldBytes"/> bytes.</param>
    public void ToBytesSubfield(ReadOnlySpan<byte> element, Span<byte> destination) => toBytesSubfield(element, destination);


    /// <summary>
    /// The reference's <c>of_bytes_subfield</c>: reads <see cref="SubFieldBytes"/> bytes into a canonical
    /// scalar. The GF(2^128) basis recombination always succeeds; the Fp256 reversal applies the
    /// <c>fits</c> guard and returns <see langword="false"/> on out-of-range bytes (the parse-safe reader's
    /// graceful reject).
    /// </summary>
    /// <param name="source">The <see cref="SubFieldBytes"/> subfield bytes.</param>
    /// <param name="element">Receives the canonical scalar, or all zeros on rejection.</param>
    /// <returns><see langword="true"/> when the bytes decode to a field element; otherwise <see langword="false"/>.</returns>
    public bool OfBytesSubfield(ReadOnlySpan<byte> source, Span<byte> element) => ofBytesSubfield(source, element);


    /// <summary>Releases the pooled basis reduction, if any.</summary>
    public void Dispose()
    {
        IDisposable? local = state;
        if(local is not null)
        {
            state = null;
            local.Dispose();
        }
    }


    /// <summary>
    /// The row-echelon reduction of the GF(2^128) subfield basis, a port of the reference's
    /// <c>GF2_128::beta_ref</c> plus the per-element <c>solve</c>. It backs the three subfield
    /// serialization primitives: <see cref="InSubfield"/> (the run predicate),
    /// <see cref="ToBytesSubfield"/> (encode), and <see cref="OfBytesSubfield"/> (decode).
    /// </summary>
    /// <remarks>
    /// The basis rows are <c>β_j = g^j</c> over the field's 128-bit polynomial representation, read from
    /// <see cref="Lch14AdditiveFft.BasisElement"/>. <c>beta_ref</c> reduces the basis to row echelon,
    /// caching the echelon rows <c>u_</c>, the coordinate combination <c>linv_</c>, and the leading
    /// nonzero column per row <c>ldnz_</c>; <c>solve</c> reduces a queried element against the echelon
    /// rows, yielding a residual (zero iff the element is in the subfield) and the coordinate vector.
    /// </remarks>
    private sealed class SubfieldBasis: IDisposable
    {
        //A field element's 128-bit polynomial lives in two 64-bit limbs: limb 0 holds bits 0..63, limb 1
        //bits 64..127. The C# scalar carries them big-endian in canonical bytes 24..31 (limb 0) and
        //16..23 (limb 1), with bytes 0..15 zero (the high field bytes).
        private const int LimbCount = 2;
        private const int LowLimbByteOffset = 24;
        private const int HighLimbByteOffset = 16;

        private readonly int subFieldBits;
        private IMemoryOwner<byte>? scratchOwner;

        public int SubFieldBytes { get; }


        private SubfieldBasis(int subFieldBytes, int subFieldBits, IMemoryOwner<byte> scratchOwner)
        {
            SubFieldBytes = subFieldBytes;
            this.subFieldBits = subFieldBits;
            this.scratchOwner = scratchOwner;
        }


        //The single pooled buffer carving out the four views: basis rows, echelon rows, the
        //coordinate combinations, the leading columns — byte sizes in that order.
        private static int BasisRowsBytes(int subFieldBits) => subFieldBits * LimbCount * sizeof(ulong);

        private static int CombinationBytes(int subFieldBits) => subFieldBits * sizeof(uint);

        private static int ScratchBytes(int subFieldBits) =>
            (2 * BasisRowsBytes(subFieldBits)) + CombinationBytes(subFieldBits) + (subFieldBits * sizeof(int));


        private Span<byte> Scratch =>
            (scratchOwner ?? throw new ObjectDisposedException(nameof(SubfieldBasis))).Memory.Span[..ScratchBytes(subFieldBits)];

        //β_j: the j-th subfield basis row (g^j), two limbs; used by of_bytes_subfield to recombine.
        private Span<ulong> BasisRows => MemoryMarshal.Cast<byte, ulong>(Scratch[..BasisRowsBytes(subFieldBits)]);

        //u_[i]: the i-th echelon row, two limbs.
        private Span<ulong> EchelonRows => MemoryMarshal.Cast<byte, ulong>(Scratch.Slice(BasisRowsBytes(subFieldBits), BasisRowsBytes(subFieldBits)));

        //linv_[i]: the coordinate bits that combine to the i-th echelon row (at most 32 here, nreq fits).
        private Span<uint> CoordinateCombination => MemoryMarshal.Cast<byte, uint>(Scratch.Slice(2 * BasisRowsBytes(subFieldBits), CombinationBytes(subFieldBits)));

        //ldnz_[i]: the leading-nonzero column of the i-th echelon row.
        private Span<int> LeadingColumn => MemoryMarshal.Cast<byte, int>(Scratch[((2 * BasisRowsBytes(subFieldBits)) + CombinationBytes(subFieldBits))..]);


        //The reference's beta_ref: reduce the basis {β_0, …, β_{m−1}} to row echelon, caching the
        //echelon rows, the GF(2) coordinate combination that produced each, and the leading column.
        public static SubfieldBasis Reduce(Lch14AdditiveFft fft, int subFieldBytes, BaseMemoryPool pool)
        {
            int subFieldBits = subFieldBytes * 8;

            IMemoryOwner<byte> scratchOwner = pool.Rent(ScratchBytes(subFieldBits));
            SubfieldBasis basis = new(subFieldBytes, subFieldBits, scratchOwner);

            Span<ulong> basisRows = basis.BasisRows;
            Span<ulong> echelonRows = basis.EchelonRows;
            Span<uint> coordinateCombination = basis.CoordinateCombination;
            Span<int> leadingColumn = basis.LeadingColumn;

            //Seed: u_[i] = β_i, linv_[i] = 1 << i (the i-th coordinate). Keep the original β_i for decode.
            for(int i = 0; i < subFieldBits; i++)
            {
                (ulong low, ulong high) = ToLimbs(fft.BasisElement(i));
                basisRows[(i * LimbCount) + 0] = low;
                basisRows[(i * LimbCount) + 1] = high;
                echelonRows[(i * LimbCount) + 0] = low;
                echelonRows[(i * LimbCount) + 1] = high;
                coordinateCombination[i] = 1u << i;
                leadingColumn[i] = 0;
            }

            //Gaussian elimination over GF(2): for each column, pick a pivot row at or below the current
            //rank and eliminate that column from every lower row, tracking the coordinate combination.
            const int FieldBits = 128;
            int rank = 0;
            for(int column = 0; rank < subFieldBits && column < FieldBits; column++)
            {
                int pivot = -1;
                for(int row = rank; row < subFieldBits; row++)
                {
                    if(LimbBit(echelonRows, row, column))
                    {
                        pivot = row;
                        break;
                    }
                }

                if(pivot < 0)
                {
                    continue;
                }

                SwapRows(echelonRows, coordinateCombination, rank, pivot);
                leadingColumn[rank] = column;

                for(int row = rank + 1; row < subFieldBits; row++)
                {
                    if(LimbBit(echelonRows, row, column))
                    {
                        echelonRows[(row * LimbCount) + 0] ^= echelonRows[(rank * LimbCount) + 0];
                        echelonRows[(row * LimbCount) + 1] ^= echelonRows[(rank * LimbCount) + 1];
                        coordinateCombination[row] ^= coordinateCombination[rank];
                    }
                }

                rank++;
            }

            if(rank != subFieldBits)
            {
                basis.Dispose();

                throw new InvalidOperationException("The subfield basis did not reduce to full rank.");
            }

            return basis;
        }


        //The reference's in_subfield: the solve residual is zero exactly when the element is a GF(2)
        //combination of the subfield basis.
        public bool InSubfield(ReadOnlySpan<byte> element)
        {
            (ulong residualLow, ulong residualHigh, _) = Solve(element);

            return residualLow == 0 && residualHigh == 0;
        }


        //The reference's to_bytes_subfield: the coordinate vector u as subFieldBytes little-endian bytes.
        public void ToBytesSubfield(ReadOnlySpan<byte> element, Span<byte> destination)
        {
            (ulong residualLow, ulong residualHigh, uint coordinates) = Solve(element);
            if(residualLow != 0 || residualHigh != 0)
            {
                throw new InvalidOperationException("to_bytes_subfield called on an element outside the subfield.");
            }

            uint value = coordinates;
            for(int i = 0; i < SubFieldBytes; i++)
            {
                destination[i] = (byte)(value & 0xFF);
                value >>= 8;
            }
        }


        //The reference's of_bytes_subfield: read u little-endian and recombine of_scalar(u) = Σ_j u_j·β_j.
        public void OfBytesSubfield(ReadOnlySpan<byte> source, Span<byte> element)
        {
            uint coordinates = 0;
            for(int i = SubFieldBytes - 1; i >= 0; i--)
            {
                coordinates = (coordinates << 8) | source[i];
            }

            //of_scalar(u) = Σ_{set bit j of u} β_j over the original (pre-echelon) subfield basis.
            ulong low = 0;
            ulong high = 0;
            Span<ulong> basisRows = BasisRows;
            uint bits = coordinates;
            for(int j = 0; bits != 0; j++, bits >>= 1)
            {
                if((bits & 1) != 0)
                {
                    low ^= basisRows[(j * LimbCount) + 0];
                    high ^= basisRows[(j * LimbCount) + 1];
                }
            }

            FromLimbs(low, high, element);
        }


        //The reference's solve: reduce the queried element against the cached echelon rows, returning the
        //residual (zero iff in subfield) and the recovered coordinate vector u.
        private (ulong ResidualLow, ulong ResidualHigh, uint Coordinates) Solve(ReadOnlySpan<byte> element)
        {
            (ulong low, ulong high) = ToLimbs(element);
            uint coordinates = 0;

            Span<ulong> echelonRows = EchelonRows;
            Span<uint> coordinateCombination = CoordinateCombination;
            Span<int> leadingColumn = LeadingColumn;
            for(int rank = 0; rank < subFieldBits; rank++)
            {
                int column = leadingColumn[rank];
                bool bit = column < 64 ? ((low >> column) & 1) != 0 : ((high >> (column - 64)) & 1) != 0;
                if(bit)
                {
                    low ^= echelonRows[(rank * LimbCount) + 0];
                    high ^= echelonRows[(rank * LimbCount) + 1];
                    coordinates ^= coordinateCombination[rank];
                }
            }

            return (low, high, coordinates);
        }


        public void Dispose()
        {
            IMemoryOwner<byte>? local = scratchOwner;
            if(local is not null)
            {
                scratchOwner = null;
                local.Memory.Span[..ScratchBytes(subFieldBits)].Clear();
                local.Dispose();
            }
        }


        private static (ulong Low, ulong High) ToLimbs(ReadOnlySpan<byte> canonical)
        {
            ulong low = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(LowLimbByteOffset, 8));
            ulong high = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(HighLimbByteOffset, 8));

            return (low, high);
        }


        //The inverse of ToLimbs: the two GF(2^128) limbs back into a 32-byte big-endian canonical scalar.
        private static void FromLimbs(ulong low, ulong high, Span<byte> canonical)
        {
            canonical.Clear();
            BinaryPrimitives.WriteUInt64BigEndian(canonical.Slice(LowLimbByteOffset, 8), low);
            BinaryPrimitives.WriteUInt64BigEndian(canonical.Slice(HighLimbByteOffset, 8), high);
        }


        private static bool LimbBit(ReadOnlySpan<ulong> rows, int row, int column)
        {
            ulong limb = column < 64 ? rows[(row * LimbCount) + 0] : rows[(row * LimbCount) + 1];
            int shift = column < 64 ? column : column - 64;

            return ((limb >> shift) & 1) != 0;
        }


        private static void SwapRows(Span<ulong> rows, Span<uint> combination, int a, int b)
        {
            if(a == b)
            {
                return;
            }

            (rows[(a * LimbCount) + 0], rows[(b * LimbCount) + 0]) = (rows[(b * LimbCount) + 0], rows[(a * LimbCount) + 0]);
            (rows[(a * LimbCount) + 1], rows[(b * LimbCount) + 1]) = (rows[(b * LimbCount) + 1], rows[(a * LimbCount) + 1]);
            (combination[a], combination[b]) = (combination[b], combination[a]);
        }
    }
}
