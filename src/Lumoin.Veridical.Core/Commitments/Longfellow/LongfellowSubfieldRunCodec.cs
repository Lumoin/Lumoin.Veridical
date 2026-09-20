using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The field-specific subfield handling the Ligero proof serializer's run-length encoder needs: the
/// <c>in_subfield</c> predicate that bounds each run, the subfield element byte width
/// (<c>Field::kSubFieldBytes</c>), and the <c>to_bytes_subfield</c> / <c>of_bytes_subfield</c> framing.
/// It is the serializer's seam between the fields without a type hierarchy: the binary hash circuit
/// builds <see cref="ForGf2k128"/> (the GF(2^128) basis solve over a pooled row-echelon reduction), the
/// prime signature circuit builds <see cref="ForFp256"/> (the base field is its own subfield, so every
/// element is in-subfield and the subfield framing equals the full-field framing), and the FIPS 204
/// sextic ML-DSA circuit field builds <see cref="ForFp24Sextic"/> (the subfield is the base field
/// <c>F_q</c>, so an in-subfield element compresses to its 4-byte coordinate 0).
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
    /// <summary>The field-specific <c>in_subfield</c> predicate this codec was built with.</summary>
    private Func<ReadOnlySpan<byte>, bool> InSubfieldPredicate { get; }

    /// <summary>The field-specific <c>to_bytes_subfield</c> encoder this codec was built with.</summary>
    private EncodeSubfieldDelegate ToBytesSubfieldEncoder { get; }

    /// <summary>The field-specific <c>of_bytes_subfield</c> decoder this codec was built with.</summary>
    private DecodeSubfieldDelegate OfBytesSubfieldDecoder { get; }

    /// <summary>The pooled basis-reduction state this codec owns, or <see langword="null"/> for a codec that owns none.</summary>
    private IDisposable? state;


    /// <summary>Encodes a canonical scalar known to be in-subfield into its subfield wire bytes: the GF basis solve or the Fp256 identity reversal, sharing one shape without an interface.</summary>
    private delegate void EncodeSubfieldDelegate(ReadOnlySpan<byte> element, Span<byte> destination);

    /// <summary>Decodes subfield wire bytes into a canonical scalar: the GF basis recombination or the Fp256 identity reversal, sharing one shape without an interface.</summary>
    private delegate bool DecodeSubfieldDelegate(ReadOnlySpan<byte> source, Span<byte> element);


    /// <summary>Assembles a codec from its field-specific subfield operations.</summary>
    /// <param name="subFieldBytes">The subfield element byte width.</param>
    /// <param name="inSubfield">The <c>in_subfield</c> predicate.</param>
    /// <param name="toBytesSubfield">The <c>to_bytes_subfield</c> encoder.</param>
    /// <param name="ofBytesSubfield">The <c>of_bytes_subfield</c> decoder.</param>
    /// <param name="state">The pooled state this codec takes ownership of, or <see langword="null"/> when it owns none.</param>
    private LongfellowSubfieldRunCodec(
        int subFieldBytes,
        Func<ReadOnlySpan<byte>, bool> inSubfield,
        EncodeSubfieldDelegate toBytesSubfield,
        DecodeSubfieldDelegate ofBytesSubfield,
        IDisposable? state)
    {
        SubFieldBytes = subFieldBytes;
        this.InSubfieldPredicate = inSubfield;
        this.ToBytesSubfieldEncoder = toBytesSubfield;
        this.OfBytesSubfieldDecoder = ofBytesSubfield;
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


    /// <summary>
    /// The FIPS 204 sextic ML-DSA circuit-field codec: the subfield is the base field <c>F_q</c>
    /// (<c>fp24_6.h</c>: <c>kSubFieldBytes = 4</c>, <c>in_subfield</c> = coordinates 1…5 zero), so an
    /// in-subfield element compresses to its 4-byte little-endian coordinate 0 and
    /// <c>of_bytes_subfield</c> applies the base field's <c>fits</c> guard. It owns no pooled state.
    /// </summary>
    /// <param name="profile">The sextic field profile (validated as the sextic profile is the serializer's caller; carried for symmetry with <see cref="ForFp256"/>).</param>
    public static LongfellowSubfieldRunCodec ForFp24Sextic(LongfellowFieldProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        return new LongfellowSubfieldRunCodec(
            Fp24SexticSubFieldBytes,
            Fp24SexticInSubfield,
            Fp24SexticToBytesSubfield,
            Fp24SexticOfBytesSubfield,
            state: null);
    }


    /// <summary>The sextic codec's subfield element width (the reference <c>Fp24_6</c>'s <c>kSubFieldBytes</c>: one 4-byte base-field coordinate).</summary>
    private const int Fp24SexticSubFieldBytes = 4;

    /// <summary>The byte offset of coordinate 0 inside the canonical sextic container (the least-significant 4-byte big-endian limb).</summary>
    private const int Fp24SexticLimbZeroOffset = Scalar.SizeBytes - Fp24SexticSubFieldBytes;

    /// <summary>The byte offset where the canonical sextic container's coordinates 1…5 begin (they span up to coordinate 0's offset).</summary>
    private const int Fp24SexticUpperLimbsOffset = 8;

    /// <summary>The FIPS 204 prime <c>q = 2^23 − 2^13 + 1</c>: the <c>fits</c> bound of the sextic codec's <c>of_bytes_subfield</c>.</summary>
    private const uint Fp24SexticFieldModulus = 8380417;


    /// <summary>The reference's <c>in_subfield(req[i])</c>: whether the run-length pass should treat the element as a subfield element.</summary>
    /// <param name="element">The canonical scalar to test.</param>
    public bool InSubfield(ReadOnlySpan<byte> element) => InSubfieldPredicate(element);


    /// <summary>The sextic <c>in_subfield</c> (<c>fp24_6.h</c>): coordinates 1…5 all zero.</summary>
    /// <param name="element">The canonical sextic scalar to test.</param>
    /// <returns><see langword="true"/> when the element lies in the base field.</returns>
    private static bool Fp24SexticInSubfield(ReadOnlySpan<byte> element)
    {
        ReadOnlySpan<byte> upperLimbs = element[Fp24SexticUpperLimbsOffset..Fp24SexticLimbZeroOffset];
        for(int i = 0; i < upperLimbs.Length; i++)
        {
            if(upperLimbs[i] != 0)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>The sextic <c>to_bytes_subfield</c>: coordinate 0 as its 4 little-endian wire bytes.</summary>
    /// <param name="element">The canonical sextic scalar (asserted in-subfield by the caller's run logic).</param>
    /// <param name="destination">Receives the 4 subfield bytes.</param>
    private static void Fp24SexticToBytesSubfield(ReadOnlySpan<byte> element, Span<byte> destination)
    {
        uint coordinate = BinaryPrimitives.ReadUInt32BigEndian(element.Slice(Fp24SexticLimbZeroOffset, Fp24SexticSubFieldBytes));
        BinaryPrimitives.WriteUInt32LittleEndian(destination[..Fp24SexticSubFieldBytes], coordinate);
    }


    /// <summary>The sextic <c>of_bytes_subfield</c>: 4 little-endian wire bytes into coordinate 0, with the base field's <c>fits</c> guard (the parse-safe reader's graceful reject).</summary>
    /// <param name="source">The 4 subfield bytes.</param>
    /// <param name="element">Receives the canonical sextic scalar, or all zeros on rejection.</param>
    /// <returns><see langword="true"/> when the bytes encode a base-field element.</returns>
    private static bool Fp24SexticOfBytesSubfield(ReadOnlySpan<byte> source, Span<byte> element)
    {
        element.Clear();
        uint coordinate = BinaryPrimitives.ReadUInt32LittleEndian(source[..Fp24SexticSubFieldBytes]);
        if(coordinate >= Fp24SexticFieldModulus)
        {
            return false;
        }

        BinaryPrimitives.WriteUInt32BigEndian(element.Slice(Fp24SexticLimbZeroOffset, Fp24SexticSubFieldBytes), coordinate);

        return true;
    }


    /// <summary>The reference's <c>to_bytes_subfield</c>: writes the element's <see cref="SubFieldBytes"/> subfield bytes.</summary>
    /// <param name="element">The canonical scalar (asserted in-subfield by the caller's run logic).</param>
    /// <param name="destination">Receives <see cref="SubFieldBytes"/> bytes.</param>
    public void ToBytesSubfield(ReadOnlySpan<byte> element, Span<byte> destination) => ToBytesSubfieldEncoder(element, destination);


    /// <summary>
    /// The reference's <c>of_bytes_subfield</c>: reads <see cref="SubFieldBytes"/> bytes into a canonical
    /// scalar. The GF(2^128) basis recombination always succeeds; the Fp256 reversal applies the
    /// <c>fits</c> guard and returns <see langword="false"/> on out-of-range bytes (the parse-safe reader's
    /// graceful reject).
    /// </summary>
    /// <param name="source">The <see cref="SubFieldBytes"/> subfield bytes.</param>
    /// <param name="element">Receives the canonical scalar, or all zeros on rejection.</param>
    /// <returns><see langword="true"/> when the bytes decode to a field element; otherwise <see langword="false"/>.</returns>
    public bool OfBytesSubfield(ReadOnlySpan<byte> source, Span<byte> element) => OfBytesSubfieldDecoder(source, element);


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
        /// <summary>The number of 64-bit limbs a GF(2^128) element's polynomial representation splits into: two, limb 0 holding bits 0..63 and limb 1 holding bits 64..127.</summary>
        private const int LimbCount = 2;

        /// <summary>The canonical big-endian byte offset of limb 0 (bits 0..63): bytes 24..31, since the high field bytes 0..15 are zero.</summary>
        private const int LowLimbByteOffset = 24;

        /// <summary>The canonical big-endian byte offset of limb 1 (bits 64..127): bytes 16..23.</summary>
        private const int HighLimbByteOffset = 16;

        /// <summary>The subfield element width in bits (<see cref="SubFieldBytes"/> times 8), the row and column count of the reduced basis.</summary>
        private int SubFieldBits { get; }

        /// <summary>The pooled buffer backing the basis rows, echelon rows, coordinate combinations and leading columns.</summary>
        private IMemoryOwner<byte>? scratchOwner;

        /// <summary>The subfield element byte width this basis was reduced for.</summary>
        public int SubFieldBytes { get; }


        /// <summary>Wraps an already-rented scratch buffer as an as-yet-unreduced basis; <see cref="Reduce"/> is the only caller.</summary>
        /// <param name="subFieldBytes">The subfield element byte width.</param>
        /// <param name="subFieldBits">The subfield element width in bits.</param>
        /// <param name="scratchOwner">The rented scratch buffer backing every view.</param>
        private SubfieldBasis(int subFieldBytes, int subFieldBits, IMemoryOwner<byte> scratchOwner)
        {
            SubFieldBytes = subFieldBytes;
            this.SubFieldBits = subFieldBits;
            this.scratchOwner = scratchOwner;
        }


        /// <summary>The byte size of the basis-rows view: <paramref name="subFieldBits"/> rows of two 64-bit limbs each.</summary>
        private static int BasisRowsBytes(int subFieldBits) => subFieldBits * LimbCount * sizeof(ulong);

        /// <summary>The byte size of the coordinate-combination view: one 32-bit word per row.</summary>
        private static int CombinationBytes(int subFieldBits) => subFieldBits * sizeof(uint);

        /// <summary>
        /// The total byte size of the single pooled scratch buffer, carving out the four views in
        /// order: basis rows, echelon rows (each <see cref="BasisRowsBytes"/>), the coordinate
        /// combinations (<see cref="CombinationBytes"/>), and the leading columns (one 32-bit word
        /// per row).
        /// </summary>
        private static int ScratchBytes(int subFieldBits) =>
            (2 * BasisRowsBytes(subFieldBits)) + CombinationBytes(subFieldBits) + (subFieldBits * sizeof(int));


        /// <summary>The current view over the rented scratch buffer, sized to this basis's <see cref="ScratchBytes"/>.</summary>
        private Span<byte> Scratch =>
            (scratchOwner ?? throw new ObjectDisposedException(nameof(SubfieldBasis))).Memory.Span[..ScratchBytes(SubFieldBits)];

        /// <summary>The original subfield basis rows <c>β_j = g^j</c>, two limbs each; used by <see cref="OfBytesSubfield"/> to recombine.</summary>
        private Span<ulong> BasisRows => MemoryMarshal.Cast<byte, ulong>(Scratch[..BasisRowsBytes(SubFieldBits)]);

        /// <summary>The reduced echelon rows <c>u_[i]</c>, two limbs each.</summary>
        private Span<ulong> EchelonRows => MemoryMarshal.Cast<byte, ulong>(Scratch.Slice(BasisRowsBytes(SubFieldBits), BasisRowsBytes(SubFieldBits)));

        /// <summary>The coordinate bits <c>linv_[i]</c> that combine to produce the i-th echelon row.</summary>
        private Span<uint> CoordinateCombination => MemoryMarshal.Cast<byte, uint>(Scratch.Slice(2 * BasisRowsBytes(SubFieldBits), CombinationBytes(SubFieldBits)));

        /// <summary>The leading-nonzero column <c>ldnz_[i]</c> of the i-th echelon row.</summary>
        private Span<int> LeadingColumn => MemoryMarshal.Cast<byte, int>(Scratch[((2 * BasisRowsBytes(SubFieldBits)) + CombinationBytes(SubFieldBits))..]);


        /// <summary>
        /// The reference's <c>beta_ref</c>: reduces the basis <c>{β_0, …, β_{m−1}}</c> to row echelon,
        /// caching the echelon rows, the GF(2) coordinate combination that produced each, and the
        /// leading column.
        /// </summary>
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


        /// <summary>The reference's <c>in_subfield</c>: the solve residual is zero exactly when the element is a GF(2) combination of the subfield basis.</summary>
        public bool InSubfield(ReadOnlySpan<byte> element)
        {
            (ulong residualLow, ulong residualHigh, _) = Solve(element);

            return residualLow == 0 && residualHigh == 0;
        }


        /// <summary>The reference's <c>to_bytes_subfield</c>: writes the coordinate vector <c>u</c> as <see cref="SubFieldBytes"/> little-endian bytes.</summary>
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


        /// <summary>The reference's <c>of_bytes_subfield</c>: reads <c>u</c> little-endian and recombines <c>of_scalar(u) = Σ_j u_j·β_j</c>.</summary>
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


        /// <summary>The reference's <c>solve</c>: reduces the queried element against the cached echelon rows, returning the residual (zero iff the element is in the subfield) and the recovered coordinate vector <c>u</c>.</summary>
        private (ulong ResidualLow, ulong ResidualHigh, uint Coordinates) Solve(ReadOnlySpan<byte> element)
        {
            (ulong low, ulong high) = ToLimbs(element);
            uint coordinates = 0;

            Span<ulong> echelonRows = EchelonRows;
            Span<uint> coordinateCombination = CoordinateCombination;
            Span<int> leadingColumn = LeadingColumn;
            for(int rank = 0; rank < SubFieldBits; rank++)
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


        /// <summary>Releases the pooled scratch buffer, clearing it first.</summary>
        public void Dispose()
        {
            IMemoryOwner<byte>? local = scratchOwner;
            if(local is not null)
            {
                scratchOwner = null;
                local.Memory.Span[..ScratchBytes(SubFieldBits)].Clear();
                local.Dispose();
            }
        }


        /// <summary>Splits a canonical big-endian scalar into its two GF(2^128) limbs.</summary>
        private static (ulong Low, ulong High) ToLimbs(ReadOnlySpan<byte> canonical)
        {
            ulong low = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(LowLimbByteOffset, 8));
            ulong high = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(HighLimbByteOffset, 8));

            return (low, high);
        }


        /// <summary>The inverse of <see cref="ToLimbs"/>: writes the two GF(2^128) limbs back into a 32-byte big-endian canonical scalar.</summary>
        private static void FromLimbs(ulong low, ulong high, Span<byte> canonical)
        {
            canonical.Clear();
            BinaryPrimitives.WriteUInt64BigEndian(canonical.Slice(LowLimbByteOffset, 8), low);
            BinaryPrimitives.WriteUInt64BigEndian(canonical.Slice(HighLimbByteOffset, 8), high);
        }


        /// <summary>Reads bit <paramref name="column"/> (0..127) of the two-limb row at <paramref name="row"/>.</summary>
        private static bool LimbBit(ReadOnlySpan<ulong> rows, int row, int column)
        {
            ulong limb = column < 64 ? rows[(row * LimbCount) + 0] : rows[(row * LimbCount) + 1];
            int shift = column < 64 ? column : column - 64;

            return ((limb >> shift) & 1) != 0;
        }


        /// <summary>Swaps echelon rows <paramref name="a"/> and <paramref name="b"/> (both limbs) along with their coordinate combinations; a no-op when the indices are equal.</summary>
        [SuppressMessage("Performance", "CA1517", Justification = "The swap below writes through both indexers via tuple deconstruction; the analyzer does not recognize that as a write and misidentifies the parameters as read-only.")]
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
