using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// Parses the serialized circuit bytes that google/longfellow-zk's <c>generate_circuit</c> emits (the
/// raw, decompressed form the ZkSpec pins by hash) into a <see cref="LongfellowSumcheckCircuit"/>, a
/// faithful port of <c>CircuitReader&lt;Field&gt;::from_bytes</c> (<c>lib/proto/circuit_reader.h</c>) over
/// the writer's layout in <c>CircuitWriter&lt;Field&gt;::to_bytes</c> (<c>lib/proto/circuit_writer.h</c>).
/// </summary>
/// <remarks>
/// <para>
/// The serialized stream is, in order (all multi-byte size/index/value fields are
/// <see cref="BytesPerSizeT"/>-byte little-endian fixed-width numbers, the reference's
/// <c>kBytesPerSizeT == 3</c>):
/// </para>
/// <list type="number">
///   <item><description>One version byte; must be <see cref="FormatVersion"/> (1).</description></item>
///   <item><description>The field id (validated against <c>fieldId</c>), then <c>nv</c>, <c>nc</c>, <c>npub_in</c>, <c>subfield_boundary</c>, <c>ninputs</c>, <c>nl</c>, <c>numconst</c>. Note the on-wire order places <c>npub_in</c> and <c>subfield_boundary</c> before <c>ninputs</c> — the reverse of the in-memory struct order.</description></item>
///   <item><description><c>numconst</c> field constants, each <c>elementBytes</c> little-endian bytes, reversed into the 32-byte big-endian canonical scalar form. The constant at index 0 is the assert-zero coefficient and is conventionally zero.</description></item>
///   <item><description>Per layer: <c>logw</c>, <c>nw</c>, <c>nq</c>, then <c>nq</c> quad terms. Each term is the gate index <c>g</c> (delta-encoded from the previous term's <c>g</c>), the two hand indices <c>h0</c>, <c>h1</c> (each delta-encoded), and a value index <c>vi</c> into the constant table. The reference resolves <c>vi</c> to the constant value; this reader stores the resolved big-endian coefficient bytes on the term, matching <see cref="LongfellowSumcheckQuadTerm"/>.</description></item>
///   <item><description>A 32-byte circuit id.</description></item>
/// </list>
/// <para>
/// Indices are delta-encoded with the low bit as sign (the reference's <c>read_index</c>): an even delta
/// adds <c>delta &gt;&gt; 1</c> to the previous index, an odd delta subtracts <c>delta &gt;&gt; 1</c>. The
/// per-term reset state (<c>prevg</c>, <c>prevhl</c>, <c>prevhr</c>) starts at zero each layer.
/// </para>
/// <para>
/// The reader is parse-safe: every read is bounds-checked, and any truncation, version mismatch, field-id
/// mismatch, out-of-range index, or relation violation (the reference's sanity checks —
/// <c>npub_in ≤ ninputs</c>, <c>subfield_boundary ≤ ninputs</c>, <c>nl ≤ kMaxLayers</c>,
/// <c>g &lt; max_g</c>, <c>h &lt; nw</c>, <c>vi &lt; numconst</c>) yields <see langword="false"/> with no
/// allocation leaked. It does not deduplicate corners (the reference's <c>ApproximateDeltaTableBuilder</c>
/// is a performance optimization for the quad weight table, not a semantic transformation) — the term
/// list is returned in stream order, which is the order <c>bind_quad</c> iterates.
/// </para>
/// <para>
/// The stream may hold several concatenated circuits over different fields (the mdoc bundle is a P256
/// signature circuit followed by a GF(2^128) hash circuit). <see cref="TryRead"/> reports the number of
/// bytes it consumed so the caller can read the next circuit from the continuation of the span.
/// </para>
/// </remarks>
internal static class LongfellowCircuitReader
{
    /// <summary>The reference's <c>CircuitIO::kBytesPerSizeT</c>: sizes, indices and value indices are 3-byte little-endian.</summary>
    internal const int BytesPerSizeT = 3;

    /// <summary>The serialization version the writer stamps and this reader requires.</summary>
    internal const int FormatVersion = 1;

    /// <summary>The reference's <c>CircuitIO::kIdSize</c>: the trailing circuit id is 32 bytes.</summary>
    internal const int IdLength = LongfellowSumcheckCircuit.IdLength;

    /// <summary>The reference's <c>CircuitIO::kMaxLayers</c>: deeper circuits are treated as malformed.</summary>
    internal const int MaxLayers = 10000;

    /// <summary>The reference's <c>LayerProof::kMaxBindings</c>: the per-hand binding-round ceiling.</summary>
    internal const int MaxBindings = 40;

    /// <summary>The in-memory canonical scalar width in bytes, the width every constant-table element is reversed into.</summary>
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Attempts to parse one serialized circuit from the front of <paramref name="bytes"/>.
    /// </summary>
    /// <param name="bytes">The raw serialized circuit bytes, possibly with further concatenated circuits after this one.</param>
    /// <param name="fieldId">The expected field id (the reference's <c>FieldID</c>: P256 = 1, GF2_128 = 4); the stream's field id must equal it.</param>
    /// <param name="elementBytes">The field's element byte size — 16 for GF(2^128), 32 for the P-256 base field — used for the constant table.</param>
    /// <param name="pool">The pool supplying the parsed circuit's owned bytes.</param>
    /// <param name="circuit">On success, the disposable parsed circuit owning its bytes; otherwise <see langword="null"/>.</param>
    /// <param name="subfieldBoundary">On success, the reference's <c>subfield_boundary</c> (the least input wire not known to be in the subfield), which the <see cref="LongfellowSumcheckCircuit"/> shape does not itself carry — the prover and commit take it as a separate argument, so it is surfaced here rather than dropped; otherwise zero.</param>
    /// <param name="bytesConsumed">On success, the number of bytes consumed (the start offset of the next circuit, or the trailing length); otherwise zero.</param>
    /// <param name="constantRange">An optional canonical-range predicate for the field; when supplied, a constant-table element at or above the field modulus makes the parse fail. GF(2^128) needs none (every 16-byte pattern is a field element); the prime field passes its <c>an &lt; p</c> guard.</param>
    /// <returns><see langword="true"/> when a well-formed circuit was parsed; <see langword="false"/> on any malformation.</returns>
    public static bool TryRead(
        ReadOnlySpan<byte> bytes,
        int fieldId,
        int elementBytes,
        BaseMemoryPool pool,
        out LongfellowSumcheckCircuit? circuit,
        out int subfieldBoundary,
        out int bytesConsumed,
        LongfellowCanonicalRangeDelegate? constantRange = null)
    {
        circuit = null;
        subfieldBoundary = 0;
        bytesConsumed = 0;

        if(elementBytes <= 0 || elementBytes > ScalarSize)
        {
            return false;
        }

        var reader = new SpanReader(bytes);

        //The reference requires at least the version byte plus the eight header size_t fields up front.
        if(!reader.Have(1 + (8 * BytesPerSizeT)))
        {
            return false;
        }

        if(reader.ReadByte() != FormatVersion)
        {
            return false;
        }

        if(!reader.TryReadNum(out long fieldIdAsNum)
            || !reader.TryReadNum(out long nv)
            || !reader.TryReadNum(out long nc)
            || !reader.TryReadNum(out long publicInputCount)
            || !reader.TryReadNum(out long subfieldBoundaryValue)
            || !reader.TryReadNum(out long inputCount)
            || !reader.TryReadNum(out long layerCount)
            || !reader.TryReadNum(out long constantCount))
        {
            return false;
        }

        //The reference's basic sanity checks, plus the lower bounds this representation requires: a
        //circuit needs at least one output, one copy and one layer, and a layer at least one hand
        //round — malformed values must parse to false, never throw through the constructors.
        if(fieldIdAsNum != fieldId
            || publicInputCount > inputCount
            || subfieldBoundaryValue > inputCount
            || layerCount < 1
            || layerCount > MaxLayers
            || nv < 1
            || nc < 1
            || constantCount < 0)
        {
            return false;
        }

        //The constant table: numconst field elements, each elementBytes little-endian, reversed to the
        //32-byte big-endian canonical scalar. Terms resolve constants strictly by table position; the
        //writer assigns indices in first-encounter order across the layers' terms, so no position
        //carries a guaranteed value.
        if(!TryCheckedMultiply(constantCount, elementBytes, out long constantBytes) || !reader.Have(constantBytes))
        {
            return false;
        }

        LongfellowCircuitStorage? storage = new(pool);
        try
        {
            Memory<byte> constants = constantCount == 0
                ? Memory<byte>.Empty
                : storage.Allocate(checked((int)constantCount * ScalarSize));
            for(int i = 0; i < constantCount; i++)
            {
                Span<byte> canonical = constants.Span.Slice(i * ScalarSize, ScalarSize);
                reader.ReadElementCanonical(elementBytes, canonical);

                //A constant at or above the field modulus is malformed: the constants
                //resolve onto quad-term coefficients, so an out-of-range value would
                //diverge between its stream bytes and its reduced arithmetic value.
                if(constantRange is not null && !constantRange(canonical))
                {
                    return false;
                }
            }

            var layers = new LongfellowSumcheckLayer[layerCount];

            //The reference seeds max_g (the upper bound on a term's gate index) with nv, then sets it to the
            //previous layer's nw after each layer.
            long maxGate = nv;

            for(int ly = 0; ly < layerCount; ly++)
            {
                //Each layer header is three size_t fields.
                if(!reader.Have(3L * BytesPerSizeT))
                {
                    return false;
                }

                reader.TryReadNum(out long handRounds);
                reader.TryReadNum(out long layerInputCount);
                reader.TryReadNum(out long termCount);

                //A layer's wire count must be representable in its hand rounds: lw ≤ nw ≤ 2^lw, the
                //reference's consistency relation between logw and nw.
                if(handRounds < 1
                    || handRounds > MaxBindings
                    || layerInputCount <= 0
                    || layerInputCount < handRounds
                    || layerInputCount > 1L << (int)handRounds
                    || termCount <= 0)
                {
                    return false;
                }

                //Each quad term is four size_t fields (g-delta, h0-delta, h1-delta, vi).
                if(!TryCheckedMultiply(termCount, 4L * BytesPerSizeT, out long termBytes) || !reader.Have(termBytes))
                {
                    return false;
                }

                var terms = new LongfellowSumcheckQuadTerm[termCount];
                long previousGate = 0;
                long previousLeft = 0;
                long previousRight = 0;

                for(int t = 0; t < termCount; t++)
                {
                    long gate = reader.ReadIndex(previousGate);
                    if(gate < 0 || gate >= maxGate)
                    {
                        return false;
                    }

                    long left = reader.ReadIndex(previousLeft);
                    long right = reader.ReadIndex(previousRight);
                    if(left < 0 || left >= layerInputCount || right < 0 || right >= layerInputCount)
                    {
                        return false;
                    }

                    reader.TryReadNum(out long valueIndex);
                    if(valueIndex < 0 || valueIndex >= constantCount)
                    {
                        return false;
                    }

                    terms[t] = new LongfellowSumcheckQuadTerm((int)gate, (int)left, (int)right, constants.Slice(checked((int)valueIndex * ScalarSize), ScalarSize));

                    previousGate = gate;
                    previousLeft = left;
                    previousRight = right;
                }

                layers[ly] = new LongfellowSumcheckLayer((int)layerInputCount, (int)handRounds, (int)termCount, terms);

                //The outputs of this layer become the next layer's inputs, so the gate bound advances to nw.
                maxGate = layerInputCount;
            }

            if(!reader.Have(IdLength))
            {
                return false;
            }

            Memory<byte> id = storage.Allocate(IdLength);
            reader.ReadBytes(id.Span);

            circuit = new LongfellowSumcheckCircuit(
                (int)nv,
                Lg(nv),
                (int)nc,
                Lg(nc),
                (int)inputCount,
                (int)publicInputCount,
                id,
                layers,
                pool,
                storage);
            storage = null;
        }
        finally
        {
            storage?.Dispose();
        }

        subfieldBoundary = (int)subfieldBoundaryValue;
        bytesConsumed = reader.Position;

        return true;
    }


    /// <summary>
    /// The reference's <c>lg(n)</c> (<c>lib/util/ceildiv.h</c>): the smallest <c>k</c> with <c>2^k ≥ n</c>,
    /// so <c>lg(0) == lg(1) == 0</c>. Used to derive <c>logv</c> from <c>nv</c> and <c>logc</c> from
    /// <c>nc</c>, neither of which is stored in the serialization.
    /// </summary>
    /// <param name="n">The value to take the ceiling base-2 logarithm of.</param>
    /// <returns>The smallest <c>k</c> with <c>2^k &gt;= n</c>.</returns>
    internal static int Lg(long n)
    {
        int log = 0;
        long power = 1;
        while(power < n)
        {
            power *= 2;
            log++;
        }

        return log;
    }


    /// <summary>The reference's <c>CircuitIO::checked_mul</c>: multiplies two non-negative counts, reporting overflow instead of wrapping.</summary>
    /// <param name="a">The first non-negative factor.</param>
    /// <param name="b">The second non-negative factor.</param>
    /// <param name="product">On success, the product; otherwise zero.</param>
    /// <returns><see langword="true"/> when both factors are non-negative and the product did not overflow.</returns>
    private static bool TryCheckedMultiply(long a, long b, out long product)
    {
        product = 0;
        if(a < 0 || b < 0)
        {
            return false;
        }

        if(a == 0 || b == 0)
        {
            return true;
        }

        long candidate = a * b;
        if(candidate / a != b)
        {
            return false;
        }

        product = candidate;

        return true;
    }


    /// <summary>A bounds-checked cursor over the serialized bytes that mirrors the reference's <c>ReadBuffer</c> reads.</summary>
    private ref struct SpanReader
    {
        /// <summary>The serialized bytes this cursor reads from.</summary>
        private ReadOnlySpan<byte> Bytes { get; }

        /// <summary>The next unread offset into <see cref="Bytes"/>.</summary>
        private int position;


        /// <summary>Creates a cursor positioned at the start of the given bytes.</summary>
        /// <param name="bytes">The serialized bytes to read from.</param>
        public SpanReader(ReadOnlySpan<byte> bytes)
        {
            this.Bytes = bytes;
            position = 0;
        }


        /// <summary>The number of bytes consumed so far, the start offset of whatever comes next in the stream.</summary>
        public int Position => position;


        /// <summary>Reports whether at least <paramref name="count"/> more bytes remain unread.</summary>
        /// <param name="count">The number of bytes to check for.</param>
        /// <returns><see langword="true"/> when <paramref name="count"/> is non-negative and that many bytes remain.</returns>
        public readonly bool Have(long count) => count >= 0 && position + count <= Bytes.Length;


        /// <summary>Reads and consumes one byte.</summary>
        /// <returns>The byte at the current position.</returns>
        public byte ReadByte() => Bytes[position++];


        /// <summary>The reference's <c>read_num</c>: reads a <see cref="BytesPerSizeT"/>-byte little-endian value, returning <see langword="false"/> on underflow. The value is returned as a <see langword="long"/> so the caller can range-check before narrowing to <see langword="int"/>.</summary>
        /// <param name="value">On success, the decoded value; otherwise zero.</param>
        /// <returns><see langword="true"/> when enough bytes remained to decode a value.</returns>
        public bool TryReadNum(out long value)
        {
            value = 0;
            if(position + BytesPerSizeT > Bytes.Length)
            {
                return false;
            }

            long result = 0;
            for(int i = 0; i < BytesPerSizeT; i++)
            {
                result |= (long)Bytes[position + i] << (i * 8);
            }

            position += BytesPerSizeT;
            value = result;

            return true;
        }


        /// <summary>
        /// The reference's <c>read_index</c>: decodes the signed-LSB delta from <paramref name="previousIndex"/>.
        /// An even delta adds <c>delta &gt;&gt; 1</c>; an odd delta subtracts <c>delta &gt;&gt; 1</c>. Returns a
        /// negative result on underflow so the caller's range check rejects it, the same effect the reference
        /// gets from its later h/g bounds checks.
        /// </summary>
        /// <param name="previousIndex">The previous index this delta is relative to.</param>
        /// <returns>The decoded index, or a negative value on underflow.</returns>
        public long ReadIndex(long previousIndex)
        {
            if(!TryReadNum(out long delta))
            {
                return -1;
            }

            return (delta & 1) != 0
                ? previousIndex - (delta >> 1)
                : previousIndex + (delta >> 1);
        }


        /// <summary>
        /// Reads one field element of <paramref name="elementBytes"/> little-endian bytes into the 32-byte
        /// big-endian canonical destination (the low <paramref name="elementBytes"/> bytes reversed, the high
        /// bytes left zero), the inverse of the reference's <c>to_bytes_field</c> for the constant table.
        /// </summary>
        /// <param name="elementBytes">The field element's on-wire width in bytes.</param>
        /// <param name="canonical">The 32-byte buffer receiving the canonical big-endian scalar.</param>
        public void ReadElementCanonical(int elementBytes, Span<byte> canonical)
        {
            canonical.Clear();
            for(int i = 0; i < elementBytes; i++)
            {
                canonical[ScalarSize - 1 - i] = Bytes[position + i];
            }

            position += elementBytes;
        }


        /// <summary>Reads and consumes exactly <c>destination.Length</c> bytes into <paramref name="destination"/>.</summary>
        /// <param name="destination">The buffer receiving the read bytes; its length fixes how many bytes are consumed.</param>
        public void ReadBytes(Span<byte> destination)
        {
            Bytes.Slice(position, destination.Length).CopyTo(destination);
            position += destination.Length;
        }
    }
}
