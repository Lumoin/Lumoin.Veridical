using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The wire-format-conformant Fiat–Shamir transcript, a faithful port of google/longfellow-zk's
/// <c>lib/random/transcript.h</c> <c>Transcript</c> together with its <c>FSPRF</c> and the
/// <c>RandomEngine</c> challenge generators in <c>lib/random/random.h</c>. The transcript absorbs the
/// prover's messages with a typed framing and squeezes the verifier's challenges from a pseudo-random
/// function keyed by a SHA-256 snapshot of everything absorbed so far. The deployed Longfellow proof's
/// challenge sequence is exactly this object's output, so reproducing it bit for bit is the wire
/// format: prover and verifier must derive byte-identical challenges or the proof does not verify.
/// </summary>
/// <remarks>
/// <para>
/// The mechanics, byte for byte. <em>Construction</em> hashes nothing yet; the seed is the first
/// thing absorbed, through the same typed byte-array write any later message uses, so the very first
/// state is <c>tag(0) ‖ length(seed) ‖ seed</c>. <em>Absorption</em> is typed: a byte array writes a
/// 1-byte tag <c>0</c>, an 8-byte little-endian length, then the raw bytes; a field element writes a
/// 1-byte tag <c>1</c> then the element's 16 little-endian bytes (<c>to_bytes_field</c>, the low 128
/// bits, least-significant byte first); a field-element array writes a 1-byte tag <c>2</c>, an 8-byte
/// little-endian length (the element count), then each element's 16 little-endian bytes. The tag and
/// length are themselves untyped writes, so the absorbed byte stream is fully self-describing.
/// </para>
/// <para>
/// <em>The PRF.</em> A challenge squeeze first snapshots the transcript: it SHA-256-hashes the entire
/// absorbed byte stream so far to a 32-byte key. The snapshot is taken by forking the running incremental
/// SHA-256 state and finalizing the fork (the reference's <c>SHA256 tmp; tmp.CopyState(sha_);
/// tmp.DigestData(key)</c>), so the running state keeps absorbing undisturbed and the snapshot costs one
/// partial-block finalize, never a re-hash of the whole stream. That key seeds an AES-256-ECB pseudo-random
/// function (<see cref="LongfellowTranscriptBlockCipher"/>): the n-th 16-byte output block is
/// <c>AES-256-ECB(key, littleEndian64(n))</c> for a block counter that starts at 0 and increments. Bytes
/// are drawn from this block stream as needed, refilling a new block when the read pointer reaches the end.
/// <em>Any absorption invalidates the PRF</em>: after a write, the next squeeze re-snapshots the (now
/// longer) byte stream to a fresh key and restarts the block counter at 0. This is what makes the challenges
/// depend on every prior message.
/// </para>
/// <para>
/// <em>Challenge derivations.</em> A raw-byte challenge is a direct draw from the PRF stream. A field
/// element draws 16 raw bytes and interprets them little-endian as the 128-bit element — every 16-byte
/// sequence is a valid GF(2^128) element, so no rejection is needed (the reference's <c>elt(F)</c> /
/// <c>F.sample</c>). A natural below a bound draws the minimal number of whole bytes to cover the
/// bound, reads them little-endian, masks off the high bits above the bound's top set bit, and rejects
/// and redraws if the masked value still reaches the bound (uniform rejection sampling; the mask is
/// the smallest value <c>m</c> with <c>(bound &amp; m) == bound</c>). A distinct-natural subset of size
/// <c>k</c> over <c>[0, n)</c> runs a partial Fisher–Yates shuffle: start with the identity array
/// <c>0..n−1</c>, and for <c>i = 0..k−1</c> swap position <c>i</c> with position <c>i + nat(n − i)</c>,
/// emitting the swapped-in value. This is the Ligero column-selection generator (<c>gen_idx</c>).
/// </para>
/// <para>
/// <em>Versioning.</em> The constructor takes a version (the deployed mdoc flow uses 6; the reference's
/// own transcript test uses 4). In this reference snapshot the version is stored but never branched on
/// in any path the Ligero flow exercises — the field-element-array write unconditionally tags <c>2</c>;
/// the comment "version 4+ fixes the TAG_ARRAY typo" describes a fix already applied to every version
/// in this snapshot. The version is carried for fidelity and forward compatibility, and the
/// conformance gate confirms versions 4 and 6 produce byte-identical streams.
/// </para>
/// <para>
/// Disposable: the PRF block and key buffers are pool-rented and cleared on disposal. The incremental hash
/// and the block cipher are delegate-injected (they must be SHA-256 and AES-256-ECB to match the reference)
/// so the construction stays consistent with the library's primitive-agnostic commitment infrastructure.
/// </para>
/// </remarks>
internal sealed class LongfellowTranscript: IDisposable
{
    //The reference's tag bytes for the typed writes: byte-array, field element, array-of-field-element.
    private const byte TagByteString = 0;
    private const byte TagFieldElement = 1;
    private const byte TagArray = 2;

    //The reference's kPRFKeySize == kSHA256DigestSize: the snapshot key and the SHA-256 digest are 32
    //bytes. kPRFInputSize == kPRFOutputSize == 16: one AES block in, one AES block out.
    private const int PrfKeySize = 32;
    private const int PrfInputSize = 16;
    private const int PrfOutputSize = 16;

    //The reference's u64 length encoding: every typed length is 8 little-endian bytes.
    private const int LengthBytes = 8;

    //The reference's FSPRF::kMaxBlocks: 2^40 blocks suffice for the application (the 2^64 limit is far
    //out of reach). The transcript panics past it rather than wrapping the counter.
    private const ulong MaxBlocks = 0x10000000000UL;

    private readonly LongfellowTranscriptBlockCipher blockCipher;
    private readonly BaseMemoryPool pool;
    private readonly int version;

    //The forkable incremental SHA-256 state. WriteUntyped feeds it exactly the bytes it would have appended
    //to a retained buffer, in the same order, so a fork-finalize in SnapshotKey yields SHA-256 of the full
    //absorbed stream in O(1) per squeeze — the reference's sha_ running state. This is the only snapshot
    //path; the transcript never retains the absorbed bytes.
    private readonly ILongfellowIncrementalHash incrementalHash;

    //The on-wire element width this stack instance frames absorbs and squeezes at (Field::kBytes): 16 for
    //GF(2^128), 32 for the P-256 base field. Carried so the single transcript port serves both fields.
    private readonly int fieldElementBytes;

    //The number of bytes absorbed so far (tag/length/payload of every write). A plain counter — the bytes
    //themselves are not retained; the incremental SHA state carries them. The snapshot is SHA-256 of this
    //many bytes' worth of input.
    private int absorbedLength;

    //The PRF block state. saved holds the current 16-byte AES output; readPointer indexes into it;
    //blockCounter is the next block index. prfActive is false until the first squeeze after the last
    //write — a write invalidates it (the reference resets the unique_ptr), forcing a re-key.
    private readonly IMemoryOwner<byte> saved;
    private readonly IMemoryOwner<byte> prfKey;
    private int readPointer;
    private ulong blockCounter;
    private bool prfActive;
    private bool disposed;


    /// <summary>The transcript version (the deployed mdoc flow uses 6); carried for fidelity, not branched on in this snapshot.</summary>
    public int Version => version;

    /// <summary>The number of bytes absorbed so far (the length of the byte stream the PRF snapshots over); a pure read used by the width-threading gates.</summary>
    public int AbsorbedLength => absorbedLength;


    /// <summary>
    /// Constructs a transcript and absorbs <paramref name="seed"/> as the initial message, exactly as
    /// the reference's <c>Transcript(init, init_len, version)</c> does.
    /// </summary>
    /// <param name="seed">The domain-separating seed; absorbed through the typed byte-array write.</param>
    /// <param name="version">The transcript version (6 for the deployed mdoc flow, 4 for the reference's transcript test).</param>
    /// <param name="fieldElementBytes">The on-wire element width this stack instance frames elements at (<c>Field::kBytes</c>): 16 for GF(2^128), 32 for the P-256 base field.</param>
    /// <param name="blockCipher">The AES-256-ECB single-block transform the PRF squeezes through.</param>
    /// <param name="pool">Pool to rent the PRF buffers from.</param>
    /// <param name="incrementalHashFactory">
    /// The forkable incremental SHA-256 seam. The snapshot forks the running state and finalizes the fork in
    /// O(1) per squeeze; the digest is SHA-256 of the full absorbed byte stream. This is the sole snapshot
    /// path — the transcript is SHA-256 by conformance and never retains the absorbed bytes.
    /// </param>
    /// <exception cref="ArgumentNullException">When a delegate, the factory or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="fieldElementBytes"/> is below 1.</exception>
    public LongfellowTranscript(
        ReadOnlySpan<byte> seed,
        int version,
        int fieldElementBytes,
        LongfellowTranscriptBlockCipher blockCipher,
        BaseMemoryPool pool,
        LongfellowIncrementalHashFactory incrementalHashFactory)
    {
        ArgumentNullException.ThrowIfNull(blockCipher);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(incrementalHashFactory);
        ArgumentOutOfRangeException.ThrowIfLessThan(fieldElementBytes, 1);

        this.blockCipher = blockCipher;
        this.pool = pool;
        this.version = version;
        this.fieldElementBytes = fieldElementBytes;
        incrementalHash = incrementalHashFactory();

        saved = pool.Rent(PrfOutputSize);
        prfKey = pool.Rent(PrfKeySize);
        readPointer = PrfOutputSize;
        blockCounter = 0;
        prfActive = false;

        absorbedLength = 0;

        AbsorbByteString(seed);
    }


    //The clone constructor: same delegate/version/width/pool but no seed absorb; the caller carries the
    //absorbed length over directly. The forked incremental state is passed in (the reference's
    //Transcript(sha_, version_) — a CopyState of the source's running SHA state).
    private LongfellowTranscript(
        int version,
        int fieldElementBytes,
        LongfellowTranscriptBlockCipher blockCipher,
        BaseMemoryPool pool,
        ILongfellowIncrementalHash forkedIncrementalHash)
    {
        this.blockCipher = blockCipher;
        this.pool = pool;
        this.version = version;
        this.fieldElementBytes = fieldElementBytes;
        incrementalHash = forkedIncrementalHash;

        saved = pool.Rent(PrfOutputSize);
        prfKey = pool.Rent(PrfKeySize);
        readPointer = PrfOutputSize;
        blockCounter = 0;
        prfActive = false;

        absorbedLength = 0;
    }


    /// <summary>
    /// Absorbs a byte string with the reference's typed framing: tag <c>0</c>, the 8-byte little-endian
    /// length, then the raw bytes. The reference's <c>write(data, n)</c>.
    /// </summary>
    /// <param name="data">The bytes to absorb.</param>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    public void AbsorbByteString(ReadOnlySpan<byte> data)
    {
        WriteTag(TagByteString);
        WriteLength(data.Length);

        WriteUntyped(data);
    }


    /// <summary>
    /// Absorbs a single field element with the reference's typed framing: tag <c>1</c> then the element's
    /// little-endian bytes at the transcript's baked element width. The reference's <c>write(Elt, F)</c>.
    /// </summary>
    /// <param name="elementBytes">The element's little-endian bytes (<c>to_bytes_field</c>); the baked element width.</param>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    /// <exception cref="ArgumentException">When <paramref name="elementBytes"/> is not the baked element width.</exception>
    public void AbsorbFieldElement(ReadOnlySpan<byte> elementBytes) => AbsorbFieldElement(elementBytes, fieldElementBytes);


    /// <summary>
    /// Absorbs a single field element framed at <paramref name="elementWidth"/> little-endian bytes (per D3
    /// the cross-field driver frames the GF and Fp256 absorbs on one transcript at their own widths). The
    /// reference's <c>write(Elt, F)</c>.
    /// </summary>
    /// <param name="elementBytes">The element's little-endian bytes (<c>to_bytes_field</c>); exactly <paramref name="elementWidth"/> bytes.</param>
    /// <param name="elementWidth">The on-wire element width to frame at (16 for GF(2^128), 32 for the P-256 base field).</param>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    /// <exception cref="ArgumentException">When <paramref name="elementBytes"/> is not <paramref name="elementWidth"/> bytes.</exception>
    public void AbsorbFieldElement(ReadOnlySpan<byte> elementBytes, int elementWidth)
    {
        if(elementBytes.Length != elementWidth)
        {
            throw new ArgumentException($"A field element is {elementWidth} little-endian bytes; received {elementBytes.Length}.", nameof(elementBytes));
        }

        WriteTag(TagFieldElement);

        WriteUntyped(elementBytes);
    }


    /// <summary>
    /// Absorbs an array of field elements with the reference's typed framing: tag <c>2</c>, the 8-byte
    /// little-endian element count, then each element's 16 little-endian bytes. The reference's
    /// <c>write(Elt[], ince, n, F)</c> with unit stride.
    /// </summary>
    /// <param name="elementsBytes">The concatenated element bytes; exactly <paramref name="elementCount"/> · the baked element width.</param>
    /// <param name="elementCount">The number of elements.</param>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="elementCount"/> is negative.</exception>
    /// <exception cref="ArgumentException">When <paramref name="elementsBytes"/> is not <paramref name="elementCount"/> · the baked element width.</exception>
    public void AbsorbFieldElementArray(ReadOnlySpan<byte> elementsBytes, int elementCount) => AbsorbFieldElementArray(elementsBytes, elementCount, fieldElementBytes);


    /// <summary>
    /// Absorbs an array of field elements framed at <paramref name="elementWidth"/> little-endian bytes each
    /// (per D3). The reference's <c>write(Elt[], ince, n, F)</c> with unit stride.
    /// </summary>
    /// <param name="elementsBytes">The concatenated element bytes; exactly <paramref name="elementCount"/> · <paramref name="elementWidth"/> bytes.</param>
    /// <param name="elementCount">The number of elements.</param>
    /// <param name="elementWidth">The on-wire element width to frame at.</param>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="elementCount"/> is negative.</exception>
    /// <exception cref="ArgumentException">When <paramref name="elementsBytes"/> is not <paramref name="elementCount"/> · <paramref name="elementWidth"/> bytes.</exception>
    public void AbsorbFieldElementArray(ReadOnlySpan<byte> elementsBytes, int elementCount, int elementWidth)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(elementCount);

        if(elementsBytes.Length != elementCount * elementWidth)
        {
            throw new ArgumentException($"Expected {elementCount * elementWidth} bytes for {elementCount} elements; received {elementsBytes.Length}.", nameof(elementsBytes));
        }

        WriteTag(TagArray);
        WriteLength(elementCount);

        WriteUntyped(elementsBytes);
    }


    /// <summary>
    /// Absorbs a 32-byte commitment root exactly as google/longfellow-zk's
    /// <c>LigeroTranscript::write_commitment</c> does: the raw root bytes through the typed byte-array
    /// write. This is the cross-layer entry point — the C.2 commitment root absorbs here before any
    /// challenge is squeezed.
    /// </summary>
    /// <param name="root">The 32-byte commitment root.</param>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    /// <exception cref="ArgumentException">When <paramref name="root"/> is not 32 bytes.</exception>
    public void AbsorbCommitmentRoot(ReadOnlySpan<byte> root)
    {
        if(root.Length != PrfKeySize)
        {
            throw new ArgumentException($"The commitment root is {PrfKeySize} bytes; received {root.Length}.", nameof(root));
        }

        AbsorbByteString(root);
    }


    /// <summary>
    /// Snapshots the PRF key — SHA-256 of the entire absorbed byte stream so far — into
    /// <paramref name="key"/>. The reference's <c>get(key)</c>; a pure read that does not advance the
    /// transcript.
    /// </summary>
    /// <param name="key">Receives the 32-byte snapshot.</param>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    /// <exception cref="ArgumentException">When <paramref name="key"/> is not 32 bytes.</exception>
    public void SnapshotKey(Span<byte> key)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if(key.Length != PrfKeySize)
        {
            throw new ArgumentException($"The PRF key is {PrfKeySize} bytes; received {key.Length}.", nameof(key));
        }

        //Fork the running state and finalize the fork (the reference's SHA256 tmp; tmp.CopyState(sha_);
        //tmp.DigestData(key)). O(1) per squeeze — one partial-block finalize, not a full re-hash. The
        //fork leaves the running state undisturbed so absorption can continue.
        ILongfellowIncrementalHash fork = incrementalHash.Fork();
        fork.FinalizeInto(key);
    }


    /// <summary>
    /// Clones the transcript, the reference's <c>Transcript::clone()</c> (<c>lib/random/transcript.h</c>):
    /// the clone carries the same absorbed byte stream (the running SHA-256 state) but a fresh, inactive
    /// PRF, so its first squeeze re-keys from the shared snapshot and the clone produces the identical
    /// challenge stream the original would. The ZK prover clones AFTER the Fiat–Shamir setup so the
    /// sumcheck (driven on the clone) and the verifier-constraint replay (driven on the original) squeeze
    /// the same challenges.
    /// </summary>
    /// <returns>A new transcript sharing this transcript's absorbed state; the caller owns its disposal.</returns>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    public LongfellowTranscript Clone()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        //Fork the running SHA state by value (the reference's CopyState) so the clone carries the same
        //absorbed state and produces the identical challenge stream.
        var clone = new LongfellowTranscript(version, fieldElementBytes, blockCipher, pool, incrementalHash.Fork());
        clone.absorbedLength = absorbedLength;

        return clone;
    }


    /// <summary>
    /// Squeezes <paramref name="destination"/> raw pseudo-random bytes from the PRF, the reference's
    /// <c>bytes(buf, n)</c>. The first squeeze after construction or after any absorption re-keys the
    /// PRF from the current snapshot and restarts the block counter at 0.
    /// </summary>
    /// <param name="destination">The span to fill completely.</param>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    public void SqueezeBytes(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(!prfActive)
        {
            //The reference lazily builds the FSPRF from the current snapshot on the first byte draw.
            SnapshotKey(prfKey.Memory.Span[..PrfKeySize]);
            blockCounter = 0;
            readPointer = PrfOutputSize;
            prfActive = true;
        }

        Span<byte> savedSpan = saved.Memory.Span[..PrfOutputSize];
        for(int i = 0; i < destination.Length; i++)
        {
            if(readPointer == PrfOutputSize)
            {
                RefillBlock();
            }

            destination[i] = savedSpan[readPointer];
            readPointer++;
        }
    }


    /// <summary>
    /// Squeezes one field element's little-endian bytes (<c>to_bytes_field</c>) at the baked element width.
    /// This is the RAW <c>of_bytes_field</c> draw the reference's <c>generate_mac_key</c> uses (<c>t.bytes(buf,
    /// kBytes)</c>, <c>mdoc_zk.cc:280</c>): exactly one block, never the <c>sample</c> reject loop. For the
    /// challenge-element draws (<c>elt(F)</c>) use <see cref="SqueezeFieldElement(LongfellowFieldProfile, Span{byte})"/>.
    /// </summary>
    /// <param name="elementBytes">Receives the little-endian element bytes; the baked element width.</param>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    /// <exception cref="ArgumentException">When <paramref name="elementBytes"/> is not the baked element width.</exception>
    public void SqueezeFieldElementBytes(Span<byte> elementBytes) => SqueezeFieldElementBytes(elementBytes, fieldElementBytes);


    /// <summary>
    /// Squeezes one field element's little-endian bytes (<c>of_bytes_field</c>) framed at <paramref name="elementWidth"/>
    /// bytes (per D3 the cross-field driver draws the 16-byte <c>generate_mac_key</c> a_v explicitly, never against
    /// the baked width). This is the RAW <c>of_bytes_field</c> draw the reference's <c>generate_mac_key</c> uses
    /// (<c>t.bytes(buf, kBytes)</c>, <c>mdoc_zk.cc:280</c>): exactly one block of <paramref name="elementWidth"/>
    /// bytes, never the <c>sample</c> reject loop.
    /// </summary>
    /// <param name="elementBytes">Receives the little-endian element bytes; exactly <paramref name="elementWidth"/> bytes.</param>
    /// <param name="elementWidth">The on-wire element width to draw (16 for the GF(2^128) MAC key, 32 for the P-256 base field).</param>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    /// <exception cref="ArgumentException">When <paramref name="elementBytes"/> is not <paramref name="elementWidth"/> bytes.</exception>
    public void SqueezeFieldElementBytes(Span<byte> elementBytes, int elementWidth)
    {
        if(elementBytes.Length != elementWidth)
        {
            throw new ArgumentException($"A field element is {elementWidth} little-endian bytes; received {elementBytes.Length}.", nameof(elementBytes));
        }

        SqueezeBytes(elementBytes);
    }


    /// <summary>
    /// Squeezes one challenge field element through the field's <c>sample</c> mask-then-reject loop and
    /// writes it into <paramref name="canonical"/> — the reference's <c>elt(F)</c> (<c>random.h:39-41</c>),
    /// the transcript being a <c>RandomEngine</c>. GF(2^128) consumes one 16-byte block (never rejects);
    /// the prime field draws 32-byte blocks until one is below the modulus. This is the path EVERY
    /// transcript challenge element takes; the raw <see cref="SqueezeFieldElementBytes(Span{byte})"/> is
    /// only the <c>generate_mac_key</c> a_v draw.
    /// </summary>
    /// <param name="profile">The field profile carrying the <c>sample</c> byte count, mask and range predicate.</param>
    /// <param name="canonical">Receives the canonical scalar.</param>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    /// <exception cref="ArgumentNullException">When <paramref name="profile"/> is <see langword="null"/>.</exception>
    public void SqueezeFieldElement(LongfellowFieldProfile profile, Span<byte> canonical)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ObjectDisposedException.ThrowIf(disposed, this);

        profile.SampleElement(SqueezeBytes, canonical);
    }


    /// <summary>
    /// Squeezes <paramref name="elementCount"/> chained field elements from the continuing PRF
    /// stream — the reference's <c>elt(Elt[], n, F)</c>, the shape of every Ligero array generator
    /// (<c>gen_uldt</c>, <c>gen_alphal</c>, <c>gen_alphaq</c>, <c>gen_uquad</c>). One call here is
    /// one generator call there; the elements land concatenated, 16 little-endian bytes each.
    /// </summary>
    /// <param name="elementsBytes">Receives the concatenated element bytes; exactly <paramref name="elementCount"/> · 16 bytes.</param>
    /// <param name="elementCount">The number of elements to squeeze.</param>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="elementCount"/> is negative.</exception>
    /// <exception cref="ArgumentException">When <paramref name="elementsBytes"/> is not <paramref name="elementCount"/> · 16 bytes.</exception>
    public void SqueezeFieldElements(Span<byte> elementsBytes, int elementCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(elementCount);

        if(elementsBytes.Length != elementCount * fieldElementBytes)
        {
            throw new ArgumentException($"{elementCount} field elements are {elementCount * fieldElementBytes} bytes; received {elementsBytes.Length}.", nameof(elementsBytes));
        }

        for(int i = 0; i < elementCount; i++)
        {
            SqueezeBytes(elementsBytes.Slice(i * fieldElementBytes, fieldElementBytes));
        }
    }


    /// <summary>
    /// Squeezes a uniform natural in <c>[0, bound)</c> by rejection sampling, the reference's
    /// <c>nat(n)</c>. Draws the minimal whole bytes covering the bound, reads them little-endian, masks
    /// off bits above the bound's top set bit, and redraws while the masked value reaches the bound.
    /// </summary>
    /// <param name="bound">The exclusive upper bound; at least 1.</param>
    /// <returns>A uniform value in <c>[0, bound)</c>.</returns>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="bound"/> is below 1.</exception>
    public ulong SqueezeNatural(ulong bound)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(bound, 1UL);

        //The minimal number of whole bytes that can hold the bound: shift it down a byte at a time.
        int byteCount = 0;
        ulong remaining = bound;
        while(remaining != 0)
        {
            remaining >>= 8;
            byteCount++;
        }

        ulong mask = SmallestCoveringMask(bound);

        Span<byte> drawn = stackalloc byte[sizeof(ulong)];
        ulong value;
        do
        {
            //Consume byteCount random bytes and read them little-endian.
            SqueezeBytes(drawn[..byteCount]);

            value = 0;
            for(int i = byteCount; i-- > 0;)
            {
                value = (value << 8) | drawn[i];
            }

            value &= mask;
        }
        while(value >= bound);

        return value;
    }


    /// <summary>
    /// Squeezes <paramref name="count"/> distinct naturals in <c>[0, bound)</c> via a partial
    /// Fisher–Yates shuffle, the reference's <c>choose(res, n, k)</c> and the Ligero column selector
    /// <c>gen_idx</c>. The identity array <c>0..bound−1</c> is rented from the pool.
    /// </summary>
    /// <param name="bound">The exclusive upper bound of the universe; at least <paramref name="count"/>.</param>
    /// <param name="count">The number of distinct naturals to choose.</param>
    /// <param name="destination">Receives the <paramref name="count"/> chosen naturals in selection order.</param>
    /// <exception cref="ObjectDisposedException">When the transcript has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="count"/> is negative or exceeds <paramref name="bound"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is not <paramref name="count"/> long.</exception>
    public void SqueezeIndexSubset(int bound, int count, Span<int> destination)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, bound);

        if(destination.Length != count)
        {
            throw new ArgumentException($"The destination must hold {count} naturals; received {destination.Length}.", nameof(destination));
        }

        //The textbook O(n)-space selection: A = identity, then for i in [0, count) swap A[i] with
        //A[i + nat(n - i)] and emit A[i]. Each int is 4 bytes; the universe array is pool-rented.
        using IMemoryOwner<byte> universeOwner = pool.Rent(bound * sizeof(int));
        Span<int> universe = MemoryMarshal.Cast<byte, int>(universeOwner.Memory.Span)[..bound];
        for(int i = 0; i < bound; i++)
        {
            universe[i] = i;
        }

        for(int i = 0; i < count; i++)
        {
            int j = i + (int)SqueezeNatural((ulong)(bound - i));
            (universe[i], universe[j]) = (universe[j], universe[i]);
            destination[i] = universe[i];
        }

        universe.Clear();
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        try
        {
            saved.Memory.Span[..PrfOutputSize].Clear();
            saved.Dispose();
            prfKey.Memory.Span[..PrfKeySize].Clear();
            prfKey.Dispose();
        }
        catch
        {
            //Disposal must not throw; an orphaned buffer is preferable to a crash.
        }
    }


    //Refills saved with the next PRF block: AES-256-ECB(key, littleEndian64(blockCounter++)). The
    //reference's FSPRF::refill. Panics past kMaxBlocks rather than wrapping the counter.
    private void RefillBlock()
    {
        if(blockCounter >= MaxBlocks)
        {
            throw new InvalidOperationException("The Longfellow transcript PRF exhausted its block budget (2^40 blocks).");
        }

        Span<byte> input = stackalloc byte[PrfInputSize];
        input.Clear();
        WriteUInt64LittleEndian(input, blockCounter);
        blockCounter++;

        blockCipher(prfKey.Memory.Span[..PrfKeySize], input, saved.Memory.Span[..PrfOutputSize]);
        readPointer = 0;
    }


    //Writes a 1-byte tag through the untyped path (the reference tags via write_untyped of one byte).
    private void WriteTag(byte tag)
    {
        Span<byte> one = stackalloc byte[1];
        one[0] = tag;
        WriteUntyped(one);
    }


    //Writes an 8-byte little-endian length through the untyped path (the reference's length(x)).
    private void WriteLength(long length)
    {
        Span<byte> encoded = stackalloc byte[LengthBytes];
        WriteUInt64LittleEndian(encoded, (ulong)length);
        WriteUntyped(encoded);
    }


    //Feeds raw bytes to the running incremental hash and invalidates the PRF (the reference's write_untyped
    //-> sha_.Update, then resets the FSPRF on every write). The next squeeze re-keys from the longer
    //snapshot. The bytes are not retained; absorbedLength counts them for the width-threading gates.
    private void WriteUntyped(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        //Feed the incremental hasher exactly the bytes that frame this write, in the same order, so its
        //fork-finalize equals SHA-256 of the full absorbed stream (the reference's write_untyped ->
        //sha_.Update). This is the sole snapshot input — nothing is retained.
        incrementalHash.Update(data);
        absorbedLength += data.Length;

        prfActive = false;
    }


    //The reference's mask(n): the smallest m such that (n & m) == n — i.e. all-ones up to n's top set
    //bit. Used by the natural-rejection sampler to discard the high bits before the bound test.
    private static ulong SmallestCoveringMask(ulong n)
    {
        ulong mask = 0;
        while((n & mask) != n)
        {
            mask <<= 1;
            mask |= 1UL;
        }

        return mask;
    }


    private static void WriteUInt64LittleEndian(Span<byte> destination, ulong value)
    {
        for(int i = 0; i < LengthBytes; i++)
        {
            destination[i] = (byte)(value & 0xFF);
            value >>= 8;
        }
    }
}
