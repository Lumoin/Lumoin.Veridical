using Lumoin.Veridical.Hashing.Internal;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace Lumoin.Veridical.Hashing;

/// <summary>
/// Inline storage for a <see cref="Blake3Hasher"/>'s working state —
/// chaining value, partially-filled block, key words, and
/// chaining-value stack. The <see cref="InlineArrayAttribute"/> places
/// every byte of state inside the containing ref struct's stack layout,
/// removing the need for a separate heap or pool allocation.
/// </summary>
[InlineArray(Blake3HasherStateBufferLength.Bytes)]
internal struct Blake3HasherStateBuffer
{
    private byte _element0;
}


/// <summary>
/// Compile-time constant for the size of the inline state buffer.
/// Lives in its own type so the <see cref="InlineArrayAttribute"/>
/// argument on <see cref="Blake3HasherStateBuffer"/> can name a single
/// constant rather than embed the arithmetic.
/// </summary>
internal static class Blake3HasherStateBufferLength
{
    public const int Bytes =
        Blake3Constants.OutputLength                                  // chunk chaining value
        + Blake3Constants.BlockLength                                 // chunk block
        + Blake3Constants.OutputLength                                // key words
        + (Blake3Constants.CvStackDepth * Blake3Constants.OutputLength); // cv stack
}


/// <summary>
/// Incremental BLAKE3 hasher. Construct via one of the static factories
/// (<see cref="Create"/>, <see cref="CreateKeyed"/>,
/// <see cref="CreateDeriveKey"/>, or <see cref="CreateAutoSelected"/>),
/// feed input through <see cref="Update"/>, and produce the final output
/// through <see cref="Finalize"/> or <see cref="FinalizeXof"/>.
/// </summary>
/// <remarks>
/// <para>
/// The hasher is a <see langword="ref struct"/>: its entire working
/// state — chaining value, partially-filled block, key words, and
/// chaining-value stack — lives inline on the stack, with no managed
/// heap or pool allocation per hash call. The trade-off is that a
/// <c>Blake3Hasher</c> cannot escape its declaring method or be stored
/// in fields, async state machines, or arrays; for the one-shot
/// fire-and-forget API see the <see cref="Blake3"/> static class.
/// </para>
/// <para>
/// The hasher carries a <see cref="Blake3Backend"/> wired at
/// construction. The portable scalar backend is always available; the
/// accelerated backends (AVX2, AVX-512, NEON) substitute the same
/// delegate signatures with a CPU-specific implementation.
/// </para>
/// <para>
/// All three BLAKE3 modes are supported. Hash mode uses the BLAKE3 IV
/// as the chunk-state seed; keyed_hash uses the supplied 32-byte key
/// in its place; derive_key first hashes the application-supplied
/// context string under the DERIVE_KEY_CONTEXT flag and uses the
/// resulting 32-byte digest as the seed for the DERIVE_KEY_MATERIAL
/// hashing of the supplied key material.
/// </para>
/// <para>
/// A <see cref="Dispose"/> method is provided; <see langword="using"/>
/// recognises it via the pattern-based dispose protocol that ref
/// struct types support. Dispose clears the inline state so sensitive
/// key material does not survive in the stack frame after the hasher
/// is finished.
/// </para>
/// </remarks>
public ref struct Blake3Hasher
{
    //State layout inside the inline buffer (1856 bytes total):
    //  [0..32)      chunkChainingValue — 8 u32 in native byte order
    //  [32..96)     chunkBlock         — 64 raw bytes accumulating the next block
    //  [96..128)    keyWords           — 8 u32 in native byte order
    //  [128..1856)  cvStack            — 54 entries × 8 u32 in native byte order
    private const int ChunkChainingValueOffset = 0;
    private const int ChunkBlockOffset = ChunkChainingValueOffset + Blake3Constants.OutputLength;
    private const int KeyWordsOffset = ChunkBlockOffset + Blake3Constants.BlockLength;
    private const int CvStackOffset = KeyWordsOffset + Blake3Constants.OutputLength;
    private const int CvStackByteLength =
        Blake3Constants.CvStackDepth * Blake3Constants.OutputLength;


    private Blake3HasherStateBuffer state;
    private readonly Blake3Backend backend;
    private readonly uint flags;
    private byte chunkBlockLen;
    private byte chunkBlocksCompressed;
    private byte cvStackLen;
    private bool disposed;
    private ulong chunkCounter;


    /// <summary>
    /// Default fixed-output length in bytes. The XOF mode supports any
    /// length; the standard BLAKE3 digest is exactly this many bytes.
    /// </summary>
    public const int DefaultOutputSizeBytes = Blake3Constants.OutputLength;

    /// <summary>Key length in bytes for the keyed-hash mode.</summary>
    public const int KeySizeBytes = Blake3Constants.KeyLength;


    private Blake3Hasher(Blake3Backend backend, scoped ReadOnlySpan<uint> seedKeyWords, uint flags)
    {
        //All fields zero-initialise via `this = default`, then specific
        //fields are assigned. This pattern keeps the constructor body
        //within the ref struct's "all fields must be definitely
        //assigned before any instance member is touched" rule.
        this = default;
        this.backend = backend;
        this.flags = flags;

        seedKeyWords.CopyTo(KeyWordsView);
        seedKeyWords.CopyTo(ChunkChainingValueView);
    }


    [UnscopedRef]
    private Span<byte> StateBuffer => MemoryMarshal.CreateSpan(
        ref Unsafe.As<Blake3HasherStateBuffer, byte>(ref state),
        Blake3HasherStateBufferLength.Bytes);


    [UnscopedRef]
    private Span<uint> ChunkChainingValueView => MemoryMarshal.Cast<byte, uint>(
        StateBuffer.Slice(ChunkChainingValueOffset, Blake3Constants.OutputLength));


    [UnscopedRef]
    private Span<byte> ChunkBlockView =>
        StateBuffer.Slice(ChunkBlockOffset, Blake3Constants.BlockLength);


    [UnscopedRef]
    private Span<uint> KeyWordsView => MemoryMarshal.Cast<byte, uint>(
        StateBuffer.Slice(KeyWordsOffset, Blake3Constants.OutputLength));


    [UnscopedRef]
    private Span<uint> CvStackView => MemoryMarshal.Cast<byte, uint>(
        StateBuffer.Slice(CvStackOffset, CvStackByteLength));


    /// <summary>
    /// Constructs a new hasher for the regular hash mode, wired to the
    /// specified backend bundle. The hasher's entire working state lives
    /// inline on the stack; no allocation is performed.
    /// </summary>
    /// <param name="backend">The backend bundle (single-compression + many-chunks delegates).</param>
    /// <returns>A fresh hasher in regular hash mode.</returns>
    public static Blake3Hasher Create(Blake3Backend backend) =>
        new(backend, Blake3Constants.Iv, 0u);


    /// <summary>
    /// Constructs a new hasher for the keyed-hash mode.
    /// </summary>
    /// <param name="key">Exactly <see cref="KeySizeBytes"/> bytes of key material.</param>
    /// <param name="backend">The backend bundle.</param>
    /// <returns>A fresh hasher in keyed-hash mode.</returns>
    /// <exception cref="ArgumentException">When <paramref name="key"/> is not exactly <see cref="KeySizeBytes"/> bytes long.</exception>
    public static Blake3Hasher CreateKeyed(ReadOnlySpan<byte> key, Blake3Backend backend)
    {
        if(key.Length != KeySizeBytes)
        {
            throw new ArgumentException(
                $"BLAKE3 keyed-hash mode requires exactly {KeySizeBytes} bytes of key; got {key.Length}.",
                nameof(key));
        }

        Span<uint> seed = stackalloc uint[Blake3Constants.ChainingValueWords];
        ReadWordsLittleEndian(key, seed);

        return new Blake3Hasher(backend, seed, Blake3Constants.KeyedHash);
    }


    /// <summary>
    /// Constructs a new hasher for the derive_key mode. The
    /// <paramref name="context"/> string is hashed first under the
    /// DERIVE_KEY_CONTEXT flag; the resulting 32-byte digest seeds the
    /// material-hashing phase that <see cref="Update"/> feeds.
    /// </summary>
    /// <param name="context">The application-specific context string (hardcoded, globally unique). Encoded as UTF-8.</param>
    /// <param name="backend">The backend bundle.</param>
    /// <returns>A fresh hasher in derive_key material-hashing mode.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> is <see langword="null"/>.</exception>
    public static Blake3Hasher CreateDeriveKey(string context, Blake3Backend backend)
    {
        ArgumentNullException.ThrowIfNull(context);

        //Phase 1: hash the context string under DERIVE_KEY_CONTEXT to
        //produce a 32-byte context digest. The short-context fast path
        //uses stackalloc; longer contexts borrow a buffer from
        //ArrayPool<byte>.Shared so the path stays allocation-free.
        const int contextStackBufferLength = 256;
        Span<byte> contextKey = stackalloc byte[Blake3Constants.KeyLength];
        int contextByteCount = Encoding.UTF8.GetByteCount(context);

        if(contextByteCount <= contextStackBufferLength)
        {
            Span<byte> contextStackBuffer = stackalloc byte[contextStackBufferLength];
            Span<byte> contextBytes = contextStackBuffer[..contextByteCount];
            Encoding.UTF8.GetBytes(context, contextBytes);
            HashContextInto(backend, contextBytes, contextKey);
            contextBytes.Clear();
        }
        else
        {
            byte[] rented = ArrayPool<byte>.Shared.Rent(contextByteCount);
            try
            {
                Span<byte> contextBytes = rented.AsSpan(0, contextByteCount);
                Encoding.UTF8.GetBytes(context, contextBytes);
                HashContextInto(backend, contextBytes, contextKey);
                contextBytes.Clear();
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        //Phase 2: the 32-byte context digest becomes the seed for the
        //material-hashing phase carried by the returned hasher.
        Span<uint> contextKeyWords = stackalloc uint[Blake3Constants.ChainingValueWords];
        ReadWordsLittleEndian(contextKey, contextKeyWords);
        contextKey.Clear();

        return new Blake3Hasher(backend, contextKeyWords, Blake3Constants.DeriveKeyMaterial);
    }


    private static void HashContextInto(
        Blake3Backend backend,
        ReadOnlySpan<byte> contextBytes,
        Span<byte> contextKey)
    {
        using Blake3Hasher contextHasher = new(
            backend, Blake3Constants.Iv, Blake3Constants.DeriveKeyContext);
        contextHasher.Update(contextBytes);
        contextHasher.Finalize(contextKey);
    }


    /// <summary>
    /// Constructs a new hasher for the regular hash mode, wired to the
    /// highest-capability backend supported on the current CPU. The
    /// portable scalar backend is the fallback when no accelerated
    /// backend is available.
    /// </summary>
    /// <returns>A fresh hasher in regular hash mode.</returns>
    public static Blake3Hasher CreateAutoSelected() =>
        Create(Blake3BackendSelection.SelectBest());


    /// <summary>
    /// Feeds bytes into the hash state. May be called any number of
    /// times; concatenating input across calls is byte-equivalent to a
    /// single call over the concatenated input.
    /// </summary>
    /// <param name="input">Bytes to feed into the hash state.</param>
    /// <exception cref="ObjectDisposedException">When the hasher has been disposed.</exception>
    public void Update(ReadOnlySpan<byte> input)
    {
        ObjectDisposedException.ThrowIf(disposed, typeof(Blake3Hasher));

        Span<uint> chunkCv = stackalloc uint[Blake3Constants.ChainingValueWords];

        while(!input.IsEmpty)
        {
            if(CurrentChunkLength() == Blake3Constants.ChunkLength)
            {
                ChunkOutputChainingValue(chunkCv);
                ulong totalChunks = chunkCounter + 1;
                AddChunkChainingValue(chunkCv, totalChunks);
                ResetChunkState(totalChunks);
            }

            //Chunk-parallel SIMD fast path: chunk state is empty and we
            //have at least one batch's worth of fresh input plus one
            //trailing chunk's worth (so the latest chunk stays in the
            //chunk-state buffer for finalisation).
            if(chunkBlockLen == 0
                && chunkBlocksCompressed == 0
                && backend.ManyChunksBatchSize > 1
                && input.Length >= (backend.ManyChunksBatchSize + 1) * Blake3Constants.ChunkLength)
            {
                int batchSize = backend.ManyChunksBatchSize;
                int batchByteCount = batchSize * Blake3Constants.ChunkLength;
                ProcessChunkBatch(input[..batchByteCount], batchSize);
                input = input[batchByteCount..];
                continue;
            }

            int want = Blake3Constants.ChunkLength - CurrentChunkLength();
            int take = Math.Min(want, input.Length);
            UpdateChunkState(input[..take]);
            input = input[take..];
        }
    }


    /// <summary>
    /// Produces the default fixed-output BLAKE3 digest into the supplied
    /// destination, which must be exactly <see cref="DefaultOutputSizeBytes"/>
    /// bytes. For arbitrary output lengths use <see cref="FinalizeXof"/>.
    /// </summary>
    /// <param name="output">Destination for exactly <see cref="DefaultOutputSizeBytes"/> bytes.</param>
    /// <exception cref="ArgumentException">When <paramref name="output"/> length is not <see cref="DefaultOutputSizeBytes"/>.</exception>
    /// <exception cref="ObjectDisposedException">When the hasher has been disposed.</exception>
    public void Finalize(Span<byte> output)
    {
        if(output.Length != DefaultOutputSizeBytes)
        {
            throw new ArgumentException(
                $"BLAKE3 fixed-output digest requires exactly {DefaultOutputSizeBytes} bytes; use FinalizeXof for arbitrary lengths.",
                nameof(output));
        }

        FinalizeXof(output);
    }


    /// <summary>
    /// Produces BLAKE3 output of any length into the supplied destination
    /// using the extendable-output mode. The first <see cref="DefaultOutputSizeBytes"/>
    /// bytes match the fixed-output digest produced by <see cref="Finalize"/>.
    /// </summary>
    /// <param name="output">Destination for any number of output bytes.</param>
    /// <exception cref="ObjectDisposedException">When the hasher has been disposed.</exception>
    public void FinalizeXof(Span<byte> output)
    {
        ObjectDisposedException.ThrowIf(disposed, typeof(Blake3Hasher));

        //Walk up the right edge of the tree, parent-hashing the chunk's
        //chaining value into each stack entry from top to bottom. The
        //last computation is the root, whose XOF expansion produces the
        //output bytes.
        Span<uint> currentInputCv = stackalloc uint[Blake3Constants.ChainingValueWords];
        Span<uint> currentBlockWords = stackalloc uint[Blake3Constants.BlockWords];
        ulong currentCounter;
        uint currentBlockLength;
        uint currentFlags;

        ChunkChainingValueView.CopyTo(currentInputCv);
        ReadWordsLittleEndian(ChunkBlockView, currentBlockWords);
        currentCounter = chunkCounter;
        currentBlockLength = chunkBlockLen;
        currentFlags = flags | CurrentChunkStartFlag() | Blake3Constants.ChunkEnd;

        Span<uint> keyWordsLocal = stackalloc uint[Blake3Constants.ChainingValueWords];
        KeyWordsView.CopyTo(keyWordsLocal);

        Span<uint> parentCompressionOutput = stackalloc uint[Blake3Constants.CompressionOutputWords];
        int parentsRemaining = cvStackLen;
        while(parentsRemaining > 0)
        {
            parentsRemaining--;

            backend.Compression(
                currentInputCv,
                currentBlockWords,
                currentCounter,
                currentBlockLength,
                currentFlags,
                parentCompressionOutput);

            ReadOnlySpan<uint> leftCv = CvStackView.Slice(
                parentsRemaining * Blake3Constants.ChainingValueWords,
                Blake3Constants.ChainingValueWords);
            leftCv.CopyTo(currentBlockWords[..Blake3Constants.ChainingValueWords]);
            parentCompressionOutput[..Blake3Constants.ChainingValueWords]
                .CopyTo(currentBlockWords[Blake3Constants.ChainingValueWords..]);

            keyWordsLocal.CopyTo(currentInputCv);
            currentCounter = 0UL;
            currentBlockLength = Blake3Constants.BlockLength;
            currentFlags = Blake3Constants.Parent | flags;
        }

        ulong outputBlockCounter = 0UL;
        Span<byte> remaining = output;
        Span<uint> rootWords = stackalloc uint[Blake3Constants.CompressionOutputWords];
        Span<byte> rootBytes = stackalloc byte[2 * Blake3Constants.OutputLength];

        while(!remaining.IsEmpty)
        {
            backend.Compression(
                currentInputCv,
                currentBlockWords,
                outputBlockCounter,
                currentBlockLength,
                currentFlags | Blake3Constants.Root,
                rootWords);

            WriteWordsLittleEndian(rootWords, rootBytes);
            int take = Math.Min(remaining.Length, rootBytes.Length);
            rootBytes[..take].CopyTo(remaining);
            remaining = remaining[take..];
            outputBlockCounter++;
        }
    }


    /// <summary>Clears the inline state buffer so sensitive key material does not survive in the stack frame.</summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        StateBuffer.Clear();
        chunkBlockLen = 0;
        chunkBlocksCompressed = 0;
        chunkCounter = 0UL;
        cvStackLen = 0;
    }


    private readonly int CurrentChunkLength() =>
        Blake3Constants.BlockLength * chunkBlocksCompressed + chunkBlockLen;


    private readonly uint CurrentChunkStartFlag() =>
        chunkBlocksCompressed == 0 ? Blake3Constants.ChunkStart : 0u;


    private void ProcessChunkBatch(ReadOnlySpan<byte> batchInput, int batchSize)
    {
        const int maxBatchSize = 16;
        Span<byte> chunkCvBuffer = stackalloc byte[maxBatchSize * Blake3Constants.OutputLength];
        Span<byte> chunkCvBytes = chunkCvBuffer[..(batchSize * Blake3Constants.OutputLength)];

        backend.ManyChunks(
            batchInput,
            batchSize,
            chunkCounter,
            KeyWordsView,
            flags,
            chunkCvBytes);

        Span<uint> chunkCv = stackalloc uint[Blake3Constants.ChainingValueWords];
        for(int chunkIndex = 0; chunkIndex < batchSize; chunkIndex++)
        {
            int offset = chunkIndex * Blake3Constants.OutputLength;
            ReadWordsLittleEndian(
                chunkCvBytes.Slice(start: offset, length: Blake3Constants.OutputLength),
                chunkCv);

            chunkCounter++;
            AddChunkChainingValue(chunkCv, chunkCounter);
        }
    }


    private void UpdateChunkState(ReadOnlySpan<byte> input)
    {
        Span<uint> blockWords = stackalloc uint[Blake3Constants.BlockWords];
        Span<uint> compressionOutput = stackalloc uint[Blake3Constants.CompressionOutputWords];

        while(!input.IsEmpty)
        {
            if(chunkBlockLen == Blake3Constants.BlockLength)
            {
                ReadWordsLittleEndian(ChunkBlockView, blockWords);
                backend.Compression(
                    ChunkChainingValueView,
                    blockWords,
                    chunkCounter,
                    Blake3Constants.BlockLength,
                    flags | CurrentChunkStartFlag(),
                    compressionOutput);
                compressionOutput[..Blake3Constants.ChainingValueWords]
                    .CopyTo(ChunkChainingValueView);
                chunkBlocksCompressed++;
                ChunkBlockView.Clear();
                chunkBlockLen = 0;
            }

            int want = Blake3Constants.BlockLength - chunkBlockLen;
            int take = Math.Min(want, input.Length);
            input[..take].CopyTo(ChunkBlockView[chunkBlockLen..]);
            chunkBlockLen = (byte)(chunkBlockLen + take);
            input = input[take..];
        }
    }


    private void ChunkOutputChainingValue(scoped Span<uint> output)
    {
        Span<uint> blockWords = stackalloc uint[Blake3Constants.BlockWords];
        ReadWordsLittleEndian(ChunkBlockView, blockWords);
        Span<uint> compressionOutput = stackalloc uint[Blake3Constants.CompressionOutputWords];
        backend.Compression(
            ChunkChainingValueView,
            blockWords,
            chunkCounter,
            chunkBlockLen,
            flags | CurrentChunkStartFlag() | Blake3Constants.ChunkEnd,
            compressionOutput);
        compressionOutput[..Blake3Constants.ChainingValueWords].CopyTo(output);
    }


    private void ResetChunkState(ulong newChunkCounter)
    {
        KeyWordsView.CopyTo(ChunkChainingValueView);
        ChunkBlockView.Clear();
        chunkBlockLen = 0;
        chunkBlocksCompressed = 0;
        chunkCounter = newChunkCounter;
    }


    private void AddChunkChainingValue(scoped Span<uint> newCv, ulong totalChunks)
    {
        Span<uint> combined = stackalloc uint[Blake3Constants.ChainingValueWords];
        while((totalChunks & 1UL) == 0UL)
        {
            Span<uint> leftCv = CvStackView.Slice(
                (cvStackLen - 1) * Blake3Constants.ChainingValueWords,
                Blake3Constants.ChainingValueWords);
            ParentCv(leftCv, newCv, combined);
            combined.CopyTo(newCv);
            cvStackLen--;
            totalChunks >>= 1;
        }

        newCv.CopyTo(CvStackView.Slice(
            cvStackLen * Blake3Constants.ChainingValueWords,
            Blake3Constants.ChainingValueWords));
        cvStackLen++;
    }


    private void ParentCv(
        scoped ReadOnlySpan<uint> leftCv,
        scoped ReadOnlySpan<uint> rightCv,
        scoped Span<uint> output)
    {
        Span<uint> blockWords = stackalloc uint[Blake3Constants.BlockWords];
        leftCv.CopyTo(blockWords[..Blake3Constants.ChainingValueWords]);
        rightCv.CopyTo(blockWords[Blake3Constants.ChainingValueWords..]);

        Span<uint> compressionOutput = stackalloc uint[Blake3Constants.CompressionOutputWords];
        backend.Compression(
            KeyWordsView,
            blockWords,
            0UL,
            Blake3Constants.BlockLength,
            Blake3Constants.Parent | flags,
            compressionOutput);
        compressionOutput[..Blake3Constants.ChainingValueWords].CopyTo(output);
    }


    /// <summary>
    /// Decodes <paramref name="bytes"/> as a sequence of little-endian
    /// 32-bit words and writes them into <paramref name="words"/>.
    /// <paramref name="bytes"/> must contain exactly
    /// <c>words.Length * Blake3Constants.WordSizeBytes</c> bytes.
    /// Returns no value — the destination span is populated in place.
    /// </summary>
    internal static void ReadWordsLittleEndian(ReadOnlySpan<byte> bytes, Span<uint> words)
    {
        for(int wordIndex = 0; wordIndex < words.Length; wordIndex++)
        {
            int byteOffset = wordIndex * Blake3Constants.WordSizeBytes;
            words[wordIndex] = BinaryPrimitives.ReadUInt32LittleEndian(
                bytes.Slice(start: byteOffset, length: Blake3Constants.WordSizeBytes));
        }
    }


    /// <summary>
    /// Encodes <paramref name="words"/> as little-endian bytes into
    /// <paramref name="bytes"/>. <paramref name="bytes"/> must have
    /// room for exactly
    /// <c>words.Length * Blake3Constants.WordSizeBytes</c> bytes.
    /// Returns no value — the destination span is populated in place.
    /// </summary>
    internal static void WriteWordsLittleEndian(ReadOnlySpan<uint> words, Span<byte> bytes)
    {
        for(int wordIndex = 0; wordIndex < words.Length; wordIndex++)
        {
            int byteOffset = wordIndex * Blake3Constants.WordSizeBytes;
            BinaryPrimitives.WriteUInt32LittleEndian(
                bytes.Slice(start: byteOffset, length: Blake3Constants.WordSizeBytes),
                words[wordIndex]);
        }
    }
}