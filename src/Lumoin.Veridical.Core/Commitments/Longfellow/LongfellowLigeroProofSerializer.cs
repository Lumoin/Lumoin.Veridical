using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The wire-format-conformant byte serialization of a <see cref="LongfellowLigeroProof"/>, a faithful
/// port of google/longfellow-zk's <c>ZkProof&lt;Field&gt;::write_com_proof</c> /
/// <c>read_com_proof</c> (<c>lib/zk/zk_proof.h</c>) — the lowest real serialization boundary the
/// reference exposes for the Ligero layer. The reference's <c>ZkProof::write</c> lays down three
/// segments in order: the commitment root (<c>write_com</c>), the GKR/sumcheck transcript
/// (<c>write_sc_proof</c>), and finally the Ligero proof (<c>write_com_proof</c>). This serializer
/// implements the third segment byte for byte; the first two belong to the zk envelope above the
/// Ligero layer (the commitment root the caller already holds, the GKR transcript the data-parallel
/// engine produces) and are out of scope here.
/// </summary>
/// <remarks>
/// <para>
/// The byte layout of <c>write_com_proof</c>, in order:
/// </para>
/// <list type="number">
///   <item><description><c>y_ldt</c>: <c>block</c> full-field elements, each <c>LongfellowFieldProfile.ElementBytes</c> little-endian bytes (<c>to_bytes_field</c>).</description></item>
///   <item><description><c>y_dot</c>: <c>dblock</c> full-field elements.</description></item>
///   <item><description><c>y_quad_0</c>: <c>r</c> full-field elements.</description></item>
///   <item><description><c>y_quad_2</c>: <c>dblock − block</c> full-field elements.</description></item>
///   <item><description>nonces: <c>nreq</c> · 32 bytes, one per opened column.</description></item>
///   <item><description><c>req</c>: the <c>nrow × nreq</c> opened-column matrix in row-major order, run-length encoded. Runs alternate between full-field and subfield, the first run being full-field (<c>subfield_run = false</c>). Each run is a 4-byte little-endian length followed by its elements: full-field runs write <c>LongfellowFieldProfile.ElementBytes</c> bytes per element, subfield runs write <c>subFieldBytes</c> bytes per element (<c>to_bytes_subfield</c>). The run boundary is the change of the <c>in_subfield</c> predicate.</description></item>
///   <item><description>Merkle path: a 4-byte little-endian digest count followed by that many 32-byte digests.</description></item>
/// </list>
/// <para>
/// The <c>in_subfield</c> predicate and the subfield element framing are field-specific and enter
/// through the <see cref="LongfellowSubfieldRunCodec"/> seam. For GF(2^128) (<see cref="LongfellowSubfieldRunCodec.ForGf2k128"/>)
/// a field element lies in the subfield when it is a GF(2)-linear combination of the subfield basis
/// <c>{β_0, …, β_{m−1}}</c> with <c>β_j = g^j</c> (the LCH14 evaluation-node basis, supplied by
/// <see cref="Lch14AdditiveFft.BasisElement"/>); <c>m = subFieldBytes · 8</c>. The encode
/// (<c>to_bytes_subfield</c>) recovers the coordinate vector <c>u</c> with <c>element = Σ_j u_j · β_j</c>
/// and writes <c>u</c> as <c>subFieldBytes</c> little-endian bytes; the decode (<c>of_bytes_subfield</c>)
/// reads <c>u</c> and recombines the basis. Both go through a one-time row-echelon reduction of the basis
/// (<c>beta_ref</c>), reproduced here over the field's 128-bit polynomial representation.
/// </para>
/// <para>
/// For the P-256 base field (<see cref="LongfellowSubfieldRunCodec.ForFp256"/>) the subfield IS the base
/// field: <c>fp_generic.h</c> has <c>in_subfield(e) ≡ true</c> (line 284),
/// <c>kSubFieldBytes = kBytes = 32</c> (line 47), and <c>to_bytes_subfield ≡ to_bytes_field</c> /
/// <c>of_bytes_subfield ≡ of_bytes_field</c> (lines 382–388). So the run-length pass produces a length-0
/// leading full-field run followed by one subfield run covering all <c>nreq · nrow</c> elements, every
/// element written as its 32-byte <c>to_bytes_field</c> bytes — no basis solve.
/// </para>
/// <para>
/// The library's serialization ban forbids JSON/CBOR; this is plain span writing, which the ban
/// permits. Any envelope-level compression (zstd) or framing belongs to a caller-supplied codec seam,
/// not here.
/// </para>
/// </remarks>
internal static class LongfellowLigeroProofSerializer
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The reference's MerkleNonce::kLength and Digest::kLength: nonce and digest are 32 bytes each.
    private const int NonceLength = 32;
    private const int DigestLength = 32;

    //The reference's write_size / read_size: a length prefix is exactly 4 little-endian bytes.
    private const int SizePrefixBytes = 4;

    //The reference's ZkProof::kMaxRunLen: a run-length-encoded run may not reach 2^25 elements.
    private const int MaxRunLength = 1 << 25;

    //The reference's ZkProof::kMaxNumDigests: a Merkle path may not reach 2^25 digests.
    private const int MaxDigestCount = 1 << 25;


    /// <summary>
    /// Returns the exact serialized byte size of <paramref name="proof"/> under the given subfield byte
    /// size, by running the same run-length pass the writer uses. The actual size is data-dependent
    /// because the opened columns compress to subfield bytes wherever an element lies in the subfield.
    /// </summary>
    /// <param name="proof">The proof to size.</param>
    /// <param name="subFieldBytes">The subfield element byte size (2 for GF(2^16), 4 for GF(2^32)).</param>
    /// <param name="profile">The field profile; supplies the full-field on-wire element width.</param>
    /// <param name="fft">The LCH14 engine over the matching subfield, supplying the basis for the subfield test.</param>
    /// <param name="pool">The pool the temporary basis reduction rents from.</param>
    public static int SerializedSize(
        LongfellowLigeroProof proof,
        int subFieldBytes,
        LongfellowFieldProfile profile,
        Lch14AdditiveFft fft,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(fft);
        ArgumentNullException.ThrowIfNull(pool);

        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForGf2k128(profile, fft, subFieldBytes, pool);

        return SerializedSize(proof, profile, codec);
    }


    /// <summary>
    /// Returns the exact serialized byte size of <paramref name="proof"/> under the supplied subfield-run
    /// codec — the field-generic core the GF(2^128) <see cref="SerializedSize(LongfellowLigeroProof, int, LongfellowFieldProfile, Lch14AdditiveFft, BaseMemoryPool)"/>
    /// overload delegates to and the Fp256 callers reach through
    /// <see cref="LongfellowSubfieldRunCodec.ForFp256"/>.
    /// </summary>
    /// <param name="proof">The proof to size.</param>
    /// <param name="profile">The field profile; supplies the full-field on-wire element width.</param>
    /// <param name="codec">The subfield-run codec for the field.</param>
    public static int SerializedSize(LongfellowLigeroProof proof, LongfellowFieldProfile profile, LongfellowSubfieldRunCodec codec)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(codec);

        return SerializedSizeWithCodec(proof, proof.Parameters, profile.ElementBytes, codec);
    }


    /// <summary>
    /// Writes <paramref name="proof"/> into <paramref name="destination"/> in the reference's
    /// <c>write_com_proof</c> byte layout and returns the number of bytes written.
    /// </summary>
    /// <param name="proof">The proof to serialize.</param>
    /// <param name="subFieldBytes">The subfield element byte size (2 for GF(2^16), 4 for GF(2^32)).</param>
    /// <param name="profile">The field profile; supplies the full-field on-wire element width and the <c>to_bytes_field</c> framing.</param>
    /// <param name="fft">The LCH14 engine over the matching subfield.</param>
    /// <param name="pool">The pool the temporary basis reduction rents from.</param>
    /// <param name="destination">The buffer to write into; must be at least <see cref="SerializedSize(LongfellowLigeroProof, int, LongfellowFieldProfile, Lch14AdditiveFft, BaseMemoryPool)"/> bytes.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is too small.</exception>
    public static int Write(
        LongfellowLigeroProof proof,
        int subFieldBytes,
        LongfellowFieldProfile profile,
        Lch14AdditiveFft fft,
        BaseMemoryPool pool,
        Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(fft);
        ArgumentNullException.ThrowIfNull(pool);

        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForGf2k128(profile, fft, subFieldBytes, pool);

        return Write(proof, profile, codec, destination);
    }


    /// <summary>
    /// Writes <paramref name="proof"/> into <paramref name="destination"/> in the reference's
    /// <c>write_com_proof</c> byte layout under the supplied subfield-run codec — the field-generic core
    /// the GF(2^128) overload delegates to and the Fp256 callers reach through
    /// <see cref="LongfellowSubfieldRunCodec.ForFp256"/>.
    /// </summary>
    /// <param name="proof">The proof to serialize.</param>
    /// <param name="profile">The field profile; supplies the full-field on-wire element width and the <c>to_bytes_field</c> framing.</param>
    /// <param name="codec">The subfield-run codec for the field.</param>
    /// <param name="destination">The buffer to write into; must be at least <see cref="SerializedSize(LongfellowLigeroProof, LongfellowFieldProfile, LongfellowSubfieldRunCodec)"/> bytes.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is too small.</exception>
    public static int Write(
        LongfellowLigeroProof proof,
        LongfellowFieldProfile profile,
        LongfellowSubfieldRunCodec codec,
        Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(codec);

        LongfellowLigeroParameters parameters = proof.Parameters;
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int r = parameters.RandomCount;
        int quadHigh = dblock - block;
        int nreq = parameters.OpenedColumnCount;
        int elementBytes = profile.ElementBytes;

        int required = SerializedSizeWithCodec(proof, parameters, elementBytes, codec);
        if(destination.Length < required)
        {
            throw new ArgumentException($"The destination holds {destination.Length} bytes; the proof needs {required}.", nameof(destination));
        }

        int offset = 0;

        //y_ldt | y_dot | y_quad_0 | y_quad_2, all full-field.
        offset += WriteElements(proof.LowDegreeResponse, block, profile, destination[offset..]);
        offset += WriteElements(proof.DotResponse, dblock, profile, destination[offset..]);
        offset += WriteElements(proof.QuadraticResponseLow, r, profile, destination[offset..]);
        offset += WriteElements(proof.QuadraticResponseHigh, quadHigh, profile, destination[offset..]);

        //The per-leaf nonces.
        for(int j = 0; j < nreq; j++)
        {
            proof.Nonce(j).CopyTo(destination.Slice(offset, NonceLength));
            offset += NonceLength;
        }

        //The run-length-encoded opened columns.
        offset += WriteOpenedColumns(proof, parameters, profile, codec, destination[offset..]);

        //The Merkle path: 4-byte count then the digests.
        WriteSize(proof.MerklePathLength, destination[offset..]);
        offset += SizePrefixBytes;
        for(int i = 0; i < proof.MerklePathLength; i++)
        {
            proof.PathDigest(i).CopyTo(destination.Slice(offset, DigestLength));
            offset += DigestLength;
        }

        return offset;
    }


    /// <summary>
    /// Reads a <see cref="LongfellowLigeroProof"/> out of <paramref name="source"/> in the reference's
    /// <c>read_com_proof</c> byte layout. The shapes come from <paramref name="parameters"/>; the bytes
    /// supply the values. Returns the parsed proof on success, or <see langword="null"/> on any
    /// underflow or malformed run/path length — mirroring the reference's <c>false</c> return.
    /// </summary>
    /// <param name="parameters">The layout the proof was produced for.</param>
    /// <param name="subFieldBytes">The subfield element byte size (2 for GF(2^16), 4 for GF(2^32)).</param>
    /// <param name="profile">The field profile; supplies the full-field on-wire element width and the <c>of_bytes_field</c> framing.</param>
    /// <param name="fft">The LCH14 engine over the matching subfield.</param>
    /// <param name="pool">The pool the proof's buffers and the temporary basis reduction rent from.</param>
    /// <param name="source">The serialized bytes.</param>
    /// <param name="bytesRead">The number of bytes consumed on success; <c>0</c> on failure.</param>
    /// <returns>The parsed proof, or <see langword="null"/> on malformed input. The caller owns and disposes a non-null result.</returns>
    public static LongfellowLigeroProof? Read(
        LongfellowLigeroParameters parameters,
        int subFieldBytes,
        LongfellowFieldProfile profile,
        Lch14AdditiveFft fft,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> source,
        out int bytesRead)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(fft);
        ArgumentNullException.ThrowIfNull(pool);

        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForGf2k128(profile, fft, subFieldBytes, pool);

        return Read(parameters, profile, codec, pool, source, out bytesRead);
    }


    /// <summary>
    /// Reads a <see cref="LongfellowLigeroProof"/> out of <paramref name="source"/> in the reference's
    /// <c>read_com_proof</c> byte layout under the supplied subfield-run codec — the field-generic core
    /// the GF(2^128) overload delegates to and the Fp256 callers reach through
    /// <see cref="LongfellowSubfieldRunCodec.ForFp256"/>.
    /// </summary>
    /// <param name="parameters">The layout the proof was produced for.</param>
    /// <param name="profile">The field profile; supplies the full-field on-wire element width and the <c>of_bytes_field</c> framing.</param>
    /// <param name="codec">The subfield-run codec for the field.</param>
    /// <param name="pool">The pool the proof's buffers rent from.</param>
    /// <param name="source">The serialized bytes.</param>
    /// <param name="bytesRead">The number of bytes consumed on success; <c>0</c> on failure.</param>
    /// <returns>The parsed proof, or <see langword="null"/> on malformed input. The caller owns and disposes a non-null result.</returns>
    public static LongfellowLigeroProof? Read(
        LongfellowLigeroParameters parameters,
        LongfellowFieldProfile profile,
        LongfellowSubfieldRunCodec codec,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> source,
        out int bytesRead)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(codec);
        ArgumentNullException.ThrowIfNull(pool);

        bytesRead = 0;
        int elementBytes = profile.ElementBytes;

        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int r = parameters.RandomCount;
        int quadHigh = dblock - block;
        int nreq = parameters.OpenedColumnCount;
        int nrow = parameters.RowCount;

        IMemoryOwner<byte> responseOwner = pool.Rent(LongfellowLigeroProof.ResponseBufferSize(parameters));
        IMemoryOwner<byte> openedColumnsOwner = pool.Rent(nrow * nreq * ScalarSize);
        IMemoryOwner<byte> indicesOwner = pool.Rent(nreq * sizeof(int));
        IMemoryOwner<byte> nonceOwner = pool.Rent(nreq * NonceLength);
        IMemoryOwner<byte>? merklePathOwner = null;

        bool ok = false;
        try
        {
            Span<byte> responses = responseOwner.Memory.Span[..LongfellowLigeroProof.ResponseBufferSize(parameters)];
            int offset = 0;

            //The four response rows. The indices the proof carries are not transmitted here; they are
            //re-derived from the verifier's transcript replay, so the parsed proof leaves them zero (a
            //read-back proof feeds the verifier, which squeezes idx itself).
            MemoryMarshal.Cast<byte, int>(indicesOwner.Memory.Span[..(nreq * sizeof(int))]).Clear();

            if(!ReadElements(source, ref offset, block, profile, responses[..(block * ScalarSize)]))
            {
                return null;
            }

            if(!ReadElements(source, ref offset, dblock, profile, responses.Slice(block * ScalarSize, dblock * ScalarSize)))
            {
                return null;
            }

            if(!ReadElements(source, ref offset, r, profile, responses.Slice((block + dblock) * ScalarSize, r * ScalarSize)))
            {
                return null;
            }

            if(!ReadElements(source, ref offset, quadHigh, profile, responses.Slice(((block + dblock) * ScalarSize) + (r * ScalarSize), quadHigh * ScalarSize)))
            {
                return null;
            }

            //The per-leaf nonces.
            if(source.Length - offset < nreq * NonceLength)
            {
                return null;
            }

            source.Slice(offset, nreq * NonceLength).CopyTo(nonceOwner.Memory.Span[..(nreq * NonceLength)]);
            offset += nreq * NonceLength;

            //The run-length-encoded opened columns.
            if(!ReadOpenedColumns(source, ref offset, parameters, profile, codec, openedColumnsOwner.Memory.Span[..(nrow * nreq * ScalarSize)]))
            {
                return null;
            }

            //The Merkle path: 4-byte count then the digests.
            if(source.Length - offset < SizePrefixBytes)
            {
                return null;
            }

            long pathCount = ReadSize(source, ref offset);

            //Merkle proofs of length < nreq are invalid in the zk setting; cap by the parameter bound.
            if(pathCount < nreq || pathCount >= MaxDigestCount)
            {
                return null;
            }

            if(pathCount > (long)nreq * MerklePathLengthBound(parameters))
            {
                return null;
            }

            if(source.Length - offset < pathCount * DigestLength)
            {
                return null;
            }

            int pathLength = (int)pathCount;
            merklePathOwner = pool.Rent(Math.Max(pathLength, 1) * DigestLength);
            source.Slice(offset, pathLength * DigestLength).CopyTo(merklePathOwner.Memory.Span[..(pathLength * DigestLength)]);
            offset += pathLength * DigestLength;

            bytesRead = offset;
            ok = true;

            return new LongfellowLigeroProof(parameters, responseOwner, openedColumnsOwner, indicesOwner, nonceOwner, merklePathOwner, pathLength);
        }
        finally
        {
            if(!ok)
            {
                responseOwner.Dispose();
                openedColumnsOwner.Dispose();
                indicesOwner.Dispose();
                nonceOwner.Dispose();
                merklePathOwner?.Dispose();
            }
        }
    }


    //The reference's mc_pathlen = merkle_tree_len(block_ext): read_com_proof rejects any path longer
    //than nreq · mc_pathlen. The unsigned arithmetic mirrors the reference's merkle_tree_len exactly so
    //the read bound matches bit for bit (the same formula LongfellowLigeroParameters ports for the
    //layout estimate).
    private static long MerklePathLengthBound(LongfellowLigeroParameters parameters)
    {
        int leafCount = parameters.BlockExtension;
        long result = 1;
        ulong position = unchecked((ulong)((long)leafCount - 1)) + (ulong)leafCount;
        for(; position > 1; position >>= 1)
        {
            ++result;
        }

        return result;
    }


    private static int SerializedSizeWithCodec(LongfellowLigeroProof proof, LongfellowLigeroParameters parameters, int elementBytes, LongfellowSubfieldRunCodec codec)
    {
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int r = parameters.RandomCount;
        int quadHigh = dblock - block;
        int nreq = parameters.OpenedColumnCount;

        int size = (block + dblock + r + quadHigh) * elementBytes;
        size += nreq * NonceLength;
        size += MeasureOpenedColumns(proof, parameters, elementBytes, codec);
        size += SizePrefixBytes + (proof.MerklePathLength * DigestLength);

        return size;
    }


    //Walks the run-length encoding of req[nrow, nreq] without writing, returning the byte count: a
    //4-byte prefix per run, plus per-element bytes (full-field or subfield) per the in_subfield flag.
    private static int MeasureOpenedColumns(LongfellowLigeroProof proof, LongfellowLigeroParameters parameters, int elementBytes, LongfellowSubfieldRunCodec codec)
    {
        int total = parameters.OpenedColumnCount * parameters.RowCount;
        int subFieldBytes = codec.SubFieldBytes;

        int size = 0;
        int ci = 0;
        bool subfieldRun = false;
        while(ci < total)
        {
            int runLength = MeasureRun(proof, parameters, codec, ci, total, subfieldRun);
            size += SizePrefixBytes + (runLength * (subfieldRun ? subFieldBytes : elementBytes));
            ci += runLength;
            subfieldRun = !subfieldRun;
        }

        return size;
    }


    //The reference's run-length pass over req: writes a 4-byte length per run then the run's elements,
    //alternating full-field/subfield runs starting full-field. The run boundary is the in_subfield flip.
    private static int WriteOpenedColumns(LongfellowLigeroProof proof, LongfellowLigeroParameters parameters, LongfellowFieldProfile profile, LongfellowSubfieldRunCodec codec, Span<byte> destination)
    {
        int total = parameters.OpenedColumnCount * parameters.RowCount;
        int nreq = parameters.OpenedColumnCount;
        int subFieldBytes = codec.SubFieldBytes;
        int elementBytes = profile.ElementBytes;

        int offset = 0;
        int ci = 0;
        bool subfieldRun = false;
        while(ci < total)
        {
            int runLength = MeasureRun(proof, parameters, codec, ci, total, subfieldRun);

            WriteSize(runLength, destination[offset..]);
            offset += SizePrefixBytes;

            for(int i = ci; i < ci + runLength; i++)
            {
                int rowIndex = i / nreq;
                int slot = i % nreq;
                ReadOnlySpan<byte> element = proof.OpenedColumnElement(rowIndex, slot);
                if(subfieldRun)
                {
                    codec.ToBytesSubfield(element, destination.Slice(offset, subFieldBytes));
                    offset += subFieldBytes;
                }
                else
                {
                    profile.ToBytesField(element, destination.Slice(offset, elementBytes));
                    offset += elementBytes;
                }
            }

            ci += runLength;
            subfieldRun = !subfieldRun;
        }

        return offset;
    }


    //Length of the run that starts at ci while in_subfield matches subfieldRun, capped at kMaxRunLen.
    private static int MeasureRun(LongfellowLigeroProof proof, LongfellowLigeroParameters parameters, LongfellowSubfieldRunCodec codec, int ci, int total, bool subfieldRun)
    {
        int nreq = parameters.OpenedColumnCount;
        int runLength = 0;
        while(ci + runLength < total && runLength < MaxRunLength)
        {
            int index = ci + runLength;
            int rowIndex = index / nreq;
            int slot = index % nreq;
            if(codec.InSubfield(proof.OpenedColumnElement(rowIndex, slot)) != subfieldRun)
            {
                break;
            }

            runLength++;
        }

        return runLength;
    }


    //The reference's run-decoding pass: alternating full-field/subfield runs, each a 4-byte length then
    //the run's elements, filling req[nrow, nreq] row-major into `destination`.
    private static bool ReadOpenedColumns(ReadOnlySpan<byte> source, ref int offset, LongfellowLigeroParameters parameters, LongfellowFieldProfile profile, LongfellowSubfieldRunCodec codec, Span<byte> destination)
    {
        int total = parameters.OpenedColumnCount * parameters.RowCount;
        int subFieldBytes = codec.SubFieldBytes;
        int fieldBytes = profile.ElementBytes;

        int ci = 0;
        bool subfieldRun = false;
        while(ci < total)
        {
            if(source.Length - offset < SizePrefixBytes)
            {
                return false;
            }

            long runLength = ReadSize(source, ref offset);
            if(runLength >= MaxRunLength || ci + runLength > total)
            {
                return false;
            }

            int elementBytes = subfieldRun ? subFieldBytes : fieldBytes;
            if(source.Length - offset < runLength * elementBytes)
            {
                return false;
            }

            for(int i = ci; i < ci + (int)runLength; i++)
            {
                Span<byte> element = destination.Slice(i * ScalarSize, ScalarSize);
                if(subfieldRun)
                {
                    if(!codec.OfBytesSubfield(source.Slice(offset, subFieldBytes), element))
                    {
                        return false;
                    }

                    offset += subFieldBytes;
                }
                else
                {
                    if(!profile.TryFromBytesField(source.Slice(offset, fieldBytes), element))
                    {
                        return false;
                    }

                    offset += fieldBytes;
                }
            }

            ci += (int)runLength;
            subfieldRun = !subfieldRun;
        }

        return true;
    }


    //Writes `count` consecutive full-field elements from a packed scalar source.
    private static int WriteElements(ReadOnlySpan<byte> scalars, int count, LongfellowFieldProfile profile, Span<byte> destination)
    {
        int elementBytes = profile.ElementBytes;
        int offset = 0;
        for(int i = 0; i < count; i++)
        {
            profile.ToBytesField(scalars.Slice(i * ScalarSize, ScalarSize), destination.Slice(offset, elementBytes));
            offset += elementBytes;
        }

        return offset;
    }


    //Reads `count` consecutive full-field elements into a packed scalar destination; false on underflow
    //or on an element the field rejects.
    private static bool ReadElements(ReadOnlySpan<byte> source, ref int offset, int count, LongfellowFieldProfile profile, Span<byte> destination)
    {
        int elementBytes = profile.ElementBytes;
        if(source.Length - offset < count * elementBytes)
        {
            return false;
        }

        for(int i = 0; i < count; i++)
        {
            if(!profile.TryFromBytesField(source.Slice(offset, elementBytes), destination.Slice(i * ScalarSize, ScalarSize)))
            {
                return false;
            }

            offset += elementBytes;
        }

        return true;
    }


    //The reference's write_size: a size as 4 little-endian bytes.
    private static void WriteSize(int value, Span<byte> destination) =>
        BinaryPrimitives.WriteUInt32LittleEndian(destination[..SizePrefixBytes], (uint)value);


    //The reference's read_size: 4 little-endian bytes as an unsigned 32-bit size.
    private static long ReadSize(ReadOnlySpan<byte> source, ref int offset)
    {
        uint value = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(offset, SizePrefixBytes));
        offset += SizePrefixBytes;

        return value;
    }
}
