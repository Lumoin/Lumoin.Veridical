using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The dual-field mdoc PROOF driver, the prove-side mirror of <see cref="LongfellowMdocVerifier"/> and a
/// faithful port of google/longfellow-zk's <c>run_mdoc_prover</c> (<c>lib/circuits/mdoc/mdoc_zk.cc</c>): it
/// produces a real mdoc <c>ZkProof</c> envelope <c>[6 macs] ‖ [hash ZkProof] ‖ [sig ZkProof]</c> by driving
/// ONE transcript across both circuits — the GF(2^128) hash circuit and the P-256 base-field signature
/// circuit — in the reference's exact order, so the shared MAC key <c>a_v</c> binds the two proofs together.
/// </summary>
/// <remarks>
/// <para>
/// The flow is the byte target (<c>mdoc_zk.cc run_mdoc_prover</c>): commit the hash circuit then the sig
/// circuit (each over its private witness + the proof pad, the public mac/av region left at the filler's
/// zeros), <c>recv_commitment</c> the hash root then the sig root onto the shared transcript (both absorbed
/// BEFORE any challenge), squeeze <c>a_v = generate_mac_key</c> — ONE 16-byte <c>of_bytes_field</c> draw
/// (NOT the <c>sample</c> reject loop; <c>mdoc_zk.cc:277-282</c>, identical to the verifier's lines
/// 137-148), compute the six macs <c>(a_v + ap_i)·m_i</c> over GF(2^128) (<see cref="ComputeMacs"/>), patch
/// the six macs and <c>a_v</c> into BOTH columns' public regions (<c>update_macs</c>,
/// <c>mdoc_zk.cc:286-303</c>), then finish the hash proof and the sig proof on the continuing transcript.
/// The envelope is the 96-byte mac prefix followed by the two <c>ZkProof</c> envelopes.
/// </para>
/// <para>
/// The post-commit patch is SOUND because the commitment binds ONLY the private witness tail
/// <c>W[npub_in..]</c> + the proof pad (see <see cref="LongfellowZkProver.Commit"/>); the public mac/av
/// region is absorbed at Fiat–Shamir-init and folded into <c>b</c>, never committed, so it can be written
/// after the commit. The driver copies the two supplied columns into pooled buffers it owns, patches the
/// public region of each, proves, and clears the buffers on return.
/// </para>
/// <para>
/// Per D6 the circuits and parameters are pre-derived; the field bindings (row-encoder factory, profile,
/// subfield-run codec, arithmetic delegates, subfield boundary) ride in the two
/// <see cref="LongfellowMdocFieldProver"/> bundles. The transcript, the SHA-256 / Merkle hash delegates and
/// the pool are shared. The GF arithmetic the macs and the squeeze use is the hash bundle's
/// <see cref="LongfellowMdocFieldProver.Add"/> / <see cref="LongfellowMdocFieldProver.Multiply"/> (the hash
/// side IS GF(2^128)).
/// </para>
/// </remarks>
internal static class LongfellowMdocProver
{
    private const int ScalarSize = Scalar.SizeBytes;

    //f_128::kBytes: a_v is one 16-byte GF(2^128) element (generate_mac_key, mdoc_zk.cc:280).
    private const int MacKeyBytes = 16;

    //f_128::kBits: a GF(2^128) element expands to 128 LSB-first base-field wires on the sig side.
    private const int MacKeyBits = 128;

    //The six per-credential macs and the one a_v key, in both public regions (mdoc_zk.cc:286-303).
    private const int MacCount = LongfellowMdocEnvelope.MacCount;

    //compute_macs operates on the 3 common Fp256 values e_, dpkx, dpky (mdoc_zk.cc:124-140).
    private const int CommonValueCount = 3;


    /// <summary>
    /// Produces a dual-field mdoc proof envelope, the reference's <c>run_mdoc_prover</c>.
    /// </summary>
    /// <param name="hash">The GF(2^128) hash-circuit prove bundle.</param>
    /// <param name="sig">The P-256 base-field signature-circuit prove bundle.</param>
    /// <param name="hashWitnessColumn">The full hash column, <c>ninputs_hash</c> · 32 canonical bytes, with the public mac/av region zeroed (the driver patches it post-commit).</param>
    /// <param name="sigWitnessColumn">The full sig column, <c>ninputs_sig</c> · 32 canonical bytes, with the public mac/av region zeroed.</param>
    /// <param name="hashRandom">The hash side's raw-byte entropy source (pad draws, then Ligero commit draws).</param>
    /// <param name="sigRandom">The sig side's raw-byte entropy source.</param>
    /// <param name="commonValues">The three common Fp256 values <c>e_</c>, <c>dpkx</c>, <c>dpky</c> as canonical 32-byte big-endian scalars (the compute_macs message source).</param>
    /// <param name="apKeys">The six per-element MAC keys <c>ap</c> as canonical 32-byte GF(2^128) scalars.</param>
    /// <param name="hashMacIndex">The hash circuit's first public mac element index (the reference's <c>getHashMacIndex</c>, 945 for v7 one-attribute).</param>
    /// <param name="sigMacIndex">The sig circuit's first public mac wire index (the reference's <c>kSigMacIndex</c>, 4).</param>
    /// <param name="transcript">A fresh transcript seeded the way the verifier seeds it; this call drives both commits, the squeeze and both proofs.</param>
    /// <param name="merkleHash">The two-to-one <c>SHA256(L ‖ R)</c> Merkle compression.</param>
    /// <param name="leafHash">The one-shot SHA-256 over a contiguous span.</param>
    /// <param name="hashAlgorithm">The canonical hash-function name (SHA-256).</param>
    /// <param name="pool">The pool the working buffers rent from.</param>
    /// <returns>The full envelope <c>[6 macs] ‖ [hash ZkProof] ‖ [sig ZkProof]</c>; the caller owns it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a column or a mac/common/ap length is wrong.</exception>
    public static byte[] Prove(
        LongfellowMdocFieldProver hash,
        LongfellowMdocFieldProver sig,
        ReadOnlySpan<byte> hashWitnessColumn,
        ReadOnlySpan<byte> sigWitnessColumn,
        LongfellowRandomByteSource hashRandom,
        LongfellowRandomByteSource sigRandom,
        ReadOnlySpan<byte> commonValues,
        ReadOnlySpan<byte> apKeys,
        int hashMacIndex,
        int sigMacIndex,
        LongfellowTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        string hashAlgorithm,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(sig);
        ArgumentNullException.ThrowIfNull(hashRandom);
        ArgumentNullException.ThrowIfNull(sigRandom);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(leafHash);
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(pool);

        if(hashWitnessColumn.Length != hash.Circuit.InputCount * ScalarSize)
        {
            throw new ArgumentException($"Expected {hash.Circuit.InputCount * ScalarSize} hash witness-column bytes; received {hashWitnessColumn.Length}.", nameof(hashWitnessColumn));
        }

        if(sigWitnessColumn.Length != sig.Circuit.InputCount * ScalarSize)
        {
            throw new ArgumentException($"Expected {sig.Circuit.InputCount * ScalarSize} sig witness-column bytes; received {sigWitnessColumn.Length}.", nameof(sigWitnessColumn));
        }

        if(commonValues.Length != CommonValueCount * ScalarSize)
        {
            throw new ArgumentException($"Expected {CommonValueCount * ScalarSize} common-value bytes; received {commonValues.Length}.", nameof(commonValues));
        }

        if(apKeys.Length != MacCount * ScalarSize)
        {
            throw new ArgumentException($"Expected {MacCount * ScalarSize} ap-key bytes; received {apKeys.Length}.", nameof(apKeys));
        }

        //The driver owns mutable copies of the two columns so it can patch the public mac/av region after the
        //commit; the supplied spans stay untouched.
        using IMemoryOwner<byte> hashColumnOwner = pool.Rent(hashWitnessColumn.Length);
        using IMemoryOwner<byte> sigColumnOwner = pool.Rent(sigWitnessColumn.Length);
        Span<byte> hashColumn = hashColumnOwner.Memory.Span[..hashWitnessColumn.Length];
        Span<byte> sigColumn = sigColumnOwner.Memory.Span[..sigWitnessColumn.Length];
        hashWitnessColumn.CopyTo(hashColumn);
        sigWitnessColumn.CopyTo(sigColumn);

        using IMemoryOwner<byte> macsOwner = pool.Rent(MacCount * ScalarSize);
        Span<byte> macs = macsOwner.Memory.Span[..(MacCount * ScalarSize)];
        Span<byte> avLittleEndian = stackalloc byte[MacKeyBytes];
        Span<byte> av = stackalloc byte[ScalarSize];
        byte[] macsBytes = new byte[LongfellowMdocEnvelope.MacRegionBytes];
        try
        {
            //commit(hash) then commit(sig): each over its private witness + the proof pad (the public mac/av
            //region is the filler's zeros, NOT committed). The driver absorbs both roots.
            using LongfellowZkCommitment hashCommit = LongfellowZkProver.Commit(
                hash.Circuit, hash.Parameters, hashColumn, hash.SubfieldBoundary, hashRandom, hash.EncoderFactory, hash.Profile, hash.Codec,
                hash.Add, hash.Subtract, hash.Multiply, merkleHash, leafHash, hashAlgorithm, hash.Curve, pool);

            using LongfellowZkCommitment sigCommit = LongfellowZkProver.Commit(
                sig.Circuit, sig.Parameters, sigColumn, sig.SubfieldBoundary, sigRandom, sig.EncoderFactory, sig.Profile, sig.Codec,
                sig.Add, sig.Subtract, sig.Multiply, merkleHash, leafHash, hashAlgorithm, sig.Curve, pool);

            //recv_commitment(hash) then recv_commitment(sig): both roots absorbed BEFORE a_v (the verifier's
            //lines 134-135 order, mdoc_zk.cc:667-668).
            LongfellowZkVerifier.RecvCommitment(hashCommit.RootSpan, transcript);
            LongfellowZkVerifier.RecvCommitment(sigCommit.RootSpan, transcript);

            //a_v = generate_mac_key(tp): ONE 16-byte of_bytes_field draw (the verifier's lines 141-148
            //recipe). The 16 raw little-endian bytes reverse into the canonical low bytes.
            transcript.SqueezeFieldElementBytes(avLittleEndian, MacKeyBytes);
            av.Clear();
            for(int b = 0; b < MacKeyBytes; b++)
            {
                av[ScalarSize - 1 - b] = avLittleEndian[b];
            }

            avLittleEndian.Clear();

            //compute_macs(3, common, macs, macs_b, ap, av): the six GF(2^128) macs and the 96 envelope bytes.
            ComputeMacs(commonValues, apKeys, av, hash.Add, hash.Multiply, macs, macsBytes);

            //update_macs: patch the six macs THEN a_v into both columns' public regions (mdoc_zk.cc:286-303).
            PatchHashPublicRegion(hashColumn, macs, av, hashMacIndex);
            PatchSigPublicRegion(sig.Profile, sigColumn, macs, av, sigMacIndex);

            //prove(hash) then prove(sig): finish both proofs on the continuing transcript over the PATCHED
            //columns (the FS-init + EvaluateCircuit read the patched public region).
            byte[] hashProof = LongfellowZkProver.ProveFromCommitment(
                hash.Circuit, hash.Parameters, hashCommit, hashColumn, transcript, hash.EncoderFactory, hash.Profile, hash.Codec,
                hash.Add, hash.Subtract, hash.Multiply, hash.Invert, merkleHash, leafHash, hashAlgorithm, hash.Curve, pool, hash.BroadcastMultiplyAccumulate, hash.BindQuadReduce, hash.GatherMultiplyAccumulate, hash.Fp256BatchMultiply);

            byte[] sigProof = LongfellowZkProver.ProveFromCommitment(
                sig.Circuit, sig.Parameters, sigCommit, sigColumn, transcript, sig.EncoderFactory, sig.Profile, sig.Codec,
                sig.Add, sig.Subtract, sig.Multiply, sig.Invert, merkleHash, leafHash, hashAlgorithm, sig.Curve, pool, sig.BroadcastMultiplyAccumulate, sig.BindQuadReduce, sig.GatherMultiplyAccumulate, sig.Fp256BatchMultiply);

            //serialize: [macs_b (96)] ‖ [hash ZkProof] ‖ [sig ZkProof].
            byte[] envelope = new byte[macsBytes.Length + hashProof.Length + sigProof.Length];
            macsBytes.CopyTo(envelope.AsSpan(0, macsBytes.Length));
            hashProof.CopyTo(envelope.AsSpan(macsBytes.Length, hashProof.Length));
            sigProof.CopyTo(envelope.AsSpan(macsBytes.Length + hashProof.Length, sigProof.Length));

            return envelope;
        }
        finally
        {
            hashColumn.Clear();
            sigColumn.Clear();
            macs.Clear();
            av.Clear();
            avLittleEndian.Clear();
        }
    }


    /// <summary>
    /// The cross-field MAC computation, a port of <c>compute_macs</c> (<c>mdoc_zk.cc:124-140</c>) over
    /// <c>MACReference::compute</c> (<c>mac_reference.h:43-51</c>): for each of the three common Fp256 values
    /// <c>x[i]</c> the two 16-byte halves of its <c>to_bytes_field</c> (32 little-endian) bytes are read as
    /// GF(2^128) elements <c>m</c> and MAC'd as <c>mac = (a_v + ap)·m</c>. Six macs in total (two per value).
    /// </summary>
    /// <param name="commonValues">The three common values as canonical 32-byte big-endian scalars.</param>
    /// <param name="apKeys">The six per-element MAC keys as canonical 32-byte GF(2^128) scalars.</param>
    /// <param name="av">The shared MAC key as a canonical 32-byte GF(2^128) scalar.</param>
    /// <param name="gfAdd">GF(2^128) addition.</param>
    /// <param name="gfMultiply">GF(2^128) multiplication.</param>
    /// <param name="macs">Receives the six macs as canonical 32-byte scalars (<c>6 · 32</c> bytes).</param>
    /// <param name="macsBytes">Receives the 96 envelope bytes (<c>to_bytes_field</c> of each mac: the low 16 bytes reversed to little-endian).</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length is wrong.</exception>
    public static void ComputeMacs(
        ReadOnlySpan<byte> commonValues,
        ReadOnlySpan<byte> apKeys,
        ReadOnlySpan<byte> av,
        ScalarAddDelegate gfAdd,
        ScalarMultiplyDelegate gfMultiply,
        Span<byte> macs,
        Span<byte> macsBytes)
    {
        ArgumentNullException.ThrowIfNull(gfAdd);
        ArgumentNullException.ThrowIfNull(gfMultiply);

        if(commonValues.Length != CommonValueCount * ScalarSize)
        {
            throw new ArgumentException($"Expected {CommonValueCount * ScalarSize} common-value bytes; received {commonValues.Length}.", nameof(commonValues));
        }

        if(apKeys.Length != MacCount * ScalarSize)
        {
            throw new ArgumentException($"Expected {MacCount * ScalarSize} ap-key bytes; received {apKeys.Length}.", nameof(apKeys));
        }

        if(av.Length != ScalarSize)
        {
            throw new ArgumentException($"Expected {ScalarSize} av bytes; received {av.Length}.", nameof(av));
        }

        if(macs.Length != MacCount * ScalarSize)
        {
            throw new ArgumentException($"Expected {MacCount * ScalarSize} mac bytes; received {macs.Length}.", nameof(macs));
        }

        if(macsBytes.Length != LongfellowMdocEnvelope.MacRegionBytes)
        {
            throw new ArgumentException($"Expected {LongfellowMdocEnvelope.MacRegionBytes} mac envelope bytes; received {macsBytes.Length}.", nameof(macsBytes));
        }

        Span<byte> littleEndian = stackalloc byte[ScalarSize];
        Span<byte> m = stackalloc byte[ScalarSize];
        Span<byte> keyed = stackalloc byte[ScalarSize];
        for(int i = 0; i < CommonValueCount; i++)
        {
            //buf = to_bytes_field(x[i]): the canonical big-endian value reversed to 32 little-endian bytes.
            ReadOnlySpan<byte> value = commonValues.Slice(i * ScalarSize, ScalarSize);
            for(int b = 0; b < ScalarSize; b++)
            {
                littleEndian[b] = value[ScalarSize - 1 - b];
            }

            for(int half = 0; half < 2; half++)
            {
                int macIndex = (2 * i) + half;
                Span<byte> mac = macs.Slice(macIndex * ScalarSize, ScalarSize);

                //m = of_bytes_field(buf[half*16 .. +16]): the 16 little-endian bytes as a GF element (byte j ->
                //canonical[31 - j]).
                m.Clear();
                for(int j = 0; j < MacKeyBytes; j++)
                {
                    m[ScalarSize - 1 - j] = littleEndian[(half * MacKeyBytes) + j];
                }

                //mac = (a_v + ap)·m over GF(2^128).
                gfAdd(av, apKeys.Slice(macIndex * ScalarSize, ScalarSize), keyed, CurveParameterSet.None);
                gfMultiply(keyed, m, mac, CurveParameterSet.None);

                //macs_b[macIndex*16 .. +16] = to_bytes_field(mac): the low 16 bytes reversed to little-endian.
                Span<byte> envelopeHalf = macsBytes.Slice(macIndex * MacKeyBytes, MacKeyBytes);
                for(int b = 0; b < MacKeyBytes; b++)
                {
                    envelopeHalf[b] = mac[ScalarSize - 1 - b];
                }
            }
        }

        littleEndian.Clear();
        m.Clear();
        keyed.Clear();
    }


    //update_macs (GF side, mdoc_zk.cc:286-294): W_hash[hi++] = mac for each of the six macs, then a_v, each
    //as ONE canonical GF(2^128) element (fill_gf2k<f_128, f_128> = push_back). Seven elements at hashMacIndex.
    private static void PatchHashPublicRegion(Span<byte> hashColumn, ReadOnlySpan<byte> macs, ReadOnlySpan<byte> av, int hashMacIndex)
    {
        for(int i = 0; i < MacCount; i++)
        {
            macs.Slice(i * ScalarSize, ScalarSize).CopyTo(hashColumn.Slice((hashMacIndex + i) * ScalarSize, ScalarSize));
        }

        av.CopyTo(hashColumn.Slice((hashMacIndex + MacCount) * ScalarSize, ScalarSize));
    }


    //update_macs (Fp256 side, mdoc_zk.cc:296-303): for each of the six macs then a_v, W_sig[si++] = bit j ?
    //one : zero for j in 0..127, the GF element's polynomial bits least-significant first
    //(fill_gf2k<f_128, Fp256Base>). 7·128 = 896 wires at sigMacIndex.
    private static void PatchSigPublicRegion(LongfellowFieldProfile profile, Span<byte> sigColumn, ReadOnlySpan<byte> macs, ReadOnlySpan<byte> av, int sigMacIndex)
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        Span<byte> zero = stackalloc byte[ScalarSize];
        profile.OfScalar(1, one);
        profile.OfScalar(0, zero);

        int si = sigMacIndex;
        for(int i = 0; i < MacCount; i++)
        {
            si = ExpandGfBits(macs.Slice(i * ScalarSize, ScalarSize), one, zero, sigColumn, si);
        }

        ExpandGfBits(av, one, zero, sigColumn, si);

        one.Clear();
        zero.Clear();
    }


    //Writes the 128 base-field wires of one GF(2^128) element, least-significant bit first: bit j picks one
    //or zero. The canonical scalar is big-endian with the 16-byte element in its low bytes, so bit j sits in
    //canonical[ScalarSize - 1 - (j / 8)] at position j mod 8 (mac[j], mac_reference.h:66). Returns the next
    //wire index.
    private static int ExpandGfBits(ReadOnlySpan<byte> element, ReadOnlySpan<byte> one, ReadOnlySpan<byte> zero, Span<byte> sigColumn, int wireIndex)
    {
        for(int j = 0; j < MacKeyBits; j++)
        {
            int bit = (element[ScalarSize - 1 - (j / 8)] >> (j % 8)) & 1;
            (bit == 1 ? one : zero).CopyTo(sigColumn.Slice(wireIndex * ScalarSize, ScalarSize));
            wireIndex++;
        }

        return wireIndex;
    }
}
