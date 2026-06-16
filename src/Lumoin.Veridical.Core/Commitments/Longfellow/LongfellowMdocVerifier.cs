using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The dual-field mdoc proof driver, a faithful port of google/longfellow-zk's <c>run_mdoc_verifier</c>
/// (<c>lib/circuits/mdoc/mdoc_zk.cc:560-695</c>): it verifies a real mdoc <c>ZkProof</c> envelope
/// <c>[6 macs] ‖ [hash ZkProof] ‖ [sig ZkProof]</c> by driving ONE transcript across both circuits — the
/// GF(2^128) hash circuit and the P-256 base-field signature circuit — in the reference's exact order, so
/// the shared MAC key <c>a_v</c> binds the two proofs together.
/// </summary>
/// <remarks>
/// <para>
/// The transcript order is the byte target (<c>mdoc_zk.cc:665-694</c>): construct the transcript from the
/// session seed, <c>recv_commitment</c> the hash root then the sig root (both absorbed BEFORE any
/// challenge), squeeze <c>a_v = generate_mac_key</c> — ONE 16-byte <c>of_bytes_field</c> draw (NOT the
/// <c>sample</c> reject loop; <c>mdoc_zk.cc:277-282</c>) — splice the six macs and <c>a_v</c> into the two
/// public-input vectors, guard their sizes against the circuits' <c>npub_in</c>
/// (<c>mdoc_zk.cc:686-689</c>), then verify the hash proof and the sig proof. Accept iff both verify
/// (<c>ok &amp;&amp; ok2</c>).
/// </para>
/// <para>
/// The splice, byte for byte (<c>update_mac_in_dense</c> / <c>fill_gf2k</c>, <c>mdoc_zk.cc:286-302</c> +
/// <c>mac_reference.h:62-68</c>): on the GF(2^128) hash side each mac and <c>a_v</c> is appended as ONE
/// 16-byte element (the <c>fill_gf2k&lt;f_128, f_128&gt;</c> specialization = <c>push_back(m)</c>, NOT
/// bit-expanded); on the Fp256 sig side each is appended as 128 one/zero base-field wires, the GF
/// element's bits least-significant first (the generic <c>fill_gf2k&lt;f_128, Fp256Base&gt;</c>). Per D5 the
/// caller supplies the public-input TEMPLATES — the hash template <c>[one, attrs…, now-bits]</c> and the sig
/// template <c>[one, pkX, pkY, e2]</c> (the CBOR/attribute/<c>now</c> walk and the <c>e2 =
/// to_montgomery(compute_transcript_hash)</c> computation stay caller-side per the serialization-ban
/// architecture) — and the driver appends the seven mac/av slots and runs the size guard.
/// </para>
/// <para>
/// Parse-safe: malformed envelope bytes yield <see cref="LongfellowMdocVerificationResult.MalformedEnvelope"/>
/// and <see langword="false"/>, never an exception. Per D6 the circuits and parameters are pre-derived; the
/// field bindings (row-encoder factory, profile, subfield-run codec, arithmetic delegates) ride in the two
/// <see cref="LongfellowMdocFieldVerifier"/> bundles. The transcript, the SHA-256 / Merkle hash delegates
/// and the pool are shared.
/// </para>
/// </remarks>
internal static class LongfellowMdocVerifier
{
    //Digest::kLength: the ZkProof commitment root (write_com).
    private const int DigestLength = 32;

    //f_128::kBytes: a_v is one 16-byte GF(2^128) element (generate_mac_key, mdoc_zk.cc:280).
    private const int MacKeyBytes = 16;

    //The six per-credential macs (read from the envelope prefix), in both public vectors.
    private const int MacCount = LongfellowMdocEnvelope.MacCount;

    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Verifies a dual-field mdoc proof envelope, the reference's <c>run_mdoc_verifier</c>.
    /// </summary>
    /// <param name="envelope">The full proof envelope <c>[6 macs] ‖ [hash ZkProof] ‖ [sig ZkProof]</c>.</param>
    /// <param name="hash">The GF(2^128) hash-circuit verification bundle.</param>
    /// <param name="sig">The P-256 base-field signature-circuit verification bundle.</param>
    /// <param name="hashPublicInputsTemplate">The hash public-input template <c>[one, attrs…, now-bits]</c>, <c>(npub_in − 7)</c> · 16 little-endian element bytes (the 6 macs + a_v slots are appended by the driver).</param>
    /// <param name="sigPublicInputsTemplate">The sig public-input template <c>[one, pkX, pkY, e2]</c>, <c>(npub_in − 7·128)</c> · 32 little-endian element bytes (the 6·128 mac bits + 128 a_v bits are appended by the driver).</param>
    /// <param name="transcript">A fresh transcript seeded from the session transcript the way the prover seeded it.</param>
    /// <param name="merkleHash">The two-to-one <c>SHA256(L ‖ R)</c> Merkle compression.</param>
    /// <param name="leafHash">The one-shot SHA-256 over a contiguous span.</param>
    /// <param name="hashAlgorithm">The canonical hash-function name (SHA-256).</param>
    /// <param name="pool">The pool the working buffers rent from.</param>
    /// <param name="result">The verdict cause; <see cref="LongfellowMdocVerificationResult.Accepted"/> on success.</param>
    /// <returns><see langword="true"/> when both proofs verify, <see langword="false"/> otherwise.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    public static bool Verify(
        ReadOnlySpan<byte> envelope,
        LongfellowMdocFieldVerifier hash,
        LongfellowMdocFieldVerifier sig,
        ReadOnlySpan<byte> hashPublicInputsTemplate,
        ReadOnlySpan<byte> sigPublicInputsTemplate,
        LongfellowTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        string hashAlgorithm,
        BaseMemoryPool pool,
        out LongfellowMdocVerificationResult result)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(sig);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(leafHash);
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(pool);

        result = LongfellowMdocVerificationResult.MalformedEnvelope;

        //Read the six 16-byte macs as canonical scalars (Fs.of_bytes_field, mdoc_zk.cc:632-634). A short
        //envelope underflows here.
        if(envelope.Length < LongfellowMdocEnvelope.MacRegionBytes)
        {
            return false;
        }

        using IMemoryOwner<byte> macsOwner = pool.Rent(MacCount * ScalarSize);
        Span<byte> macs = macsOwner.Memory.Span[..(MacCount * ScalarSize)];
        LongfellowMdocEnvelope.ReadMacs(envelope, macs);

        //Parse the hash ZkProof (com || sc || com_proof) from after the mac region.
        ReadOnlySpan<byte> afterMacs = envelope[LongfellowMdocEnvelope.MacRegionBytes..];
        using ParsedProof hashProof = ParseProof(hash, afterMacs, pool);
        if(!hashProof.Ok)
        {
            macs.Clear();

            return false;
        }

        //Parse the sig ZkProof from the bytes after the hash proof; require zero remaining (rb.remaining()
        //!= 0 is a parse failure, mdoc_zk.cc:645-648).
        ReadOnlySpan<byte> afterHash = afterMacs[hashProof.TotalBytes..];
        using ParsedProof sigProof = ParseProof(sig, afterHash, pool);
        if(!sigProof.Ok || sigProof.TotalBytes != afterHash.Length)
        {
            macs.Clear();

            return false;
        }

        try
        {
            //recv_commitment(hash) then recv_commitment(sig): both roots absorbed BEFORE a_v (mdoc_zk.cc:667-668).
            LongfellowZkVerifier.RecvCommitment(hashProof.Root, transcript);
            LongfellowZkVerifier.RecvCommitment(sigProof.Root, transcript);

            //a_v = generate_mac_key(tv): ONE 16-byte of_bytes_field draw, NOT the sample reject loop
            //(mdoc_zk.cc:277-282). The MAC key is always the 16-byte GF(2^128) width, drawn explicitly so
            //the driver does not depend on the shared transcript's baked element width. The 16 raw bytes
            //reverse into the canonical low bytes.
            Span<byte> avLittleEndian = stackalloc byte[MacKeyBytes];
            transcript.SqueezeFieldElementBytes(avLittleEndian, MacKeyBytes);
            Span<byte> av = stackalloc byte[ScalarSize];
            av.Clear();
            for(int b = 0; b < MacKeyBytes; b++)
            {
                av[ScalarSize - 1 - b] = avLittleEndian[b];
            }

            avLittleEndian.Clear();

            //Build the spliced public-input vectors: template ‖ [macs ‖ av] in each field's framing. After
            //the splice the macs and a_v are copied into the (public) pub vectors and no longer needed here.
            using IMemoryOwner<byte>? hashPub = LongfellowMdocPublicInputs.SpliceHash(hash.Profile, hashPublicInputsTemplate, macs, av, hash.Circuit.PublicInputCount, pool);
            using IMemoryOwner<byte>? sigPub = LongfellowMdocPublicInputs.SpliceSig(sig.Profile, sigPublicInputsTemplate, macs, av, sig.Circuit.PublicInputCount, pool);
            av.Clear();

            if(hashPub is null || sigPub is null)
            {
                //The spliced vector did not reach npub_in (the filler.size() != npub_in guard).
                result = LongfellowMdocVerificationResult.AttributeNumberMismatch;

                return false;
            }

            int hashPubBytes = hash.Circuit.PublicInputCount * hash.Profile.ElementBytes;
            int sigPubBytes = sig.Circuit.PublicInputCount * sig.Profile.ElementBytes;

            //hash_v.verify then sig_v.verify, both from the absorbed roots on the shared transcript.
            bool ok = LongfellowZkVerifier.VerifyFromAbsorbedRoot(
                hash.Circuit, hash.Parameters, hashProof.Sumcheck!, hashProof.Ligero!, hashProof.Root,
                hashPub.Memory.Span[..hashPubBytes], transcript, hash.EncoderFactory, hash.Profile,
                hash.Add, hash.Subtract, hash.Multiply, hash.Invert, merkleHash, leafHash, hashAlgorithm, hash.Curve, pool, out _, hash.BindQuadReduce, hash.BroadcastMultiplyAccumulate, hash.Fp256BatchMultiply);

            if(!ok)
            {
                result = LongfellowMdocVerificationResult.HashRejected;

                return false;
            }

            bool ok2 = LongfellowZkVerifier.VerifyFromAbsorbedRoot(
                sig.Circuit, sig.Parameters, sigProof.Sumcheck!, sigProof.Ligero!, sigProof.Root,
                sigPub.Memory.Span[..sigPubBytes], transcript, sig.EncoderFactory, sig.Profile,
                sig.Add, sig.Subtract, sig.Multiply, sig.Invert, merkleHash, leafHash, hashAlgorithm, sig.Curve, pool, out _, fp256BatchMultiply: sig.Fp256BatchMultiply);

            if(!ok2)
            {
                result = LongfellowMdocVerificationResult.SigRejected;

                return false;
            }

            result = LongfellowMdocVerificationResult.Accepted;

            return true;
        }
        finally
        {
            macs.Clear();
        }
    }


    //Parses one field's ZkProof (com || sc || com_proof) from the front of `source`, field-generically
    //through the supplied codec. Parse-safe: any underflow or malformed segment leaves Ok == false.
    [SuppressMessage("Reliability", "CA2000", Justification = "The parsed sumcheck and Ligero proofs transfer ownership into the returned ParsedProof, which the caller disposes through its own using declaration; on the Ligero-read failure path the already-parsed sumcheck proof is disposed before returning.")]
    private static ParsedProof ParseProof(LongfellowMdocFieldVerifier field, ReadOnlySpan<byte> source, BaseMemoryPool pool)
    {
        if(source.Length < DigestLength)
        {
            return ParsedProof.Failed;
        }

        byte[] root = source[..DigestLength].ToArray();
        int scSize = LongfellowSumcheckProofSerializer.SerializedSize(field.Circuit, field.Profile);
        if(source.Length < DigestLength + scSize)
        {
            return ParsedProof.Failed;
        }

        ReadOnlySpan<byte> scBytes = source.Slice(DigestLength, scSize);
        LongfellowSumcheckProof? sumcheck = LongfellowSumcheckProofSerializer.Read(field.Circuit, field.Profile, pool, scBytes, out _);
        if(sumcheck is null)
        {
            return ParsedProof.Failed;
        }

        ReadOnlySpan<byte> comProofBytes = source[(DigestLength + scSize)..];
        LongfellowLigeroProof? ligero = LongfellowLigeroProofSerializer.Read(field.Parameters, field.Profile, field.Codec, pool, comProofBytes, out int comProofBytesRead);
        if(ligero is null)
        {
            sumcheck.Dispose();

            return ParsedProof.Failed;
        }

        return new ParsedProof(root, sumcheck, ligero, DigestLength + scSize + comProofBytesRead);
    }


    //One field's parsed ZkProof: the 32-byte root and the two parsed segments, plus the total bytes
    //consumed (so the next region starts where this one ends). Disposable: it owns the two proof objects.
    private readonly struct ParsedProof: IDisposable
    {
        public static ParsedProof Failed => default;

        public ParsedProof(byte[] root, LongfellowSumcheckProof sumcheck, LongfellowLigeroProof ligero, int totalBytes)
        {
            Root = root;
            Sumcheck = sumcheck;
            Ligero = ligero;
            TotalBytes = totalBytes;
            Ok = true;
        }

        public bool Ok { get; }

        public byte[]? Root { get; }

        public LongfellowSumcheckProof? Sumcheck { get; }

        public LongfellowLigeroProof? Ligero { get; }

        public int TotalBytes { get; }

        public void Dispose()
        {
            Sumcheck?.Dispose();
            Ligero?.Dispose();
        }
    }
}
