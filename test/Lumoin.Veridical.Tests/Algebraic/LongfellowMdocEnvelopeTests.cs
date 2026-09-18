using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The dual-field mdoc proof ENVELOPE reader, gated as a faithful port of
/// the byte layout google/longfellow-zk's <c>run_mdoc_prover</c> serializes and <c>run_mdoc_verifier</c>
/// reads (<c>lib/circuits/mdoc/mdoc_zk.cc</c>): <c>[6 mac values] ‖ [hash ZkProof] ‖ [sig ZkProof]</c>.
/// </summary>
/// <remarks>
/// <para>
/// The reference assembles the envelope by inserting the six 16-byte MAC values, then appending the
/// GF(2^128) hash <c>ZkProof</c>, then the P-256 signature <c>ZkProof</c>; the verifier reads them back in
/// the same order from a <c>ReadBuffer</c>, requiring zero bytes remaining. This gate constructs a real
/// GF(2^128) hash <c>ZkProof</c> through the end-to-end prover over the small sumcheck-segment circuit (the anchor's
/// <c>w == (x + y)·(x + z)·x</c> relation), prefixes six known MAC values, appends an arbitrary
/// signature-proof tail, and checks <see cref="LongfellowMdocEnvelope.TrySplit"/> resolves the three regions
/// exactly and <see cref="LongfellowMdocEnvelope.ReadMacs"/> recovers the MAC values byte for byte.
/// </para>
/// <para>
/// The hash-proof split is the load-bearing part: the hash <c>ZkProof</c> length is its 32-byte commitment
/// root plus the shape-derived sumcheck segment plus the data-dependent Ligero <c>com_proof</c> bytes, so the
/// reader length-probes the real GF serializers rather than assuming a fixed size. Isolating the signature
/// proof's internal structure additionally needs the width-32 sumcheck/Ligero serializers; here the
/// signature tail is opaque bytes and the gate confirms it lands at the correct offset with the correct
/// length.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowMdocEnvelopeTests: IDisposable
{
    /// <summary>The independent compiler and circuit lifetime for this test.</summary>
    private LongfellowCircuitTestScope CircuitScope { get; } = new();

    /// <summary>Calls <see cref="Dispose"/> after each test, including when an assertion fails.</summary>
    [TestCleanup]
    public void DisposeCircuits()
    {
        Dispose();
    }


    /// <summary>Releases this test's compiler and circuit storage. Repeated calls have no effect.</summary>
    public void Dispose()
    {
        CircuitScope.Dispose();
    }


    /// <summary>The relative path to the small functional circuit's reference-computed anchor values.</summary>
    private const string ZkAnchorRelativePath = "TestMaterial/Longfellow/zk-anchor-output.txt";

    /// <summary>The on-wire element width this test's witness and public-input byte columns use (GF(2^128), 16 bytes).</summary>
    private const int ElementBytes = 16;

    /// <summary>The width in bytes of one field element in its canonical scalar representation.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The byte width of one SHA-256 digest, the size of the placeholder hash-proof region <see cref="ReadMacsRecoversTheSixMacValues"/> appends after the MAC region.</summary>
    private const int DigestSize = 32;

    /// <summary>The transcript wire-format version the hash-proof gate's transcript is seeded with.</summary>
    private const int TranscriptVersion = 6;

    /// <summary>The field's canonical element width passed to the prove and parameter-derivation calls.</summary>
    private const int FieldBytes = 16;

    /// <summary>The subfield element width of the production-16 subfield code the hash-proof gate's parameters are derived over.</summary>
    private const int Production16SubFieldBytes = 2;

    /// <summary>The Ligero code's inverse rate used to derive the hash-proof gate's parameters.</summary>
    private const int InverseRate = 4;

    /// <summary>The number of Ligero columns the hash-proof gate's parameters open.</summary>
    private const int OpenedColumnCount = 2;

    /// <summary>The subfield boundary the anchor circuit's witness is proved with: zero, since it carries no subfield-encoded elements.</summary>
    private const int SubfieldBoundary = 0;

    /// <summary>The fixed transcript seed ("zk8") the hash-proof gate uses, so the transcript's driven values are deterministic across runs.</summary>
    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("zk8");

    /// <summary>The GF(2^128) field addition delegate the hash proof and its FFT are driven through.</summary>
    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) field subtraction delegate the hash proof and its FFT are driven through.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) field multiplication delegate the hash proof and its FFT are driven through.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) field inversion delegate the hash proof and its FFT are driven through.</summary>
    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>The reference-computed values loaded from <see cref="ZkAnchorRelativePath"/>, keyed by field name.</summary>
    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(ZkAnchorRelativePath);


    /// <summary>Verifies that <c>TrySplit</c> resolves a well-formed envelope's MAC region, hash-proof region and signature-proof tail at the correct offsets and lengths, and that the resolved slices equal the original bytes.</summary>
    [TestMethod]
    public void TheEnvelopeSplitsIntoMacsHashProofAndSigProof()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        using LongfellowZkProofEnvelope hashProof = ProduceHashProof(circuit);

        byte[] macRegion = BuildMacRegion();
        byte[] sigTail = BuildSigTail(257);
        byte[] envelope = Concatenate(macRegion, hashProof.Bytes, sigTail);

        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, FieldBytes, Production16SubFieldBytes);
        using Lch14AdditiveFft fft = NewFft();

        bool split = LongfellowMdocEnvelope.TrySplit(envelope, circuit, parameters, Production16SubFieldBytes, fft, BaseMemoryPool.Shared, out LongfellowMdocEnvelopeLayout layout);

        Assert.IsTrue(split, "A well-formed envelope must split.");
        Assert.AreEqual(0, layout.MacRegionOffset, "The MAC region starts the envelope.");
        Assert.AreEqual(LongfellowMdocEnvelope.MacRegionBytes, layout.MacRegionBytes, "The MAC region is 96 bytes.");
        Assert.AreEqual(LongfellowMdocEnvelope.MacRegionBytes, layout.HashProofOffset, "The hash proof follows the MACs.");
        Assert.AreEqual(hashProof.Length, layout.HashProofBytes, "The hash proof length must match the produced proof.");
        Assert.AreEqual(LongfellowMdocEnvelope.MacRegionBytes + hashProof.Length, layout.SigProofOffset, "The sig proof follows the hash proof.");
        Assert.AreEqual(sigTail.Length, layout.SigProofBytes, "The sig proof length must be the remaining bytes.");

        //The resolved hash-proof slice must equal the produced proof byte for byte.
        Assert.IsTrue(envelope.AsSpan(layout.HashProofOffset, layout.HashProofBytes).SequenceEqual(hashProof.Bytes), "The split hash proof must equal the produced proof.");
        Assert.IsTrue(envelope.AsSpan(layout.SigProofOffset, layout.SigProofBytes).SequenceEqual(sigTail), "The split sig proof must equal the appended tail.");
    }


    /// <summary>Verifies that <c>ReadMacs</c> recovers each of the six 16-byte little-endian MAC values reversed into the low 16 bytes of a canonical 32-byte big-endian scalar, with the leading 16 bytes zero.</summary>
    [TestMethod]
    public void ReadMacsRecoversTheSixMacValues()
    {
        byte[] macRegion = BuildMacRegion();
        byte[] envelope = Concatenate(macRegion, new byte[DigestSize], []);

        byte[] macs = new byte[LongfellowMdocEnvelope.MacCount * ScalarSize];
        LongfellowMdocEnvelope.ReadMacs(envelope, macs);

        //Each MAC is the 16-byte little-endian wire element reversed into the low 16 bytes of a canonical
        //32-byte big-endian scalar; the leading 16 bytes stay zero.
        Span<byte> expected = stackalloc byte[ScalarSize];
        for(int i = 0; i < LongfellowMdocEnvelope.MacCount; i++)
        {
            ReadOnlySpan<byte> littleEndian = macRegion.AsSpan(i * ElementBytes, ElementBytes);
            expected.Clear();
            for(int b = 0; b < ElementBytes; b++)
            {
                expected[ScalarSize - 1 - b] = littleEndian[b];
            }

            Assert.IsTrue(macs.AsSpan(i * ScalarSize, ScalarSize).SequenceEqual(expected), $"MAC {i} must round-trip.");
        }
    }


    /// <summary>Verifies that an envelope one byte shorter than the fixed MAC region fails to split.</summary>
    [TestMethod]
    public void ATruncatedMacRegionDoesNotSplit()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, FieldBytes, Production16SubFieldBytes);
        using Lch14AdditiveFft fft = NewFft();

        byte[] tooShort = new byte[LongfellowMdocEnvelope.MacRegionBytes - 1];

        bool split = LongfellowMdocEnvelope.TrySplit(tooShort, circuit, parameters, Production16SubFieldBytes, fft, BaseMemoryPool.Shared, out _);

        Assert.IsFalse(split, "An envelope shorter than the MAC region must not split.");
    }


    /// <summary>Verifies that dropping the last byte of the hash proof, underflowing its Ligero <c>com_proof</c> read, fails to split.</summary>
    [TestMethod]
    public void ATruncatedHashProofDoesNotSplit()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        using LongfellowZkProofEnvelope hashProof = ProduceHashProof(circuit);

        //Drop the last byte of the hash proof so the Ligero com_proof read underflows.
        byte[] envelope = Concatenate(BuildMacRegion(), hashProof.Bytes[..^1], []);

        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, FieldBytes, Production16SubFieldBytes);
        using Lch14AdditiveFft fft = NewFft();

        bool split = LongfellowMdocEnvelope.TrySplit(envelope, circuit, parameters, Production16SubFieldBytes, fft, BaseMemoryPool.Shared, out _);

        Assert.IsFalse(split, "A truncated hash proof must not split.");
    }


    /// <summary>Produces the real GF(2^128) hash <c>ZkProof</c> through the end-to-end prover over the anchor's small circuit; the caller disposes the returned pooled proof envelope.</summary>
    private static LongfellowZkProofEnvelope ProduceHashProof(LongfellowSumcheckCircuit circuit)
    {
        byte[] witnessColumn = BuildWitnessColumn(circuit);
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, FieldBytes, Production16SubFieldBytes);

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowTranscript transcript = NewTranscript(TranscriptSeed);
        LongfellowRandomByteSource random = NewCounterSource();

        return LongfellowZkProver.Prove(
            circuit, parameters, witnessColumn, Production16SubFieldBytes, SubfieldBoundary, random, transcript, fft,
            Add, Subtract, Multiply, Invert, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    /// <summary>Builds six distinct 16-byte MAC values: MAC <c>i</c> has every byte set to <c>0x10 + i</c>.</summary>
    private static byte[] BuildMacRegion()
    {
        byte[] region = new byte[LongfellowMdocEnvelope.MacRegionBytes];
        for(int i = 0; i < LongfellowMdocEnvelope.MacCount; i++)
        {
            region.AsSpan(i * ElementBytes, ElementBytes).Fill((byte)(0x10 + i));
        }

        return region;
    }


    /// <summary>Builds an opaque, deterministic <paramref name="length"/>-byte stand-in for a signature-proof tail.</summary>
    private static byte[] BuildSigTail(int length)
    {
        byte[] tail = new byte[length];
        for(int i = 0; i < length; i++)
        {
            tail[i] = (byte)(0xA0 + (i & 0x0F));
        }

        return tail;
    }


    /// <summary>Concatenates three byte spans, in order, into one freshly allocated array.</summary>
    private static byte[] Concatenate(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third)
    {
        byte[] result = new byte[first.Length + second.Length + third.Length];
        first.CopyTo(result.AsSpan(0));
        second.CopyTo(result.AsSpan(first.Length));
        third.CopyTo(result.AsSpan(first.Length + second.Length));

        return result;
    }


    /// <summary>Reconstructs the anchor's small GF(2^128) circuit from its recorded shape, quad terms and id; the caller disposes it through <see cref="CircuitScope"/> at test cleanup.</summary>
    private LongfellowSumcheckCircuit BuildCircuit()
    {
        int nl = Anchor("nl");
        var layers = new LongfellowSumcheckLayer[nl];
        for(int i = 0; i < nl; i++)
        {
            int nw = Anchor($"layer{i}_nw");
            int logw = Anchor($"layer{i}_logw");
            int nterms = Anchor($"layer{i}_nterms");

            var quadTerms = new LongfellowSumcheckQuadTerm[nterms];
            for(int t = 0; t < nterms; t++)
            {
                int gate = Anchor($"L{i}_t{t}_g");
                int left = Anchor($"L{i}_t{t}_h0");
                int right = Anchor($"L{i}_t{t}_h1");
                byte[] v = ParseElement(Anchors[$"L{i}_t{t}_v"]);
                quadTerms[t] = new LongfellowSumcheckQuadTerm(gate, left, right, v);
            }

            layers[i] = new LongfellowSumcheckLayer(nw, logw, nterms, quadTerms);
        }

        byte[] id = Convert.FromHexString(Anchors["id"]);

        return CircuitScope.CreateCircuit(
            Anchor("nv"),
            Anchor("logv"),
            Anchor("nc"),
            Anchor("logc"),
            Anchor("ninputs"),
            Anchor("npub_in"),
            id,
            layers);
    }


    /// <summary>Builds the full witness column (all inputs) as canonical scalars, from the anchor's <c>input0</c>..<c>input(n-1)</c>.</summary>
    private static byte[] BuildWitnessColumn(LongfellowSumcheckCircuit circuit)
    {
        byte[] column = new byte[circuit.InputCount * ScalarSize];
        for(int i = 0; i < circuit.InputCount; i++)
        {
            byte[] element = ParseElement(Anchors[$"input{i}"]);
            element.CopyTo(column.AsSpan(i * ScalarSize, ScalarSize));
        }

        return column;
    }


    /// <summary>Parses a 16-byte little-endian element into a 32-byte big-endian canonical scalar.</summary>
    private static byte[] ParseElement(string hex)
    {
        byte[] littleEndian = Convert.FromHexString(hex);
        byte[] canonical = new byte[ScalarSize];
        for(int i = 0; i < ElementBytes; i++)
        {
            canonical[ScalarSize - 1 - i] = littleEndian[i];
        }

        return canonical;
    }


    /// <summary>Parses the reference-computed anchor value keyed by <paramref name="key"/> as an integer.</summary>
    private static int Anchor(string key) => int.Parse(Anchors[key], CultureInfo.InvariantCulture);


    /// <summary>Creates a deterministic <see cref="LongfellowRandomByteSource"/> that fills its output with an incrementing byte counter.</summary>
    private static LongfellowRandomByteSource NewCounterSource()
    {
        ulong counter = 0;

        return destination =>
        {
            for(int i = 0; i < destination.Length; i++)
            {
                destination[i] = (byte)(counter & 0xFF);
                counter++;
            }
        };
    }


    /// <summary>Creates a transcript seeded with <paramref name="seed"/>, wired to this file's AES-256-ECB and SHA-256 delegates.</summary>
    private static LongfellowTranscript NewTranscript(byte[] seed) =>
        new(seed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Creates the production-16 subfield additive FFT used to drive the hash-proof gate.</summary>
    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>Computes the one-shot SHA-256 digest of <paramref name="input"/> into <paramref name="output"/>; <paramref name="hashFunction"/> is unused since this file only ever selects SHA-256.</summary>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) => SHA256.HashData(input, output);


    /// <summary>Computes the two-to-one SHA-256 compression of <paramref name="left"/> concatenated with <paramref name="right"/> into <paramref name="output"/>.</summary>
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[left.Length + right.Length];
        left.CopyTo(combined);
        right.CopyTo(combined[left.Length..]);
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>Encrypts one AES-256 block in ECB mode (no padding) with <paramref name="key"/>, the transcript's block cipher.</summary>
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    /// <summary>Loads a fixture's <c>key=value</c> tokens from every non-empty line into a case-sensitive lookup, skipping any token without an <c>=</c>.</summary>
    private static Dictionary<string, string> LoadAnchors(string relativePath)
    {
        string path = $"../../../{relativePath}";
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach(string line in File.ReadAllLines(path))
        {
            if(line.Length == 0)
            {
                continue;
            }

            foreach(string token in line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                int separator = token.IndexOf('=', StringComparison.Ordinal);
                if(separator < 0)
                {
                    continue;
                }

                map[token[..separator]] = token[(separator + 1)..];
            }
        }

        return map;
    }
}
