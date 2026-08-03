using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The single place the JWT-statement bundles are assembled, so the facade's prove and verify
/// paths cannot drift: the pinned Ligero run shape, the P-256 base-field arithmetic delegates,
/// the kernel compilation of the statement circuit, the witness-generator and FFT/profile/codec
/// builders, the public-input assembly, and the prove and verify drivers.
/// </summary>
/// <remarks>
/// <para>
/// The statement runs single-field over the P-256 base field in the CANONICAL domain — the same
/// path the kernel end-to-end gates pin; the mdoc facade's Montgomery working-domain lift is a
/// later performance refinement. The circuit is kernel-compiled per call (not parsed from
/// definition bytes); caching the compiled circuit across calls is likewise a later performance
/// refinement.
/// </para>
/// <para>
/// The structural circuit identity is computed over a fixed SHA-256 incremental hash — it is a
/// conformance surface, not a swappable primitive, so it deliberately does not ride the crypto
/// suite.
/// </para>
/// </remarks>
internal static class LongfellowJwtBundles
{
    //The reference ZK run shape for the JWT statement: zk_testing.h's kLigeroRate/kLigeroNreq,
    //the same 7/132 pair the mdoc v7 registry selects.
    internal const int InverseRate = 7;
    internal const int OpenedColumnCount = 132;

    //One canonical field element per 32-byte big-endian slot.
    internal const int Fp256ElementBytes = Scalar.SizeBytes;

    //The Ligero sub-field element width of the production-16 profile the Fp256 encoding uses.
    internal const int SubFieldBytes = 2;

    //The Fiat-Shamir transcript version tag of the kernel-compiled statement ceremony.
    internal const int TranscriptVersion = 6;

    //The reference's single-copy circuit shape.
    private const int CopyCount = 1;

    //The commitment root digest width heading every proof envelope.
    internal const int DigestSize = 32;

    //The canonical-domain P-256 base-field delegates (the pinned end-to-end path) and the
    //order-field delegates the witness generator's ECDSA advice computation dispatches on.
    private static ScalarAddDelegate Fp256Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();
    private static ScalarSubtractDelegate Fp256Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();
    private static ScalarMultiplyDelegate Fp256Multiply { get; } = P256BaseFieldMontgomeryBackend.GetMultiply();
    private static ScalarInvertDelegate Fp256Invert { get; } = P256BaseFieldMontgomeryBackend.GetInvert();
    private static ScalarMultiplyDelegate OrderMultiply { get; } = P256ScalarMontgomeryBackend.GetMultiply();
    private static ScalarSubtractDelegate OrderSubtract { get; } = P256ScalarMontgomeryBackend.GetSubtract();
    private static ScalarInvertDelegate OrderInvert { get; } = P256ScalarMontgomeryBackend.GetInvert();

    //The curve constants shared by the statement circuit and the witness generator.
    private static LongfellowEllipticCurveParameters Curve { get; } = LongfellowEllipticCurveParameters.CreateP256();

    //The canonical big-endian p − 1 the field bundle's negation constant closes over.
    private static byte[] CanonicalPrimeMinusOne { get; } = BuildCanonicalPrimeMinusOne();


    /// <summary>Builds the canonical-domain P-256 base-field bundle the compiler, witness generator and drivers share.</summary>
    /// <returns>The field bundle.</returns>
    internal static LongfellowLogicFieldOperations NewFieldBundle() =>
        LongfellowLogicFieldOperations.CreateFp256(Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, CanonicalPrimeMinusOne);


    /// <summary>Builds the witness generator over the same field bundle and curve the statement circuit uses.</summary>
    /// <param name="field">The field bundle.</param>
    /// <param name="blockCapacity">The preimage capacity in SHA-256 blocks.</param>
    /// <returns>The generator.</returns>
    internal static LongfellowJwtWitness NewWitnessGenerator(LongfellowLogicFieldOperations field, int blockCapacity) =>
        new(field, OrderMultiply, OrderSubtract, OrderInvert, CurveParameterSet.P256, Curve, blockCapacity);


    /// <summary>
    /// Kernel-compiles the statement circuit in the reference's <c>make_circuit</c> shape: the
    /// statement gadget constructed first, then the public inputs (issuer key, key-binding
    /// digest, the disclosed attributes), the private boundary, and the witness declaration.
    /// </summary>
    /// <param name="field">The field bundle to compile over.</param>
    /// <param name="blockCapacity">The block capacity.</param>
    /// <param name="attributeCount">The disclosed attribute count.</param>
    /// <returns>The compiled circuit.</returns>
    internal static LongfellowSumcheckCircuit CompileStatement(LongfellowLogicFieldOperations field, int blockCapacity, int attributeCount)
    {
        var builder = new LongfellowQuadCircuitBuilder(field.Compiler);
        var backend = new LongfellowCompileLogicBackend(field, builder);
        var logic = new LongfellowLogic(backend, field);
        var circuit = new LongfellowJwtCircuit(logic, Curve, blockCapacity);

        int pkX = logic.InputElement();
        int pkY = logic.InputElement();
        int e2 = logic.InputElement();
        var attributes = new LongfellowJwtOpenedAttributeWires[attributeCount];
        for(int i = 0; i < attributeCount; i++)
        {
            attributes[i] = LongfellowJwtOpenedAttributeWires.Input(logic);
        }

        builder.PrivateInput();
        LongfellowJwtWitnessWires witness = circuit.InputWitness(attributeCount);

        circuit.AssertJwtAttributes(pkX, pkY, e2, attributes, witness);

        return builder.MakeCircuit(CopyCount, Sha256FiatShamirBackend.GetIncrementalFactory());
    }


    /// <summary>Derives the Ligero parameters for a compiled statement at the pinned reference run shape.</summary>
    /// <param name="circuit">The compiled circuit.</param>
    /// <returns>The parameters.</returns>
    internal static LongfellowLigeroParameters DeriveParameters(LongfellowSumcheckCircuit circuit) =>
        LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, Fp256ElementBytes, SubFieldBytes);


    /// <summary>The public-input element count of the statement at a given attribute count: the constant one, the issuer key pair, the key-binding digest, and each attribute's padded pattern bits and length bits.</summary>
    /// <param name="attributeCount">The disclosed attribute count.</param>
    /// <returns>The element count.</returns>
    internal static int PublicInputElementCount(int attributeCount) =>
        4 + (attributeCount * (LongfellowJwtOpenedAttributeWires.PatternLength + 1) * LongfellowLogic.BitWidth8);


    /// <summary>
    /// Fills the public region of the witness column in declaration order — the constant one,
    /// the issuer key coordinates, the key-binding digest, and each disclosed attribute — one
    /// canonical scalar per wire. The prover's column head and the verifier's public-input
    /// assembly both come through here, so the two sides cannot drift.
    /// </summary>
    /// <param name="field">The field bundle supplying the constant one and the attribute bit elements.</param>
    /// <param name="statement">The statement supplying the issuer key and the attributes.</param>
    /// <param name="keyBindingDigest">The canonical key-binding digest scalar <c>e2</c>.</param>
    /// <param name="column">The column being filled.</param>
    /// <param name="cursor">The element cursor, advanced past the public region.</param>
    internal static void FillPublicRegionCanonical(LongfellowLogicFieldOperations field, LongfellowJwtStatement statement, ReadOnlySpan<byte> keyBindingDigest, Span<byte> column, ref int cursor)
    {
        field.Compiler.One.Span.CopyTo(column.Slice(cursor * Fp256ElementBytes, Fp256ElementBytes));
        cursor++;
        statement.IssuerKeyX.Span.CopyTo(column.Slice(cursor * Fp256ElementBytes, Fp256ElementBytes));
        cursor++;
        statement.IssuerKeyY.Span.CopyTo(column.Slice(cursor * Fp256ElementBytes, Fp256ElementBytes));
        cursor++;
        keyBindingDigest.CopyTo(column.Slice(cursor * Fp256ElementBytes, Fp256ElementBytes));
        cursor++;

        for(int i = 0; i < statement.Attributes.Count; i++)
        {
            LongfellowJwtWitness.FillAttribute(field, statement.Attributes[i].ToOpenedAttribute(), column, ref cursor);
        }
    }


    /// <summary>
    /// Assembles the verifier-side public-input bytes: the public region's canonical elements
    /// dropped to the little-endian wire form the verifier splices, byte-identical to extracting
    /// the region from the column the prover commits.
    /// </summary>
    /// <param name="field">The field bundle.</param>
    /// <param name="statement">The statement.</param>
    /// <param name="keyBindingDigest">The canonical key-binding digest scalar <c>e2</c> recomputed from the presentation.</param>
    /// <param name="destination">Receives <see cref="PublicInputElementCount"/> little-endian elements of <see cref="Fp256ElementBytes"/> bytes each.</param>
    /// <param name="pool">The pool the canonical scratch region rents from.</param>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is not exactly the region's byte length.</exception>
    internal static void AssembleVerifierPublicInputs(LongfellowLogicFieldOperations field, LongfellowJwtStatement statement, ReadOnlySpan<byte> keyBindingDigest, Span<byte> destination, BaseMemoryPool pool)
    {
        int elementCount = PublicInputElementCount(statement.Attributes.Count);
        int regionBytes = elementCount * Fp256ElementBytes;
        if(destination.Length != regionBytes)
        {
            throw new ArgumentException($"The public-input region is exactly {elementCount} elements of {Fp256ElementBytes} bytes.", nameof(destination));
        }

        using IMemoryOwner<byte> canonicalOwner = pool.Rent(regionBytes);
        Span<byte> canonical = canonicalOwner.Memory.Span[..regionBytes];
        int cursor = 0;
        FillPublicRegionCanonical(field, statement, keyBindingDigest, canonical, ref cursor);

        //Each canonical big-endian element drops to the little-endian to_bytes_field wire form by
        //byte reversal, the Fp256 profile's framing.
        for(int i = 0; i < elementCount; i++)
        {
            for(int b = 0; b < Fp256ElementBytes; b++)
            {
                destination[(i * Fp256ElementBytes) + b] = canonical[(i * Fp256ElementBytes) + Fp256ElementBytes - 1 - b];
            }
        }

        canonical.Clear();
    }


    /// <summary>Builds the real FFT over the P-256 base field from the production root of unity.</summary>
    /// <param name="pool">The pool the twiddle table and scratch rent from.</param>
    /// <returns>The FFT.</returns>
    internal static Fp256RealFft NewFft(BaseMemoryPool pool)
    {
        Span<byte> root = stackalloc byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnity(root);

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, LongfellowMdocBundles.OfScalarFp256, CurveParameterSet.None, pool);
    }


    /// <summary>Builds the canonical-domain Fp256 field profile; the caller disposes it. The shared <c>of_scalar</c> and range predicate live on the mdoc bundles.</summary>
    /// <param name="pool">The pool the profile's retained constant scalars rent from.</param>
    /// <returns>The profile.</returns>
    internal static LongfellowFieldProfile NewProfile(BaseMemoryPool pool) =>
        LongfellowFp256Encoding.CreateProfile(LongfellowMdocBundles.OfScalarFp256, LongfellowMdocBundles.InRangeFp256, pool);


    /// <summary>Builds the Fp256 subfield-run codec (the base field is its own subfield); the caller disposes it.</summary>
    /// <param name="profile">The field profile.</param>
    /// <returns>The codec.</returns>
    internal static LongfellowSubfieldRunCodec NewCodec(LongfellowFieldProfile profile) => LongfellowSubfieldRunCodec.ForFp256(profile);


    /// <summary>Builds the Fp256 row-encoder factory over the canonical-domain delegates.</summary>
    /// <param name="fft">The real FFT.</param>
    /// <param name="pool">The pool the row encoders rent from.</param>
    /// <returns>The factory.</returns>
    internal static LongfellowRowEncoderFactory NewEncoderFactory(Fp256RealFft fft, BaseMemoryPool pool) =>
        LongfellowFp256Encoding.CreateEncoderFactory(fft, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, LongfellowMdocBundles.OfScalarFp256, CurveParameterSet.None, pool);


    /// <summary>Drives the ZK prover over an assembled column with the bundle's field delegates.</summary>
    /// <param name="circuit">The compiled circuit.</param>
    /// <param name="parameters">The derived Ligero parameters.</param>
    /// <param name="column">The witness column, one canonical scalar per declared input wire.</param>
    /// <param name="random">The prover entropy source.</param>
    /// <param name="transcript">The Fiat-Shamir transcript.</param>
    /// <param name="encoderFactory">The row-encoder factory.</param>
    /// <param name="profile">The field profile.</param>
    /// <param name="codec">The subfield-run codec.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="leafHash">The one-shot leaf hash.</param>
    /// <param name="pool">The pool the proof and working buffers rent from.</param>
    /// <returns>The pooled proof envelope; the caller disposes it.</returns>
    internal static LongfellowZkProofEnvelope Prove(
        LongfellowSumcheckCircuit circuit,
        LongfellowLigeroParameters parameters,
        ReadOnlySpan<byte> column,
        LongfellowRandomByteSource random,
        LongfellowTranscript transcript,
        LongfellowRowEncoderFactory encoderFactory,
        LongfellowFieldProfile profile,
        LongfellowSubfieldRunCodec codec,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        BaseMemoryPool pool) =>
        LongfellowZkProver.Prove(
            circuit,
            parameters,
            column,
            LongfellowFp256Encoding.SignatureSubfieldBoundary,
            random,
            transcript,
            encoderFactory,
            profile,
            codec,
            Fp256Add,
            Fp256Subtract,
            Fp256Multiply,
            Fp256Invert,
            merkleHash,
            leafHash,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            pool);


    /// <summary>
    /// Parses a proof envelope's segments and verifies it against the assembled public inputs:
    /// a segment that fails to parse answers <see cref="LongfellowJwtVerdict.MalformedProof"/>,
    /// a parsed envelope the verifier refuses answers <see cref="LongfellowJwtVerdict.Rejected"/>.
    /// </summary>
    /// <param name="circuit">The compiled circuit the proof claims.</param>
    /// <param name="parameters">The derived Ligero parameters.</param>
    /// <param name="proof">The proof envelope bytes.</param>
    /// <param name="publicInputs">The little-endian public-input bytes.</param>
    /// <param name="transcript">The Fiat-Shamir transcript.</param>
    /// <param name="encoderFactory">The row-encoder factory.</param>
    /// <param name="profile">The field profile.</param>
    /// <param name="codec">The subfield-run codec.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="leafHash">The one-shot leaf hash.</param>
    /// <param name="pool">The pool the parsed segments rent from.</param>
    /// <returns>The verdict.</returns>
    internal static LongfellowJwtVerdict Verify(
        LongfellowSumcheckCircuit circuit,
        LongfellowLigeroParameters parameters,
        ReadOnlySpan<byte> proof,
        ReadOnlySpan<byte> publicInputs,
        LongfellowTranscript transcript,
        LongfellowRowEncoderFactory encoderFactory,
        LongfellowFieldProfile profile,
        LongfellowSubfieldRunCodec codec,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        BaseMemoryPool pool)
    {
        if(proof.Length < DigestSize)
        {
            return LongfellowJwtVerdict.MalformedProof;
        }

        ReadOnlySpan<byte> root = proof[..DigestSize];
        int sumcheckSize = LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile);
        if(proof.Length < DigestSize + sumcheckSize)
        {
            return LongfellowJwtVerdict.MalformedProof;
        }

        using LongfellowSumcheckProof? sumcheckProof = LongfellowSumcheckProofSerializer.Read(circuit, profile, pool, proof.Slice(DigestSize, sumcheckSize), out _);
        if(sumcheckProof is null)
        {
            return LongfellowJwtVerdict.MalformedProof;
        }

        using LongfellowLigeroProof? ligeroProof = LongfellowLigeroProofSerializer.Read(parameters, profile, codec, pool, proof[(DigestSize + sumcheckSize)..], out _);
        if(ligeroProof is null)
        {
            return LongfellowJwtVerdict.MalformedProof;
        }

        LongfellowZkVerifier.RecvCommitment(root, transcript);
        bool accepted = LongfellowZkVerifier.VerifyFromAbsorbedRoot(
            circuit,
            parameters,
            sumcheckProof,
            ligeroProof,
            root,
            publicInputs,
            transcript,
            encoderFactory,
            profile,
            Fp256Add,
            Fp256Subtract,
            Fp256Multiply,
            Fp256Invert,
            merkleHash,
            leafHash,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            pool,
            out _);

        return accepted ? LongfellowJwtVerdict.Accepted : LongfellowJwtVerdict.Rejected;
    }


    //The P-256 base-field prime is exactly 32 big-endian bytes, so the minimal unsigned write of
    //p − 1 fills the canonical scalar completely.
    private static byte[] BuildCanonicalPrimeMinusOne()
    {
        byte[] canonical = new byte[Fp256ElementBytes];
        BigInteger primeMinusOne = P256BigIntegerG1Reference.BaseFieldPrime - BigInteger.One;
        _ = primeMinusOne.TryWriteBytes(canonical, out _, isUnsigned: true, isBigEndian: true);

        return canonical;
    }
}
