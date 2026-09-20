using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Ligero.Gadgets;

/// <summary>
/// The public inputs to one ECDSA verification: the public-key point (Qx, Qy), the
/// message hash <c>e</c> (reduced modulo the curve order), and the signature
/// (<c>r</c>, <c>s</c>). All are canonical big-endian field elements; they are pinned
/// in-circuit by <see cref="LigeroConstraintSystemBuilder.AddConstant"/>, so the
/// verifier supplies their constraint targets as the claimed statement.
/// </summary>
internal readonly record struct EcdsaPublicInputs(
    ReadOnlyMemory<byte> PublicKeyX,
    ReadOnlyMemory<byte> PublicKeyY,
    ReadOnlyMemory<byte> MessageHash,
    ReadOnlyMemory<byte> SignatureR,
    ReadOnlyMemory<byte> SignatureS);


/// <summary>
/// The private witness for one ECDSA verification under the Longfellow Alg.4
/// reformulation: the affine coordinates of the nonce point <c>R = k·G</c>. R is
/// witnessed (with <c>z = 1</c>), proven on-curve, and its x-coordinate is bound to the
/// public <c>r</c> by <c>r = R.x mod n</c>.
/// </summary>
internal readonly record struct EcdsaWitness(
    ReadOnlyMemory<byte> NonceX,
    ReadOnlyMemory<byte> NonceY);


/// <summary>
/// Public inputs to an ECDSA verification whose message hash is proven in-circuit: the
/// public key (Qx, Qy) and the signature (r, s). The message hash e is not supplied — it
/// is derived from <see cref="EcdsaHashedWitness.Message"/> by SHA-256 inside the circuit.
/// </summary>
internal readonly record struct EcdsaHashedPublicInputs(
    ReadOnlyMemory<byte> PublicKeyX,
    ReadOnlyMemory<byte> PublicKeyY,
    ReadOnlyMemory<byte> SignatureR,
    ReadOnlyMemory<byte> SignatureS);


/// <summary>
/// Private witness for a hashed-message ECDSA verification: the signed message (whose
/// SHA-256 is the message hash) and the nonce point coordinates.
/// </summary>
internal readonly record struct EcdsaHashedWitness(
    ReadOnlyMemory<byte> Message,
    ReadOnlyMemory<byte> NonceX,
    ReadOnlyMemory<byte> NonceY);


/// <summary>
/// Private witness for a two-level mdoc verification: the signed MobileSecurityObject (whose
/// SHA-256 is what the issuer signed), the IssuerSignedItem that carries the attribute (and
/// whose SHA-256 the MSO holds), and the nonce point coordinates.
/// </summary>
internal readonly record struct EcdsaMdocWitness(
    ReadOnlyMemory<byte> MobileSecurityObject,
    ReadOnlyMemory<byte> IssuerSignedItem,
    ReadOnlyMemory<byte> NonceX,
    ReadOnlyMemory<byte> NonceY);


/// <summary>
/// The curve data for in-circuit ECDSA verification: the short-Weierstrass
/// <see cref="WeierstrassCurve"/>, the generator (Gx, Gy), and the scalar field order
/// <c>n</c> (all canonical field-element bytes). A data-only companion to the
/// <see cref="EcdsaVerificationGadgetExtensions"/> builder extension methods.
/// </summary>
internal sealed record EcdsaCurve(
    WeierstrassCurve Curve,
    ReadOnlyMemory<byte> GeneratorX,
    ReadOnlyMemory<byte> GeneratorY,
    ReadOnlyMemory<byte> Order);


/// <summary>
/// Native in-circuit ECDSA-P256 verification over the curve's base field Fp256,
/// expressed as Ligero linear + quadratic constraints and composed as extension methods
/// on <see cref="LigeroConstraintSystemBuilder"/>. It proves a public signature
/// (<c>r</c>, <c>s</c>) verifies under a public key <c>Q</c> for a message hash
/// <c>e</c>, via the Longfellow Alg.4 identity <c>e·G + r·Q − s·R = O</c>, where
/// <c>R</c> is the witnessed nonce point and <c>r = R.x mod n</c>.
/// </summary>
/// <remarks>
/// <para>
/// Soundness rests on the cross-modulus bindings the constraint builder provides:
/// canonical bit-decompositions pin every scalar to its unique integer in
/// <c>[0, n)</c> — so the ladder cannot be fed a non-canonical representative
/// <c>scalar + p</c> — and <see cref="LigeroConstraintSystemBuilder.AddReduceModOrder"/>
/// ties <c>r</c> to <c>R.x mod n</c> through a wrap-free integer identity, defeating the
/// mod-p alias <c>r' = R.x + p − n</c>. <c>r</c> and <c>s</c> are checked to lie in
/// <c>[1, n−1]</c>; <c>Q</c> and <c>R</c> are checked to be on the curve. The complete
/// projective addition the multi-scalar multiply composes from is inversion-free and
/// edge-case-free, so the identity (which passes through <c>O</c>) needs no branching.
/// </para>
/// </remarks>
internal static class EcdsaVerificationGadgetExtensions
{
    /// <summary>The canonical scalar width in bytes.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The SHA-256 digest width in bits, the length of the most-significant-first bit vector fed to the ladder as the <c>e·G</c> scalar.</summary>
    private const int DigestBits = 256;


    /// <summary>
    /// Asserts that the public signature verifies under the public key for the message hash, via the
    /// Longfellow Alg.4 identity <c>e·G + r·Q − s·R = O</c>.
    /// </summary>
    /// <param name="builder">The constraint system being built.</param>
    /// <param name="ecdsa">The curve, generator and scalar-field order.</param>
    /// <param name="publicInputs">The public key, message hash and signature.</param>
    /// <param name="witness">The witnessed nonce point.</param>
    /// <returns>The wire holding the identity accumulator's <c>Z</c>, asserted zero (the <c>O</c> check); returned so a test can perturb it.</returns>
    public static int AssertVerifies(this LigeroConstraintSystemBuilder builder, EcdsaCurve ecdsa, EcdsaPublicInputs publicInputs, EcdsaWitness witness)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(ecdsa);

        //Public inputs pinned by AddConstant — their targets are the claimed statement
        //the verifier supplies and checks. One 1-wire serves every base point's Z.
        Span<byte> oneValue = stackalloc byte[ScalarSize];
        LigeroConstraintSystemBuilder.EncodeConstant(1, oneValue);
        int oneWire = builder.AddConstant(oneValue);
        int gx = builder.AddConstant(ecdsa.GeneratorX.Span);
        int gy = builder.AddConstant(ecdsa.GeneratorY.Span);
        int qx = builder.AddConstant(publicInputs.PublicKeyX.Span);
        int qy = builder.AddConstant(publicInputs.PublicKeyY.Span);

        //Q on the curve (affine ⇒ a finite point ≠ O).
        builder.AddOnCurveCheck(ecdsa.Curve, qx, qy);

        //Witnessed nonce point R = (rx, ry, 1), on the curve (z = 1 ⇒ ≠ O).
        int rxWire = builder.AddWire(witness.NonceX.Span);
        int ryWire = builder.AddWire(witness.NonceY.Span);
        builder.AddOnCurveCheck(ecdsa.Curve, rxWire, ryWire);

        //Public scalars: e and s pinned and proven < n; r bound to R.x mod n. The
        //returned bits are canonical and most-significant first for the ladder.
        (int _, WireWord eBits) = builder.AddPublicScalarBits(publicInputs.MessageHash.Span, ecdsa.Order.Span);
        (int sWire, WireWord sBits) = builder.AddPublicScalarBits(publicInputs.SignatureS.Span, ecdsa.Order.Span);
        (int rWire, WireWord rBits) = builder.AddReduceModOrder(rxWire, publicInputs.SignatureR.Span, ecdsa.Order.Span);

        //r, s ∈ [1, n−1]: nonzero on top of the < n range proof.
        builder.AddNonzeroCheck(rWire);
        builder.AddNonzeroCheck(sWire);

        //−R = (rx, −ry), so [s]·(−R) = −[s]·R.
        int negativeRy = builder.AddNegateY(ecdsa.Curve, ryWire);

        //Alg.4 identity e·G + r·Q + s·(−R) = O via the three-scalar multi-scalar multiply.
        (int X, int Y, int Z) sum = builder.AddThreeScalarMultiScalarMultiply(ecdsa.Curve,
            (gx, gy, oneWire), (qx, qy, oneWire), (rxWire, negativeRy, oneWire),
            eBits, rBits, sBits);

        builder.AddAssertZero(sum.Z);

        return sum.Z;
    }


    /// <summary>
    /// Asserts that the signature verifies under the public key for the SHA-256 of a witnessed message:
    /// the message hash <c>e</c> is computed in-circuit, binding the proof to the signed bytes rather
    /// than to a supplied <c>e</c>. The 256-bit digest <c>D</c> is fed directly as the <c>e·G</c> scalar:
    /// the ladder computes <c>D·G = (D mod n)·G = e·G</c>, so no separate mod-n reduction of the digest
    /// is needed.
    /// </summary>
    /// <param name="builder">The constraint system being built.</param>
    /// <param name="ecdsa">The curve, generator and scalar-field order.</param>
    /// <param name="publicInputs">The public key and signature; the message hash is derived in-circuit.</param>
    /// <param name="witness">The signed message and the witnessed nonce point.</param>
    /// <returns>The asserted-<c>O</c> wire.</returns>
    public static int AssertVerifiesHashedMessage(this LigeroConstraintSystemBuilder builder, EcdsaCurve ecdsa, EcdsaHashedPublicInputs publicInputs, EcdsaHashedWitness witness)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(ecdsa);

        //e = SHA-256(message): the in-circuit digest's 256 bit wires, most-significant first,
        //then the shared verification over those bits. The digest bits are pinned to {0,1} by
        //the SHA gadget's own boolean constraints, so the bits-only entry needs none added.
        var sha = new Sha256Gadget(builder);
        WireWord[] digest = sha.Hash(witness.Message.Span);
        WireWord eBits = DigestBitsMostSignificantFirst(builder, digest);

        return builder.AssertVerifiesDigestBits(ecdsa, publicInputs, new EcdsaWitness(witness.NonceX, witness.NonceY), eBits);
    }


    /// <summary>
    /// Asserts that the signature verifies under the public key for a message hash already present in
    /// the circuit as 256 caller-supplied bit wires (most-significant first): the shared verification
    /// core behind <see cref="AssertVerifiesHashedMessage"/>, with the SHA-256 step removed. The supplied
    /// bits ARE the <c>e·G</c> ladder scalar, so the ladder computes <c>D·G = (D mod n)·G = e·G</c> with
    /// no separate mod-n reduction of the digest. The caller MUST constrain the supplied bit wires to
    /// <c>{0,1}</c> — this method adds no bitness for them (in the cross-field engine the MAC region's
    /// bitness quadratics provide it).
    /// </summary>
    /// <param name="builder">The constraint system being built.</param>
    /// <param name="ecdsa">The curve, generator and scalar-field order.</param>
    /// <param name="publicInputs">The public key and signature.</param>
    /// <param name="witness">The witnessed nonce point.</param>
    /// <param name="digestBitsMostSignificantFirst">The 256 message-hash bit wires, most-significant first.</param>
    /// <returns>The asserted-<c>O</c> wire.</returns>
    /// <exception cref="ArgumentException">When <paramref name="digestBitsMostSignificantFirst"/> is not exactly <see cref="DigestBits"/> wires long.</exception>
    public static int AssertVerifiesDigestBits(this LigeroConstraintSystemBuilder builder, EcdsaCurve ecdsa, EcdsaHashedPublicInputs publicInputs, EcdsaWitness witness, ReadOnlySpan<int> digestBitsMostSignificantFirst)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(ecdsa);
        if(digestBitsMostSignificantFirst.Length != DigestBits)
        {
            throw new ArgumentException($"Digest bit wires must be {DigestBits} bits; received {digestBitsMostSignificantFirst.Length}.", nameof(digestBitsMostSignificantFirst));
        }

        Span<byte> oneValue = stackalloc byte[ScalarSize];
        LigeroConstraintSystemBuilder.EncodeConstant(1, oneValue);
        int oneWire = builder.AddConstant(oneValue);
        int gx = builder.AddConstant(ecdsa.GeneratorX.Span);
        int gy = builder.AddConstant(ecdsa.GeneratorY.Span);
        int qx = builder.AddConstant(publicInputs.PublicKeyX.Span);
        int qy = builder.AddConstant(publicInputs.PublicKeyY.Span);

        builder.AddOnCurveCheck(ecdsa.Curve, qx, qy);

        int rxWire = builder.AddWire(witness.NonceX.Span);
        int ryWire = builder.AddWire(witness.NonceY.Span);
        builder.AddOnCurveCheck(ecdsa.Curve, rxWire, ryWire);

        (int sWire, WireWord sBits) = builder.AddPublicScalarBits(publicInputs.SignatureS.Span, ecdsa.Order.Span);
        (int rWire, WireWord rBits) = builder.AddReduceModOrder(rxWire, publicInputs.SignatureR.Span, ecdsa.Order.Span);
        builder.AddNonzeroCheck(rWire);
        builder.AddNonzeroCheck(sWire);

        int negativeRy = builder.AddNegateY(ecdsa.Curve, ryWire);
        (int X, int Y, int Z) sum = builder.AddThreeScalarMultiScalarMultiply(ecdsa.Curve,
            (gx, gy, oneWire), (qx, qy, oneWire), (rxWire, negativeRy, oneWire),
            digestBitsMostSignificantFirst, rBits, sBits);

        builder.AddAssertZero(sum.Z);

        return sum.Z;
    }


    /// <summary>
    /// Asserts the full mdoc-shaped statement: the signature verifies under <c>Q</c> for
    /// <c>e = SHA-256(message)</c>, AND the message contains the public attribute encoding at a
    /// witnessed offset — all over a single witnessed message, so the disclosed attribute is provably
    /// in the signed bytes. The message stays private; only the attribute (e.g. the CBOR for
    /// <c>age_over_18 = true</c>) is public.
    /// </summary>
    /// <param name="builder">The constraint system being built.</param>
    /// <param name="ecdsa">The curve, generator and scalar-field order.</param>
    /// <param name="publicInputs">The public key and signature.</param>
    /// <param name="witness">The signed message and the witnessed nonce point.</param>
    /// <param name="attribute">The disclosed attribute's expected bytes.</param>
    /// <param name="attributeOffset">The byte offset of the attribute within the witnessed message.</param>
    /// <returns>The asserted-<c>O</c> wire.</returns>
    public static int AssertVerifiesDisclosedAttribute(
        this LigeroConstraintSystemBuilder builder,
        EcdsaCurve ecdsa,
        EcdsaHashedPublicInputs publicInputs,
        EcdsaHashedWitness witness,
        ReadOnlySpan<byte> attribute,
        int attributeOffset)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(ecdsa);

        Span<byte> oneValue = stackalloc byte[ScalarSize];
        LigeroConstraintSystemBuilder.EncodeConstant(1, oneValue);
        int oneWire = builder.AddConstant(oneValue);
        int gx = builder.AddConstant(ecdsa.GeneratorX.Span);
        int gy = builder.AddConstant(ecdsa.GeneratorY.Span);
        int qx = builder.AddConstant(publicInputs.PublicKeyX.Span);
        int qy = builder.AddConstant(publicInputs.PublicKeyY.Span);

        builder.AddOnCurveCheck(ecdsa.Curve, qx, qy);

        int rxWire = builder.AddWire(witness.NonceX.Span);
        int ryWire = builder.AddWire(witness.NonceY.Span);
        builder.AddOnCurveCheck(ecdsa.Curve, rxWire, ryWire);

        //Witness the message once, then both hash it and search it over the same byte wires.
        WireWord messageBytes = builder.WitnessMessage(witness.Message.Span);

        var sha = new Sha256Gadget(builder);
        WireWord[] digest = sha.Hash(messageBytes);
        WireWord eBits = DigestBitsMostSignificantFirst(builder, digest);

        (int sWire, WireWord sBits) = builder.AddPublicScalarBits(publicInputs.SignatureS.Span, ecdsa.Order.Span);
        (int rWire, WireWord rBits) = builder.AddReduceModOrder(rxWire, publicInputs.SignatureR.Span, ecdsa.Order.Span);
        builder.AddNonzeroCheck(rWire);
        builder.AddNonzeroCheck(sWire);

        int negativeRy = builder.AddNegateY(ecdsa.Curve, ryWire);
        (int X, int Y, int Z) sum = builder.AddThreeScalarMultiScalarMultiply(ecdsa.Curve,
            (gx, gy, oneWire), (qx, qy, oneWire), (rxWire, negativeRy, oneWire),
            eBits, rBits, sBits);

        builder.AddAssertZero(sum.Z);

        //The disclosed attribute is a substring of the same witnessed (and now hashed) message.
        builder.AssertContainsAt(messageBytes, attributeOffset, attribute);

        return sum.Z;
    }


    /// <summary>
    /// Asserts the full two-level mdoc statement in one proof: a valid issuer signature over
    /// <c>e = SHA-256(MSO)</c>; the MSO holds <c>SHA-256(IssuerSignedItem)</c> at a witnessed offset; and
    /// the item holds the public attribute encoding at a witnessed offset. A disclosed attribute is thus
    /// bound through the item digest up to the signature, exactly as ISO 18013-5 mdoc structures it — the
    /// MSO and the item stay private, only the attribute (e.g. <c>age_over_18 = true</c>) is public.
    /// </summary>
    /// <param name="builder">The constraint system being built.</param>
    /// <param name="ecdsa">The curve, generator and scalar-field order.</param>
    /// <param name="publicInputs">The public key and signature.</param>
    /// <param name="witness">The signed MobileSecurityObject, the signed IssuerSignedItem, and the witnessed nonce point.</param>
    /// <param name="attribute">The disclosed attribute's expected bytes.</param>
    /// <param name="itemDigestOffset">The byte offset of the item's digest within the MSO.</param>
    /// <param name="attributeOffset">The byte offset of the attribute within the item.</param>
    /// <returns>The asserted-<c>O</c> wire.</returns>
    public static int AssertVerifiesMdocAttribute(
        this LigeroConstraintSystemBuilder builder,
        EcdsaCurve ecdsa,
        EcdsaHashedPublicInputs publicInputs,
        EcdsaMdocWitness witness,
        ReadOnlySpan<byte> attribute,
        int itemDigestOffset,
        int attributeOffset)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(ecdsa);

        Span<byte> oneValue = stackalloc byte[ScalarSize];
        LigeroConstraintSystemBuilder.EncodeConstant(1, oneValue);
        int oneWire = builder.AddConstant(oneValue);
        int gx = builder.AddConstant(ecdsa.GeneratorX.Span);
        int gy = builder.AddConstant(ecdsa.GeneratorY.Span);
        int qx = builder.AddConstant(publicInputs.PublicKeyX.Span);
        int qy = builder.AddConstant(publicInputs.PublicKeyY.Span);

        builder.AddOnCurveCheck(ecdsa.Curve, qx, qy);

        int rxWire = builder.AddWire(witness.NonceX.Span);
        int ryWire = builder.AddWire(witness.NonceY.Span);
        builder.AddOnCurveCheck(ecdsa.Curve, rxWire, ryWire);

        var sha = new Sha256Gadget(builder);

        //Outer level: the signature is over e = SHA-256(MSO).
        WireWord msoBytes = builder.WitnessMessage(witness.MobileSecurityObject.Span);
        WireWord eBits = DigestBitsMostSignificantFirst(builder, sha.Hash(msoBytes));

        (int sWire, WireWord sBits) = builder.AddPublicScalarBits(publicInputs.SignatureS.Span, ecdsa.Order.Span);
        (int rWire, WireWord rBits) = builder.AddReduceModOrder(rxWire, publicInputs.SignatureR.Span, ecdsa.Order.Span);
        builder.AddNonzeroCheck(rWire);
        builder.AddNonzeroCheck(sWire);

        int negativeRy = builder.AddNegateY(ecdsa.Curve, ryWire);
        (int X, int Y, int Z) sum = builder.AddThreeScalarMultiScalarMultiply(ecdsa.Curve,
            (gx, gy, oneWire), (qx, qy, oneWire), (rxWire, negativeRy, oneWire),
            eBits, rBits, sBits);

        builder.AddAssertZero(sum.Z);

        //Inner level: the MSO holds SHA-256(item), and the item holds the attribute.
        WireWord itemBytes = builder.WitnessMessage(witness.IssuerSignedItem.Span);
        WireWord itemDigestBytes = sha.DigestByteWires(sha.Hash(itemBytes));
        builder.AssertContainsBytesAt(msoBytes, itemDigestOffset, itemDigestBytes);
        builder.AssertContainsAt(itemBytes, attributeOffset, attribute);

        return sum.Z;
    }


    /// <summary>Writes a transcript seed bound to the domain and the five public scalar slots.</summary>
    /// <param name="publicInputs">The public statement; short scalar slots are zero-padded.</param>
    /// <param name="domainSeparator">The protocol domain bytes.</param>
    /// <param name="hash">The Fiat-Shamir hash delegate.</param>
    /// <param name="hashFunction">The hash algorithm identifier.</param>
    /// <param name="pool">The caller's pool for the temporary transcript message.</param>
    /// <param name="seed">Receives the scalar-sized transcript seed.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="hash"/> or <paramref name="pool"/> is null.</exception>
    /// <remarks>
    /// The seed is bound to <c>domain ‖ Qx ‖ Qy ‖ e ‖ r ‖ s</c>. Driving both the proof and the verification
    /// from it makes a proof non-transferable: a verifier reconstructs the seed from the statement it
    /// believes, so a proof for one <c>(Q, e, r, s)</c> yields different challenges — and is rejected — under
    /// any other. The public inputs are already bound as AddConstant targets; this binds the transcript to
    /// them too (domain separation), mirroring the R1CS path's AbsorbR1csInstance without touching the
    /// prover/verifier. Inputs must be canonical (<c>ScalarSize</c> bytes each).
    /// </remarks>
    public static void DeriveTranscriptSeed(EcdsaPublicInputs publicInputs, ReadOnlySpan<byte> domainSeparator, FiatShamirHashDelegate hash, string hashFunction, BaseMemoryPool pool, Span<byte> seed)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(pool);

        //The statement binds Qx, Qy, e, r and s, each in its own scalar slot.
        const int PublicScalarCount = 5;
        int messageLength = checked(domainSeparator.Length + (PublicScalarCount * ScalarSize));
        using IMemoryOwner<byte> owner = pool.Rent(messageLength);
        Span<byte> span = owner.Memory.Span[..messageLength];
        span.Clear();
        domainSeparator.CopyTo(span);
        int offset = domainSeparator.Length;
        publicInputs.PublicKeyX.Span.CopyTo(span.Slice(offset, ScalarSize));
        publicInputs.PublicKeyY.Span.CopyTo(span.Slice(offset + ScalarSize, ScalarSize));
        publicInputs.MessageHash.Span.CopyTo(span.Slice(offset + (2 * ScalarSize), ScalarSize));
        publicInputs.SignatureR.Span.CopyTo(span.Slice(offset + (3 * ScalarSize), ScalarSize));
        publicInputs.SignatureS.Span.CopyTo(span.Slice(offset + (4 * ScalarSize), ScalarSize));

        seed.Clear();
        hash(span, seed, hashFunction);
    }


    /// <summary>
    /// Rearranges a SHA-256 digest's eight 32-bit words into a flat 256-bit vector for use as a ladder
    /// scalar: the words are most-significant first, and each word's bit wires are least-significant
    /// first, so they are emitted high-to-low.
    /// </summary>
    /// <param name="builder">The constraint system to rent the result wire word from.</param>
    /// <param name="digestWords">The digest's eight 32-bit wire words, most-significant word first.</param>
    /// <returns>The 256 digest bit wires, most-significant bit first.</returns>
    private static WireWord DigestBitsMostSignificantFirst(LigeroConstraintSystemBuilder builder, WireWord[] digestWords)
    {
        const int wordBits = 32;
        WireWord bits = builder.RentWireWord(DigestBits);
        int index = 0;
        for(int word = 0; word < 8; word++)
        {
            for(int bit = wordBits - 1; bit >= 0; bit--)
            {
                bits[index++] = digestWords[word][bit];
            }
        }

        return bits;
    }
}
