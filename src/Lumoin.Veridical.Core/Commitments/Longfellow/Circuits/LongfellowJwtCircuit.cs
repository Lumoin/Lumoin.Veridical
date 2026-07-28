using System;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The JWT statement's shared shape constants, a faithful port of google/longfellow-zk's
/// <c>circuits/tests/jwt/jwt_constants.h</c>.
/// </summary>
internal static class LongfellowJwtConstants
{
    /// <summary>The SHA-256 witness packing width the JWT statement uses (the reference's <c>kSHAJWTPluckerBits</c>).</summary>
    public const int ShaJwtPluckerBits = 4;

    /// <summary>The payload index bit width (the reference's <c>kJWTIndexBits</c>).</summary>
    public const int JwtIndexBits = 10;

    /// <summary>The tail blocks the payload region may not reach: the padded preimage always ends with at least nine padding bytes, and the reference reserves two whole blocks past the payload, so a usable statement needs strictly more blocks than this.</summary>
    public const int ReservedTailBlocks = 2;

    /// <summary>The block-capacity cap shared by the circuit and the witness generator; the reference instantiates the statement up to fifteen blocks, and the cap keeps a hostile shape from driving an unbounded declaration or allocation.</summary>
    public const int MaxShaBlocks = 32;
}


/// <summary>
/// The public wires one disclosed attribute occupies, a faithful port of the reference's
/// <c>JWT::OpenedAttribute</c>: the quoted <c>"id":"value"</c> pattern padded to its fixed width,
/// and the pattern's genuine length.
/// </summary>
internal sealed class LongfellowJwtOpenedAttributeWires
{
    /// <summary>The fixed pattern width in bytes.</summary>
    public const int PatternLength = 128;

    /// <summary>The pattern bytes as eight-bit vectors, zero-padded past the genuine length.</summary>
    public LongfellowBitWire[][] Pattern { get; }

    /// <summary>The pattern's genuine byte length as an eight-bit vector.</summary>
    public LongfellowBitWire[] Length { get; }


    /// <summary>
    /// Constructs the bundle from already-produced wire vectors.
    /// </summary>
    /// <param name="pattern">The pattern byte vectors.</param>
    /// <param name="length">The length vector.</param>
    /// <exception cref="ArgumentNullException">When an array is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the pattern is not exactly <see cref="PatternLength"/> vectors.</exception>
    public LongfellowJwtOpenedAttributeWires(LongfellowBitWire[][] pattern, LongfellowBitWire[] length)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        ArgumentNullException.ThrowIfNull(length);

        if(pattern.Length != PatternLength)
        {
            throw new ArgumentException($"The pattern is exactly {PatternLength} byte vectors.", nameof(pattern));
        }

        Pattern = pattern;
        Length = length;
    }


    /// <summary>
    /// The reference's <c>OpenedAttribute::input</c>: declares the pattern bytes then the length,
    /// in order. The JWT statement declares attributes before the private-input boundary, so these
    /// wires are public.
    /// </summary>
    /// <param name="logic">The gadget layer to declare inputs on.</param>
    /// <returns>The declared bundle.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="logic"/> is <see langword="null"/>.</exception>
    public static LongfellowJwtOpenedAttributeWires Input(LongfellowLogic logic)
    {
        ArgumentNullException.ThrowIfNull(logic);

        var pattern = new LongfellowBitWire[PatternLength][];
        for(int i = 0; i < PatternLength; i++)
        {
            pattern[i] = logic.InputVector(LongfellowLogic.BitWidth8);
        }

        LongfellowBitWire[] length = logic.InputVector(LongfellowLogic.BitWidth8);

        return new LongfellowJwtOpenedAttributeWires(pattern, length);
    }
}


/// <summary>
/// The private witness wires of the JWT statement, a faithful port of the reference's
/// <c>JWT::Witness</c>: the issuer digest and device key, both ECDSA advice bundles, the padded
/// signing preimage with its SHA-256 block advice, and the payload and attribute positions.
/// </summary>
internal sealed class LongfellowJwtWitnessWires
{
    /// <summary>The issuer signature's digest wire.</summary>
    public int E { get; }

    /// <summary>The device key's x coordinate wire: unconstrained private witness that the prover, by convention, extracts from the payload's <c>cnf</c> claim — the circuit itself does not tie it to the payload.</summary>
    public int DpkX { get; }

    /// <summary>The device key's y coordinate wire: unconstrained private witness, like <see cref="DpkX"/>.</summary>
    public int DpkY { get; }

    /// <summary>The issuer signature's ECDSA advice.</summary>
    public LongfellowEcdsaVerifyWitnessWires JwtSignature { get; }

    /// <summary>The key-binding signature's ECDSA advice.</summary>
    public LongfellowEcdsaVerifyWitnessWires KbSignature { get; }

    /// <summary>The padded signing preimage's bytes as eight-bit vectors.</summary>
    public LongfellowBitWire[][] Preimage { get; }

    /// <summary>The digest's 256 bits, least significant first.</summary>
    public LongfellowBitWire[] EBits { get; }

    /// <summary>The per-block SHA-256 advice.</summary>
    public LongfellowFlatSha256PackedBlockWitness[] Sha { get; }

    /// <summary>The index of the block holding the genuine digest, as an eight-bit vector.</summary>
    public LongfellowBitWire[] BlockNumber { get; }

    /// <summary>The per-attribute start indices into the decoded payload.</summary>
    public LongfellowBitWire[][] AttributeIndices { get; }

    /// <summary>The payload's start index in the preimage.</summary>
    public LongfellowBitWire[] PayloadIndex { get; }

    /// <summary>The payload's byte length.</summary>
    public LongfellowBitWire[] PayloadLength { get; }


    /// <summary>
    /// Constructs the bundle from already-produced wires.
    /// </summary>
    /// <param name="e">The digest wire.</param>
    /// <param name="dpkX">The device key's x wire.</param>
    /// <param name="dpkY">The device key's y wire.</param>
    /// <param name="jwtSignature">The issuer advice.</param>
    /// <param name="kbSignature">The key-binding advice.</param>
    /// <param name="preimage">The preimage byte vectors.</param>
    /// <param name="eBits">The digest bits.</param>
    /// <param name="sha">The SHA-256 block advice.</param>
    /// <param name="blockNumber">The digest block index vector.</param>
    /// <param name="attributeIndices">The attribute start index vectors.</param>
    /// <param name="payloadIndex">The payload start index vector.</param>
    /// <param name="payloadLength">The payload length vector.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public LongfellowJwtWitnessWires(
        int e,
        int dpkX,
        int dpkY,
        LongfellowEcdsaVerifyWitnessWires jwtSignature,
        LongfellowEcdsaVerifyWitnessWires kbSignature,
        LongfellowBitWire[][] preimage,
        LongfellowBitWire[] eBits,
        LongfellowFlatSha256PackedBlockWitness[] sha,
        LongfellowBitWire[] blockNumber,
        LongfellowBitWire[][] attributeIndices,
        LongfellowBitWire[] payloadIndex,
        LongfellowBitWire[] payloadLength)
    {
        ArgumentNullException.ThrowIfNull(jwtSignature);
        ArgumentNullException.ThrowIfNull(kbSignature);
        ArgumentNullException.ThrowIfNull(preimage);
        ArgumentNullException.ThrowIfNull(eBits);
        ArgumentNullException.ThrowIfNull(sha);
        ArgumentNullException.ThrowIfNull(blockNumber);
        ArgumentNullException.ThrowIfNull(attributeIndices);
        ArgumentNullException.ThrowIfNull(payloadIndex);
        ArgumentNullException.ThrowIfNull(payloadLength);

        E = e;
        DpkX = dpkX;
        DpkY = dpkY;
        JwtSignature = jwtSignature;
        KbSignature = kbSignature;
        Preimage = preimage;
        EBits = eBits;
        Sha = sha;
        BlockNumber = blockNumber;
        AttributeIndices = attributeIndices;
        PayloadIndex = payloadIndex;
        PayloadLength = payloadLength;
    }
}


/// <summary>
/// The restricted JWT+KB2 statement circuit, a faithful port of google/longfellow-zk's
/// <c>JWT&lt;LogicCircuit, Field, EC, SHABlocks&gt;</c> (<c>circuits/tests/jwt/jwt.h</c>): a token
/// in the <c>header.payload.signature~kb</c> shape whose issuer signature verifies over
/// SHA-256(header.payload), whose key-binding signature verifies under a device key pair supplied
/// as private witness, whose payload decodes correctly from base64url, and whose disclosed
/// attributes occur as <c>"id":"value"</c> substrings of the decoded payload. The circuit does NOT
/// constrain the witnessed device key to equal the payload's <c>cnf</c> claim — reading the key
/// from <c>cnf</c> is a prover-side convention (<c>LongfellowJwtWitness</c>), exactly as in the
/// reference, whose enumerated verified claims omit that binding; a relying party needing the
/// binding must enforce it outside this statement.
/// </summary>
/// <remarks>
/// <para>
/// The substring check stands in for JSON parsing under the reference's stated format
/// restrictions: attribute identifiers avoid the colon, quote and solidus characters, all
/// attributes are string-encoded, the issuer adds no spaces and escapes no quotes, and the colon
/// appears only as a separator. The soundness of the attribute claim rests on those restrictions
/// exactly as documented in the reference.
/// </para>
/// <para>
/// The key-binding digest <c>e2</c> is a PUBLIC input computed outside the circuit: the verifier
/// must recompute it from the presented key-binding JWT. The circuit proves only that a valid
/// device signature on it exists under the payload-carried key. The issuer digest, by contrast, is
/// recomputed in-circuit from the preimage, which also supplies the <c>e ≠ 0</c> guarantee the
/// ECDSA gadget requires.
/// </para>
/// </remarks>
internal sealed class LongfellowJwtCircuit
{
    /// <summary>One SHA-256 block's byte width.</summary>
    private const int BytesPerBlock = 64;

    //The reference's unroll parameter for both the payload and the attribute shifts.
    private const int ShiftUnroll = 3;

    private readonly LongfellowLogic logic;
    private readonly LongfellowLogicBackend backend;
    private readonly LongfellowLogicFieldOperations field;
    private readonly LongfellowEllipticCurveParameters curve;
    private readonly LongfellowFlatSha256Circuit sha;
    private readonly LongfellowRouting routing;
    private readonly int maxBlocks;


    /// <summary>
    /// Constructs the statement over a gadget layer, a curve, and the block capacity, building the
    /// SHA-256 gadget at the JWT packing width (the reference constructor's member initialization).
    /// </summary>
    /// <param name="logic">The gadget layer every sub-circuit builds on.</param>
    /// <param name="curve">The curve constants.</param>
    /// <param name="maxShaBlocks">The preimage capacity in SHA-256 blocks (the reference's <c>SHABlocks</c> template parameter).</param>
    /// <exception cref="ArgumentNullException">When <paramref name="logic"/> or <paramref name="curve"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="maxShaBlocks"/> does not exceed the reserved tail, exceeds the shared cap, or the payload index width cannot address the capacity (the reference's <c>JWT index bits too small</c> check).</exception>
    public LongfellowJwtCircuit(LongfellowLogic logic, LongfellowEllipticCurveParameters curve, int maxShaBlocks)
    {
        ArgumentNullException.ThrowIfNull(logic);
        ArgumentNullException.ThrowIfNull(curve);

        //The payload region occupies the blocks before the reserved tail, so a capacity at or below
        //the tail would make the payload shift's destination empty or negative.
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxShaBlocks, LongfellowJwtConstants.ReservedTailBlocks);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxShaBlocks, LongfellowJwtConstants.MaxShaBlocks);

        if((1 << LongfellowJwtConstants.JwtIndexBits) <= (maxShaBlocks * BytesPerBlock) - 9)
        {
            throw new ArgumentOutOfRangeException(nameof(maxShaBlocks), "The JWT index bit width cannot address the block capacity.");
        }

        this.logic = logic;
        this.curve = curve;
        backend = logic.Backend;
        field = logic.Field;
        maxBlocks = maxShaBlocks;
        sha = new LongfellowFlatSha256Circuit(logic, new LongfellowBitPlucker(logic, LongfellowJwtConstants.ShaJwtPluckerBits));
        routing = new LongfellowRouting(logic);
    }


    /// <summary>
    /// The reference's <c>Witness::input</c>: declares every private witness wire in the reference
    /// order — the digest and device key, both ECDSA advice bundles, the preimage bytes, the digest
    /// bits, the SHA-256 block advice, the digest block index, the attribute indices, and the
    /// payload position pair.
    /// </summary>
    /// <param name="attributeCount">The disclosed attribute count.</param>
    /// <returns>The declared bundle.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="attributeCount"/> is negative.</exception>
    public LongfellowJwtWitnessWires InputWitness(int attributeCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(attributeCount);

        int e = logic.InputElement();
        int dpkX = logic.InputElement();
        int dpkY = logic.InputElement();
        LongfellowEcdsaVerifyWitnessWires jwtSignature = LongfellowEcdsaVerifyWitnessWires.Input(logic, curve.ScalarBitCount);
        LongfellowEcdsaVerifyWitnessWires kbSignature = LongfellowEcdsaVerifyWitnessWires.Input(logic, curve.ScalarBitCount);

        var preimage = new LongfellowBitWire[maxBlocks * BytesPerBlock][];
        for(int i = 0; i < preimage.Length; i++)
        {
            preimage[i] = logic.InputVector(LongfellowLogic.BitWidth8);
        }

        LongfellowBitWire[] eBits = logic.InputVector(LongfellowLogic.BitWidth256);

        var shaWitness = new LongfellowFlatSha256PackedBlockWitness[maxBlocks];
        for(int j = 0; j < maxBlocks; j++)
        {
            shaWitness[j] = new LongfellowFlatSha256PackedBlockWitness();
            shaWitness[j].Input(sha);
        }

        LongfellowBitWire[] blockNumber = logic.InputVector(LongfellowLogic.BitWidth8);

        var attributeIndices = new LongfellowBitWire[attributeCount][];
        for(int i = 0; i < attributeCount; i++)
        {
            attributeIndices[i] = logic.InputVector(LongfellowJwtConstants.JwtIndexBits);
        }

        LongfellowBitWire[] payloadIndex = logic.InputVector(LongfellowJwtConstants.JwtIndexBits);
        LongfellowBitWire[] payloadLength = logic.InputVector(LongfellowJwtConstants.JwtIndexBits);

        return new LongfellowJwtWitnessWires(e, dpkX, dpkY, jwtSignature, kbSignature, preimage, eBits, shaWitness, blockNumber, attributeIndices, payloadIndex, payloadLength);
    }


    /// <summary>
    /// The reference's <c>assert_jwt_attributes</c>: verifies both signatures, ties the preimage's
    /// SHA-256 digest to the issuer signature bit for bit, decodes the payload region from
    /// base64url, and asserts every disclosed attribute pattern occurs at its claimed position in
    /// the decoded payload.
    /// </summary>
    /// <param name="pkX">The issuer public key's x coordinate wire (public).</param>
    /// <param name="pkY">The issuer public key's y coordinate wire (public).</param>
    /// <param name="e2">The key-binding digest wire (public; computed outside the circuit).</param>
    /// <param name="attributes">The disclosed attribute wire bundles (public).</param>
    /// <param name="witness">The private witness wires.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="attributes"/> or <paramref name="witness"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the attribute bundles disagree with the witness's index count.</exception>
    public void AssertJwtAttributes(int pkX, int pkY, int e2, LongfellowJwtOpenedAttributeWires[] attributes, LongfellowJwtWitnessWires witness)
    {
        ArgumentNullException.ThrowIfNull(attributes);
        ArgumentNullException.ThrowIfNull(witness);

        if(attributes.Length != witness.AttributeIndices.Length)
        {
            throw new ArgumentException("The attribute bundles disagree with the witness's index count.", nameof(attributes));
        }

        var ecdsa = new LongfellowEcdsaVerifyCircuit(logic, curve);

        ecdsa.VerifySignature3(pkX, pkY, witness.E, witness.JwtSignature);
        ecdsa.VerifySignature3(witness.DpkX, witness.DpkY, e2, witness.KbSignature);

        sha.AssertMessageHash(maxBlocks, witness.BlockNumber, witness.Preimage, witness.EBits, witness.Sha);
        logic.AssertIsBit(witness.EBits);

        //Recompose the digest bits into a field element and tie it to the signature's digest; this
        //is also what guarantees e is nonzero advice-independently.
        ReadOnlyMemory<byte> powerOfTwo = field.Compiler.One;
        int est = backend.Constant(field.Compiler.Zero.Span);
        for(int i = 0; i < LongfellowLogic.BitWidth256; i++)
        {
            est = backend.Axpy(est, powerOfTwo.Span, logic.Eval(witness.EBits[i]));

            var doubled = new byte[Scalar.SizeBytes];
            field.Compiler.Add(powerOfTwo.Span, powerOfTwo.Span, doubled, field.Compiler.Curve);
            powerOfTwo = doubled;
        }

        _ = logic.AssertEqual(est, witness.E);

        //The zero byte cannot appear in the token's strings, so it is the shift filler.
        LongfellowBitWire[] zeroByte = logic.BitVector(LongfellowLogic.BitWidth8, 0);

        //Shift the payload region to the front, then decode it. The undecoded output tail keeps the
        //value-initialized shape the reference's C++ default construction produces (a zero affine
        //reading over wire zero), which the attribute shifts below consume as-is.
        int payloadCapacity = BytesPerBlock * (maxBlocks - LongfellowJwtConstants.ReservedTailBlocks);
        var shiftBuffer = NewByteVectorArray(payloadCapacity);
        routing.Shift(witness.PayloadIndex, shiftBuffer, witness.Preimage, zeroByte, ShiftUnroll);

        var decodeBuffer = new LongfellowBitWire[BytesPerBlock * maxBlocks][];
        for(int i = 0; i < decodeBuffer.Length; i++)
        {
            decodeBuffer[i] = DefaultByteVector();
        }

        var decoder = new LongfellowBase64Decoder(logic);
        decoder.RawUrlDecodeWithLength(shiftBuffer, decodeBuffer, payloadCapacity, witness.PayloadLength);

        //Shift each attribute's claimed position to the front and compare against the disclosed
        //pattern up to its genuine length.
        for(int i = 0; i < witness.AttributeIndices.Length; i++)
        {
            var attributeWindow = NewByteVectorArray(LongfellowJwtOpenedAttributeWires.PatternLength);
            routing.Shift(witness.AttributeIndices[i], attributeWindow, decodeBuffer, zeroByte, ShiftUnroll);
            AssertStringEqual(LongfellowJwtOpenedAttributeWires.PatternLength, attributes[i].Length, attributeWindow, attributes[i].Pattern);
        }
    }


    /// <summary>
    /// The reference's <c>assert_string_eq</c>: for every position below the claimed length,
    /// asserts the shifted byte equals the disclosed pattern byte.
    /// </summary>
    /// <param name="max">The fixed comparison width.</param>
    /// <param name="length">The claimed length vector.</param>
    /// <param name="got">The shifted bytes.</param>
    /// <param name="want">The disclosed pattern bytes.</param>
    public void AssertStringEqual(int max, LongfellowBitWire[] length, LongfellowBitWire[][] got, LongfellowBitWire[][] want)
    {
        ArgumentNullException.ThrowIfNull(length);
        ArgumentNullException.ThrowIfNull(got);
        ArgumentNullException.ThrowIfNull(want);

        for(int j = 0; j < max; j++)
        {
            LongfellowBitWire inRange = logic.LessThan((ulong)j, length);
            LongfellowBitWire same = logic.Equal(got[j], want[j]);
            _ = logic.AssertImplies(inRange, same);
        }
    }


    /// <summary>Allocates an array of empty byte vectors for a shift destination (every entry is fully overwritten by the shift's final copy).</summary>
    /// <param name="count">The vector count.</param>
    /// <returns>The array.</returns>
    private static LongfellowBitWire[][] NewByteVectorArray(int count)
    {
        var array = new LongfellowBitWire[count][];
        for(int i = 0; i < count; i++)
        {
            array[i] = new LongfellowBitWire[LongfellowLogic.BitWidth8];
        }

        return array;
    }


    /// <summary>
    /// One byte vector of value-initialized bits — the replica of the reference's default-constructed
    /// C++ <c>BitW</c> (zero constant term, zero linear coefficient, wire zero). The decode buffer's
    /// undecoded tail must hold exactly this shape, not a constant-zero bit, for the compiled circuit
    /// to match the reference structure.
    /// </summary>
    /// <returns>The vector.</returns>
    private LongfellowBitWire[] DefaultByteVector()
    {
        var vector = new LongfellowBitWire[LongfellowLogic.BitWidth8];
        for(int i = 0; i < vector.Length; i++)
        {
            vector[i] = new LongfellowBitWire(field.Compiler.Zero, field.Compiler.Zero, 0);
        }

        return vector;
    }
}
