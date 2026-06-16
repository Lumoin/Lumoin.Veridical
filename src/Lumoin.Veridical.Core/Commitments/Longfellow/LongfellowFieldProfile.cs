using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The field-specific pieces the wire-format Ligero / ZK port needs but that are not already carried by the
/// injected arithmetic delegates: the on-wire element byte width, the conversion between the wire's
/// little-endian <c>to_bytes_field</c> framing and the library's canonical 32-byte big-endian scalar, the
/// subfield <c>of_scalar</c> generator the commit's padding draws map through, and the third polynomial
/// evaluation point the degree-2 round-polynomial Lagrange fold uses.
/// </summary>
/// <remarks>
/// <para>
/// The two production instances:
/// </para>
/// <list type="bullet">
///   <item><description><b>GF(2^128) hash circuit</b> (<see cref="ForGf2k128"/>): element width 16, the wire bytes are the low 16 bytes least-significant first; the subfield is the LCH14 basis subfield, so <c>of_scalar(u)</c> is <c>Lch14AdditiveFft.NodeElement(u)</c>; the evaluation points are <c>{0, 1, g}</c> with <c>g</c> the subfield generator <c>BasisElement(1)</c>, and subtraction coincides with addition (XOR), so negation is the identity.</description></item>
///   <item><description><b>P-256 base-field signature circuit</b> (<see cref="ForFp256"/>): element width 32, the wire bytes are the whole element least-significant first; the subfield IS the base field, so <c>of_scalar(u)</c> is the integer <c>u</c> reduced mod p as a canonical scalar; the evaluation points are <c>{0, 1, 2}</c>, and subtraction is genuine field subtraction.</description></item>
/// </list>
/// <para>
/// Keeping these field-specific behaviours in one injected bundle is what lets the single Ligero/ZK port
/// serve both fields. The GF instance reproduces exactly the values the original binary-only port baked in
/// (16-byte framing, <c>g</c> as the third point, add-as-subtract), so wiring the GF path through this
/// profile leaves its bytes unchanged.
/// </para>
/// </remarks>
internal sealed class LongfellowFieldProfile
{
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly byte[] thirdEvaluationPoint;
    private readonly byte[] workingOne;
    private readonly Action<uint, Span<byte>> ofScalar;
    private readonly LongfellowCanonicalRangeDelegate? inRange;
    private readonly int sampleByteLength;
    private readonly int exactBits;

    //The canonical<->working-domain converters (Perf Increment 1). For the GF profile and the canonical Fp
    //profile these are null (the working domain IS canonical); for the Montgomery Fp profile toWorking lifts
    //canonical->Montgomery (to_montgomery) and toCanonical drops Montgomery->canonical (from_montgomery).
    //The range check / mask-to-exact-bits ALWAYS run on the canonical representative; the lift to the working
    //domain happens only after acceptance.
    private readonly LongfellowDomainConvertDelegate? toWorking;
    private readonly LongfellowDomainConvertDelegate? toCanonical;


    /// <summary>The on-wire element byte width (<c>Field::kBytes</c>): 16 for GF(2^128), 32 for the P-256 base field.</summary>
    public int ElementBytes { get; }


    private LongfellowFieldProfile(int elementBytes, byte[] thirdEvaluationPoint, Action<uint, Span<byte>> ofScalar, LongfellowCanonicalRangeDelegate? inRange, int sampleByteLength, int exactBits, LongfellowDomainConvertDelegate? toWorking, LongfellowDomainConvertDelegate? toCanonical)
    {
        ElementBytes = elementBytes;
        this.thirdEvaluationPoint = thirdEvaluationPoint;
        this.ofScalar = ofScalar;
        this.inRange = inRange;
        this.sampleByteLength = sampleByteLength;
        this.exactBits = exactBits;
        this.toWorking = toWorking;
        this.toCanonical = toCanonical;

        //The field multiplicative one in the WORKING domain. The canonical representative is the integer 1
        //(the last byte of the big-endian scalar = 0x01); for the canonical working domain (GF and the
        //canonical Fp profile) that IS the working one, byte-identical to the stack's former hardcoded
        //SetOne. For the Montgomery Fp profile toWorking lifts it to to_montgomery(1) = R. This is a
        //DEDICATED working-domain one, distinct from OfScalar(1) (which for GF is the Lch14 NodeElement(1),
        //a node element, not the field one).
        workingOne = new byte[ScalarSize];
        workingOne[ScalarSize - 1] = 0x01;
        toWorking?.Invoke(workingOne, workingOne);
    }


    /// <summary>
    /// The GF(2^128) hash-circuit profile: 16-byte framing, the LCH14 subfield <c>of_scalar</c>, and the
    /// third evaluation point <c>g = BasisElement(1)</c>.
    /// </summary>
    /// <param name="fft">The LCH14 additive-FFT engine supplying the subfield generator and node elements.</param>
    public static LongfellowFieldProfile ForGf2k128(Lch14AdditiveFft fft)
    {
        ArgumentNullException.ThrowIfNull(fft);

        byte[] g = new byte[ScalarSize];
        fft.BasisElement(1).CopyTo(g);

        //GF(2^128): exact_bits_ == 128 ⇒ sample draws (128 + 7) / 8 = 16 bytes per attempt and never rejects
        //(every 16-byte sequence is a valid element — gf2_128.h:181-188).
        return new LongfellowFieldProfile(16, g, (coordinate, destination) => fft.NodeElement(coordinate, destination), inRange: null, sampleByteLength: 16, exactBits: 128, toWorking: null, toCanonical: null);
    }


    /// <summary>
    /// The P-256 base-field signature-circuit profile: 32-byte framing, <c>of_scalar(u) = u mod p</c>, and
    /// the third evaluation point <c>2</c>.
    /// </summary>
    /// <param name="ofScalar">The base-field <c>of_scalar</c>: the integer <paramref name="ofScalar"/> argument reduced mod p as a canonical big-endian scalar.</param>
    /// <param name="inRange">The <c>fits</c> predicate (<c>an &lt; p</c>) the <c>of_bytes_field</c> reversal applies to a freshly read element; the wire bytes are rejected when the integer reaches the modulus.</param>
    public static LongfellowFieldProfile ForFp256(Action<uint, Span<byte>> ofScalar, LongfellowCanonicalRangeDelegate inRange)
    {
        ArgumentNullException.ThrowIfNull(ofScalar);
        ArgumentNullException.ThrowIfNull(inRange);

        byte[] two = new byte[ScalarSize];
        ofScalar(2, two);

        //P-256 base field: p's top byte is 0xff ⇒ exact_bits_ == 256 ⇒ sample draws (256 + 7) / 8 = 32 bytes
        //per attempt and the mask-to-exact-bits is a no-op (fp_generic.h:360-371; p256.h:26).
        return new LongfellowFieldProfile(32, two, ofScalar, inRange, sampleByteLength: 32, exactBits: 256, toWorking: null, toCanonical: null);
    }


    /// <summary>
    /// The Montgomery-domain P-256 base-field signature-circuit profile (Perf Increment 1): identical wire
    /// behaviour to <see cref="ForFp256"/>, but the working domain is the Montgomery residue. Every value the
    /// profile produces into the working set is lifted to Montgomery via <paramref name="toMontgomery"/>
    /// (<c>of_scalar</c>, the third evaluation point, the accepted <c>of_bytes_field</c>/<c>sample</c> draw);
    /// every value it emits to the wire is dropped to canonical via <paramref name="fromMontgomery"/> first
    /// (<c>to_bytes_field</c>). The <c>fits</c> range check and the mask-to-exact-bits ALWAYS run on the
    /// canonical representative — the lift to Montgomery happens only after acceptance — so the wire bytes are
    /// byte-identical to the canonical profile's.
    /// </summary>
    /// <param name="ofScalar">The base-field <c>of_scalar(u)</c> producing the canonical big-endian scalar (the lift to Montgomery is applied internally).</param>
    /// <param name="inRange">The <c>fits</c> predicate (<c>an &lt; p</c>) applied to the CANONICAL value before the Montgomery lift.</param>
    /// <param name="toMontgomery">The canonical-&gt;Montgomery lift (<c>to_montgomery</c>).</param>
    /// <param name="fromMontgomery">The Montgomery-&gt;canonical drop (<c>from_montgomery</c>).</param>
    public static LongfellowFieldProfile ForFp256Montgomery(Action<uint, Span<byte>> ofScalar, LongfellowCanonicalRangeDelegate inRange, LongfellowDomainConvertDelegate toMontgomery, LongfellowDomainConvertDelegate fromMontgomery)
    {
        ArgumentNullException.ThrowIfNull(ofScalar);
        ArgumentNullException.ThrowIfNull(inRange);
        ArgumentNullException.ThrowIfNull(toMontgomery);
        ArgumentNullException.ThrowIfNull(fromMontgomery);

        //of_scalar(2) is built canonical then lifted, so the stored third point is Montgomery(2) — the value
        //the degree-2 Lagrange fold multiplies in the Montgomery working domain.
        byte[] twoCanonical = new byte[ScalarSize];
        ofScalar(2, twoCanonical);
        byte[] two = new byte[ScalarSize];
        toMontgomery(twoCanonical, two);

        return new LongfellowFieldProfile(32, two, ofScalar, inRange, sampleByteLength: 32, exactBits: 256, toWorking: toMontgomery, toCanonical: fromMontgomery);
    }


    /// <summary>Copies the third polynomial evaluation point (<c>{0, 1, thirdPoint}</c>) into <paramref name="destination"/>.</summary>
    /// <param name="destination">Receives the canonical scalar; must be <see cref="Scalar.SizeBytes"/> bytes.</param>
    public void CopyThirdEvaluationPoint(Span<byte> destination) => thirdEvaluationPoint.CopyTo(destination);


    /// <summary>
    /// Copies the field multiplicative one in the WORKING domain into <paramref name="destination"/>: the
    /// canonical <c>0x01</c> for GF / the canonical Fp profile (byte-identical to the stack's former
    /// hardcoded one), <c>to_montgomery(1) = R</c> for the Montgomery Fp profile. This is the dedicated
    /// working-domain one the shared sumcheck/eq/zk logic multiplies, NOT <see cref="OfScalar"/>(1).
    /// </summary>
    /// <param name="destination">Receives the working-domain scalar; must be <see cref="Scalar.SizeBytes"/> bytes.</param>
    public void CopyWorkingOne(Span<byte> destination) => workingOne.CopyTo(destination);


    /// <summary>The subfield <c>of_scalar(coordinate)</c> the commit's padding draws map through, produced in
    /// the working domain (canonical for GF / the canonical Fp profile, Montgomery for the Montgomery Fp
    /// profile).</summary>
    /// <param name="coordinate">The little-endian-read coordinate integer.</param>
    /// <param name="destination">Receives the working-domain scalar; must be <see cref="Scalar.SizeBytes"/> bytes.</param>
    public void OfScalar(uint coordinate, Span<byte> destination)
    {
        ofScalar(coordinate, destination);
        toWorking?.Invoke(destination, destination);
    }


    /// <summary>
    /// <c>of_bytes_field</c>: reverses the <see cref="ElementBytes"/> little-endian wire bytes into the low
    /// bytes of a canonical 32-byte big-endian scalar, the leading bytes zeroed. For the GF(2^128) profile
    /// every 16-byte sequence is a valid element, so the reversal is total; the Fp256 profile additionally
    /// applies the reference's <c>fits</c> guard (<c>an &lt; p</c>) and rejects out-of-range wire bytes — the
    /// reference's <c>fp_generic.h of_bytes_field</c> returns <c>std::nullopt</c> there, and every reference
    /// caller in this stack <c>check()</c>s the value is present, so an out-of-range draw aborts.
    /// </summary>
    /// <param name="littleEndian">The <see cref="ElementBytes"/> wire bytes, least-significant first.</param>
    /// <param name="working">Receives the working-domain scalar (canonical, or Montgomery for the Montgomery Fp profile).</param>
    /// <exception cref="ArgumentOutOfRangeException">For the Fp256 profile, when the little-endian integer is not below the modulus.</exception>
    public void FromBytesField(ReadOnlySpan<byte> littleEndian, Span<byte> working)
    {
        working.Clear();
        for(int i = 0; i < ElementBytes; i++)
        {
            working[ScalarSize - 1 - i] = littleEndian[i];
        }

        //The fits guard runs on the CANONICAL value, before any working-domain lift.
        if(inRange is not null && !inRange(working))
        {
            throw new ArgumentOutOfRangeException(nameof(littleEndian), "of_bytes_field: the little-endian wire bytes encode an integer at or above the field modulus.");
        }

        toWorking?.Invoke(working, working);
    }


    /// <summary>
    /// The non-throwing <c>of_bytes_field</c> the parse-safe proof readers use: as
    /// <see cref="FromBytesField"/>, but an out-of-range Fp256 element returns <see langword="false"/>
    /// (with <paramref name="canonical"/> cleared) instead of throwing — the reference's
    /// <c>read_sc_proof</c>/<c>read_elt</c> turn the <c>std::nullopt</c> into a graceful
    /// <c>return false</c>, never a panic, because the wire bytes are attacker-controlled there.
    /// </summary>
    /// <param name="littleEndian">The <see cref="ElementBytes"/> wire bytes, least-significant first.</param>
    /// <param name="working">Receives the working-domain scalar (canonical, or Montgomery for the Montgomery Fp profile), or all zeros on rejection.</param>
    /// <returns><see langword="true"/> when the bytes encode a field element; otherwise <see langword="false"/>.</returns>
    public bool TryFromBytesField(ReadOnlySpan<byte> littleEndian, Span<byte> working)
    {
        working.Clear();
        for(int i = 0; i < ElementBytes; i++)
        {
            working[ScalarSize - 1 - i] = littleEndian[i];
        }

        //The fits guard runs on the CANONICAL value, before any working-domain lift.
        if(inRange is not null && !inRange(working))
        {
            working.Clear();

            return false;
        }

        toWorking?.Invoke(working, working);

        return true;
    }


    /// <summary>
    /// <c>sample</c> (<c>fp_generic.h:360-371</c>, dispatched from <c>RandomEngine::elt(F)</c> at
    /// <c>random.h:39-41</c>): draws a uniformly random field element by the mask-then-reject loop. Each
    /// attempt fills <see cref="sampleByteLength"/> = <c>(exact_bits_ + 7) / 8</c> raw bytes through
    /// <paramref name="fillBytes"/>, reads them little-endian into the canonical low bytes, masks off the
    /// bits above <see cref="exactBits"/>, and — for the prime field — redraws a fresh block while the value
    /// reaches the modulus (<c>an &lt; m_</c>). The GF(2^128) profile has no range predicate, so the first
    /// 16-byte draw is always accepted and this coincides byte-for-byte with <see cref="FromBytesField"/>;
    /// the Fp256 profile's mask is a no-op (<c>exact_bits_ == 256</c> spans the whole 32-byte draw) and the
    /// reject probability is ≈ 2⁻²²⁴, but the loop is byte-faithful — a fresh draw per attempt, no reuse.
    /// </summary>
    /// <param name="fillBytes">The raw-byte fill callback (the reference's <c>fill_bytes(total_l, buf)</c>): the transcript PRF squeeze, the commit's entropy source, or the pad's random stream.</param>
    /// <param name="working">Receives the working-domain scalar (canonical, or Montgomery for the Montgomery Fp profile).</param>
    /// <exception cref="ArgumentNullException">When <paramref name="fillBytes"/> is <see langword="null"/>.</exception>
    public void SampleElement(LongfellowRandomByteSource fillBytes, Span<byte> working)
    {
        ArgumentNullException.ThrowIfNull(fillBytes);

        Span<byte> littleEndianBuffer = stackalloc byte[ScalarSize];
        Span<byte> littleEndian = littleEndianBuffer[..sampleByteLength];
        for(;;)
        {
            fillBytes(littleEndian);

            //of_bytes(buf, exact_bits_): the little-endian bytes reverse into the canonical low bytes, then
            //the bits above exact_bits_ are masked off (nat.h:111-120). The draw covers sampleByteLength
            //bytes; exact_bits_ <= sampleByteLength·8, so the reversal fills the low sampleByteLength bytes.
            working.Clear();
            for(int i = 0; i < sampleByteLength; i++)
            {
                working[ScalarSize - 1 - i] = littleEndian[i];
            }

            MaskToExactBits(working);

            //fits(an): accept when below the modulus. The mask and the range check run on the CANONICAL
            //representative; the working-domain lift happens only after acceptance. The GF profile has no
            //predicate (always accepts); the Fp256 profile redraws a fresh block on an out-of-range draw.
            if(inRange is null || inRange(working))
            {
                toWorking?.Invoke(working, working);
                littleEndian.Clear();

                return;
            }
        }
    }


    /// <summary>
    /// <c>to_bytes_field</c>: drops the working-domain scalar to canonical (a no-op for GF / the canonical Fp
    /// profile; <c>from_montgomery</c> for the Montgomery Fp profile), then reverses the low
    /// <see cref="ElementBytes"/> big-endian bytes into <see cref="ElementBytes"/> little-endian wire bytes.
    /// </summary>
    /// <param name="working">The working-domain scalar (canonical, or Montgomery for the Montgomery Fp profile).</param>
    /// <param name="littleEndian">Receives the <see cref="ElementBytes"/> wire bytes, least-significant first.</param>
    public void ToBytesField(ReadOnlySpan<byte> working, Span<byte> littleEndian)
    {
        if(toCanonical is not null)
        {
            Span<byte> canonical = stackalloc byte[ScalarSize];
            toCanonical(working, canonical);
            for(int i = 0; i < ElementBytes; i++)
            {
                littleEndian[i] = canonical[ScalarSize - 1 - i];
            }

            return;
        }

        for(int i = 0; i < ElementBytes; i++)
        {
            littleEndian[i] = working[ScalarSize - 1 - i];
        }
    }


    //of_bytes(a, nbits) masks the value to its low exact_bits_ bits (nat.h:111-120): the byte holding the
    //bit-exactBits boundary keeps its low (exactBits mod 8) bits, every more-significant element byte is
    //cleared. The canonical scalar is big-endian with the element in its low bytes, so bit b sits in
    //canonical[ScalarSize - 1 - (b / 8)] at position b mod 8. For the production fields exactBits is a byte
    //multiple equal to ElementBytes·8, so nothing is cleared; the loop is faithful for the general case.
    private void MaskToExactBits(Span<byte> canonical)
    {
        int wholeBytes = exactBits / 8;
        int remainderBits = exactBits % 8;

        if(remainderBits != 0)
        {
            int boundaryIndex = ScalarSize - 1 - wholeBytes;
            canonical[boundaryIndex] &= (byte)((1 << remainderBits) - 1);
        }

        //Clear the element bytes strictly above the boundary (the leading bytes are already zero from the
        //of_bytes reversal, but the loop keeps the mask correct for any exactBits below ElementBytes·8).
        for(int byteIndex = wholeBytes + (remainderBits != 0 ? 1 : 0); byteIndex < ElementBytes; byteIndex++)
        {
            canonical[ScalarSize - 1 - byteIndex] = 0;
        }
    }
}
