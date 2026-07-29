using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

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
/// The three production instances:
/// </para>
/// <list type="bullet">
///   <item><description><b>GF(2^128) hash circuit</b> (<see cref="ForGf2k128"/>): element width 16, the wire bytes are the low 16 bytes least-significant first; the subfield is the LCH14 basis subfield, so <c>of_scalar(u)</c> is <c>Lch14AdditiveFft.NodeElement(u)</c>; the evaluation points are <c>{0, 1, g}</c> with <c>g</c> the subfield generator <c>BasisElement(1)</c>, and subtraction coincides with addition (XOR), so negation is the identity.</description></item>
///   <item><description><b>P-256 base-field signature circuit</b> (<see cref="ForFp256"/>): element width 32, the wire bytes are the whole element least-significant first; the subfield IS the base field, so <c>of_scalar(u)</c> is the integer <c>u</c> reduced mod p as a canonical scalar; the evaluation points are <c>{0, 1, 2}</c>, and subtraction is genuine field subtraction.</description></item>
///   <item><description><b>FIPS 204 sextic ML-DSA circuit field</b> (<see cref="ForFp24Sextic"/>): element width 24 — six 4-byte little-endian coordinates on the wire, limb 0 first (<c>fp24_6.h to_bytes_field</c>); <c>of_scalar(u)</c> embeds into coordinate 0; the evaluation points are <c>{0, 1, 2}</c>; sampling rejects per 23-bit coordinate through the injected <see cref="LongfellowElementSampleDelegate"/>.</description></item>
/// </list>
/// <para>
/// Keeping these field-specific behaviours in one injected bundle is what lets the single Ligero/ZK port
/// serve both fields. The GF instance reproduces exactly the values the original binary-only port baked in
/// (16-byte framing, <c>g</c> as the third point, add-as-subtract), so wiring the GF path through this
/// profile leaves its bytes unchanged.
/// </para>
/// <para>
/// Disposable: the two retained constant scalars (the third evaluation point and the working-domain one)
/// are pool-rented, cleared and released on disposal.
/// </para>
/// </remarks>
internal sealed class LongfellowFieldProfile: IDisposable
{
    /// <summary>The canonical scalar container width every profile frames its retained constants and working values at.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The GF(2^128) on-wire element width in bytes (the reference <c>GF2_128</c>'s <c>kBytes</c>); the sample draw covers exactly the element width, so it also serves as that profile's <c>sampleByteLength</c>.</summary>
    private const int Gf2128ElementBytes = 16;

    /// <summary>The GF(2^128) field bit count (the reference <c>GF2_128</c>'s <c>kBits</c>); that profile's <c>exact_bits_</c>.</summary>
    private const int Gf2128BitCount = 128;

    /// <summary>The P-256 base-field on-wire element width in bytes (the reference <c>Fp256Base</c>'s <c>kBytes</c>); also that profile's <c>sampleByteLength</c>.</summary>
    private const int Fp256ElementBytes = 32;

    /// <summary>The P-256 base-field bit count (the reference <c>Fp256Base</c>'s <c>kBits</c>: p's top byte is <c>0xff</c>, so <c>exact_bits_</c> spans the whole element).</summary>
    private const int Fp256BitCount = 256;

    /// <summary>The FIPS 204 sextic-extension on-wire element width in bytes (the reference <c>Fp24_6</c>'s <c>kBytes</c>: six four-byte coordinates); also that profile's <c>sampleByteLength</c>.</summary>
    private const int Fp24SexticElementBytes = 24;

    /// <summary>The FIPS 204 sextic-extension field bit count (the reference <c>Fp24_6</c>'s <c>kBits</c>).</summary>
    private const int Fp24SexticBitCount = 192;

    /// <summary>The prime profiles' third polynomial evaluation point (<c>poly_evaluation_point(2)</c> of <c>{0, 1, 2}</c>); the GF profile uses the subfield generator instead.</summary>
    private const uint PrimeThirdEvaluationPoint = 2;

    /// <summary>The number of retained constant scalars in the pooled rent: the third evaluation point and the working-domain one.</summary>
    private const int ConstantSlotCount = 2;

    /// <summary>The byte offset of the third evaluation point inside the pooled constant rent.</summary>
    private const int ThirdPointSlotOffset = 0;

    /// <summary>The byte offset of the working-domain one inside the pooled constant rent.</summary>
    private const int WorkingOneSlotOffset = ScalarSize;

    /// <summary>The pooled rent holding the two retained constant scalars side by side; cleared and released on disposal, <see langword="null"/> once disposed.</summary>
    private IMemoryOwner<byte>? constants;

    private readonly Action<uint, Span<byte>> ofScalar;
    private readonly LongfellowCanonicalRangeDelegate? inRange;
    private readonly int sampleByteLength;
    private readonly int exactBits;

    /// <summary>The field's own sample loop for elements that are not a single little-endian integer (the sextic profile's per-coordinate rejection); <see langword="null"/> for the single-integer fields, which use the generic mask-then-reject loop.</summary>
    private readonly LongfellowElementSampleDelegate? sampleOverride;

    //The canonical<->working-domain converters (Perf Increment 1). For the GF profile and the canonical Fp
    //profile these are null (the working domain IS canonical); for the Montgomery Fp profile toWorking lifts
    //canonical->Montgomery (to_montgomery) and toCanonical drops Montgomery->canonical (from_montgomery).
    //The range check / mask-to-exact-bits ALWAYS run on the canonical representative; the lift to the working
    //domain happens only after acceptance.
    private readonly LongfellowDomainConvertDelegate? toWorking;
    private readonly LongfellowDomainConvertDelegate? toCanonical;


    /// <summary>The on-wire element byte width (<c>Field::kBytes</c>): 16 for GF(2^128), 32 for the P-256 base field, 24 for the FIPS 204 sextic circuit field.</summary>
    public int ElementBytes { get; }


    private LongfellowFieldProfile(int elementBytes, ReadOnlySpan<byte> thirdEvaluationPoint, Action<uint, Span<byte>> ofScalar, LongfellowCanonicalRangeDelegate? inRange, int sampleByteLength, int exactBits, LongfellowDomainConvertDelegate? toWorking, LongfellowDomainConvertDelegate? toCanonical, BaseMemoryPool pool, LongfellowElementSampleDelegate? sampleOverride = null)
    {
        ElementBytes = elementBytes;
        this.ofScalar = ofScalar;
        this.inRange = inRange;
        this.sampleByteLength = sampleByteLength;
        this.exactBits = exactBits;
        this.toWorking = toWorking;
        this.toCanonical = toCanonical;
        this.sampleOverride = sampleOverride;

        IMemoryOwner<byte> rentedConstants = pool.Rent(ConstantSlotCount * ScalarSize);
        try
        {
            Span<byte> slots = rentedConstants.Memory.Span[..(ConstantSlotCount * ScalarSize)];
            slots.Clear();
            thirdEvaluationPoint.CopyTo(slots.Slice(ThirdPointSlotOffset, ScalarSize));

            //The field multiplicative one in the WORKING domain. The canonical representative is the integer 1
            //(the last byte of the big-endian scalar = 0x01); for the canonical working domain (GF and the
            //canonical Fp profile) that IS the working one, byte-identical to the stack's former hardcoded
            //SetOne. For the Montgomery Fp profile toWorking lifts it to to_montgomery(1) = R. This is a
            //DEDICATED working-domain one, distinct from OfScalar(1) (which for GF is the Lch14 NodeElement(1),
            //a node element, not the field one).
            Span<byte> workingOne = slots.Slice(WorkingOneSlotOffset, ScalarSize);
            workingOne[ScalarSize - 1] = 0x01;
            toWorking?.Invoke(workingOne, workingOne);
        }
        catch
        {
            rentedConstants.Dispose();
            throw;
        }

        constants = rentedConstants;
    }


    /// <summary>
    /// The GF(2^128) hash-circuit profile: 16-byte framing, the LCH14 subfield <c>of_scalar</c>, and the
    /// third evaluation point <c>g = BasisElement(1)</c>.
    /// </summary>
    /// <param name="fft">The LCH14 additive-FFT engine supplying the subfield generator and node elements.</param>
    /// <param name="pool">Pool the retained constant scalars rent from.</param>
    public static LongfellowFieldProfile ForGf2k128(Lch14AdditiveFft fft, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(fft);
        ArgumentNullException.ThrowIfNull(pool);

        Span<byte> g = stackalloc byte[ScalarSize];
        fft.BasisElement(1).CopyTo(g);

        //GF(2^128): exact_bits_ == 128 ⇒ sample draws (128 + 7) / 8 = 16 bytes per attempt and never rejects
        //(every 16-byte sequence is a valid element — gf2_128.h:181-188).
        return new LongfellowFieldProfile(Gf2128ElementBytes, g, (coordinate, destination) => fft.NodeElement(coordinate, destination), inRange: null, sampleByteLength: Gf2128ElementBytes, exactBits: Gf2128BitCount, toWorking: null, toCanonical: null, pool);
    }


    /// <summary>
    /// The P-256 base-field signature-circuit profile: 32-byte framing, <c>of_scalar(u) = u mod p</c>, and
    /// the third evaluation point <c>2</c>.
    /// </summary>
    /// <param name="ofScalar">The base-field <c>of_scalar</c>: the integer <paramref name="ofScalar"/> argument reduced mod p as a canonical big-endian scalar.</param>
    /// <param name="inRange">The <c>fits</c> predicate (<c>an &lt; p</c>) the <c>of_bytes_field</c> reversal applies to a freshly read element; the wire bytes are rejected when the integer reaches the modulus.</param>
    /// <param name="pool">Pool the retained constant scalars rent from.</param>
    public static LongfellowFieldProfile ForFp256(Action<uint, Span<byte>> ofScalar, LongfellowCanonicalRangeDelegate inRange, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(ofScalar);
        ArgumentNullException.ThrowIfNull(inRange);
        ArgumentNullException.ThrowIfNull(pool);

        Span<byte> two = stackalloc byte[ScalarSize];
        ofScalar(PrimeThirdEvaluationPoint, two);

        //P-256 base field: p's top byte is 0xff ⇒ exact_bits_ == 256 ⇒ sample draws (256 + 7) / 8 = 32 bytes
        //per attempt and the mask-to-exact-bits is a no-op (fp_generic.h:360-371; p256.h:26).
        return new LongfellowFieldProfile(Fp256ElementBytes, two, ofScalar, inRange, sampleByteLength: Fp256ElementBytes, exactBits: Fp256BitCount, toWorking: null, toCanonical: null, pool);
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
    /// <param name="pool">Pool the retained constant scalars rent from.</param>
    public static LongfellowFieldProfile ForFp256Montgomery(Action<uint, Span<byte>> ofScalar, LongfellowCanonicalRangeDelegate inRange, LongfellowDomainConvertDelegate toMontgomery, LongfellowDomainConvertDelegate fromMontgomery, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(ofScalar);
        ArgumentNullException.ThrowIfNull(inRange);
        ArgumentNullException.ThrowIfNull(toMontgomery);
        ArgumentNullException.ThrowIfNull(fromMontgomery);
        ArgumentNullException.ThrowIfNull(pool);

        //of_scalar(2) is built canonical then lifted, so the stored third point is Montgomery(2) — the value
        //the degree-2 Lagrange fold multiplies in the Montgomery working domain.
        Span<byte> two = stackalloc byte[ScalarSize];
        ofScalar(PrimeThirdEvaluationPoint, two);
        toMontgomery(two, two);

        return new LongfellowFieldProfile(Fp256ElementBytes, two, ofScalar, inRange, sampleByteLength: Fp256ElementBytes, exactBits: Fp256BitCount, toWorking: toMontgomery, toCanonical: fromMontgomery, pool);
    }


    /// <summary>
    /// The FIPS 204 sextic ML-DSA circuit-field profile: 24-byte framing (six 4-byte little-endian
    /// coordinates, limb 0 first — <c>fp24_6.h to_bytes_field</c>), <c>of_scalar(u)</c> embedding into
    /// coordinate 0, the third evaluation point <c>2</c>, and the per-coordinate rejection sampler
    /// (<c>Fp24_6::sample</c>: six independent 23-bit base-field draws, which the single-integer mask
    /// below cannot express).
    /// </summary>
    /// <param name="ofScalar">The field's <c>of_scalar(u)</c>: the integer <paramref name="ofScalar"/> argument reduced mod q into coordinate 0 of the canonical scalar.</param>
    /// <param name="inRange">The <c>fits</c> predicate applied to a freshly read element: every 4-byte big-endian coordinate below q and the container's zero prefix intact.</param>
    /// <param name="sampler">The per-coordinate rejection sampler (the reference's <c>Fp24_6::sample</c> draw structure).</param>
    /// <param name="pool">Pool the retained constant scalars rent from.</param>
    public static LongfellowFieldProfile ForFp24Sextic(Action<uint, Span<byte>> ofScalar, LongfellowCanonicalRangeDelegate inRange, LongfellowElementSampleDelegate sampler, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(ofScalar);
        ArgumentNullException.ThrowIfNull(inRange);
        ArgumentNullException.ThrowIfNull(sampler);
        ArgumentNullException.ThrowIfNull(pool);

        Span<byte> two = stackalloc byte[ScalarSize];
        ofScalar(PrimeThirdEvaluationPoint, two);

        //sampleByteLength/exactBits describe the element width for the wire framing; the sampler override
        //replaces the generic single-integer loop, which cannot mask six 23-bit coordinates.
        return new LongfellowFieldProfile(Fp24SexticElementBytes, two, ofScalar, inRange, sampleByteLength: Fp24SexticElementBytes, exactBits: Fp24SexticBitCount, toWorking: null, toCanonical: null, pool, sampleOverride: sampler);
    }


    /// <summary>Copies the third polynomial evaluation point (<c>{0, 1, thirdPoint}</c>) into <paramref name="destination"/>.</summary>
    /// <param name="destination">Receives the canonical scalar; must be <see cref="Scalar.SizeBytes"/> bytes.</param>
    /// <exception cref="ObjectDisposedException">When the profile has been disposed.</exception>
    public void CopyThirdEvaluationPoint(Span<byte> destination) => ConstantSlot(ThirdPointSlotOffset).CopyTo(destination);


    /// <summary>
    /// Copies the field multiplicative one in the WORKING domain into <paramref name="destination"/>: the
    /// canonical <c>0x01</c> for GF / the canonical Fp profile (byte-identical to the stack's former
    /// hardcoded one), <c>to_montgomery(1) = R</c> for the Montgomery Fp profile. This is the dedicated
    /// working-domain one the shared sumcheck/eq/zk logic multiplies, NOT <see cref="OfScalar"/>(1).
    /// </summary>
    /// <param name="destination">Receives the working-domain scalar; must be <see cref="Scalar.SizeBytes"/> bytes.</param>
    /// <exception cref="ObjectDisposedException">When the profile has been disposed.</exception>
    public void CopyWorkingOne(Span<byte> destination) => ConstantSlot(WorkingOneSlotOffset).CopyTo(destination);


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
    /// every 16-byte sequence is a valid element, so the reversal is total; the prime-field profiles apply
    /// the reference's <c>fits</c> guard — <c>an &lt; p</c> for Fp256, every 4-byte coordinate below <c>q</c>
    /// for the FIPS 204 sextic field — and reject out-of-range wire bytes: the reference's
    /// <c>fp_generic.h</c>/<c>fp24_6.h</c> <c>of_bytes_field</c> return <c>std::nullopt</c> there, and every
    /// reference caller in this stack <c>check()</c>s the value is present, so an out-of-range draw aborts.
    /// </summary>
    /// <param name="littleEndian">The <see cref="ElementBytes"/> wire bytes, least-significant first.</param>
    /// <param name="working">Receives the working-domain scalar (canonical, or Montgomery for the Montgomery Fp profile).</param>
    /// <exception cref="ArgumentOutOfRangeException">For a prime-field profile, when the wire bytes encode an out-of-range element.</exception>
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
    /// <see cref="FromBytesField"/>, but an out-of-range prime-field element (an Fp256 integer at or
    /// above <c>p</c>, or a sextic element with a coordinate at or above <c>q</c>) returns
    /// <see langword="false"/> (with <paramref name="working"/> cleared) instead of throwing — the reference's
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
    /// <c>random.h:39-41</c>): draws a uniformly random field element. A profile whose element is not a
    /// single little-endian integer supplies its own draw structure through the injected
    /// <see cref="LongfellowElementSampleDelegate"/> (the sextic profile's per-coordinate 23-bit rejection,
    /// the reference's <c>Fp24_6::sample</c>) and never enters the generic loop; the single-integer fields
    /// draw by the mask-then-reject loop. Each
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

        //A field whose element is not a single little-endian integer supplies its own draw structure
        //(the sextic profile's per-coordinate rejection); the generic loop below serves the rest.
        if(sampleOverride is not null)
        {
            sampleOverride(fillBytes, working);

            return;
        }

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


    /// <summary>
    /// Releases the pooled constant rent (cleared first). Safe to call more than once; the copy accessors
    /// throw once disposed.
    /// </summary>
    public void Dispose()
    {
        IMemoryOwner<byte>? local = constants;
        if(local is not null)
        {
            constants = null;
            local.Memory.Span[..(ConstantSlotCount * ScalarSize)].Clear();
            local.Dispose();
        }
    }


    /// <summary>Reads one retained constant scalar from the pooled rent.</summary>
    /// <param name="offset">The slot's byte offset inside the rent.</param>
    /// <returns>The constant's canonical bytes.</returns>
    /// <exception cref="ObjectDisposedException">When the profile has been disposed.</exception>
    private ReadOnlySpan<byte> ConstantSlot(int offset)
    {
        IMemoryOwner<byte> owner = constants ?? throw new ObjectDisposedException(nameof(LongfellowFieldProfile));

        return owner.Memory.Span.Slice(offset, ScalarSize);
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
