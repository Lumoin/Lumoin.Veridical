using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The Fiat-Shamir transcript leaf type: a labelled-sponge state plus
/// squeeze counter that threads through every interactive-proof
/// protocol's rounds. Absorbs prover messages and protocol public
/// inputs, deterministically produces verifier challenges.
/// </summary>
/// <remarks>
/// <para>
/// The construction is a labelled sponge over a fixed-output hash plus
/// the same hash's XOF mode for variable-length squeezes, following the
/// shape:
/// </para>
/// <code>
/// init:         state = H("transcript:init"         || domain || seed)
/// absorb:       state = H("transcript:absorb"       || state  || domain || label || data)
/// squeeze:      out   = XOF("transcript:challenge"  || state  || domain || label || counterBE)
///               state = H("transcript:state-update" || state  || out)
///               counter++
/// </code>
/// <para>
/// The four operation prefixes <c>init</c>, <c>absorb</c>,
/// <c>challenge</c>, and <c>state-update</c> are domain separators between
/// the construction's internal kinds of hash call; an adversary cannot
/// confuse a state value with a challenge or with an absorbed message.
/// The domain label provides separation across protocols; the operation
/// labels provide separation across operations within a protocol.
/// </para>
/// <para>
/// The type is broad in the rules-document sense — one transcript
/// instance serves any curve, with the curve identity carried in the
/// absorbed bytes (a scalar's bytes, a G1 point's bytes) rather than in
/// the type. The Tag still carries the hash function and the domain
/// label so consumers can read both without unwrapping the leaf.
/// </para>
/// <para>
/// <b>Mutability note.</b> Unlike the other leaf types in this library,
/// the transcript mutates. Its 32-byte hash state changes on every
/// absorb and every squeeze; the squeeze counter increments after every
/// squeeze. This is deliberate — a transcript is genuinely a stateful
/// object across protocol rounds, and forcing it to be immutable would
/// mean returning a new transcript instance per operation (and thereby
/// renting a fresh state buffer per operation, defeating the
/// pool-amortisation pattern the leaf types are built around). Mutation
/// is contained: only this type's internal <see cref="UpdateState"/> and
/// <see cref="Squeeze"/> methods touch the buffer, and they are called
/// only through the absorb / squeeze extension blocks in this assembly.
/// </para>
/// <para>
/// <b>Domain-separation discipline for protocol implementers.</b> The
/// construction concatenates variable-length fields without explicit
/// length prefixes, following the toy-zkvm reference. Within a single
/// protocol no ambiguity arises because the domain label is fixed and
/// the operation labels are protocol-chosen. Across protocols the domain
/// labels distinguish hash inputs. Protocol implementers must pick
/// operation labels such that no label is a prefix of another that
/// could appear in the same transcript with different following data —
/// in practice, a hierarchical naming scheme such as
/// <c>"sumcheck.round.3.polynomial"</c> versus
/// <c>"sumcheck.round.3.challenge"</c> trivially satisfies this.
/// </para>
/// </remarks>
public sealed class FiatShamirTranscript: SensitiveMemory
{
    /// <summary>The fixed size of the transcript's hash state buffer.</summary>
    public const int StateSizeBytes = 32;


    //Operation prefixes encoded as UTF-8 byte literals. The four kinds
    //of hash call the construction performs are distinguished by these
    //fixed-length prefixes; their distinctness is a soundness invariant.
    private static readonly byte[] InitPrefix = Encoding.UTF8.GetBytes("transcript:init");
    private static readonly byte[] AbsorbPrefix = Encoding.UTF8.GetBytes("transcript:absorb");
    private static readonly byte[] ChallengePrefix = Encoding.UTF8.GetBytes("transcript:challenge");
    private static readonly byte[] StateUpdatePrefix = Encoding.UTF8.GetBytes("transcript:state-update");


    private readonly byte[] domainLabelBytes;
    private readonly BaseMemoryPool pool;
    private long squeezeCount;


    /// <summary>The canonical name of the hash function this transcript uses.</summary>
    public string HashFunction { get; }

    /// <summary>The protocol-identifying domain label.</summary>
    public FiatShamirDomainLabel DomainLabel { get; }

    /// <summary>The number of squeezes performed so far. Counts only successful squeezes; the counter increments after the squeeze writes its output.</summary>
    public long SqueezeCount => squeezeCount;


    /// <summary>
    /// Constructs a transcript over a pre-rented state buffer. The
    /// instance takes ownership of <paramref name="owner"/> and is
    /// responsible for clearing and returning it on disposal.
    /// </summary>
    /// <param name="owner">A pool-rented 32-byte buffer whose contents will be the transcript's initial hash state.</param>
    /// <param name="hashFunction">The canonical hash function name.</param>
    /// <param name="domainLabel">The protocol-identifying label.</param>
    /// <param name="cachedDomainLabelBytes">The UTF-8 bytes of <paramref name="domainLabel"/>, cached once to avoid per-absorb allocation.</param>
    /// <param name="pool">The pool absorb and squeeze operations rent scratch buffers from.</param>
    /// <param name="tag">The runtime tag.</param>
    internal FiatShamirTranscript(
        IMemoryOwner<byte> owner,
        string hashFunction,
        FiatShamirDomainLabel domainLabel,
        byte[] cachedDomainLabelBytes,
        BaseMemoryPool pool,
        Tag tag)
        : base(owner, StateSizeBytes, tag)
    {
        HashFunction = hashFunction;
        DomainLabel = domainLabel;
        this.domainLabelBytes = cachedDomainLabelBytes;
        this.pool = pool;
        this.squeezeCount = 0;
    }


    /// <summary>
    /// Initialises a fresh transcript. The initial state is
    /// <c>H("transcript:init" || domainLabel || seed)</c>.
    /// </summary>
    /// <param name="domainLabel">The protocol-identifying label.</param>
    /// <param name="seed">The public-input commitment that binds this transcript to a specific statement. Typically a hash of the protocol's public parameters and inputs.</param>
    /// <param name="hashFunction">The canonical hash function name; must satisfy <c>WellKnownHashAlgorithms.IsBlake3(hashFunction)</c> or another supported algorithm of the wired backend.</param>
    /// <param name="hash">The backend implementation of the fixed-output hash.</param>
    /// <param name="pool">The pool to rent the state buffer and scratch buffers from.</param>
    /// <returns>A freshly initialised transcript.</returns>
    /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="hashFunction"/> is not a recognised <see cref="WellKnownHashAlgorithms"/> name.</exception>
    public static FiatShamirTranscript Initialise(
        FiatShamirDomainLabel domainLabel,
        ReadOnlySpan<byte> seed,
        string hashFunction,
        FiatShamirHashDelegate hash,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(hashFunction);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(pool);

        if(!IsKnownHashAlgorithm(hashFunction))
        {
            throw new ArgumentException(
                $"Hash function '{hashFunction}' is not in WellKnownHashAlgorithms. Use the canonical constants (for example WellKnownHashAlgorithms.Blake3) so backends can recognise the name.",
                nameof(hashFunction));
        }

        byte[] domainBytes = domainLabel.Bytes;

        //Compose the initial-state input: prefix || domain || seed.
        int inputLength = InitPrefix.Length + domainBytes.Length + seed.Length;
        IMemoryOwner<byte> stateOwner = pool.Rent(StateSizeBytes);
        using IMemoryOwner<byte> scratchOwner = pool.Rent(inputLength);
        Span<byte> scratch = scratchOwner.Memory.Span[..inputLength];
        int offset = 0;
        InitPrefix.CopyTo(scratch[offset..]);
        offset += InitPrefix.Length;
        domainBytes.CopyTo(scratch[offset..]);
        offset += domainBytes.Length;
        seed.CopyTo(scratch[offset..]);

        hash(scratch, stateOwner.Memory.Span[..StateSizeBytes], hashFunction);

        CryptographicOperationCounters.Increment(CryptographicOperationKind.TranscriptInitialise, CurveParameterSet.None);

        Tag tag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.FiatShamirTranscript),
            (typeof(WellKnownHashAlgorithms), (object)hashFunction),
            (typeof(FiatShamirDomainLabel), (object)domainLabel));

        return new FiatShamirTranscript(stateOwner, hashFunction, domainLabel, domainBytes, pool, tag);
    }


    /// <summary>
    /// Internal API for absorb operations. Computes the new state as
    /// <c>H("transcript:absorb" || currentState || domain || label || data)</c>
    /// and writes it in place over the existing state.
    /// </summary>
    internal void UpdateState(
        FiatShamirOperationLabel label,
        ReadOnlySpan<byte> data,
        FiatShamirHashDelegate hash)
    {
        ArgumentNullException.ThrowIfNull(hash);

        byte[] labelBytes = label.Bytes;
        int inputLength = AbsorbPrefix.Length + StateSizeBytes + domainLabelBytes.Length + labelBytes.Length + data.Length;
        using IMemoryOwner<byte> scratchOwner = pool.Rent(inputLength);
        Span<byte> scratch = scratchOwner.Memory.Span[..inputLength];
        int offset = 0;
        AbsorbPrefix.CopyTo(scratch[offset..]);
        offset += AbsorbPrefix.Length;
        AsReadOnlySpan().CopyTo(scratch.Slice(offset, StateSizeBytes));
        offset += StateSizeBytes;
        domainLabelBytes.CopyTo(scratch[offset..]);
        offset += domainLabelBytes.Length;
        labelBytes.CopyTo(scratch[offset..]);
        offset += labelBytes.Length;
        data.CopyTo(scratch[offset..]);

        //Hash writes into a fresh scratch slot to avoid input/output overlap,
        //then we copy the result into the persistent state. Backends that
        //treat input and output as disjoint windows would corrupt the input
        //if we hashed in-place over the same span.
        Span<byte> newState = stackalloc byte[StateSizeBytes];
        hash(scratch, newState, HashFunction);
        newState.CopyTo(AsSpan());

        CryptographicOperationCounters.Increment(CryptographicOperationKind.TranscriptAbsorbBytes, CurveParameterSet.None);
    }


    /// <summary>
    /// Internal API for squeeze operations. Writes the squeeze output to
    /// <paramref name="destination"/>, then updates the state through a
    /// chained hash call, then increments the squeeze counter.
    /// </summary>
    internal void Squeeze(
        FiatShamirOperationLabel label,
        Span<byte> destination,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash)
    {
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(hash);

        byte[] labelBytes = label.Bytes;
        int xofInputLength = ChallengePrefix.Length + StateSizeBytes + domainLabelBytes.Length + labelBytes.Length + sizeof(long);
        using IMemoryOwner<byte> xofInputOwner = pool.Rent(xofInputLength);
        Span<byte> xofInput = xofInputOwner.Memory.Span[..xofInputLength];
        int offset = 0;
        ChallengePrefix.CopyTo(xofInput[offset..]);
        offset += ChallengePrefix.Length;
        AsReadOnlySpan().CopyTo(xofInput.Slice(offset, StateSizeBytes));
        offset += StateSizeBytes;
        domainLabelBytes.CopyTo(xofInput[offset..]);
        offset += domainLabelBytes.Length;
        labelBytes.CopyTo(xofInput[offset..]);
        offset += labelBytes.Length;
        BinaryPrimitives.WriteInt64BigEndian(xofInput.Slice(offset, sizeof(long)), squeezeCount);

        squeeze(xofInput, destination, HashFunction);
        CryptographicOperationCounters.Increment(CryptographicOperationKind.TranscriptSqueezeBytes, CurveParameterSet.None);

        //State update: H("transcript:state-update" || currentState || squeezedOutput).
        int updateInputLength = StateUpdatePrefix.Length + StateSizeBytes + destination.Length;
        using IMemoryOwner<byte> updateInputOwner = pool.Rent(updateInputLength);
        Span<byte> updateInput = updateInputOwner.Memory.Span[..updateInputLength];
        int updateOffset = 0;
        StateUpdatePrefix.CopyTo(updateInput[updateOffset..]);
        updateOffset += StateUpdatePrefix.Length;
        AsReadOnlySpan().CopyTo(updateInput.Slice(updateOffset, StateSizeBytes));
        updateOffset += StateSizeBytes;
        destination.CopyTo(updateInput[updateOffset..]);

        Span<byte> newState = stackalloc byte[StateSizeBytes];
        hash(updateInput, newState, HashFunction);
        newState.CopyTo(AsSpan());

        CryptographicOperationCounters.Increment(CryptographicOperationKind.TranscriptUpdateState, CurveParameterSet.None);

        squeezeCount++;
    }


    private static bool IsKnownHashAlgorithm(string hashFunction)
    {
        return WellKnownHashAlgorithms.IsBlake3(hashFunction)
            || WellKnownHashAlgorithms.IsSha256(hashFunction)
            || WellKnownHashAlgorithms.IsSha512(hashFunction)
            || WellKnownHashAlgorithms.IsSha3_256(hashFunction)
            || WellKnownHashAlgorithms.IsSha3_512(hashFunction)
            || WellKnownHashAlgorithms.IsShake128(hashFunction)
            || WellKnownHashAlgorithms.IsShake256(hashFunction);
    }
}