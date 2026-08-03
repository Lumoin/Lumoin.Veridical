namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// One entry in the closed registry of oracle-pinned block capacities the JWT statement's SHA-256 preimage
/// circuit is compiled for: each instance names a block capacity whose kernel-compiled circuit is pinned
/// counter for counter against the reference compiler. The set is closed because a free capacity would
/// compile an un-pinned shape; block capacity is the natural registry axis for this statement — it has no
/// upstream version registry, unlike the mdoc facade's <c>kZkSpecs</c> rows.
/// </summary>
public sealed class LongfellowJwtZkSpec
{
    //One SHA-256 block.
    private const int ShaBlockBytes = 64;

    //The mandatory 0x80 pad byte plus the eight-byte bit-length field every SHA-256 padding reserves.
    private const int ReservedTailBytes = 9;


    private LongfellowJwtZkSpec(int blockCapacity)
    {
        BlockCapacity = blockCapacity;
    }


    /// <summary>The seven-block capacity, the reference's smaller pinned shape.</summary>
    public static LongfellowJwtZkSpec SevenBlocks { get; } = new(7);

    /// <summary>The nine-block capacity, the reference's larger pinned shape.</summary>
    public static LongfellowJwtZkSpec NineBlocks { get; } = new(9);


    /// <summary>The preimage capacity in SHA-256 blocks the compiled circuit reserves.</summary>
    public int BlockCapacity { get; }

    /// <summary>The largest issuer signing input the capacity admits.</summary>
    public int MaximumMessageBytes => (BlockCapacity * ShaBlockBytes) - ReservedTailBytes;
}
