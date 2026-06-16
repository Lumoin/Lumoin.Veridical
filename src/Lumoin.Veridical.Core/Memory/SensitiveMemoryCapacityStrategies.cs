namespace Lumoin.Veridical.Core.Memory;

/// <summary>
/// Veridical-specific slab-capacity tuning for the byte memory pool, kept here rather than on any one pool
/// implementation. Each strategy is a plain <c>int → int</c> method, so it converts to the
/// <c>SlabCapacityStrategy</c> delegate of whichever pool backs the library — the shared
/// <c>Lumoin.Base.BaseMemoryPool</c> or an in-repo pool — and is supplied at construction time. Holding the
/// Veridical-shaped sizes here decouples them from the pool: the pool stays a general byte allocator and the
/// proof-system-specific amortisation lives with the library that knows those sizes, so adopting the shared
/// pool needs no change to the shared pool.
/// </summary>
public static class SensitiveMemoryCapacityStrategies
{
    /// <summary>
    /// Capacity strategy tuned for zero-knowledge prover workloads. The dominant allocation sizes during proof
    /// generation are curve scalars (32 bytes for BLS12-381 / BN254 / Pallas / Vesta / Grumpkin / Ed25519,
    /// 48 bytes for P-384, 66 bytes for P-521), base-field elements and G1 compressed points (48 bytes for
    /// BLS12-381, 32 for BN254 and Pasta), G2 compressed points (96 bytes for BLS12-381), and Gt elements
    /// (576 bytes for BLS12-381, 384 for BN254). Multi-scalar multiplication and number-theoretic transforms
    /// iterate through millions of these per proof, so the small-size buckets are allocated much deeper than a
    /// general default to amortise slab construction across one proof. Larger buckets — proving keys,
    /// structured reference strings, large polynomial coefficient vectors — stay shallow because their reuse
    /// pattern is one-per-proof rather than one-per-step.
    /// </summary>
    /// <param name="segmentSize">The size of each segment in elements.</param>
    /// <returns>The number of segments to allocate in the new slab.</returns>
    /// <example>
    /// <code>
    /// //Supply the ZK-tuned strategy at pool construction.
    /// var pool = new BaseMemoryPool(capacityStrategy: SensitiveMemoryCapacityStrategies.ZkpProver);
    /// </code>
    /// </example>
    public static int ZkpProver(int segmentSize) => segmentSize switch
    {
        <= 32 => 1024,
        <= 48 => 1024,
        <= 96 => 512,
        <= 192 => 256,
        <= 576 => 128,
        <= 4096 => 32,
        _ => 8
    };
}
