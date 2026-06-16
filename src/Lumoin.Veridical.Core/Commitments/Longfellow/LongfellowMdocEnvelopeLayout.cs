namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The byte offsets and lengths of the three regions of a dual-field mdoc proof envelope
/// <c>[6 macs] ‖ [hash ZkProof] ‖ [sig ZkProof]</c>, as resolved by
/// <see cref="LongfellowMdocEnvelope.TrySplit"/>.
/// </summary>
/// <param name="MacRegionOffset">The byte offset of the MAC prefix (always 0).</param>
/// <param name="MacRegionBytes">The MAC prefix length (<c>6 · 16 = 96</c>).</param>
/// <param name="HashProofOffset">The byte offset of the hash <c>ZkProof</c> (always 96).</param>
/// <param name="HashProofBytes">The hash <c>ZkProof</c> length (com 32 + sumcheck segment + Ligero <c>com_proof</c>).</param>
/// <param name="SigProofOffset">The byte offset of the signature <c>ZkProof</c>.</param>
/// <param name="SigProofBytes">The signature <c>ZkProof</c> length (the remaining envelope bytes).</param>
internal readonly record struct LongfellowMdocEnvelopeLayout(
    int MacRegionOffset,
    int MacRegionBytes,
    int HashProofOffset,
    int HashProofBytes,
    int SigProofOffset,
    int SigProofBytes);
