using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// One field's worth of the dual-field mdoc PROVE context — everything the driver needs to commit and prove
/// a single circuit's <c>ZkProof</c> on the shared transcript, the prove-side mirror of
/// <see cref="LongfellowMdocFieldVerifier"/>. The hash side carries the GF(2^128) hash circuit; the
/// signature side carries the P-256 base-field signature circuit. Bundling the per-field bindings keeps the
/// driver's <see cref="LongfellowMdocProver.Prove"/> signature to the two field bundles plus the per-prove
/// witness columns, random sources and the shared transcript / hash / mac arguments.
/// </summary>
/// <remarks>
/// The bundle carries only the STATIC field bindings (the circuit, the parameters, the encoding seam and the
/// arithmetic). The per-prove inputs — the full witness column with the macs/av region zeroed, and the
/// random source — are driver arguments, because they change per prove while the bindings do not. The codec
/// is borrowed, not owned — the caller that built it disposes it.
/// </remarks>
/// <param name="Circuit">The circuit shape with its per-layer <c>Quad</c> terms; must have <c>nc == 1</c>, <c>logc == 0</c>.</param>
/// <param name="Parameters">The circuit-derived Ligero parameters.</param>
/// <param name="EncoderFactory">The field's systematic Reed–Solomon row-encoder factory.</param>
/// <param name="Profile">The field profile: element width, the third evaluation point, the <c>sample</c> seam and the <c>to_bytes_field</c> framing.</param>
/// <param name="Codec">The subfield-run codec the Ligero <c>com_proof</c> serializer encodes opened columns through (borrowed; the caller disposes it).</param>
/// <param name="Add">Field addition.</param>
/// <param name="Subtract">Field subtraction.</param>
/// <param name="Multiply">Field multiplication.</param>
/// <param name="Invert">Field inversion.</param>
/// <param name="SubfieldBoundary">The reference's <c>subfield_boundary</c> rebased to start at <c>npub_in</c>; the commit draws subfield padding for witness rows below it.</param>
/// <param name="Curve">The field the delegates operate over (<see cref="CurveParameterSet.None"/> for GF(2^128)).</param>
/// <param name="BroadcastMultiplyAccumulate">The optional broadcast-scalar fused multiply primitive the <c>filleq</c> eq-array fills route their per-level scalar-times-vector products through (the GF(2^128) hash side supplies it; the Fp256 sig side leaves it <see langword="null"/> and falls back to the scalar multiply).</param>
/// <param name="BindQuadReduce">The optional fused <c>bind_quad</c> per-term reduce primitive the constraint replay's <c>BindQuad</c> routes its three-multiply-per-term reduction through (the GF(2^128) hash side supplies it; the Fp256 sig side leaves it <see langword="null"/> and falls back to the scalar reduction).</param>
/// <param name="GatherMultiplyAccumulate">The optional gather/scatter fused multiply-accumulate primitive the sumcheck prover's per-round <c>QW</c> corner precompute routes through (the GF(2^128) hash side supplies it; the Fp256 sig side leaves it <see langword="null"/> and falls back to the scalar multiply-add).</param>
/// <param name="Fp256BatchMultiply">The optional lane-parallel batch Montgomery multiply the constraint replay's <c>bind_quad</c> reduction routes its three-multiply-per-term chain through (the Fp256 sig side supplies it; the GF(2^128) hash side leaves it <see langword="null"/> and supplies <paramref name="BindQuadReduce"/> instead — the two are mutually exclusive, both bundles passing <c>curve == None</c>).</param>
internal sealed record LongfellowMdocFieldProver(
    LongfellowSumcheckCircuit Circuit,
    LongfellowLigeroParameters Parameters,
    LongfellowRowEncoderFactory EncoderFactory,
    LongfellowFieldProfile Profile,
    LongfellowSubfieldRunCodec Codec,
    ScalarAddDelegate Add,
    ScalarSubtractDelegate Subtract,
    ScalarMultiplyDelegate Multiply,
    ScalarInvertDelegate Invert,
    int SubfieldBoundary,
    CurveParameterSet Curve,
    ScalarBroadcastMultiplyAccumulateDelegate? BroadcastMultiplyAccumulate = null,
    ScalarBindQuadReduceDelegate? BindQuadReduce = null,
    ScalarGatherMultiplyAccumulateDelegate? GatherMultiplyAccumulate = null,
    ScalarBatchMultiplyDelegate? Fp256BatchMultiply = null);
