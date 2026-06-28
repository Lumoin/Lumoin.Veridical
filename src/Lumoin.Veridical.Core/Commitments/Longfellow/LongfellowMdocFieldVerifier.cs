using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// One field's worth of the dual-field mdoc verification context — everything the driver needs to parse
/// and verify a single circuit's <c>ZkProof</c> on the shared transcript. The hash side carries the
/// GF(2^128) hash circuit; the signature side carries the P-256 base-field signature circuit. Bundling the
/// per-field pieces keeps the driver's <see cref="LongfellowMdocVerifier.Verify"/> signature to the two
/// field bundles plus the shared transcript / hash / public-input arguments.
/// </summary>
/// <remarks>
/// Per D6 the circuit and parameters are pre-derived (<see cref="LongfellowCircuitReader"/> /
/// <see cref="LongfellowZkVerifier.DeriveParameters(LongfellowSumcheckCircuit, int, int, int, int, int)"/> are already-gated layers the caller drives). The
/// row-encoder factory, the field profile and the subfield-run codec are the field bindings the C.12b
/// seam produces (<see cref="LongfellowGf2k128Encoding"/> for the hash side,
/// <see cref="LongfellowFp256Encoding"/> for the signature side). The codec is borrowed, not owned — the
/// caller that built it disposes it.
/// </remarks>
/// <param name="Circuit">The circuit shape with its per-layer <c>Quad</c> terms; must have <c>logc == 0</c>.</param>
/// <param name="Parameters">The circuit-derived Ligero parameters.</param>
/// <param name="EncoderFactory">The field's systematic Reed–Solomon row-encoder factory.</param>
/// <param name="Profile">The field profile: element width, the third evaluation point, and the <c>sample</c> seam.</param>
/// <param name="Codec">The subfield-run codec the Ligero <c>com_proof</c> reader decodes opened columns through (borrowed; the caller disposes it).</param>
/// <param name="Add">Field addition.</param>
/// <param name="Subtract">Field subtraction.</param>
/// <param name="Multiply">Field multiplication.</param>
/// <param name="Invert">Field inversion.</param>
/// <param name="Curve">The field the delegates operate over (<see cref="CurveParameterSet.None"/> for GF(2^128)).</param>
/// <param name="BindQuadReduce">The optional fused <c>bind_quad</c> per-term reduce primitive (the GF(2^128) hash side supplies it; the Fp256 sig side leaves it <see langword="null"/> and falls back to the scalar reduction).</param>
/// <param name="BroadcastMultiplyAccumulate">The optional broadcast-scalar fused multiply primitive the <c>filleq</c> eq-array fills route their per-level scalar-times-vector products through (the GF(2^128) hash side supplies it; the Fp256 sig side leaves it <see langword="null"/> and falls back to the scalar multiply).</param>
/// <param name="Fp256BatchMultiply">The optional lane-parallel batch Montgomery multiply the constraint replay's <c>bind_quad</c> reduction routes its three-multiply-per-term chain through (the Fp256 sig side supplies it; the GF(2^128) hash side leaves it <see langword="null"/> and supplies <paramref name="BindQuadReduce"/> instead — the two are mutually exclusive, both bundles passing <c>curve == None</c>).</param>
internal sealed record LongfellowMdocFieldVerifier(
    LongfellowSumcheckCircuit Circuit,
    LongfellowLigeroParameters Parameters,
    LongfellowRowEncoderFactory EncoderFactory,
    LongfellowFieldProfile Profile,
    LongfellowSubfieldRunCodec Codec,
    ScalarAddDelegate Add,
    ScalarSubtractDelegate Subtract,
    ScalarMultiplyDelegate Multiply,
    ScalarInvertDelegate Invert,
    CurveParameterSet Curve,
    ScalarBindQuadReduceDelegate? BindQuadReduce = null,
    ScalarBroadcastMultiplyAccumulateDelegate? BroadcastMultiplyAccumulate = null,
    ScalarBatchMultiplyDelegate? Fp256BatchMultiply = null);
