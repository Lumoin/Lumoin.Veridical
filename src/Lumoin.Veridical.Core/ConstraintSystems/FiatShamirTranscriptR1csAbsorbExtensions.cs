using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Typed transcript absorbs for R1CS instances over BLS12-381.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class FiatShamirTranscriptR1csAbsorbExtensions
{
    private const int DimensionsBufferSize = 6 * sizeof(int);


    extension(FiatShamirTranscript transcript)
    {
        /// <summary>
        /// Absorbs a complete R1CS instance into the transcript in the
        /// pinned order: dimensions, then matrices A, B, C, then public
        /// inputs. Prover and verifier reach the same transcript state
        /// from the same instance.
        /// </summary>
        public void AbsorbR1csInstance(
            RawR1csInstance instance,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(instance);

            WellKnownCurves.ThrowIfCurveNotWired(instance.Curve);

            AbsorbInstanceCore(
                transcript,
                instance.A, instance.B, instance.C,
                instance.PublicInputCount,
                instance.GetPublicInputsBytes(),
                hash);
        }


        /// <summary>
        /// Absorbs a complete relaxed R1CS instance into the transcript:
        /// the same dimensions, matrices A/B/C and public inputs as
        /// <see cref="AbsorbR1csInstance"/>, then the relaxation scalar
        /// <c>u</c> and the Hyrax commitment to the error vector <c>E</c>.
        /// The relaxed extras fire on every relaxed proof — a
        /// raw-prepared instance carries <c>u = 1</c> and the identity
        /// error commitment and absorbs them too, so the unified prover
        /// has no "is this standard" branch.
        /// </summary>
        public void AbsorbRelaxedR1csInstance(
            RelaxedR1csInstance instance,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(instance);

            WellKnownCurves.ThrowIfCurveNotWired(instance.Curve);

            AbsorbInstanceCore(
                transcript,
                instance.A, instance.B, instance.C,
                instance.PublicInputCount,
                instance.GetPublicInputsBytes(),
                hash);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownR1csTranscriptLabels.RelaxationScalar),
                instance.GetUBytes(),
                hash);
            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownR1csTranscriptLabels.ErrorCommitment),
                instance.ErrorCommitment.AsReadOnlySpan(),
                hash);
        }
    }


    /// <summary>
    /// Absorbs the dimensions, the three coefficient matrices, and the
    /// public inputs in the pinned order shared by the raw and relaxed
    /// instance absorbs.
    /// </summary>
    private static void AbsorbInstanceCore(
        FiatShamirTranscript transcript,
        R1csMatrix a,
        R1csMatrix b,
        R1csMatrix c,
        int publicInputCount,
        ReadOnlySpan<byte> publicInputs,
        FiatShamirHashDelegate hash)
    {
        //Dimensions: m, n, publicInputCount, nnz_A, nnz_B, nnz_C as 6 × 4-byte big-endian ints.
        Span<byte> dimensions = stackalloc byte[DimensionsBufferSize];
        BinaryPrimitives.WriteInt32BigEndian(dimensions[..sizeof(int)], a.RowCount);
        BinaryPrimitives.WriteInt32BigEndian(dimensions.Slice(sizeof(int), sizeof(int)), a.ColumnCount);
        BinaryPrimitives.WriteInt32BigEndian(dimensions.Slice(2 * sizeof(int), sizeof(int)), publicInputCount);
        BinaryPrimitives.WriteInt32BigEndian(dimensions.Slice(3 * sizeof(int), sizeof(int)), a.NonzeroCount);
        BinaryPrimitives.WriteInt32BigEndian(dimensions.Slice(4 * sizeof(int), sizeof(int)), b.NonzeroCount);
        BinaryPrimitives.WriteInt32BigEndian(dimensions.Slice(5 * sizeof(int), sizeof(int)), c.NonzeroCount);

        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownR1csTranscriptLabels.Dimensions), dimensions, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownR1csTranscriptLabels.MatrixA), a.AsReadOnlySpan(), hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownR1csTranscriptLabels.MatrixB), b.AsReadOnlySpan(), hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownR1csTranscriptLabels.MatrixC), c.AsReadOnlySpan(), hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownR1csTranscriptLabels.PublicInputs), publicInputs, hash);
    }
}