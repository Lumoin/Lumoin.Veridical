namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// One FIPS 204 signature example transcribed from the reference's per-set example tables
/// (<c>ml_dsa_44_examples.cc</c>, <c>ml_dsa_65_examples.cc</c>): the raw message, the encoded
/// public key, the signing context, the derived message representative hash, and the encoded
/// signature, all as lowercase contiguous hex.
/// </summary>
/// <param name="Message">The signed message bytes, lowercase hex.</param>
/// <param name="PublicKey">The FIPS 204 encoded public key bytes, lowercase hex.</param>
/// <param name="Context">The signing context bytes, lowercase hex; empty when the example signs with the empty context.</param>
/// <param name="Mu">The 64-byte message representative <c>mu = H(tr || M', 64)</c>, lowercase hex.</param>
/// <param name="Signature">The FIPS 204 encoded signature bytes, lowercase hex.</param>
internal sealed record LongfellowMlDsaSignatureExample(string Message, string PublicKey, string Context, string Mu, string Signature);


/// <summary>
/// One SampleInBall vector transcribed from the reference's per-set tables: the hash seed and the
/// 256 challenge coefficients the constrained sampler must produce.
/// </summary>
/// <param name="Seed">The <c>c_tilde</c>-sized hash seed bytes.</param>
/// <param name="Coefficients">The 256 canonical challenge coefficients (zero, one, or the modulus less one).</param>
internal sealed record LongfellowMlDsaSampleInBallVector(byte[] Seed, uint[] Coefficients);


/// <summary>
/// One UseHint case transcribed from the reference's per-set tables: the hint bit, the input
/// coefficient, and the hinted high-bits value FIPS 204 Algorithm 40 must produce.
/// </summary>
/// <param name="Hint">The hint bit.</param>
/// <param name="R">The input coefficient.</param>
/// <param name="Expected">The hinted high-bits result.</param>
internal sealed record LongfellowMlDsaUseHintCase(bool Hint, int R, uint Expected);


/// <summary>
/// One w1Encode vector transcribed from the reference's per-set tables: the high-bits coefficient
/// matrix and the byte string FIPS 204 Algorithm 28 must pack it into.
/// </summary>
/// <param name="Coefficients">The high-bits coefficients, one 256-entry row per polynomial.</param>
/// <param name="Encoded">The packed byte string.</param>
internal sealed record LongfellowMlDsaW1EncodeVector(int[][] Coefficients, byte[] Encoded);


/// <summary>
/// One NTT vector transcribed from the reference's tables: a domain polynomial and its
/// number-theoretic transform.
/// </summary>
/// <param name="Input">The 256 domain coefficients.</param>
/// <param name="Output">The 256 transformed coefficients.</param>
internal sealed record LongfellowMlDsaNttVector(uint[] Input, uint[] Output);
