namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The outcome of the zero-knowledge signature-result conformity check (Verheul Annex F, Algorithm 41). The check
/// runs over records that come from a possibly compromised signing component, so an alarm is an expected result
/// and is returned as a value, never thrown. Every value other than <see cref="NoAlarm"/> is the paper's
/// WSCA COMPROMISE ALARM; the specific value says which step raised it.
/// </summary>
public enum SignatureResultConformity
{
    /// <summary>NO ALARM: the proof verifies and the nonce-point equation holds, so <c>(R, s)</c> is a valid signature on the message under the user key.</summary>
    NoAlarm = 0,

    /// <summary>Alarm: a point of the record or the user key is malformed, off the curve, or not finite, or an input is structurally unusable.</summary>
    AlarmMalformedRecord = 1,

    /// <summary>Alarm: the discrete-logarithm-equality proof does not verify (Algorithm 41 step 2).</summary>
    AlarmProofRejected = 2,

    /// <summary>Alarm: <c>R ≠ e·G'' + r·Q_U''</c> (Algorithm 41 step 3).</summary>
    AlarmResultMismatch = 3
}
