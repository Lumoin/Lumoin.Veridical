using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Transcribes google/longfellow-zk circuits/tests/jwt/jwt_test.cc's test token tables:
/// the well-formed presentation tokens in the 'tests' vector and the malformed or
/// mismatched tokens in the 'failure_tests' vector, each in source declaration order.
/// </summary>
internal static class LongfellowJwtTestVectors
{
    /// <summary>
    /// A single well-formed entry from the source's 'tests' vector: an SD-JWT credential
    /// concatenated with its '~'-joined key-binding JWT, plus the P-256 public key and
    /// key-binding hash the reference witness computation was run against.
    /// </summary>
    /// <param name="Token">The full presentation token string, exactly as the adjacent C++ string literals concatenate.</param>
    /// <param name="PkX">The public key affine X coordinate, the 0x-prefixed hex StaticString exactly as written in the source.</param>
    /// <param name="PkY">The public key affine Y coordinate, the 0x-prefixed hex StaticString exactly as written in the source.</param>
    /// <param name="E2">The key-binding message hash, the 0x-prefixed hex StaticString exactly as written in the source.</param>
    /// <param name="DeclaredLength">The jwtest.len field recorded alongside the token in the source, a message-length parameter distinct from the token string's character count.</param>
    internal sealed record TokenVector(string Token, string PkX, string PkY, string E2, int DeclaredLength);

    /// <summary>
    /// Gets the first entry of the source's 'tests' vector (declared length 418): the
    /// single-attribute 'given_name' = 'Erika' presentation token.
    /// </summary>
    public static TokenVector ErikaToken { get; } = new(
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2JtaS5idW5kLmV4YW1wbGUvY3JlZGVudGlhbC9waWQvMS4wIiwic3ViIjoidXNlcjEyMzQ1IiwiZXhwIjoxNzU0MDM5ODMwLCJpYXQiOjE3NTQwMzYyMzAsImdpdmVuX25hbWUiOiJFcmlrYSIsImFnZV9vdmVyXzE4Ijp0cnVlLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoicXB2czMyeXpDOGhZYXdOV181UUR5U2E4eFJfSUtCaTdSX1E1Tm5iYXVPZyIsInkiOiJCakxDb3M1eFZGMTJWSTdWSTAySUZMSGRzd1FLc0lKV0tOa1BuMFBaRFFnIn19fQ.U-2n0rGEYxGUGuQqNUPhe42rWZSJPR7ZccGRpqkzEoqnGDRmIauuA0hfLgwALkawWLSDETRR3vFzHfV6lNvb3Q~eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiMitqd3QifQ.eyJub25jZSI6IjEyMzEyMzEyMyIsImF1ZCI6IlJQIiwiaWF0IjoxNzU0MDM2MjMwfQ.SjTqd6_LBXd0-fj9pk7P1VaimaEJh6TKKHKqxaPFEbiMPStEpZGE2BdyVghn0c-GUBnm8RV0k-jUkAk0bQAsxw",
        "0x369b8ba929cf0f06be8272268f4091cfde4ef00fe35f1a25ff04e2d4293d692b",
        "0xbdf89d633ac7a622d73bee63bd00a68bcee5b3262054f4e767f7c25157182364",
        "0x7f9982db0d6de18b4c5a83044912062d8d48cca2120b3badb2b7948427360159",
        418);

    /// <summary>
    /// Gets the second entry of the source's 'tests' vector (declared length 597): the
    /// fuller 'Erika Mustermann' presentation token disclosing additional attributes.
    /// </summary>
    public static TokenVector RicherToken { get; } = new(
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2JtaS5idW5kLmV4YW1wbGUvY3JlZGVudGlhbC9waWQvMS4wIiwic3ViIjoidXNlcjEyMzQ1IiwiZXhwIjoxNzUzOTkwNDQ5LCJpYXQiOjE3NTM5ODY4NDksImdpdmVuX25hbWUiOiJFcmlrYSIsImZhbWlseV9uYW1lIjoiTXVzdGVybWFubiIsImJpcnRoZGF0ZSI6IjE5NjMtMDgtMTIiLCJnZW5kZXIiOiJGIiwiYmlydGhfZmFtaWx5X25hbWUiOiJHYWJsZXIiLCJhZ2Vfb3Zlcl8xOCI6dHJ1ZSwiYWdlX292ZXJfMjEiOnRydWUsImFnZV9vdmVyXzY1IjpmYWxzZSwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InY1d25RcElBMTdZd0JaNUlFMGk4ZlNiRldCSUQ4NkljVFBoRVpZam0wTmciLCJ5IjoiTkFhSDV1d3dFb2dnSkY5LU9mdUlYaVRWeGpfNjRmVGJETlpfU2hwclRoTSJ9fX0.UlzoYNshYAT6GglIr2nXQ4e9ERO8VPcVNZOeFo28FwfdVNqKQZnEdQCLGftFCIH8Rhmmshf5-PAPn5g5c_u2TQ~eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiMitqd3QifQ.eyJub25jZSI6IjEyMzEyMzEyMyIsImF1ZCI6IlJQIiwiaWF0IjoxNzUzOTg2ODQ5fQ.7eGDLcwBKfMj7d5p57FSVh9PeKqY66iN6-WSUL5mZQm4SoNElzAF-HMMwmy-jESy-97vUIe5DwwVSmc0Dk1Gyg",
        "0x3cce3bae0dd16e8a98e4d7647b449db9a170afc2c1fe0ce263a3768d9ba790b9",
        "0x462c7dd391d504e15bc6cdee6218ed495da244a198cf19da9217c796d58ab8aa",
        "0xaf246c556bba9ab47e3ce2802c3ae6901e7dd3deedf9557cc66d5b1050324b68",
        597);

    /// <summary>
    /// A single entry from the source's 'failure_tests' vector: a malformed or mismatched
    /// token paired with the single opened attribute the reference test asserts against.
    /// </summary>
    /// <param name="Token">The token string, exactly as the adjacent C++ string literals concatenate.</param>
    /// <param name="PkX">The public key X coordinate StaticString from the source; some entries are decimal without a 0x prefix, preserved exactly as written.</param>
    /// <param name="PkY">The public key Y coordinate StaticString from the source; some entries are decimal without a 0x prefix, preserved exactly as written.</param>
    /// <param name="E2">The key-binding message hash StaticString from the source.</param>
    /// <param name="AttributeId">The opened attribute's id string, from the OpenedAttribute initializer used for this entry.</param>
    /// <param name="AttributeValue">The opened attribute's value string, from the OpenedAttribute initializer used for this entry.</param>
    internal sealed record FailureVector(string Token, string PkX, string PkY, string E2, string AttributeId, string AttributeValue);

    /// <summary>
    /// Gets all nine entries of the source's 'failure_tests' vector, in source declaration order.
    /// </summary>
    public static IReadOnlyList<FailureVector> FailureTokens { get; } = new FailureVector[]
    {
        new("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9",
            "31954033929749730965973534972267758182682385570370472232340378963542000270086",
            "14222769864755572911479659839191103711055765814064207704721481731130688302439",
            "0",
            "name",
            "John Doe"),
        new("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6I",
            "31954033929749730965973534972267758182682385570370472232340378963542000270086",
            "14222769864755572911479659839191103711055765814064207704721481731130688302439",
            "0",
            "name",
            "John Doe"),
        new("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA",
            "7850540730117855537377310150564140534713067357541121232721010766305002029006",
            "65316312644653463644210322201871599477553959356638327946530363791985981247174",
            "0",
            "name",
            "John Doe"),
        new("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzd#IiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA~",
            "7850540730117855537377310150564140534713067357541121232721010766305002029006",
            "65316312644653463644210322201871599477553959356638327946530363791985981247174",
            "0",
            "name",
            "John Doe"),
        new("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGY(DlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA~",
            "7850540730117855537377310150564140534713067357541121232721010766305002029006",
            "65316312644653463644210322201871599477553959356638327946530363791985981247174",
            "0",
            "name",
            "John Doe"),
        new("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA~",
            "7850540730117855537377310150564140534713067357541121232721010766305002029006",
            "65316312644653463644210322201871599477553959356638327946530363791985981247174",
            "0",
            "name",
            "John Doe"),
        new("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqVSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA~",
            "7850540730117855537377310150564140534713067357541121232721010766305002029006",
            "65316312644653463644210322201871599477553959356638327946530363791985981247174",
            "0",
            "name",
            "John Doe"),
        new("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA~",
            "7850540730117855537377310150564140534713067357541121232721010766305002029006",
            "65316312644653463644210322201871599477553959356638327946530363791985981247174",
            "0",
            "fame",
            "John Doe"),
        new("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA~",
            "7850540730117855537377310150564140534713067357541121232721010766305002029006",
            "65316312644653463644210322201871599477553959356638327946530363791985981247174",
            "0",
            "name",
            "Kohn Doe"),
    };
}
