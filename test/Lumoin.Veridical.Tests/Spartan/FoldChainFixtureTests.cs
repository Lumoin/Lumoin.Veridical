using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Spartan;
using System;
using System.Text;

using static Lumoin.Veridical.Tests.Spartan.FoldChainTestFixtures;
using static Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Byte-stability leg of the <see cref="FoldChain"/> gate: with one
/// deterministic <see cref="ScalarRandomDelegate"/> seed threaded
/// through Start → Step → Step → Finalize, two independent runs produce
/// byte-identical compressed proofs that match a captured-at-commit-time
/// hex constant and verify against the final folded instance. Any future
/// change that alters the wire bytes for fixed inputs — in the fold
/// algebra, the blinding-instance construction, the transcript schedule,
/// or the compression — trips this test.
/// </summary>
[TestClass]
internal sealed class FoldChainFixtureTests
{
    private const int HyraxVectorLength = 2;

    //Fixed seed for the deterministic RNG so the fixture is reproducible.
    //Distinct from the masked prover's fixture seed to keep the two
    //fixtures independent regression detectors.
    private static byte[] FixtureRandomSeed { get; } = Encoding.UTF8.GetBytes("veridical.fold-chain.fixture.one-multiply-x2.v1");

    //Captured at commit time by running the chain once with FixtureRandomSeed
    //and pasting the recorded bytes. Any future change to the fold chain or
    //the compression that alters the wire bytes for fixed inputs trips this.
    private const string ExpectedProofHex =
        "8FA5249687E475F0D82FDD48521D5EF058C4D65DF82615A4E87FF05649325EDCEE5C0265958AB53F3E7D46FB3B7E277D" +
        "9215D75A04FD61C5367D3376D080073680548F273B89E128886BEA6689F4F08FB3C6781FEB82A5AA57BDEA9F32DBA53E" +
        "B5889B8BD86482BF41FE2CA77B2D56C92A0385E9E3CBB65315E0588FA2C9E0E5DD17C832D8A7642AD9713183CC4E0C20" +
        "8598C97F9C037F104D4118A84589B76253CB8290269862D11D0949ECD2E252B466E93D736612BDD723A2E8046313F763" +
        "2E9AAEBF3C04F72DFB2A8E71A8AD5CFDF8CF219E84C4A460FFC123D9756D04A22E69AD80E7A963D18F328C797ACA426E" +
        "5B1E8F9D229E7F0D0B1B6BE6C6BB775368E35F5466A6A396EFFB8C1891A758DF833E227521389DEBCF91320E79C90A82" +
        "3FE8B8F2AC936D970AD559C37AB37B98F73842EDDCCD2F92A462ED208EB7E8862B40FC709111A33752B513A56E88DB89" +
        "5A57AE74791F49840A882AAB4675BE0835DB1E02946D41234D954FE242E232755486F382E0EA898070C46D088723BAA9" +
        "32EE03538E41EF812337CC5DE142771995D6B2D029CB0E60688B0E2B654D8F340351D8D14557E4FC0A9B8544AA5487C0" +
        "94C65E0191B014C8EE37D67E101B78CC2BD834E95BCB1ECF6AA6534EE4E336D33761F6137E28038931DF80AB82AE5E95" +
        "70B7F1E7600DDB985D51B67612A9C095A59156F083D8B5A1B8DAA26538BEDEE3639AC8E2F8585309E0C6BDE3EE7CA19C" +
        "2C22B171007F9E4A5DBC4ECBCA098435356F5F7ED1E6EA556E4AFBE37FAE25C9660BA7106599C80D67188A1CDF1C1C2D" +
        "63DD0123E258875B69934462B9765C0D7890481806851B70E21995B7989680AF0FCC0453BB096A7D9A81C89C5DD43C76" +
        "F8097BF08215FADF3E1BECE63A157A786BBC670594F1FCACBF2F48331FE0B128F93C4240C0E8B33B28F940FF16F79BDA" +
        "4C1D33FD1E1CF2029DD8CE41FB3446B8E8EE93B9E401089D8C3F9D1F159969BB8F0F617ECA7B5D9F0E6BD48036115111" +
        "71289B748B46365C01C23EBDC945B91EE7E9EC98D4622288234395CE8243A9A5639AC8E2F8585309E0C6BDE3EE7CA19C" +
        "2C22B171007F9E4A5DBC4ECBCA098435634C98BB4D1A3D12F65AD2EE12F19E175F02E70AB777D7FC01D3AE2D96699699" +
        "5453220C55AB3DD80A17209205B3DEAF5FAF38FE566B77EF26B25559D4F636D0B764C19C701BC2C596713224A29B927B" +
        "256C610E1C0604E1E5D69A1C9C39742372C3092F371341E20CD2BA50A581462BB9DBB680E638450079E797A3C7F20FFD" +
        "F52BE59BBF62D37DDEF4380E7A172CBB6E4845DA5F9087CA237591376AD60A718D68D7D24F63F8CFF249F3D53477EA75" +
        "41A1F81B03A04F0776ECF0E7D73113C73E7B1F25934FAD132335AC8ECA9A6834A5A6BA0DC188B7E9D5CB9643163F1826" +
        "66FD0DD883EEB49F20CCEFDC2560C22F829220B8FD326A0598F28311F73A663995B1DE96FE158ABE0FEABCA4E327B10F" +
        "618C61449E64DCDED2441251C1609A45066F602E0C56B3F54C650892D6120903B28B21B177EFAECCDC0E6B5FAB761EB8" +
        "316C6A4E92FAA4514431D81422919C71650A041F6C955679B861816348F3369E841C9B907B74B940944583EA1A393058" +
        "A661E2B712D04F825A9493D9F4184D32723DA86AD0F076EA9D74193D22CA01648908DA7393808BFAB6FADF039FBA38FF" +
        "75B72F1FD663679873D7F7B9234749F4DE1CF07044C5D8E789B142DDA3CAAF1CA3C11BCB953D48E61478EA186429D738" +
        "C771CCB84196A5D44D1628E61E9C9D269A8947D7F6F5FCA9DEA4CE548BD0F25B03384601F5201561B5F4D672952B3087" +
        "F31B64C797C06D6835906235B26FF12D57BABE3BDD642C49A1FC043EBC8E975ABD40739139B685D6360EC77F893A9354" +
        "125B2E98D93F29CAC32DBF9817C36AF98A217A58C2E22E70D2E441AB4D5C9FF387820148C523428BD7BCDB43273650E8" +
        "94943C21E08A52F019693D274EC34A8FE5C72146693CF5A95A44207B22E9F611B943BAE9EBDD7259BA61AD881EC68F82" +
        "D59E4C905EC129D00C05A3618D790B1C376883B4E86AB9AC29D1EEFD4891B6D2AFC81806A934BC9CE8C5B6B32367C43B" +
        "3588BD31173F86ECBEC14E927338B5A7AE66BECAB58247F2581C1692AF8B4DC8B17FE2B098D9ED7DF2163968E8CD8317" +
        "1446022232FD79813EC556D471103FC8B2A33823E40901BEAC1363B49A437A6EAC5DEC39CBFAB57B19BF433BBDCBC2AC" +
        "57A98654B4B302225DD2759391D4E1A461254832C18F4E33F5CE049BFDDCEB59B8D9F006AD23090CD7CEAB639443B8EC" +
        "E2E90F580055867D8E382ABF8D54577AE0FA38FE9489EC1CE8D7AF6894F67A3994183FA8A90E7F966A4611FE923A81FA" +
        "20E8018B0EF398F4218A7A1CAC5143B2436ED60EB3B4E774D651F76E58FD671984AE9E9B00FA1105C4F107C03CD0EBCF" +
        "1603EABA7DC58FA99B6DA2A42C3CACD11E9485D2C8E1FB2A2145341DB17619A1A7942A34B23D8F6394CCC7A5EB097EA0" +
        "DE411D5851349ADF67A25B184A68C248F7E43FEC800D69CD4BB1FD03BDCEF5D5557662BFA378D2691DC25D4E78E4EDBB" +
        "8ADB7BAD9ECFD09D67F4064915AD454C6B7C68DEB654FFBCBE741FBA9D1A9DB39C19584570AA01CB11A86987FBE5F599" +
        "66E8DB4FA40172856044584DEA397F5B8F65720DBCC190C091BA4644921B653A8E0A9BC2E4BEEDE0CD910EFBDBB8A302" +
        "6129D7B7F368758ADC6EA7AD670613A7CA485D6584FB16366998E5BFD50C13428BA2F90A101C8CA7A69A115668AD9A29" +
        "AB286A1765F15F3ED25C9D22532B89C7AA1D52E44B8AA23D0FC961C36782B3C2B25816F01078F6F773158A2830C26729" +
        "998702684B2BE573CCC2CE8C1E531A0BFF995D3F0B843FD6E74D7DD37EDD756A4D844BDE36905EC90A1BC98ABCC5BC57" +
        "F6B116034871939C601C2823D482CFD604CB2B68ADF5419251A071EAEFEF133895FF02D7D8FFF83C33053B0F702090C0" +
        "58D9FC416A3380DA67935AE9D1363C0786FD56662586CB4F3A4183738703239A";


    [TestMethod]
    public void FoldedChainUnderFixedSeedProducesCanonicalBytes()
    {
        byte[] firstProofBytes = ProduceProofBytes(out bool firstVerified);
        byte[] secondProofBytes = ProduceProofBytes(out bool secondVerified);

        Assert.IsTrue(
            firstProofBytes.AsSpan().SequenceEqual(secondProofBytes),
            "Two fold-chain runs under the same DeterministicScalarRandom seed must produce byte-equal compressed proofs. If this fails, randomness is leaking from a source other than the threaded ScalarRandomDelegate — a regression in FoldChain or the compression.");

        Assert.IsTrue(firstVerified && secondVerified, "Both fixture compressed proofs must verify against the final folded instance.");

        string actualHex = Convert.ToHexString(firstProofBytes);
        Assert.AreEqual(
            ExpectedProofHex,
            actualHex,
            $"Fold-chain compressed-proof wire-format drift. If the change is intentional, update ExpectedProofHex to:\n{actualHex}");
    }


    private static byte[] ProduceProofBytes(out bool verified)
    {
        //One deterministic stream threaded through the whole chain so the
        //blinding instance, the per-step cross-term blinding, the error
        //commitment blinding, and the compression masking are all reproducible.
        //The chain's provider and the prover's provider both close over this
        //stream so every Hyrax blind draws from it in a fixed order.
        var rng = new DeterministicScalarRandom(FixtureRandomSeed);
        ScalarRandomDelegate random = rng.AsDelegate();

        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey(HyraxVectorLength), random);
        using MaskedSpartanProver prover = BuildMaskedProver(HyraxVectorLength, random);
        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(HyraxVectorLength, random);

        using RawR1csInstance template = BuildOneMultiplyInstance();
        using FiatShamirTranscript foldTranscript = FreshTranscript();

        using FoldChain chain = StartChain(template, provider, foldTranscript, random);
        StepRaw(chain, BuildOneMultiplyInstance(), BuildOneMultiplyWitness(), random);
        StepRaw(chain, BuildOneMultiplyInstance(), BuildAlternativeOneMultiplyWitness(), random);

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof proof = Compress(chain, prover, proverTranscript, random);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        verified = VerifyCompressed(verifier, proof, chain.Accumulator.Instance, verifierTranscript);

        return proof.AsReadOnlySpan().ToArray();
    }
}