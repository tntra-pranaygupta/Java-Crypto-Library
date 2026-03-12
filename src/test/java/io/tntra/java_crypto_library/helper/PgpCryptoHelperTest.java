package io.tntra.java_crypto_library.helper;

import io.tntra.java_crypto_library.exception.CryptoException;
import io.tntra.java_crypto_library.properties.CryptoProperties;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.jupiter.api.*;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;


@DisplayName("PgpCryptoHelper")
class PgpCryptoHelperTest {

    private PgpCryptoHelper pgpCryptoHelper;

    private static final String AES_KEY = "dvjKbD/FWcZ775VbcD0STWCdfMO9rE9jyPvkr+ySGAY=";

    private static final String PUBLIC_KEY = """
            -----BEGIN PGP PUBLIC KEY BLOCK-----
            
                  mQENBGmpLicBCADJASCQFbCj+6LIehf1dcHRlCw9Cf3ybuNCO2phG0o0i+ivkn9L
                  NFKbg1qSIUif/6V3kZIr8HMXRMg/jPITJupYpFiQGPESVEDYJKowWOfnULkCWPBb
                  6wlj78KNC6NNVjfi3J7DWbC1GC2QMj86BI3LPDMX03huCY810D7cRiPNk+UZaIOn
                  Dam+5HQkh4+WnEUyM3TNhcT3YvrRsMopz1qIgLfxzuj+TsZtog0bEGaaQ4tUdB8r
                  VyAT1nW7WtrneHAtXnKHL0p1jUCSX2QE1RcBFgvQhgFv/R+6JCwoM6F7qs4AkSN1
                  /xS5w2+r9fqfF9GEnnf1J1PU0lRn0Y7v5JPlABEBAAG0HXBvYy1zZXJ2aWNlIDxw
                  b2NAZXhhbXBsZS5jb20+iQFUBBMBCgA+FiEE5/J5uNRqBXoVdmPLld1De7RMjoEF
                  AmmpLicCGw8FCQHhM4AFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQld1De7RM
                  joHfNggAr0eIThRnOVpgyJQpeA3wEK9ADRW4FgXk5KiW0L8lPvW8bfgxCxOZXorY
                  xPhScAY7IDCZA8fkzrKYM0ASIy6b6BguqRLZs9iRN/KKKQMh+w3BSINf9TUr7YN/
                  SakgvuApRGGvQsHlVax8Eclz0ZUTjtPQp5GvF12D/R+IGUp/XuI8ckDIWfCci3wZ
                  jKecVqpq8LULEoFfvNhVotuJ6yvVZoGq6UmpeMhzPaQpcCNUJmxluFO8dQYVfTXD
                  afpfzUR3NlH+7GSFUsVSvVtKQCd/4oAL3o0868oDGgmV1uZNFYznCkxe6NrWzBE7
                  7R7CXn/cDZm0yZtcFJ6lyAglbyJJ2bkBDQRpqS4nAQgA3MyFGsQaRO0GLvB4iqHE
                  viJHwTWpic0TLMW7ZqFl7n2VZBCQ3S3m8zCe7a3MXgIejmZSzPzH0aZmtaJwn5BE
                  YBd+UQclnDPShCKSbKYZVF2bocAzK8YixAbDc913a6kJY21O2s5CIFrjqkixu87a
                  V5fZzNbdMDyDRqPiwwQevc3c2ENxu49upoJvp4/ghJ5xn5Sei/RsXTruVHDrTo5n
                  5nWfl92c3zOpPChsygGoD8s33m+X/OoDKBE0KkoFGp6EWAIrbUiRStHjWPKKxxl5
                  yByqWlhkk8qR6HlKHAoDiMZPtiP4viUAIKA+Ft+n4Ghv7kmw2qRc2CQ49IQcEJZz
                  SwARAQABiQE8BBgBCgAmFiEE5/J5uNRqBXoVdmPLld1De7RMjoEFAmmpLicCGwwF
                  CQHhM4AACgkQld1De7RMjoE+eAf/bIQNTilGfRWMwhi/yhg9g0CWTI6GvQIzzc8O
                  UzcNiwpIXbU9VTclLC0G3ig9RbwK7ZHNO+vp4xA0s8iwlagxys3QT3oya5vwFcet
                  qjJl0IlR9fsJKabx7dukLok36bnnQ/PWW+Z/aa0rdEHiuohk89Npp92+X/ziuZ7A
                  btwK2Wg4ggQSv1IO4bX4y/jzCsvv8NVE2ypiUX6jwM6R0NwlAf7/f6fq3nU48NGg
                  6xfGzuWl7aYtlFZlITemh4WiCV7vUZlD7BNMFuhMR8Kad5S6lOEM9cAqkEQl0yGY
                  bFIfXXYdd4O1AAruYaWBSNf1OJCFBQYXBcaO5NtbAnLFISCFKg==
                  =gJKU
                  -----END PGP PUBLIC KEY BLOCK-----
            """;

    private static final String PRIVATE_KEY = """
            -----BEGIN PGP PRIVATE KEY BLOCK-----
            
                  lQOYBGmpLicBCADJASCQFbCj+6LIehf1dcHRlCw9Cf3ybuNCO2phG0o0i+ivkn9L
                  NFKbg1qSIUif/6V3kZIr8HMXRMg/jPITJupYpFiQGPESVEDYJKowWOfnULkCWPBb
                  6wlj78KNC6NNVjfi3J7DWbC1GC2QMj86BI3LPDMX03huCY810D7cRiPNk+UZaIOn
                  Dam+5HQkh4+WnEUyM3TNhcT3YvrRsMopz1qIgLfxzuj+TsZtog0bEGaaQ4tUdB8r
                  VyAT1nW7WtrneHAtXnKHL0p1jUCSX2QE1RcBFgvQhgFv/R+6JCwoM6F7qs4AkSN1
                  /xS5w2+r9fqfF9GEnnf1J1PU0lRn0Y7v5JPlABEBAAEAB/4kZuKbjX4LuJTyqx/f
                  KXgUKTo4xLA7oUbhdgquMufFq+fUMhsBBuUF+mwi5km1hjIUfSXEdNuXBXMhhThK
                  7SOIMZ1DXWz9NYp3ym4S6ur2qpkS2oIPF3oAIgnxCsBEj354BJ3xAXN93HbV9C+c
                  pXn7ajfTkw3umacYpxHXSRGPV2z6XQCrVMNwwde62MZSUgCmD+BAD56MEoiUEzXQ
                  k4JwT3GIfSlblztu7SEJwti8LgpoEM1U0QvAVgkfoZHzfhd32aSsDyeamOuQ4par
                  +SzqVn2uC6RIYbW4kbXiCf0edQ/nWQeAOWeRaKVcpK0FZMSByvE/ztMr9xC6vT93
                  hCeBBADeVquuXhI+4oZ4zIIDK2GqdsmQhLZ9SAIwkuh3V9/0olEBwCfjvF4r5915
                  dy+cEYCkMNVzCl+QB2VGfFlPqocR3VqjkAPKEuR4Ekq/LBfAUrD/a4vvYno7JR2b
                  TXtnt01/JWjPjnseqSVS3gf9c4G8TuqzIWSvDMTM/jLWw1eegQQA52+YD/DbZFtz
                  0MibjxooyJN9CdqgQbjxOwoOP3zi0UT1c34VkPTGILp1z96HAPw3L6yaAp/RhLov
                  363QWRq46WiTD2TU60WROH32qVTqxA2enGf30JmzZmE9RvrOgNbA9gDmVwQBTfgR
                  NKB1+sDE5Ul4thsuDbcI9RzSvA/Di2UD/RofjWnoPsiCIwa3b3P3uFs4lER1AbCQ
                  RPGz0hgBtwNf1WKY+/iNbL1bsColv0xZY9zuBf4louUYN78jl39TodNmnBcCLZ9M
                  hxuRF+glOAg5l88rP0Zimjc5kPfxzrGM8LpmaaUzc1xHNSpIz4zgILnjX6+4OIcI
                  XpmPCzDw02smOTW0HXBvYy1zZXJ2aWNlIDxwb2NAZXhhbXBsZS5jb20+iQFUBBMB
                  CgA+FiEE5/J5uNRqBXoVdmPLld1De7RMjoEFAmmpLicCGw8FCQHhM4AFCwkIBwIG
                  FQoJCAsCBBYCAwECHgECF4AACgkQld1De7RMjoHfNggAr0eIThRnOVpgyJQpeA3w
                  EK9ADRW4FgXk5KiW0L8lPvW8bfgxCxOZXorYxPhScAY7IDCZA8fkzrKYM0ASIy6b
                  6BguqRLZs9iRN/KKKQMh+w3BSINf9TUr7YN/SakgvuApRGGvQsHlVax8Eclz0ZUT
                  jtPQp5GvF12D/R+IGUp/XuI8ckDIWfCci3wZjKecVqpq8LULEoFfvNhVotuJ6yvV
                  ZoGq6UmpeMhzPaQpcCNUJmxluFO8dQYVfTXDafpfzUR3NlH+7GSFUsVSvVtKQCd/
                  4oAL3o0868oDGgmV1uZNFYznCkxe6NrWzBE77R7CXn/cDZm0yZtcFJ6lyAglbyJJ
                  2Z0DmARpqS4nAQgA3MyFGsQaRO0GLvB4iqHEviJHwTWpic0TLMW7ZqFl7n2VZBCQ
                  3S3m8zCe7a3MXgIejmZSzPzH0aZmtaJwn5BEYBd+UQclnDPShCKSbKYZVF2bocAz
                  K8YixAbDc913a6kJY21O2s5CIFrjqkixu87aV5fZzNbdMDyDRqPiwwQevc3c2ENx
                  u49upoJvp4/ghJ5xn5Sei/RsXTruVHDrTo5n5nWfl92c3zOpPChsygGoD8s33m+X
                  /OoDKBE0KkoFGp6EWAIrbUiRStHjWPKKxxl5yByqWlhkk8qR6HlKHAoDiMZPtiP4
                  viUAIKA+Ft+n4Ghv7kmw2qRc2CQ49IQcEJZzSwARAQABAAf/TkPmuI6jmyQDaZcO
                  u2FNKnJfSfLaFkENl3S9kUsLpSZ50l724pfXQgPNigVtqDMLHsHRftzpfXyE8sRS
                  NJVAT2l0eodUgxJxgCn7Ci00VE3cEVFeMhmJEEAvfv4VSyG/dLF13qR3Fx3wjlc3
                  PRG9HohyiSPugp8oj10fT65BsVhDbKVQufQDmNirtbdA6WXsmu2BFwWBQBj+ften
                  5AosNcXzhB1p54EywT2NKfOfQA7QYl6FrXP/YHVZlvknZcNsO3v5ZS/ufAOylsdf
                  Wit6Q3MU3zFnYrofYdNXi/K6ZRYPWQtppY7Nfp40+iaSuLBs2IDSLk95whm5uDen
                  RX8BqQQA6tBfEHm8Y/nIfM8xE6TkDOiFk1lmdBHlJFANcNWal94Ct1h3Xkg0XLDZ
                  OJpBq/lP/sWTWYqU4em5BOcov7WU0mrjx+bx+hus+L6M5Kj2r1jOdEsjZPSyi7Vx
                  sbz0v4XJCwqgF+fR4aYzs928a/iVzA7HRx1URDYhFzl6bo0s97MEAPC4b2/nvonX
                  a54sn8RrgIQwl3GLn2UgakCSchgHWLhQJKaqvCO++3BronHG+WQi+jDHzy3g2aLb
                  DqzagkrjmVc4wI4JwlTHPBLkeVFx80owvb8bRsGh7nBmTDfWrK6gbU8rvxeUUMKc
                  ZBHsy8qwUalmgKXXUufTD/pAinrH+EoJBACbS1w4SLYPyYtIii/EpjGSjyi9TnkS
                  3UcPzJ/sXzKlnjnDHNwieNFgHi+qQSvFVpkofq0oe3ESsQm0cj1/6/NUhP3iPL67
                  yFlerhYXj+ebcWovFyG9Bh+78RZ75dnpcqXkTqe7xBRxIfXZz0nWC0d2pKtGHz1a
                  BQzNTcKLu6DHhD+wiQE8BBgBCgAmFiEE5/J5uNRqBXoVdmPLld1De7RMjoEFAmmp
                  LicCGwwFCQHhM4AACgkQld1De7RMjoE+eAf/bIQNTilGfRWMwhi/yhg9g0CWTI6G
                  vQIzzc8OUzcNiwpIXbU9VTclLC0G3ig9RbwK7ZHNO+vp4xA0s8iwlagxys3QT3oy
                  a5vwFcetqjJl0IlR9fsJKabx7dukLok36bnnQ/PWW+Z/aa0rdEHiuohk89Npp92+
                  X/ziuZ7AbtwK2Wg4ggQSv1IO4bX4y/jzCsvv8NVE2ypiUX6jwM6R0NwlAf7/f6fq
                  3nU48NGg6xfGzuWl7aYtlFZlITemh4WiCV7vUZlD7BNMFuhMR8Kad5S6lOEM9cAq
                  kEQl0yGYbFIfXXYdd4O1AAruYaWBSNf1OJCFBQYXBcaO5NtbAnLFISCFKg==
                  =oCpy
                  -----END PGP PRIVATE KEY BLOCK-----
            """;

    private static final String OTHER_PRIVATE_KEY = """
            -----BEGIN PGP PRIVATE KEY BLOCK-----
            
            lQOYBGmqeuUBCACfPJWfzm6e1oddofMlLfnVa4q4t1BGrQcMr8WJc5dSMoZOBVDB
            8RjO2b+ymmKUKYcvsLYK5gSn8BbaQ3kX2pEp2gdvmEs0ofJU5ufHMawU5cLraunI
            tkBlF6YC1SGfTuFG8LYAAV5R79pwzcaOPLUPoljddPcAHoSW8+W1ZK45XptU0AjF
            6Qxhpnh2Y22uYQuyVlVMLWsK3O6QY1+gbYEGigj0122Z0quRFoD2BTycPf+CVvak
            Kka9C3iCqTVZePjhzLBzo0fk3WWp0eONrbF++PhZaY18K6wQw1gJvCvpqzUhXowJ
            TlMhkE99np3B3Z35OzEovhEoT2YKa0kYlsDlABEBAAEAB/wOgMUb7gBTRTTFCWgM
            3dggYRAcbM3J8h5vQF8cesOwf9uNpZxKXbwlst1r1fXeir2+UTjzWynXZd2e+YBA
            9O49wpbkyhknbQyWQQWhNdv3d0m+iVlLp5XL31CGd4T9boDEJk5dR8KgcdkSZxuL
            fun6x42SdgG9KAppeUNVtxrLLLbpzSI314sOKXODhs1BtYLI+kwy8sBi6Tjh4bpN
            z4Fel7EE+QNcZ4wU9xSNHbezYp9oiCV3g27y8ca/ALjH4B0rH5vILAvqtGrPQNlX
            oe/XpeKHfhOMNKYx6ihi32hgHBwEYgABHZ9QhVBw7fu4NSUUYR/Zz7yvKzmOuafJ
            RmPhBADC1jL+kAG7SlemfOPlJ04uJqErllDtIrTpqrGxBc1OrjFdof20Nezra8n7
            WGB++3Bxi8bL61vSQiWR5H9VoGDdYmyOVar0eY1Oz0lxc2ThubecDh0Gqp3vOo5P
            upksrLH3luwfiG/UHXvF8lqLZ9EcPON27bLdwjrxuh4Kep6TiQQA0TluwztGXI4L
            MwgcCrbncPl/gIxu8Nyi3CYhAxIe4X8dXxUs/7WEi3/1Leagt5OUWbf3JEKnUjI2
            2CGNmTBp77LO3/Msxj3hPnQhZw9LBXwDjQq549TDB9L5tIERRgZFMKc5aKNz/HU8
            QOF++OksO1Vm8WM/att4DXhDs5OKP30D/RtpY2hAhaDhHNJOVOi47TjOAd0VfhnH
            jmdaZjz/VZms+SHhs4tkKaX+2EnJidT2Y93PGqrHb5iOmU0kefoejOjaPZszSeJA
            ozedqYGd33gN2GwcPFSNHnh0pMEQYq38AXE+eC27ORKM+1DZ4JjOYQlQOWmFokuc
            L72v948EUJhLRVO0HXBvYy1zZXJ2aWNlIDxwb2NAZXhhbXBsZS5jb20+iQFXBBMB
            CgBBFiEECzNsko0aZXx6FY3pUzFFzpae7moFAmmqeuUCGw8FCQHhM4AFCwkIBwIC
            IgIGFQoJCAsCBBYCAwECHgcCF4AACgkQUzFFzpae7mpxBggAicGEv81kjJxo3MCI
            lf0kLg+Ft03DeM0odyg3zIzBNasuc97+ce8YpDGHn6ss7ZDngbuGoPUCsNbREm5w
            Ag7Q7xP5MmwOPrMFQ62opbdcKa+Gi9WkT4fZenW4yWWie2V+wZnHsv+vz0ILMLzW
            lgeQEnxDWHuq285yNJy2MdFtMnaFSvBUA0lSGI4QrHSm5s6senl7ZT8/HD4ynw8g
            +A9tXyE0EoT/luHnbJuKhVsc0e9TEGXyOk7X0VhTPfunTWvEtjOdtrWpi7vdJS97
            FDLatFaHbkE1NUVp+ch96gHF4I/JMA4zrRNLQguKHwrC0DY54P1mM8UObrUfFYxJ
            X7+uBZ0DmARpqnrlAQgA1FiWwYnrCVrZ6H6WbBWV2myeJfPA/uNY4OnMUSi/VIIB
            1pbbO1c3qe/DR7V29S3ZTktEfJviVJbt6m+hOxkPW2+X+21UuydfOSjK4bWm4Yxe
            LBtvbgUh/EJo6XlXz3ZMxzMLomxUr6lAfR5+BUYMtUEPtKCSM/Kyu/yuovmcGQsb
            y6MYkFAHCNUVqP+aEinvPY1SBZVwGMJqReXFHz5WhwoUzsj2VSwo/T61dsMPkhmk
            rxqy1cyW9tqGPRWZkJi4NtpOmSsilMKRGkTO5NW8Ny9uZrfCl4RtQfXbE04qVfsx
            iSXGqtvCzNt8c/zLuVsIItW/PpTzb1ykoN7STFgqMQARAQABAAf9GtZQG17Nx0K7
            C/tvvHJP8alM+uP0jjeijy53+wE+M9/d0Uat/NvNi7CN9YgAObAqk47HYEOoAQ6K
            5thmlVxZ81xGZj76TfsFub4nl2DeGgnOXx8Kir+i/MmnORbJG83KRK91YXj1N7bu
            5mv4+7v6NYWRsWpNKrvvjfsQq/AFzqjnRGpL4UohRq9uQD5HLnJ3DqcIC1nFMFxY
            RETwiB/9zidgzvOh6Vwhz8FQj8UwOWNF89LFmFvIoE9rCoMn3LkKQBHLdpbUWrLi
            r88e07hxvu+Be6iVfEkApp5mORyoLfGMXPJ6gwW63HqrEfdjulY55S8dmDKEX0Kk
            Emb5IjlWfwQA310p6URM/ITo9rblwaO0WAaa/YTe7QIMfeuxA0hRWZt2JYORt47+
            rosw3v6UWNQ4sGHP6DuVUsOAtr/NZp7jdqyupNK9VaFFCeJQWeOTIQjDbyL1p75O
            JSYIMn3K2MLmjF3ngCi/MAGnn+0YwdlZhCqfoilTTsvSuzW1MJRGXNsEAPNfTmUQ
            CoYVUG63m6XqtmNALMJoWnlb8nTXMvnSK6JSQFuAGEkU+semeV1h4Vpgx+damzRV
            DeMc2qWjTV6av4s4JsiyQLqseoNcBPZl6WYA/u2Df09MDGjPd6Dh806xIDSRkRfB
            esRaMGs8uYzs3rOZujkwTqHhJupum347ObzjA/0bYK1vPd4aGVAHiPt/v5rgVVGB
            EmputTr8DUjcJza0nFjEXJDfdbzAH3ur3Z++IbfgJ7izjA1IxvprKnrZYfuP+hWY
            colAczh+IIMluXuuIad3nVoO92kQOTFkgiY5ow7dEq1wDuOf4pwpFnWy7HapxXbP
            IGq7BJH6jfBfdIiQCUgTiQE8BBgBCgAmFiEECzNsko0aZXx6FY3pUzFFzpae7moF
            AmmqeuUCGwwFCQHhM4AACgkQUzFFzpae7moMjwf/RzSbiAHKCBEvhROPDRzrkYZl
            IhuHG07ztcVplSfvjonPf+6WxA/286joGUv4NyyrM8Fp4DEbpxPUBJ9keQRqM3tA
            CrXLIT/2fCm3XztL8rsoBQpog+WvjcYbmloE2SObL8KxsM+l/aNM1gK2100nIEfl
            uNqLHJKbvgiTgumBY2zrrzw/kzq9z0McOIPOMQZNJxUYG6cbXia39f2WhRIDJVj8
            oMKyCosNG/hvDmWgBVTZiI40GX8KbsQ1eA6PdHO6e+6CJTIsppCL2Kq6pO3Ybx7s
            51svdbqK610C+fZisn6wWKjMGj7tjDAorQxuOALfq4XJCb13aZBfD2OsPm0PWw==
            =fA08
            -----END PGP PRIVATE KEY BLOCK-----
            
            """;

    @BeforeEach
    void setup() {

        CryptoProperties.Pgp pgp =
                new CryptoProperties.Pgp(PUBLIC_KEY, PRIVATE_KEY, "");

        CryptoProperties props =
                new CryptoProperties(AES_KEY, pgp);

        pgpCryptoHelper = new PgpCryptoHelper(props);
    }

    /** Encrypts and decrypts bytes using provided public/private keys */
    @Test
    void encryptDecryptTest() {
        byte[] data = "HelloPGP".getBytes(StandardCharsets.UTF_8);

        String encrypted = pgpCryptoHelper.encrypt(data, PUBLIC_KEY);

        assertNotNull(encrypted);

        byte[] decrypted = pgpCryptoHelper.decrypt(encrypted, PRIVATE_KEY);

        assertEquals("HelloPGP", new String(decrypted, StandardCharsets.UTF_8));
    }

    /** Signs data and verifies the signature with public key */
    @Test
    void signVerifyTest() {
        byte[] data = "signature-test".getBytes(StandardCharsets.UTF_8);

        String signature = pgpCryptoHelper.sign(data, PRIVATE_KEY);

        assertNotNull(signature);

        boolean isVerified = pgpCryptoHelper.verify(data, signature, PUBLIC_KEY);

        assertEquals(true, isVerified);
    }

    /** Throws when encrypting null data */
    @Test
    void encryptNullDataTest() {

        CryptoException.PgpException ex =
                assertThrows(CryptoException.PgpException.class,
                        () -> pgpCryptoHelper.encrypt(null, PUBLIC_KEY));

        assertEquals("Data must not be null", ex.getMessage());
    }

    /** Throws when public key is blank for encryption */
    @Test
    void encryptBlankPublicKeyTest() {

        byte[] data = "abc".getBytes();

        CryptoException.PgpException ex =assertThrows(CryptoException.PgpException.class,
                () -> pgpCryptoHelper.encrypt(data, ""));
        assertEquals("Public key must not be null or blank", ex.getMessage());
    }

    /** Throws when public key is null for encryption */
    @Test
    void encryptNullPublicKeyTest() {

        byte[] data = "abc".getBytes();

        CryptoException.PgpException ex =assertThrows(CryptoException.PgpException.class,
                () -> pgpCryptoHelper.encrypt(data, null));
        assertEquals("Public key must not be null or blank", ex.getMessage());
    }

    /** Throws when decrypting with blank encrypted data */
    @Test
    void decryptBlankEncryptedDataTest() {

        assertThrows(CryptoException.PgpException.class,
                () -> pgpCryptoHelper.decrypt("", PRIVATE_KEY));
    }

    /** Throws when decrypting with blank private key */
    @Test
    void decryptBlankPrivateKeyTest() {

        assertThrows(CryptoException.PgpException.class,
                () -> pgpCryptoHelper.decrypt("abc", ""));
    }

    /** Throws when decrypting invalid Base64 encrypted text */
    @Test
    void decryptInvalidBase64Test() {

        assertThrows(CryptoException.PgpException.class,
                () -> pgpCryptoHelper.decrypt("invalid-base64%%% ", PRIVATE_KEY));
    }

    /** Throws when signing null data */
    @Test
    void signNullDataTest() {

        assertThrows(CryptoException.PgpException.class,
                () -> pgpCryptoHelper.sign(null, PRIVATE_KEY));
    }

    /** Throws when private key is blank for signing */
    @Test
    void signBlankPrivateKeyTest() {

        byte[] data = "abc".getBytes();

        assertThrows(CryptoException.PgpException.class,
                () -> pgpCryptoHelper.sign(data, ""));
    }

    /** Throws when verifying null data */
    @Test
    void verifyNullDataTest() {

        assertThrows(CryptoException.PgpException.class,
                () -> pgpCryptoHelper.verify(null, "sig", PUBLIC_KEY));
    }

    /** Throws when signature is blank during verification */
    @Test
    void verifyBlankSignatureTest() {

        byte[] data = "abc".getBytes();

        assertThrows(CryptoException.PgpException.class,
                () -> pgpCryptoHelper.verify(data, "", PUBLIC_KEY));
    }

    /** Throws when public key is blank during verification */
    @Test
    void verifyBlankPublicKeyTest() {

        byte[] data = "abc".getBytes();

        assertThrows(CryptoException.PgpException.class,
                () -> pgpCryptoHelper.verify(data, "sig", ""));
    }

    /** Throws when signature is invalid during verification */
    @Test
    void verifyInvalidSignatureTest() {

        byte[] data = "abc".getBytes();

        assertThrows(CryptoException.PgpException.class,
                () -> pgpCryptoHelper.verify(data, "invalidSignature", PUBLIC_KEY));
    }

    /** When encryption fails with invalid key, exception is thrown with cause */
    @Test
    void encryptionFailureTest() {

        byte[] data = "test-data".getBytes();

        String invalidPublicKey = """
            -----BEGIN PGP PUBLIC KEY BLOCK-----
            INVALIDKEYDATA
            -----END PGP PUBLIC KEY BLOCK-----
            """;

        CryptoException.PgpException exception =
                assertThrows(CryptoException.PgpException.class,
                        () -> pgpCryptoHelper.encrypt(data, invalidPublicKey));

        assertEquals("PGP encryption failed", exception.getMessage());

        assertNotNull(exception.getCause());
    }

    /** When signing fails with invalid private key, exception is thrown with cause */
    @Test
    void signingFailureTest() {

        byte[] data = "test-sign".getBytes();

        String invalidPrivateKey = """
            -----BEGIN PGP PRIVATE KEY BLOCK-----
            INVALIDKEYDATA
            -----END PGP PRIVATE KEY BLOCK-----
            """;

        CryptoException.PgpException exception =
                assertThrows(CryptoException.PgpException.class,
                        () -> pgpCryptoHelper.sign(data, invalidPrivateKey));

        assertEquals("PGP signing failed", exception.getMessage());

        assertNotNull(exception.getCause());
    }

    /** extractLiteralData() should throw when factory returns unexpected object */
    @Test
    void extractLiteralDataUnexpectedTypeTest() throws Exception {

        CryptoProperties props =
                new CryptoProperties("dvjKbD/FWcZ775VbcD0STWCdfMO9rE9jyPvkr+ySGAY=",
                        CryptoProperties.Pgp.EMPTY);

        PgpCryptoHelper service = new PgpCryptoHelper(props);

        PGPObjectFactory factory = org.mockito.Mockito.mock(PGPObjectFactory.class);
        org.mockito.Mockito.when(factory.nextObject()).thenReturn(new Object());

        var method = PgpCryptoHelper.class
                .getDeclaredMethod("extractLiteralData", PGPObjectFactory.class);

        method.setAccessible(true);

        Exception exception = assertThrows(Exception.class,
                () -> method.invoke(service, factory));

        Throwable cause = exception.getCause();

        assertTrue(cause instanceof CryptoException.PgpException);
        assertTrue(cause.getMessage().contains("Unexpected PGP object type"));
    }

    /** resolveEncryptedDataList() should throw when no encrypted data found */
    @Test
    void resolveEncryptedDataListNoEncryptedDataTest() throws Exception {

        CryptoProperties props =
                new CryptoProperties(AES_KEY, CryptoProperties.Pgp.EMPTY);

        PgpCryptoHelper service = new PgpCryptoHelper(props);

        PGPObjectFactory factory = org.mockito.Mockito.mock(PGPObjectFactory.class);

        org.mockito.Mockito.when(factory.nextObject())
                .thenReturn(new Object())
                .thenReturn(new Object());

        var method = PgpCryptoHelper.class
                .getDeclaredMethod("resolveEncryptedDataList", PGPObjectFactory.class);

        method.setAccessible(true);

        Exception ex = assertThrows(Exception.class,
                () -> method.invoke(service, factory));

        Throwable cause = ex.getCause();

        assertTrue(cause instanceof CryptoException.PgpException);
        assertTrue(cause.getMessage().contains("No PGP encrypted data found"));
    }

    /** readPublicKey() should return an encryption-capable public key */
    @Test
    void readPublicKeyReturnsEncryptionKeyTest() throws Exception {

        var method = PgpCryptoHelper.class
                .getDeclaredMethod("readPublicKey", String.class);

        method.setAccessible(true);

        Object result = method.invoke(pgpCryptoHelper, PUBLIC_KEY);

        assertNotNull(result);
        assertTrue(result instanceof PGPPublicKey);
        assertTrue(((PGPPublicKey) result).isEncryptionKey());
    }

    /** readPublicKey() throws when provided key material contains no public key ring */
    @Test
    void readPublicKeyNoRingTest() throws Exception {

        var method = PgpCryptoHelper.class
                .getDeclaredMethod("readPublicKey", String.class);

        method.setAccessible(true);

        Exception ex = assertThrows(Exception.class,
                () -> method.invoke(pgpCryptoHelper, PRIVATE_KEY));

        Throwable cause = ex.getCause();

        assertTrue(cause instanceof CryptoException.PgpException);
        assertEquals("No encryption-capable public key found in provided key material",
                cause.getMessage());
    }

    /** decrypt() throws when no matching private key is found for decryption */
    @Test
    void decryptNoMatchingPrivateKeyTest() {

        byte[] data = "hello".getBytes();

        String encrypted = pgpCryptoHelper.encrypt(data, PUBLIC_KEY);

        String differentPrivateKey = OTHER_PRIVATE_KEY;

        CryptoException.PgpException exception =
                assertThrows(CryptoException.PgpException.class,
                        () -> pgpCryptoHelper.decrypt(encrypted, differentPrivateKey));

        assertEquals("No matching private key found for decryption", exception.getMessage());
    }

}
