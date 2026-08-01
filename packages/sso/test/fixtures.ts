/**
 * Real cryptographic fixtures for the SAML suite.
 *
 * Generated ONCE with the `openssl` CLI (3.0.13) and committed verbatim — the
 * same tool the Rust suite (`crates/ferrogate-auth-service/src/saml/tests.rs`)
 * shells out to. They are committed rather than generated at test time for two
 * reasons:
 *
 *  1. `workerd` cannot spawn a process, so a test-time `openssl` call is
 *     impossible in the runtime we actually ship on;
 *  2. more importantly, a certificate produced by our OWN DER encoder would
 *     make `x509.ts` self-consistent: the parser would only ever be proven
 *     against bytes the same author laid out. These are real, third-party-
 *     encoded X.509 v3 certificates with extensions, an explicit version tag
 *     and a serial number — the shapes the parser has to survive.
 *
 * Reproduce with:
 *
 * ```sh
 * openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out idp.key.pem
 * openssl req -x509 -new -key idp.key.pem -days 36500 -subj /CN=test-idp -out idp.cert.pem
 * # ...same for `other` (a DIFFERENT key, for the wrong-signer test)
 * openssl ecparam -name prime256v1 -genkey -noout -out ec.key.pem
 * openssl req -x509 -new -key ec.key.pem -days 36500 -subj /CN=ec-idp -out ec.cert.pem
 * ```
 *
 * The private keys are test-only throwaways and sign nothing but assertions in
 * this file's own suite.
 */

export const IDP_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUSFE1O/+58bEVtjCfVx6ukAgHnfMwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIdGVzdC1pZHAwIBcNMjYwODAxMTAyODQ1WhgPMjEyNjA3
MDgxMDI4NDVaMBMxETAPBgNVBAMMCHRlc3QtaWRwMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA8s9imj3/91npbbhLknfygyX/PIAfeXHI7kR6wx6M2ohV
uph6E2/8Szc/X8CHb/BFhJrO+OwpTmQKDr9FHNClKCILmrLdGviNAYClBtqS/qKB
/P5zFpb0egWwZvyLzzeKl5Mu19R5QsiFPfwRIAan0ZuZCx4JuYM2EecA6hKhQd+7
OPFgkbNY7o7lldlOIuCXFEpiZKXUZAbMZvtDAV02VF314pfaL8niPZiVYVR9Mfq7
qntIOqZ52ZB2y/nG42gFfCR+aE1V5xlTpwHexMic235lACQyvImT9Aban1nL8B1u
0NflfDcR74jVcOYTPMflSCfYvjHdHwphKaHlZH1mfQIDAQABo1MwUTAdBgNVHQ4E
FgQUhsWXvXQac/KBNnlvhyPOhKwfA70wHwYDVR0jBBgwFoAUhsWXvXQac/KBNnlv
hyPOhKwfA70wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAqERV
2zD6SLRfErpZRexqJNgIJ2tTfmHMrItq+20aaFkCCyGIs0kquhnJuF4TdgQ/VqZQ
DcFhZQcawCb2m47RCfdoBxhFBZ9Mn1fAUuQAs8+sLjbHdRtgvbRuNbGz/JzR4Qxe
V/pDtnTTSKajsdQJtyK3mtjJPlFjOcomUaw8UWwvG3utubEYN4PmBsF+nhB+EQtX
OfQ/ce5WJQphJaS9uJBwuaM8knj4g0ztJKASzoUGCsDGVIqgV/hmN8W02jxZcKE0
PYfrnYVD6bnPkkN3Ix+cXwQF/1YePcJuAx5u7Xb7hIsqalz+qIMqGsKC54hhAGAQ
DSoTCM1+WTNnax7MZw==
-----END CERTIFICATE-----`;

export const IDP_KEY_PKCS8_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDyz2KaPf/3Welt
uEuSd/KDJf88gB95ccjuRHrDHozaiFW6mHoTb/xLNz9fwIdv8EWEms747ClOZAoO
v0Uc0KUoIguast0a+I0BgKUG2pL+ooH8/nMWlvR6BbBm/IvPN4qXky7X1HlCyIU9
/BEgBqfRm5kLHgm5gzYR5wDqEqFB37s48WCRs1jujuWV2U4i4JcUSmJkpdRkBsxm
+0MBXTZUXfXil9ovyeI9mJVhVH0x+ruqe0g6pnnZkHbL+cbjaAV8JH5oTVXnGVOn
Ad7EyJzbfmUAJDK8iZP0BtqfWcvwHW7Q1+V8NxHviNVw5hM8x+VIJ9i+Md0fCmEp
oeVkfWZ9AgMBAAECggEAWOz/DcJbNnnlddujQddQKBwIaF38KPw1PJ4z37YWnAqG
azpgqzG+UsW/HhBjCeoTa8dOufe0ARO+YzxF0ZHQiuw9F8EeHTyeV8iHqATxBPT7
am6+M63Bh9cBjhY8Ff4fcffjlgQpDP5nXhYtJ2+IksnLuTidEyYs7U2PFisQiBDz
09hTYtvbVZzb/blBVd5zszJDcwV1FTOndB101GWTWJvgHhvN7gzEg7Qd8EDFMIBH
pwqjV89szZYnK1l6BL7CCT7MuBepqfhaV1iBTBQzfLhA/55EOtZFIWkTfLvSFag7
z6SbRlM+B92dN+dNgRSfRvKTHo0FvEsIVpfMGiOeuQKBgQD++jOUnYW8V1ZvW85f
8j+mHv+G8PnR1O1MADoxMFANXHwtA8zGH4rIe9EhQ1vZ9xctGgBug0sqI6TCYhRW
bXB35Vd+Ha7fqI7gkTEv6Sh5sESFc/rOi94iim1l69naP6KB7Z5RvwUs4NCecWVV
d02bngJQCL7847bs2b+DfkW6SwKBgQDzyLDgwsLS6BCpT0EZ7dINE7C1YfUBZmmY
Nbl8oBHghjxZxpUxx6XTzkXN4FY5oBHzjiFcSCsd6XgJd8a1D4vBo1W3KErdukN/
WqSgY445N0KD+PXglX+mUXMtbzmQBItgrTV+NJ/wwbdp/FGlxPFrsWwZHIVz3+70
ZAUU2bLlVwKBgQDshDqEiPodEwbilU6CQbw45FgzXCTgN5tG/I7+QcqAGmI1f2jb
/zZFclUzfcAeF84v0AbGfJOkqxuSFFi5Mxs4nEzkd7RXU4v1U7lEsAsTliZ5hHQK
VEPh1nZULMsQYCbmTvyk54RtdL0PvDA7b0dWKuQKSZKgErsESZgU6XTUsQKBgQCS
59yXBSasO8ZWkPj1LBhJYxU4qJghSNrXK4Dkdf1v5NSXcRDVF695bLMp9kdfoHNQ
5tR5rM+2zctVQUWQNJcOkGQF5JUA+s7T/wZ31KaPGhrONofM16o9ypVyyrTQcbyf
/KDgtcuwJLxndPKqx3yIXjl7BHHzOv3fbiqVvv6MLwKBgQD5fE+4fKERQ/G/kWMe
Aat86hMJm6K8E6VC6ucS8/UBNvdIn7FDHJZSuFW/Y88jseC37Nn822dOAg19qo26
z89rcxbuwZrm8q8wiQOvLDJFtxRxr76BWl8Psfqx586IU37tEmTpqRiUgh6ERqWx
2LOKVbAPZjmKQm1YCUpZDALmhA==
-----END PRIVATE KEY-----`;

export const OTHER_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUaif7pvlY9nRooIq/vqv1yQvC6wcwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJb3RoZXItaWRwMCAXDTI2MDgwMTEwMjg0NVoYDzIxMjYw
NzA4MTAyODQ1WjAUMRIwEAYDVQQDDAlvdGhlci1pZHAwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDyldqwhL7oFmk2h23XrTXHBlWpX+nTCDpkG9Vv5p5U
RZy/VufNeXyQfvsczkqzsrOL+dPI/ju+uRrlF4UzjkfHj45yTzVgcCJBHXmOyvTu
kvZLIzPmwhQ3RmafIMUB2oJ38UhdxnUjHAYi/6sg5iNzu5N6rQIK0UGGGWNxbYeB
VzHHemDzEXLKZdrGt825kF0Y/JLpb6xjQ4wC7bH1whuDFc9a4UEpmE75xI/X1HW6
rnbfor7E9997jSer1i7W5xSbg0+v9a8qC7B39g6mBtZVQAxuePLGG6s4TUDCsgP1
OLreWz6a+4sVM/luPKvnQjJLeigVr/YuN0GVe+/9xOlBAgMBAAGjUzBRMB0GA1Ud
DgQWBBQlYfrt1v06mSrsrjEBL9/iaF8AvjAfBgNVHSMEGDAWgBQlYfrt1v06mSrs
rjEBL9/iaF8AvjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBL
Pc3Z364ou1Z4UcUUkW9ClWTKYZN5XEctjNHE/+JUZBI0SsNVqINPggaC8jIBWG2J
E5Gt86ZFltDdqqwh2+SZMNTCNveJy9FXub6m5q+gX6bEjbDnnQozGx35zpQ5kUwM
3eN9d06+97AlCQh22yY4JInz7LqUaHmYPeV9iHKzI2Y1fypKeFD26TCwM8Tj3oVA
OAI80d+F6Ti5MJ/LsuJ8QgzaZvp0AUJfNVEKshoFkhAgtQd7Hoe0DV+tL1NajJ8W
Zxo47XD8yDK299fAvJqEwbUwV7pMShGkQeL8GZiYiaOcqEnL6miUWLxSNUMW5RDW
jiDoJbvxBOyqPp+8UjJS
-----END CERTIFICATE-----`;

export const OTHER_KEY_PKCS8_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDyldqwhL7oFmk2
h23XrTXHBlWpX+nTCDpkG9Vv5p5URZy/VufNeXyQfvsczkqzsrOL+dPI/ju+uRrl
F4UzjkfHj45yTzVgcCJBHXmOyvTukvZLIzPmwhQ3RmafIMUB2oJ38UhdxnUjHAYi
/6sg5iNzu5N6rQIK0UGGGWNxbYeBVzHHemDzEXLKZdrGt825kF0Y/JLpb6xjQ4wC
7bH1whuDFc9a4UEpmE75xI/X1HW6rnbfor7E9997jSer1i7W5xSbg0+v9a8qC7B3
9g6mBtZVQAxuePLGG6s4TUDCsgP1OLreWz6a+4sVM/luPKvnQjJLeigVr/YuN0GV
e+/9xOlBAgMBAAECggEAJT9OqptbT7n/Miz1t+/DydkmZoEQX0OMaaofadTkeyaM
JJH0uic88dfZeUkQjcpyyJuVwe8NX+G+qC3mGS4vxcu8UL9qP/I/xDVBIKR3mrks
gYl4cuZaYclYwPawYTI6pa2B0cpC2p73L0EH9t93UpIa2TN+1IfgUnWMABLUA08C
TbvsIl+R2sgdauCo0ELiWrskTaSrftMcCr9uryZGomTkiEpCaiiYZ5KyFXQHLiWB
DeOOv8+3wI7lBr28HdzP+f07U06Ugp7Ku1qKJTsWvy1Tl5ITeiT2fV/Ym/aLbF7C
Wn3Xva0EdQhAp4WaZCJ5W3lr9TqIpQftWpW/0Cv+BQKBgQD+WpxG0no64WdNOfdC
S77NHOgNnevo6FZWkaPnsaSNZFKP2QvfHEGfL3HuWImPJ3IaeY6sInvhXswsNN/k
xEvekXU5IhViXka/LmVlXPlag16awOkS8s/c8fRSKdAU5yZBYqPzjvWRON1qGfdE
O7qrzfXaQqecyJTtNsxWfjsBrQKBgQD0J78p36ynB/MeaEztEjPstj13UIoz7T19
PSYcmgqRxdxT6XuciqUV/iEod6A2J44E9oNiMkfM08sjH22ILS446ahlHPFEWd14
hk2ro1jm9iZ+vORUKJYh+kwv0yS3t8484MD1/9ZSpXOaBrdKe+BtSV0DWagn87d5
M2pl5ppAZQKBgQDR7GS4ivQ4bln8wc+RVsSFssrOmjzfAApp7k+xZMrjqx38/Oyw
WjjKsbS9OzNlA/BHa3XWGavWaI/oGEeFHoFjkveFjNzLT/XhyeADlYVzL6M/4+E5
M09dEhBMU5gZ+GB5bHjWBnIkRiNvczjBhu5c52J2nbaKTn2jfiuNYyc+DQKBgQCx
eSrVr0b66yZn1f0E3pRr3lRzpFGxSSPHI2nOpJJGQALV5AP8WDOD9wP3PG1yr/Hl
3aLHADF8y/7++ttNfzn4GLBVP2KJAqGf+FABEW2QBSEaQwfdvNrUu/IhWWN5P9xk
GCNrLZqG3MlZDsSxGbaa+hboVoWK9PdK3Hrcs3EwmQKBgQCgAtxeLwVgStTgwsFa
8frdRF41EncLvZEazeg+PgDV197rTyL3TKrk+Qv+J4+WonQSbSuLKkDk3zvvboZ4
gIpYcE9fRxipaQoSlIrHymZNWLPiazDTA9KQIM6HfxvEak9KF86jofEBmXaYW7Hk
CGVO7rsH9NCm5pdu7zIbhofrdA==
-----END PRIVATE KEY-----`;

export const EC_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIBejCCAR+gAwIBAgIUZDlzf5Tj5EGDGc0kpPY2xk2AriwwCgYIKoZIzj0EAwIw
ETEPMA0GA1UEAwwGZWMtaWRwMCAXDTI2MDgwMTEwMjg0NVoYDzIxMjYwNzA4MTAy
ODQ1WjARMQ8wDQYDVQQDDAZlYy1pZHAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAR5Yy7n1C3JhpnmVskt08jJL4uju6ODq1ed1MGAzl5wY2iJv8lJhXj308K+QP4P
53YPjAfg+mOa+iBpqUNwAXl0o1MwUTAdBgNVHQ4EFgQUUiCb28SRo6len7kzunHd
wNNY58owHwYDVR0jBBgwFoAUUiCb28SRo6len7kzunHdwNNY58owDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAge+vLU2oOcHsBuJfhN7m7OcFtWCc
hE5VYr9CD1UMT0ECIQDD9TrURmg5wqpEQiZZ51oqGQBeq/OpY5OgfgmfSIRgUQ==
-----END CERTIFICATE-----`;
