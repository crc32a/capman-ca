package org.rackspace.capman.tools.ca.zeus;

import org.rackspace.capman.tools.ca.CertUtils;
import java.util.ArrayList;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Assert;
import org.rackspace.capman.tools.ca.StringUtils;
import org.rackspace.capman.tools.ca.primitives.RsaConst;

public class ZeusUtilTest {

    private static final String ca0Crt = "-----BEGIN CERTIFICATE-----\n"
            + "MIICjjCCAfegAwIBAgIBATANBgkqhkiG9w0BAQUFADBzMQ0wCwYDVQQDEwRjYSAx\n"
            + "MRkwFwYDVQQLExBSYWNrRXhwIDIwMTEwNDI3MRowGAYDVQQKExFSYWNrU3BhY2Ug\n"
            + "SG9zdGluZzEOMAwGA1UEBxMFVGV4YXMxDjAMBgNVBAgTBVRleGFzMQswCQYDVQQG\n"
            + "EwJVUzAeFw0xMjA0MjcxNjI0MzRaFw0xNjA0MjYxNjI0MzRaMHMxDTALBgNVBAMT\n"
            + "BGNhIDExGTAXBgNVBAsTEFJhY2tFeHAgMjAxMTA0MjcxGjAYBgNVBAoTEVJhY2tT\n"
            + "cGFjZSBIb3N0aW5nMQ4wDAYDVQQHEwVUZXhhczEOMAwGA1UECBMFVGV4YXMxCzAJ\n"
            + "BgNVBAYTAlVTMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCEGTTXBxe4TSNr\n"
            + "FXQ65xf3bS3bUQVP1XSI9Yq5dCG3KPlGd3iGVUfnPYbmAOQ9IHFiLEyJ2ucZxX0J\n"
            + "kAk8XNdGak2lnX2o5eTHkTTXwQqRN9W4BYxN4FLe93ZtwVf374FUA85ZZwEFMerl\n"
            + "wfhOurTQ4X1PtTyXxvKhF9C4ho8wRwIDAQABozIwMDAPBgNVHRMBAf8EBTADAQH/\n"
            + "MB0GA1UdDgQWBBT3yB76bym/AcM3b/NBQovLLmV1bDANBgkqhkiG9w0BAQUFAAOB\n"
            + "gQBlJgj3XPMn0JLrGPHGmNoZQZD49Pcu0+6SLvTBjlmXIVnPJfy3mFqonP7XpzNz\n"
            + "7wsyeZ1BukapZGXUkgWMnR1CsBXo0zcD7BPU3yeIzNuz00I8g10qpXvMvczxlIYK\n"
            + "qiWqtAeFTBp7H5Wy80Fsu0kwBKu5i35GnEOlYudh1+GXRA==\n"
            + "-----END CERTIFICATE-----\n";
    private static final String ca1Crt = "-----BEGIN CERTIFICATE-----\n"
            + "MIIDMDCCApmgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBzMQ0wCwYDVQQDEwRjYSAx\n"
            + "MRkwFwYDVQQLExBSYWNrRXhwIDIwMTEwNDI3MRowGAYDVQQKExFSYWNrU3BhY2Ug\n"
            + "SG9zdGluZzEOMAwGA1UEBxMFVGV4YXMxDjAMBgNVBAgTBVRleGFzMQswCQYDVQQG\n"
            + "EwJVUzAeFw0xMjA0MjcxNjI0MzRaFw0xNjA0MjUxNjI0MzRaMHMxCzAJBgNVBAYT\n"
            + "AlVTMQ4wDAYDVQQIEwVUZXhhczEOMAwGA1UEBxMFVGV4YXMxGjAYBgNVBAoTEVJh\n"
            + "Y2tTcGFjZSBIb3N0aW5nMRkwFwYDVQQLExBSYWNrRXhwIDIwMTEwNDI3MQ0wCwYD\n"
            + "VQQDEwRjYSAyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNA5MQ1OgrhwkI\n"
            + "IpML1LUEi+zKBZ342H2sJq+gdNMfFcJIL5UB7/+rJxzrAK9iSXD4HRR45UiYeTV9\n"
            + "I7JsZln4wClQZm4CdWWT3p3MZ5QEI7A+5LmdVFMzHAQRTqn3CJJkWK+nI7gsA7LG\n"
            + "1xgkxGMbE6K3L3X86Vo1FnkeXrOhrwIDAQABo4HTMIHQMA8GA1UdEwEB/wQFMAMB\n"
            + "Af8wgZ0GA1UdIwSBlTCBkoAU98ge+m8pvwHDN2/zQUKLyy5ldWyhd6R1MHMxDTAL\n"
            + "BgNVBAMTBGNhIDExGTAXBgNVBAsTEFJhY2tFeHAgMjAxMTA0MjcxGjAYBgNVBAoT\n"
            + "EVJhY2tTcGFjZSBIb3N0aW5nMQ4wDAYDVQQHEwVUZXhhczEOMAwGA1UECBMFVGV4\n"
            + "YXMxCzAJBgNVBAYTAlVTggEBMB0GA1UdDgQWBBQsBFpTTbttDhxdY76AkiTNNG7Q\n"
            + "XjANBgkqhkiG9w0BAQUFAAOBgQBQ9LqNztRwgMycLIBOniQGIsgv79OaZimF5/lN\n"
            + "KhmIrBwleye5CsulwKIXXrESpLlWCUhIm/OS+R2EgdseLy1QEPycVLhO++7EKHcz\n"
            + "CEkPMg+ayICHS9v3+KQhkO37aZZ7aeTa/2V5ztBuoO1b5Ku3up2Q/Yez0whA8bMg\n"
            + "Ox585g==\n"
            + "-----END CERTIFICATE-----\n";
    private static final String ca2Crt = "-----BEGIN CERTIFICATE-----\n"
            + "MIIDMDCCApmgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBzMQswCQYDVQQGEwJVUzEO\n"
            + "MAwGA1UECBMFVGV4YXMxDjAMBgNVBAcTBVRleGFzMRowGAYDVQQKExFSYWNrU3Bh\n"
            + "Y2UgSG9zdGluZzEZMBcGA1UECxMQUmFja0V4cCAyMDExMDQyNzENMAsGA1UEAxME\n"
            + "Y2EgMjAeFw0xMjA0MjcxNjI0MzRaFw0xNjA0MjUxNjI0MzRaMHMxCzAJBgNVBAYT\n"
            + "AlVTMQ4wDAYDVQQIEwVUZXhhczEOMAwGA1UEBxMFVGV4YXMxGjAYBgNVBAoTEVJh\n"
            + "Y2tTcGFjZSBIb3N0aW5nMRkwFwYDVQQLExBSYWNrRXhwIDIwMTEwNDI3MQ0wCwYD\n"
            + "VQQDEwRjYSAzMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzC5Jsilw8bqB2\n"
            + "FfWbkDEbcOpQXpwE+wN+MEfC7oulzCs2tx3xd0NqCfrCtGx9tBQJc+JBTBKVwUAL\n"
            + "5JnJKi1dZOgFbMDnsk7I49yC+YeclHzL+Uaw2Gf+zhBexp9b7f0WA8u1rRdUEUh2\n"
            + "AusrqOdB86gPOuTldYgVlmRkz1BuNwIDAQABo4HTMIHQMA8GA1UdEwEB/wQFMAMB\n"
            + "Af8wgZ0GA1UdIwSBlTCBkoAULARaU027bQ4cXWO+gJIkzTRu0F6hd6R1MHMxDTAL\n"
            + "BgNVBAMTBGNhIDExGTAXBgNVBAsTEFJhY2tFeHAgMjAxMTA0MjcxGjAYBgNVBAoT\n"
            + "EVJhY2tTcGFjZSBIb3N0aW5nMQ4wDAYDVQQHEwVUZXhhczEOMAwGA1UECBMFVGV4\n"
            + "YXMxCzAJBgNVBAYTAlVTggECMB0GA1UdDgQWBBSrwIx3rIsD9ig7Z6+aG47zuJZz\n"
            + "STANBgkqhkiG9w0BAQUFAAOBgQBkFSr0nq+ZIcIyvRQbk/jTpQzwGUi7XL4MmK3R\n"
            + "9VZJ0mUaR42dbX4uLvmMoWRRL2f+ATkgmKSzAlbzBT7AxBYUFWUQUTuKhjppfWMv\n"
            + "NRN0LhpHC9jDz2uS22FgvyHR05iHkjCs4T4sgNluSYeO5sxSrYfSSk/6f1yTmhsw\n"
            + "RojYLQ==\n"
            + "-----END CERTIFICATE-----\n";
    private static final String ca3Crt = "-----BEGIN CERTIFICATE-----\n"
            + "MIIDMDCCApmgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBzMQswCQYDVQQGEwJVUzEO\n"
            + "MAwGA1UECBMFVGV4YXMxDjAMBgNVBAcTBVRleGFzMRowGAYDVQQKExFSYWNrU3Bh\n"
            + "Y2UgSG9zdGluZzEZMBcGA1UECxMQUmFja0V4cCAyMDExMDQyNzENMAsGA1UEAxME\n"
            + "Y2EgMzAeFw0xMjA0MjcxNjI0MzRaFw0xNjA0MjUxNjI0MzRaMHMxCzAJBgNVBAYT\n"
            + "AlVTMQ4wDAYDVQQIEwVUZXhhczEOMAwGA1UEBxMFVGV4YXMxGjAYBgNVBAoTEVJh\n"
            + "Y2tTcGFjZSBIb3N0aW5nMRkwFwYDVQQLExBSYWNrRXhwIDIwMTEwNDI3MQ0wCwYD\n"
            + "VQQDEwRjYSA0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyV0OloShjgZXA\n"
            + "DAR7g3j/428WjzQmYlquR6cZzbXYKrtk5WQChdl2qwx49XNYVgTmJALaE/Jv1Lyj\n"
            + "e0xn/rLG6XcJXVTaME0bnVci8d1di6lQ8xN+et6b3zvx1/BsU7KdF6vgZcX9oSTW\n"
            + "fhrWslHfezD6IwgMIQgL/1F1g3UAbwIDAQABo4HTMIHQMA8GA1UdEwEB/wQFMAMB\n"
            + "Af8wgZ0GA1UdIwSBlTCBkoAUq8CMd6yLA/YoO2evmhuO87iWc0mhd6R1MHMxCzAJ\n"
            + "BgNVBAYTAlVTMQ4wDAYDVQQIEwVUZXhhczEOMAwGA1UEBxMFVGV4YXMxGjAYBgNV\n"
            + "BAoTEVJhY2tTcGFjZSBIb3N0aW5nMRkwFwYDVQQLExBSYWNrRXhwIDIwMTEwNDI3\n"
            + "MQ0wCwYDVQQDEwRjYSAyggECMB0GA1UdDgQWBBSs9FlG5oQ+F02tNj1PuL/Sb+YU\n"
            + "7zANBgkqhkiG9w0BAQUFAAOBgQB82xUEoAQnOpT0aTay96Nr2uomkyj0xj41mpso\n"
            + "cWhoIRAjx6LN0p2yZ3tmccmPHC3IMpXZ2KhFTLWWpzfwxLWqFbkI6mBsmUUnTXmF\n"
            + "hednieFi9+2CjDhmHp1pKBBUCWscFrDoKQGNwu5NsvYy61pbKHzhwntQ0hwexXvv\n"
            + "fr5LgQ==\n"
            + "-----END CERTIFICATE-----\n";
    private static final String ca4Crt = "-----BEGIN CERTIFICATE-----\n"
            + "MIIDMDCCApmgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBzMQswCQYDVQQGEwJVUzEO\n"
            + "MAwGA1UECBMFVGV4YXMxDjAMBgNVBAcTBVRleGFzMRowGAYDVQQKExFSYWNrU3Bh\n"
            + "Y2UgSG9zdGluZzEZMBcGA1UECxMQUmFja0V4cCAyMDExMDQyNzENMAsGA1UEAxME\n"
            + "Y2EgNDAeFw0xMjA0MjcxNjI0MzRaFw0xNjA0MjUxNjI0MzRaMHMxCzAJBgNVBAYT\n"
            + "AlVTMQ4wDAYDVQQIEwVUZXhhczEOMAwGA1UEBxMFVGV4YXMxGjAYBgNVBAoTEVJh\n"
            + "Y2tTcGFjZSBIb3N0aW5nMRkwFwYDVQQLExBSYWNrRXhwIDIwMTEwNDI3MQ0wCwYD\n"
            + "VQQDEwRjYSA1MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCb9YproNK35ZkG\n"
            + "J4Tr2D9fQyQhckUuF1Dq2m0gIC9faUmS6rDXqR3eBzdbsoiku0Zxv5WdSFT3/v+d\n"
            + "2uPBzvBEqlzGIA/DOb7K1nnLBR/FaqrTvg1bb6ZfH6pga361tjjCka70y9xTJNrq\n"
            + "Coa9YadNF6Hz6gzqYTjTp3Wfx0hNyQIDAQABo4HTMIHQMA8GA1UdEwEB/wQFMAMB\n"
            + "Af8wgZ0GA1UdIwSBlTCBkoAUrPRZRuaEPhdNrTY9T7i/0m/mFO+hd6R1MHMxCzAJ\n"
            + "BgNVBAYTAlVTMQ4wDAYDVQQIEwVUZXhhczEOMAwGA1UEBxMFVGV4YXMxGjAYBgNV\n"
            + "BAoTEVJhY2tTcGFjZSBIb3N0aW5nMRkwFwYDVQQLExBSYWNrRXhwIDIwMTEwNDI3\n"
            + "MQ0wCwYDVQQDEwRjYSAzggECMB0GA1UdDgQWBBR3RlRGBB5+Ay0ifMthLNNZme4a\n"
            + "SzANBgkqhkiG9w0BAQUFAAOBgQCDHToSx3I9LqQAQSGV5AB8+FX8TQ+hKFHkysBQ\n"
            + "RQaRBMudsPQ3j6F+akmburKnA/qAAPeszXnXS9wx62FeA1ziq45McFxo8I/A6Nt4\n"
            + "D6alalqbxDrKdPI2WZwAWl8dtDbNniAXojE6PL9ojoeF73hZsU4kvrmDPb1BIp8R\n"
            + "YRGLeg==\n"
            + "-----END CERTIFICATE-----\n";
    private static final String pfftKey = "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIICXgIBAAKBgQCQRTL6G8G5bKySR+bQ1rHYLYmnTfeiUYfiE15et07i5QjIuSUU\n"
            + "da5/WOBe7zMVvlqhnMifueYQ9XjI5p2fdcrLNPexglHIEbHE37g7cptDhyq9o7Ou\n"
            + "rtKx0qEO1elkgs1o5AGrlimFVLFohn2VFfnyu3zD2u98alzY0tZimRJEqwIDAQAB\n"
            + "AoGAckf+i5S1LnbhdLa0JjYLhtz7r6XZRaEj7He/R3QZby5SeP4AW2alJYd3pHwC\n"
            + "kXTKQj75xVzy2/g3B512urwKOSDfXCkXX3nJErIxv59+dl47izak8V0fIPikJGw/\n"
            + "UB9CyN0G2id+Zpz5Y6LnkoSIaY7WO/0bh7Xor/EAWLCqhVECQQDMVpUNEZKEe/n3\n"
            + "F91JgRyduXkL40sdsdICh5540ywDp3KwkXlAUGWWRTUhvRSOg0gAlBATfueBpKQx\n"
            + "IFUSLnHXAkEAtL7U3799ydeD0tuXwtZ8frOQ7/vSvH3CLWSOWnwCZfH53uYMGMv3\n"
            + "iaOELPG1cNWfTZ/BYfUW99i7lNHJoPNRTQJBAImhb7djtJpDnvPNQSE3M30Q5fUZ\n"
            + "3QhdMyS9EAI1yhmT+W3wLgkhnar/ZnAZGPV8e0zYbZOUEH6D1Iu6SVJ7sfUCQQCe\n"
            + "xTc3qP21LUSWF+Gy/Dh2EASUWrBedVX6C+fkYiS1Kp8lBw2/RoSWenXkCRsqF+0N\n"
            + "AfWct+/KHa+BZdtpL/PNAkEAulx9jSYMb+FAUmH/7Zbb4J+jREor4C1be3x568LE\n"
            + "ScbCRldAnIvCXbgf9WiWYaoKj21OmUZeLjbIvk/NOvmvRg==\n"
            + "-----END RSA PRIVATE KEY-----\n";
    private static final String pfftCrt = "-----BEGIN CERTIFICATE-----\n"
            + "MIIDPDCCAqWgAwIBAgIGATb0wr4dMA0GCSqGSIb3DQEBBQUAMHMxCzAJBgNVBAYT\n"
            + "AlVTMQ4wDAYDVQQIEwVUZXhhczEOMAwGA1UEBxMFVGV4YXMxGjAYBgNVBAoTEVJh\n"
            + "Y2tTcGFjZSBIb3N0aW5nMRkwFwYDVQQLExBSYWNrRXhwIDIwMTEwNDI3MQ0wCwYD\n"
            + "VQQDEwRjYSA1MB4XDTEyMDQyNzE3MDQyNVoXDTE0MDQyNzE3MDQyNVowfTELMAkG\n"
            + "A1UEBhMCVVMxDjAMBgNVBAgTBVRleGFzMRQwEgYDVQQHEwtTYW4gQW50b25pbzEa\n"
            + "MBgGA1UEChMRUmFja1NwYWNlIFRlc3RpbmcxFTATBgNVBAsTDFRlc3RpbmcgVW5p\n"
            + "dDEVMBMGA1UEAxMMd3d3LnBmZnQub3JnMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB\n"
            + "iQKBgQCQRTL6G8G5bKySR+bQ1rHYLYmnTfeiUYfiE15et07i5QjIuSUUda5/WOBe\n"
            + "7zMVvlqhnMifueYQ9XjI5p2fdcrLNPexglHIEbHE37g7cptDhyq9o7OurtKx0qEO\n"
            + "1elkgs1o5AGrlimFVLFohn2VFfnyu3zD2u98alzY0tZimRJEqwIDAQABo4HQMIHN\n"
            + "MAwGA1UdEwEB/wQCMAAwgZ0GA1UdIwSBlTCBkoAUd0ZURgQefgMtInzLYSzTWZnu\n"
            + "Gkuhd6R1MHMxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIEwVUZXhhczEOMAwGA1UEBxMF\n"
            + "VGV4YXMxGjAYBgNVBAoTEVJhY2tTcGFjZSBIb3N0aW5nMRkwFwYDVQQLExBSYWNr\n"
            + "RXhwIDIwMTEwNDI3MQ0wCwYDVQQDEwRjYSA0ggECMB0GA1UdDgQWBBSdtibZRk3n\n"
            + "e8j+PLWhX71FaHOrJzANBgkqhkiG9w0BAQUFAAOBgQA7kdKGArKXUiy17fqjUtNS\n"
            + "SM+Sq+IgueXYHnm94pr270V0IPEnHO+5ZGOrSmvSjmS564/cy4e9YF32RfwNXVrb\n"
            + "4aLf7RGMLwRg29OOzT1mr6S4jIRpP8xd+HgSSvMXFu22srpy6JBNwlA6HXrZjC0l\n"
            + "61pTN5UVxH+9VANJ2fN/xA==\n"
            + "-----END CERTIFICATE-----\n";
    private static final String pfftKeyPkcs8 = "-----BEGIN PRIVATE KEY-----\n"
            + "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAJBFMvobwblsrJJH\n"
            + "5tDWsdgtiadN96JRh+ITXl63TuLlCMi5JRR1rn9Y4F7vMxW+WqGcyJ+55hD1eMjm\n"
            + "nZ91yss097GCUcgRscTfuDtym0OHKr2js66u0rHSoQ7V6WSCzWjkAauWKYVUsWiG\n"
            + "fZUV+fK7fMPa73xqXNjS1mKZEkSrAgMBAAECgYByR/6LlLUuduF0trQmNguG3Puv\n"
            + "pdlFoSPsd79HdBlvLlJ4/gBbZqUlh3ekfAKRdMpCPvnFXPLb+DcHnXa6vAo5IN9c\n"
            + "KRdfeckSsjG/n352XjuLNqTxXR8g+KQkbD9QH0LI3QbaJ35mnPljoueShIhpjtY7\n"
            + "/RuHteiv8QBYsKqFUQJBAMxWlQ0RkoR7+fcX3UmBHJ25eQvjSx2x0gKHnnjTLAOn\n"
            + "crCReUBQZZZFNSG9FI6DSACUEBN+54GkpDEgVRIucdcCQQC0vtTfv33J14PS25fC\n"
            + "1nx+s5Dv+9K8fcItZI5afAJl8fne5gwYy/eJo4Qs8bVw1Z9Nn8Fh9Rb32LuU0cmg\n"
            + "81FNAkEAiaFvt2O0mkOe881BITczfRDl9RndCF0zJL0QAjXKGZP5bfAuCSGdqv9m\n"
            + "cBkY9Xx7TNhtk5QQfoPUi7pJUnux9QJBAJ7FNzeo/bUtRJYX4bL8OHYQBJRasF51\n"
            + "VfoL5+RiJLUqnyUHDb9GhJZ6deQJGyoX7Q0B9Zy378odr4Fl22kv880CQQC6XH2N\n"
            + "Jgxv4UBSYf/tltvgn6NESivgLVt7fHnrwsRJxsJGV0Cci8JduB/1aJZhqgqPbU6Z\n"
            + "Rl4uNsi+T806+a9G\n"
            + "-----END PRIVATE KEY-----\n";
    public static final List<String> dateErrorFilter;

    static {
        dateErrorFilter = new ArrayList<String>();
        dateErrorFilter.add(CertUtils.ISSUER_NOT_AFTER_FAIL);
        dateErrorFilter.add(CertUtils.ISSUER_NOT_BEFORE_FAIL);
        dateErrorFilter.add(CertUtils.SUBJECT_NOT_AFTER_FAIL);
        dateErrorFilter.add(CertUtils.SUBJECT_NOT_BEFORE_FAIL);
    }

    public ZeusUtilTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
        RsaConst.init();
    }

    @After
    public void tearDown() {
    }

    public String buildNonsenseMixed(){
        StringBuilder chain = new StringBuilder();
        chain.append("Nonsense\n\nGarbage\n");
        chain.append(ca4Crt);
        chain.append("foo\nbar\nNAN\n");
        chain.append(ca3Crt);
        chain.append("Blah\nBlah\n");
        chain.append(ca2Crt);
        chain.append("\r\n\r\nldsav\r\nrrgbsdfjkab\r\n");
        chain.append(ca1Crt);
        chain.append("djkahkdbsv\nfbdasfa\nadfbfdabfda\n");
        chain.append(ca0Crt);
        chain.append("\n\n\npfft\n");
        return chain.toString();
    }

    private String buildGoodOrderedChain() {
        StringBuilder chain = new StringBuilder();
        chain.append(ca4Crt);
        chain.append(ca3Crt);
        chain.append(ca2Crt);
        chain.append(ca1Crt);
        chain.append(ca0Crt);
        return chain.toString();
    }

    @Test
    public void noErrorsIfCertsAreInOrder() {
        String goodChain = buildGoodOrderedChain();
        ZeusCertFile zcf = ZeusUtil.getCertFile(pfftKey, pfftCrt, goodChain);
        List<String> errorList = zcf.getErrorList();
        errorList.removeAll(dateErrorFilter); // We don't cound date Errors
        String fmt = "Expected no Errors but got: [%s]";
        String errorMsg = String.format(fmt, StringUtils.joinString(errorList, ","));
        Assert.assertTrue(errorMsg, errorList.size() <= 1);
        String expPublic_cert = String.format("%s%s", pfftCrt, goodChain);
        String zCert = zcf.getPublic_cert();
        String zKey = zcf.getPrivate_key();
        Assert.assertEquals(expPublic_cert, zCert);
        Assert.assertEquals(pfftKey, zKey);
    }

    @Test
    public void shouldFilterNonsenseBetweenPemBlocks() {
        String nonsenseMixedChain = buildNonsenseMixed();
        String goodChain = buildGoodOrderedChain();
        ZeusCertFile zcf = ZeusUtil.getCertFile(pfftKey, pfftCrt, nonsenseMixedChain);
        List<String> errorList = zcf.getErrorList();
        errorList.removeAll(dateErrorFilter); // We don't cound date Errors
        String fmt = "Expected no Errors but got: [%s]";
        String errorMsg = String.format(fmt, StringUtils.joinString(errorList, ","));
        Assert.assertTrue(errorMsg, errorList.size() <= 1);
        String expPublic_cert = String.format("%s%s", pfftCrt, goodChain);
        String zCert = zcf.getPublic_cert();
        String zKey = zcf.getPrivate_key();
        Assert.assertEquals(expPublic_cert, zCert);
        Assert.assertEquals(pfftKey, zKey);
    }

    @Test
    public void shouldErrorOutWhenCertsAreOutOfOrder() {
        String chain = String.format("%s%s%s%s%s", ca4Crt, ca3Crt, ca1Crt, ca0Crt, ca2Crt);
        ZeusCertFile zcf = ZeusUtil.getCertFile(pfftKey, pfftCrt, chain);
        List<String> errorList = zcf.getErrorList();
        errorList.removeAll(dateErrorFilter); // Again ignore date Error
        Assert.assertTrue("Odd out of order certs should have triggered an error", errorList.size() > 0);
    }

    public void ZeusUtilShouldCreatePkcs1IfGivenPkcs8() {
        String goodChain = buildGoodOrderedChain();
        ZeusCertFile zcf = ZeusUtil.getCertFile(pfftKeyPkcs8, pfftCrt, goodChain);
        List<String> errorList = zcf.getErrorList();
        errorList.removeAll(dateErrorFilter);
        Assert.assertEquals(pfftKey, zcf.getPrivate_key()); // pfftKey is in pkcs1encoding
    }
}
