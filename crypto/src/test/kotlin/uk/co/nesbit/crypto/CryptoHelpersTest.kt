package uk.co.nesbit.crypto

import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import uk.co.nesbit.avro.serialize
import java.security.KeyPair
import java.security.PublicKey
import java.security.SignatureException
import kotlin.test.assertFails
import kotlin.test.assertFailsWith

class CryptoHelpersTest {
    @Test
    fun `test EdDSA serialisation round trip`() {
        val keyPair = generateEdDSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        val signatureBytes = signature.serialize()
        val deserializedSignature = DigitalSignatureAndKey.deserialize(signatureBytes)
        deserializedSignature.verify(bytes)
        val shortSignature = signature.toDigitalSignature()
        val shortSignatureBytes = shortSignature.serialize()
        val deserializedShortSignature = DigitalSignature.deserialize(shortSignatureBytes)
        deserializedShortSignature.verify(keyPair.public, bytes)
        assertEquals(signature, shortSignature.toDigitalSignatureAndKey(keyPair.public))
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test EdDSA GenericRecord round trip`() {
        val keyPair = generateEdDSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        val signatureRecord = signature.toGenericRecord()
        val signature2 = DigitalSignatureAndKey(signatureRecord)
        assertFalse(signature === signature2)
        assertEquals(signature, signature2)
        val shortSignature = signature.toDigitalSignature()
        val shortSignatureRecord = shortSignature.toGenericRecord()
        val shortSignature2 = DigitalSignature(shortSignatureRecord)
        assertFalse(shortSignature === shortSignature2)
        assertEquals(shortSignature, shortSignature2)
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test EdDSA PublicKey round trip`() {
        val keyPair = generateEdDSAKeyPair()
        val publicKeyRecord = keyPair.public.toGenericRecord()
        assertEquals(keyPair.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord))
        val serializedPublicKey = keyPair.public.serialize()
        val deserializedPublicKey = PublicKeyHelper.deserialize(serializedPublicKey)
        assertEquals(keyPair.public, deserializedPublicKey)
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test ECDSA serialisation round trip`() {
        val keyPair = generateECDSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        val signatureBytes = signature.serialize()
        val deserializedSignature = DigitalSignatureAndKey.deserialize(signatureBytes)
        deserializedSignature.verify(bytes)
        val shortSignature = signature.toDigitalSignature()
        val shortSignatureBytes = shortSignature.serialize()
        val deserializedShortSignature = DigitalSignature.deserialize(shortSignatureBytes)
        deserializedShortSignature.verify(keyPair.public, bytes)
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test ECDSA GenericRecord round trip`() {
        val keyPair = generateECDSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        val signatureRecord = signature.toGenericRecord()
        val signature2 = DigitalSignatureAndKey(signatureRecord)
        assertFalse(signature === signature2)
        assertEquals(signature, signature2)
        val shortSignature = signature.toDigitalSignature()
        val shortSignatureRecord = shortSignature.toGenericRecord()
        val shortSignature2 = DigitalSignature(shortSignatureRecord)
        assertFalse(shortSignature === shortSignature2)
        assertEquals(shortSignature, shortSignature2)
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test ECDSA PublicKey round trip`() {
        val keyPair = generateECDSAKeyPair()
        val publicKeyRecord = keyPair.public.toGenericRecord()
        assertEquals(keyPair.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord))
        val serializedPublicKey = keyPair.public.serialize()
        val deserializedPublicKey = PublicKeyHelper.deserialize(serializedPublicKey)
        assertEquals(keyPair.public, deserializedPublicKey)
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test RSA serialisation round trip`() {
        val keyPair = generateRSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        val signatureBytes = signature.serialize()
        val deserializedSignature = DigitalSignatureAndKey.deserialize(signatureBytes)
        deserializedSignature.verify(bytes)
        val shortSignature = signature.toDigitalSignature()
        val shortSignatureBytes = shortSignature.serialize()
        val deserializedShortSignature = DigitalSignature.deserialize(shortSignatureBytes)
        deserializedShortSignature.verify(keyPair.public, bytes)
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test RSA GenericRecord round trip`() {
        val keyPair = generateRSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        val signatureRecord = signature.toGenericRecord()
        val signature2 = DigitalSignatureAndKey(signatureRecord)
        assertFalse(signature === signature2)
        assertEquals(signature, signature2)
        val shortSignature = signature.toDigitalSignature()
        val shortSignatureRecord = shortSignature.toGenericRecord()
        val shortSignature2 = DigitalSignature(shortSignatureRecord)
        assertFalse(shortSignature === shortSignature2)
        assertEquals(shortSignature, shortSignature2)
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test RSA PublicKey round trip`() {
        val keyPair = generateRSAKeyPair()
        val publicKeyRecord = keyPair.public.toGenericRecord()
        assertEquals(keyPair.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord))
        val serializedPublicKey = keyPair.public.serialize()
        val deserializedPublicKey = PublicKeyHelper.deserialize(serializedPublicKey)
        assertEquals(keyPair.public, deserializedPublicKey)
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test ECDH PublicKey round trip`() {
        val keyPair1 = generateECDHKeyPair()
        val keyPair2 = generateECDHKeyPair()
        val publicKeyRecord1 = keyPair1.public.toGenericRecord()
        val publicKeyRecord2 = keyPair2.public.toGenericRecord()
        assertEquals(keyPair1.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord1))
        assertEquals(keyPair2.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord2))
        val serializedPublicKey1 = keyPair1.public.serialize()
        val serializedPublicKey2 = keyPair2.public.serialize()
        val deserializedPublicKey1 = PublicKeyHelper.deserialize(serializedPublicKey1)
        val deserializedPublicKey2 = PublicKeyHelper.deserialize(serializedPublicKey2)
        assertEquals(keyPair1.public, deserializedPublicKey1)
        assertEquals(keyPair2.public, deserializedPublicKey2)
        val sec1 = getSharedDHSecret(keyPair1, deserializedPublicKey2)
        val sec2 = getSharedDHSecret(keyPair2, deserializedPublicKey1)
        assertArrayEquals(sec1, sec2)
        keyPair1.private.safeDestroy()
        keyPair2.private.safeDestroy()
    }

    @Test
    fun `test DH PublicKey round trip`() {
        val keyPair1 = generateDHKeyPair()
        val keyPair2 = generateDHKeyPair()
        val publicKeyRecord1 = keyPair1.public.toGenericRecord()
        val publicKeyRecord2 = keyPair2.public.toGenericRecord()
        assertEquals(keyPair1.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord1))
        assertEquals(keyPair2.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord2))
        val serializedPublicKey1 = keyPair1.public.serialize()
        val serializedPublicKey2 = keyPair2.public.serialize()
        val deserializedPublicKey1 = PublicKeyHelper.deserialize(serializedPublicKey1)
        val deserializedPublicKey2 = PublicKeyHelper.deserialize(serializedPublicKey2)
        assertEquals(keyPair1.public, deserializedPublicKey1)
        assertEquals(keyPair2.public, deserializedPublicKey2)
        val sec1 = getSharedDHSecret(keyPair1, deserializedPublicKey2)
        val sec2 = getSharedDHSecret(keyPair2, deserializedPublicKey1)
        assertArrayEquals(sec1, sec2)
        keyPair1.private.safeDestroy()
        keyPair2.private.safeDestroy()
    }

    @Test
    fun `test NACL DH PublicKey round trip`() {
        val keyPair1 = generateNACLDHKeyPair()
        val keyPair2 = generateNACLDHKeyPair()
        val publicKeyRecord1 = keyPair1.public.toGenericRecord()
        val publicKeyRecord2 = keyPair2.public.toGenericRecord()
        assertEquals(keyPair1.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord1))
        assertEquals(keyPair2.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord2))
        val serializedPublicKey1 = keyPair1.public.serialize()
        val serializedPublicKey2 = keyPair2.public.serialize()
        val deserializedPublicKey1 = PublicKeyHelper.deserialize(serializedPublicKey1)
        val deserializedPublicKey2 = PublicKeyHelper.deserialize(serializedPublicKey2)
        assertEquals(keyPair1.public, deserializedPublicKey1)
        assertEquals(keyPair2.public, deserializedPublicKey2)
        val sec1 = getSharedDHSecret(keyPair1, deserializedPublicKey2)
        val sec2 = getSharedDHSecret(keyPair2, deserializedPublicKey1)
        assertArrayEquals(sec1, sec2)
        keyPair1.private.safeDestroy()
        keyPair2.private.safeDestroy()
    }

    @Test
    fun `test SecureHash serialisation round trip`() {
        val hash = SecureHash.secureHash("adasdad")
        val serialisedHash = hash.serialize()
        val deserializedHash = SecureHash.deserialize(serialisedHash)
        assertEquals(hash, deserializedHash)
    }

    @Test
    fun `test EdDSA verify`() {
        val keyPair = generateEdDSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        signature.verify(bytes)

        bytes[0] = 'k'.code.toByte()

        assertFailsWith<SignatureException> {
            signature.verify(bytes)
        }
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test ECDSA verify`() {
        val keyPair = generateECDSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        signature.verify(bytes)

        bytes[0] = 'k'.code.toByte()

        assertFailsWith<SignatureException> {
            signature.verify(bytes)
        }
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test RSA verify`() {
        val keyPair = generateRSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        signature.verify(bytes)

        bytes[0] = 'k'.code.toByte()

        assertFailsWith<SignatureException> {
            signature.verify(bytes)
        }
        keyPair.private.safeDestroy()
    }

    @Test
    fun `Test Diffie Hellman helpers`() {
        val key1 = generateDHKeyPair()
        val key2 = generateDHKeyPair()
        val sec1 = getSharedDHSecret(key1, key2.public)
        val sec2 = getSharedDHSecret(key2, key1.public)
        assertArrayEquals(sec1, sec2)

        val key3 = generateECDHKeyPair()
        val key4 = generateECDHKeyPair()
        val sec3 = getSharedDHSecret(key3, key4.public)
        val sec4 = getSharedDHSecret(key4, key3.public)
        assertArrayEquals(sec3, sec4)

        val key5 = generateNACLDHKeyPair()
        val key6 = generateNACLDHKeyPair()
        val sec5 = getSharedDHSecret(key5, key6.public)
        val sec6 = getSharedDHSecret(key6, key5.public)
        assertArrayEquals(sec5, sec6)

        val bytes = "jhASDJHKSD".toByteArray(Charsets.UTF_8)
        val hash1 = getHMAC(sec1, bytes)
        val hash2 = getHMAC(sec2, bytes)
        val hash3 = getHMAC(sec3, bytes)
        val hash4 = getHMAC(sec1, "jhASDJHKSE".toByteArray(Charsets.UTF_8))
        assertEquals(hash1, hash2)
        assertNotEquals(hash1, hash3)
        assertNotEquals(hash1, hash4)

        assertFails {
            getSharedDHSecret(key1, key3.public)
        }

        assertFails {
            getSharedDHSecret(key3, key1.public)
        }

        key1.private.safeDestroy()
        key2.private.safeDestroy()
        key3.private.safeDestroy()
        key4.private.safeDestroy()
        key5.private.safeDestroy()
        key6.private.safeDestroy()
    }

    @Test
    fun `Test signatures with hashes and bytes are interchangeable`() {
        val bytes = "112543153513456".toByteArray(Charsets.UTF_8)
        val bytes2 = "112543153513457".toByteArray(Charsets.UTF_8)

        val keyRSA = generateRSAKeyPair()
        val sig1 = keyRSA.sign(SecureHash.secureHash(bytes))
        sig1.verify(bytes)
        assertFails {
            sig1.verify(bytes2)
        }

        val keyECDSA = generateECDSAKeyPair()
        val sig2 = keyECDSA.sign(SecureHash.secureHash(bytes))
        sig2.verify(bytes)
        assertFails {
            sig2.verify(bytes2)
        }

        val sig3 = keyRSA.sign(bytes)
        sig3.verify(SecureHash.secureHash(bytes))
        assertFails {
            sig3.verify(SecureHash.secureHash(bytes2))
        }

        val sig4 = keyECDSA.sign(bytes)
        sig4.verify(SecureHash.secureHash(bytes))
        assertFails {
            sig4.verify(SecureHash.secureHash(bytes2))
        }
        keyRSA.private.safeDestroy()
        keyECDSA.private.safeDestroy()
    }

    @Test
    fun `test NACL EdDSA serialisation round trip`() {
        val keyPair = generateNACLKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        val signatureBytes = signature.serialize()
        val deserializedSignature = DigitalSignatureAndKey.deserialize(signatureBytes)
        deserializedSignature.verify(bytes)
        val shortSignature = signature.toDigitalSignature()
        val shortSignatureBytes = shortSignature.serialize()
        val deserializedShortSignature = DigitalSignature.deserialize(shortSignatureBytes)
        deserializedShortSignature.verify(keyPair.public, bytes)
        assertEquals(signature, shortSignature.toDigitalSignatureAndKey(keyPair.public))
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test NACL EdDSA GenericRecord round trip`() {
        val keyPair = generateNACLKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        val signatureRecord = signature.toGenericRecord()
        val signature2 = DigitalSignatureAndKey(signatureRecord)
        assertFalse(signature === signature2)
        assertEquals(signature, signature2)
        val shortSignature = signature.toDigitalSignature()
        val shortSignatureRecord = shortSignature.toGenericRecord()
        val shortSignature2 = DigitalSignature(shortSignatureRecord)
        assertFalse(shortSignature === shortSignature2)
        assertEquals(shortSignature, shortSignature2)
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test NACL EdDSA PublicKey round trip`() {
        val keyPair = generateNACLKeyPair()
        val publicKeyRecord = keyPair.public.toGenericRecord()
        assertEquals(keyPair.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord))
        val serializedPublicKey = keyPair.public.serialize()
        val deserializedPublicKey = PublicKeyHelper.deserialize(serializedPublicKey)
        assertEquals(keyPair.public, deserializedPublicKey)
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test NACL EdDSA verify`() {
        val keyPair = generateNACLKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        signature.verify(bytes)

        bytes[0] = 'k'.code.toByte()

        assertFailsWith<SignatureException> {
            signature.verify(bytes)
        }
        keyPair.private.safeDestroy()
    }

    @Test
    fun `NACL and BC interop`() {
        val keyPair = generateNACLKeyPair()
        val bcPublic = (keyPair.public as NACLEd25519PublicKey).toBCPublicKey()
        val bcPrivate = (keyPair.private as NACLEd25519PrivateKey).toBCPrivateKey()
        val bcKeyPair = KeyPair(bcPublic, bcPrivate)
        val naclPublic = (bcPublic as BCEdDSAPublicKey).toNACLPublicKey()
        val naclPrivate = (bcPrivate as BCEdDSAPrivateKey).toNACLPrivateKey()
        assertEquals(keyPair.public, naclPublic)
        assertEquals(keyPair.private, naclPrivate)
        val message = "1234567890".toByteArray(Charsets.UTF_8)
        val sig1 = keyPair.sign(message)
        assertEquals(keyPair.public, sig1.publicKey)
        assertEquals("NONEwithNACLEd25519", sig1.signatureAlgorithm)
        val sig2 = bcKeyPair.sign(message)
        assertEquals(bcKeyPair.public, sig2.publicKey)
        assertEquals("Ed25519", sig2.signatureAlgorithm)
        assertArrayEquals(sig1.signature, sig2.signature)
        sig1.verify(message)
        sig2.verify(message)
        val swapped1 = sig1.toDigitalSignature().toDigitalSignatureAndKey(bcKeyPair.public)
        swapped1.verify(message)
        val swapped2 = sig2.toDigitalSignature().toDigitalSignatureAndKey(keyPair.public)
        swapped2.verify(message)
        keyPair.private.safeDestroy()
        bcPrivate.safeDestroy()
        naclPrivate.safeDestroy()
    }

    @Test
    fun `test NACLCurve25519 PublicKey round trip`() {
        val keyPair1 = generateNACLDHKeyPair()
        val keyPair2 = generateNACLDHKeyPair()
        val publicKeyRecord1 = keyPair1.public.toGenericRecord()
        val publicKeyRecord2 = keyPair2.public.toGenericRecord()
        assertEquals(keyPair1.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord1))
        assertEquals(keyPair2.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord2))
        val serializedPublicKey1 = keyPair1.public.serialize()
        val serializedPublicKey2 = keyPair2.public.serialize()
        val deserializedPublicKey1 = PublicKeyHelper.deserialize(serializedPublicKey1)
        val deserializedPublicKey2 = PublicKeyHelper.deserialize(serializedPublicKey2)
        assertEquals(keyPair1.public, deserializedPublicKey1)
        assertEquals(keyPair2.public, deserializedPublicKey2)
        val sec1 = getSharedDHSecret(keyPair1, deserializedPublicKey2)
        val sec2 = getSharedDHSecret(keyPair2, deserializedPublicKey1)
        assertArrayEquals(sec1, sec2)
        keyPair1.private.safeDestroy()
        keyPair2.private.safeDestroy()
    }

    @Test
    fun `ThresholdKey test`() {
        val keyA = generateECDSAKeyPair()
        val keyB = generateNACLKeyPair()
        val keyC = generateRSAKeyPair()
        val keyD = generateEdDSAKeyPair()
        val keyPairs = listOf(keyA, keyB, keyC, keyD)
        val thresholdPublicKey = ThresholdPublicKey(
            1,
            listOf(keyA.public, keyB.public, keyC.public, keyD.public)
        )
        val encodedBytes = thresholdPublicKey.encoded
        val decoded = ThresholdPublicKey.deserialize(encodedBytes)
        assertEquals(thresholdPublicKey, decoded)

        val serializedAsPublicKey = (thresholdPublicKey as PublicKey).serialize()
        val deserialized2 = PublicKeyHelper.deserialize(serializedAsPublicKey)
        assertEquals(thresholdPublicKey, deserialized2)

        val bytes = "0123456789".toByteArray()
        val hash = SecureHash.secureHash(bytes)
        for (keypair in keyPairs) {
            val sigPair = KeyPair(thresholdPublicKey, keypair.private)
            val signature = sigPair.sign(bytes)
            signature.verify(bytes)
            if (keypair.private.algorithm in setOf("EC", "RSA")) { // test pre-hashed mode where possible
                val signature2 = sigPair.sign(hash)
                signature2.verify(bytes)
                signature.verify(hash)
                signature2.verify(hash)
            }
        }
    }

    @Test
    fun `ThresholdKey test 2`() {
        val keyA = generateECDSAKeyPair()
        val keyB = generateNACLKeyPair()
        val keyC = generateRSAKeyPair()
        val keyD = generateEdDSAKeyPair()
        val keyPairs = listOf(keyA, keyB, keyC, keyD)
        val thresholdPublicKey = ThresholdPublicKey(
            2,
            listOf(keyA.public, keyB.public, keyC.public, keyD.public)
        )
        val bytes = "0123456789".toByteArray()
        for (i in 0 until (1 shl keyPairs.size)) {
            val keys = keyPairs.map { it }.filterIndexed { index, _ -> (i and (1 shl index)) != 0 }
            val individualSignatures = keys.map { it.sign(bytes).toDigitalSignature() }
            val multiSig = thresholdPublicKey.createMultiSig(individualSignatures)
            if (i.countOneBits() < thresholdPublicKey.threshold) {
                assertFailsWith<SignatureException> {
                    multiSig.verify(bytes)
                }
            } else {
                multiSig.verify(bytes)
            }
        }

        val otherKeyPair = generateECDSAKeyPair()
        val badSig1 = otherKeyPair.sign(bytes).toDigitalSignature()
        val okSigPart = keyA.sign(bytes).toDigitalSignature()
        val badMultiSig = thresholdPublicKey.createMultiSig(
            listOf(
                badSig1,
                okSigPart
            )
        )
        assertFailsWith<SignatureException> { // unknown key not allowed
            badMultiSig.verify(bytes)
        }
        val okSigPart2 = keyA.sign(bytes).toDigitalSignature()
        val badMultiSig2 = thresholdPublicKey.createMultiSig(
            listOf(
                okSigPart,
                okSigPart2
            )
        )
        assertFailsWith<SignatureException> { // dupes don't count towards threshold
            badMultiSig2.verify(bytes)
        }
    }
}