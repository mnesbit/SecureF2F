package com.nesbit.crypto

import com.nesbit.avro.serialize
import org.junit.Assert
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import java.security.SignatureException
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals


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
    }

    @Test
    fun `test EdDSA GenericRecord round trip`() {
        val keyPair = generateEdDSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        val signatureRecord = signature.toGenericRecord()
        val signature2 = DigitalSignatureAndKey(signatureRecord)
        Assert.assertFalse(signature === signature2)
        assertEquals(signature, signature2)
        val shortSignature = signature.toDigitalSignature()
        val shortSignatureRecord = shortSignature.toGenericRecord()
        val shortSignature2 = DigitalSignature(shortSignatureRecord)
        Assert.assertFalse(shortSignature === shortSignature2)
        assertEquals(shortSignature, shortSignature2)
    }

    @Test
    fun `test EdDSA PublicKey round trip`() {
        val keyPair = generateEdDSAKeyPair()
        val publicKeyRecord = keyPair.public.toGenericRecord()
        assertEquals(keyPair.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord))
        val serializedPublicKey = keyPair.public.serialize()
        val deserializedPublicKey = PublicKeyHelper.deserialize(serializedPublicKey)
        assertEquals(keyPair.public, deserializedPublicKey)
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
    }

    @Test
    fun `test ECDSA GenericRecord round trip`() {
        val keyPair = generateECDSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        val signatureRecord = signature.toGenericRecord()
        val signature2 = DigitalSignatureAndKey(signatureRecord)
        Assert.assertFalse(signature === signature2)
        assertEquals(signature, signature2)
        val shortSignature = signature.toDigitalSignature()
        val shortSignatureRecord = shortSignature.toGenericRecord()
        val shortSignature2 = DigitalSignature(shortSignatureRecord)
        Assert.assertFalse(shortSignature === shortSignature2)
        assertEquals(shortSignature, shortSignature2)
    }

    @Test
    fun `test ECDSA PublicKey round trip`() {
        val keyPair = generateECDSAKeyPair()
        val publicKeyRecord = keyPair.public.toGenericRecord()
        assertEquals(keyPair.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord))
        val serializedPublicKey = keyPair.public.serialize()
        val deserializedPublicKey = PublicKeyHelper.deserialize(serializedPublicKey)
        assertEquals(keyPair.public, deserializedPublicKey)
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
    }

    @Test
    fun `test RSA GenericRecord round trip`() {
        val keyPair = generateRSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        val signatureRecord = signature.toGenericRecord()
        val signature2 = DigitalSignatureAndKey(signatureRecord)
        Assert.assertFalse(signature === signature2)
        assertEquals(signature, signature2)
        val shortSignature = signature.toDigitalSignature()
        val shortSignatureRecord = shortSignature.toGenericRecord()
        val shortSignature2 = DigitalSignature(shortSignatureRecord)
        Assert.assertFalse(shortSignature === shortSignature2)
        assertEquals(shortSignature, shortSignature2)
    }

    @Test
    fun `test RSA PublicKey round trip`() {
        val keyPair = generateRSAKeyPair()
        val publicKeyRecord = keyPair.public.toGenericRecord()
        assertEquals(keyPair.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord))
        val serializedPublicKey = keyPair.public.serialize()
        val deserializedPublicKey = PublicKeyHelper.deserialize(serializedPublicKey)
        assertEquals(keyPair.public, deserializedPublicKey)
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
    }

    @Test
    fun `test Curve25519 PublicKey round trip`() {
        val keyPair1 = generateCurve25519DHKeyPair()
        val keyPair2 = generateCurve25519DHKeyPair()
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

        bytes[0] = 'k'.toByte()

        assertFailsWith<SignatureException> {
            signature.verify(bytes)
        }
    }

    @Test
    fun `test ECDSA verify`() {
        val keyPair = generateECDSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        signature.verify(bytes)

        bytes[0] = 'k'.toByte()

        assertFailsWith<SignatureException> {
            signature.verify(bytes)
        }
    }

    @Test
    fun `test RSA verify`() {
        val keyPair = generateRSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        signature.verify(bytes)

        bytes[0] = 'k'.toByte()

        assertFailsWith<SignatureException> {
            signature.verify(bytes)
        }
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

        val key5 = generateCurve25519DHKeyPair()
        val key6 = generateCurve25519DHKeyPair()
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

        assertFails {
            getSharedDHSecret(key1, key5.public)
        }

        assertFails {
            getSharedDHSecret(key3, key5.public)
        }
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

    }
}