package uk.co.nesbit.crypto

import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.EdDSAPublicKey
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import uk.co.nesbit.avro.serialize
import java.security.KeyPair
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

        val key5 = generateCurve25519DHKeyPair()
        val key6 = generateCurve25519DHKeyPair()
        val sec5 = getSharedDHSecret(key5, key6.public)
        val sec6 = getSharedDHSecret(key6, key5.public)
        assertArrayEquals(sec5, sec6)

        val key7 = generateNACLDHKeyPair()
        val key8 = generateNACLDHKeyPair()
        val sec7 = getSharedDHSecret(key7, key8.public)
        val sec8 = getSharedDHSecret(key8, key7.public)
        assertArrayEquals(sec7, sec8)

        //Check interop
        val sec9 = getSharedDHSecret(key5, Curve25519PublicKey(key7.public.encoded))
        val sec10 = getSharedDHSecret(key7, NACLCurve25519PublicKey(key5.public.encoded))
        assertArrayEquals(sec9, sec10)

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
        key1.private.safeDestroy()
        key2.private.safeDestroy()
        key3.private.safeDestroy()
        key4.private.safeDestroy()
        key5.private.safeDestroy()
        key6.private.safeDestroy()
        key7.private.safeDestroy()
        key8.private.safeDestroy()
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
    fun `test Tink EdDSA serialisation round trip`() {
        val keyPair = generateTinkEd25519KeyPair()
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
    fun `test Tink EdDSA GenericRecord round trip`() {
        val keyPair = generateTinkEd25519KeyPair()
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
    fun `test Tink EdDSA PublicKey round trip`() {
        val keyPair = generateTinkEd25519KeyPair()
        val publicKeyRecord = keyPair.public.toGenericRecord()
        assertEquals(keyPair.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord))
        val serializedPublicKey = keyPair.public.serialize()
        val deserializedPublicKey = PublicKeyHelper.deserialize(serializedPublicKey)
        assertEquals(keyPair.public, deserializedPublicKey)
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test Tink EdDSA verify`() {
        val keyPair = generateTinkEd25519KeyPair()
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
    fun `Tink and i2p interop`() {
        val keyPair = generateTinkEd25519KeyPair()
        val i2pPublic = (keyPair.public as TinkEd25519PublicKey).toI2PPublicKey()
        val i2pPrivate = (keyPair.private as TinkEd25519PrivateKey).toI2PPrivateKey()
        val i2pKeyPair = KeyPair(i2pPublic, i2pPrivate)
        val tinkPublic = (i2pPublic as EdDSAPublicKey).toTinkPublicKey()
        val tinkPrivate = (i2pPrivate as EdDSAPrivateKey).toTinkPrivateKey()
        assertEquals(keyPair.public, tinkPublic)
        assertEquals(keyPair.private, tinkPrivate)
        val message = "1234567890".toByteArray(Charsets.UTF_8)
        val sig1 = keyPair.sign(message)
        assertEquals(keyPair.public, sig1.publicKey)
        assertEquals("NONEwithTinkEd25519", sig1.signatureAlgorithm)
        val sig2 = i2pKeyPair.sign(message)
        assertEquals(i2pKeyPair.public, sig2.publicKey)
        assertEquals("NONEwithEdDSA", sig2.signatureAlgorithm)
        assertArrayEquals(sig1.signature, sig2.signature)
        sig1.verify(message)
        sig2.verify(message)
        val swapped1 = sig1.toDigitalSignature().toDigitalSignatureAndKey(i2pKeyPair.public)
        swapped1.verify(message)
        val swapped2 = sig2.toDigitalSignature().toDigitalSignatureAndKey(keyPair.public)
        swapped2.verify(message)
        keyPair.private.safeDestroy()
        i2pPrivate.safeDestroy()
        tinkPrivate.safeDestroy()
    }

    @Test
    fun `Tink and NACL interop`() {
        val keyPair = generateTinkEd25519KeyPair()
        val naclPublic = (keyPair.public as TinkEd25519PublicKey).toNACLPublicKey()
        val naclPrivate = (keyPair.private as TinkEd25519PrivateKey).toNACLPrivateKey()
        val naclKeyPair = KeyPair(naclPublic, naclPrivate)
        val tinkPublic = (naclPublic as NACLEd25519PublicKey).toTinkPublicKey()
        val tinkPrivate = (naclPrivate as NACLEd25519PrivateKey).toTinkPrivateKey()
        assertEquals(keyPair.public, tinkPublic)
        assertEquals(keyPair.private, tinkPrivate)
        val message = "1234567890".toByteArray(Charsets.UTF_8)
        val sig1 = keyPair.sign(message)
        assertEquals(keyPair.public, sig1.publicKey)
        assertEquals("NONEwithTinkEd25519", sig1.signatureAlgorithm)
        val sig2 = naclKeyPair.sign(message)
        assertEquals(naclKeyPair.public, sig2.publicKey)
        assertEquals("NONEwithNACLEd25519", sig2.signatureAlgorithm)
        assertArrayEquals(sig1.signature, sig2.signature)
        sig1.verify(message)
        sig2.verify(message)
        val swapped1 = sig1.toDigitalSignature().toDigitalSignatureAndKey(naclKeyPair.public)
        swapped1.verify(message)
        val swapped2 = sig2.toDigitalSignature().toDigitalSignatureAndKey(keyPair.public)
        swapped2.verify(message)
        keyPair.private.safeDestroy()
        naclPrivate.safeDestroy()
        tinkPrivate.safeDestroy()
    }

    @Test
    fun `Tink and BC interop`() {
        val keyPair = generateTinkEd25519KeyPair()
        val bcPublic = (keyPair.public as TinkEd25519PublicKey).toBCPublicKey()
        val bcPrivate = (keyPair.private as TinkEd25519PrivateKey).toBCPrivateKey()
        val bcKeyPair = KeyPair(bcPublic, bcPrivate)
        val tinkPublic = (bcPublic as BCEdDSAPublicKey).toTinkPublicKey()
        val tinkPrivate = (bcPrivate as BCEdDSAPrivateKey).toTinkPrivateKey()
        assertEquals(keyPair.public, tinkPublic)
        assertEquals(keyPair.private, tinkPrivate)
        val message = "1234567890".toByteArray(Charsets.UTF_8)
        val sig1 = keyPair.sign(message)
        assertEquals(keyPair.public, sig1.publicKey)
        assertEquals("NONEwithTinkEd25519", sig1.signatureAlgorithm)
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
        tinkPrivate.safeDestroy()
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
    fun `NACL and i2p interop`() {
        val keyPair = generateNACLKeyPair()
        val i2pPublic = (keyPair.public as NACLEd25519PublicKey).toI2PPublicKey()
        val i2pPrivate = (keyPair.private as NACLEd25519PrivateKey).toI2PPrivateKey()
        val i2pKeyPair = KeyPair(i2pPublic, i2pPrivate)
        val naclPublic = (i2pPublic as EdDSAPublicKey).toNACLPublicKey()
        val naclPrivate = (i2pPrivate as EdDSAPrivateKey).toNACLPrivateKey()
        assertEquals(keyPair.public, naclPublic)
        assertEquals(keyPair.private, naclPrivate)
        val message = "1234567890".toByteArray(Charsets.UTF_8)
        val sig1 = keyPair.sign(message)
        assertEquals(keyPair.public, sig1.publicKey)
        assertEquals("NONEwithNACLEd25519", sig1.signatureAlgorithm)
        val sig2 = i2pKeyPair.sign(message)
        assertEquals(i2pKeyPair.public, sig2.publicKey)
        assertEquals("NONEwithEdDSA", sig2.signatureAlgorithm)
        assertArrayEquals(sig1.signature, sig2.signature)
        sig1.verify(message)
        sig2.verify(message)
        val swapped1 = sig1.toDigitalSignature().toDigitalSignatureAndKey(i2pKeyPair.public)
        swapped1.verify(message)
        val swapped2 = sig2.toDigitalSignature().toDigitalSignatureAndKey(keyPair.public)
        swapped2.verify(message)
        keyPair.private.safeDestroy()
        i2pPrivate.safeDestroy()
        naclPrivate.safeDestroy()
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
    fun `test BC EdDSA serialisation round trip`() {
        val keyPair = generateBCEdDSAKeyPair()
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
    fun `test BC EdDSA GenericRecord round trip`() {
        val keyPair = generateBCEdDSAKeyPair()
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
    fun `test BC EdDSA PublicKey round trip`() {
        val keyPair = generateBCEdDSAKeyPair()
        val publicKeyRecord = keyPair.public.toGenericRecord()
        assertEquals(keyPair.public, PublicKeyHelper.fromGenericRecord(publicKeyRecord))
        val serializedPublicKey = keyPair.public.serialize()
        val deserializedPublicKey = PublicKeyHelper.deserialize(serializedPublicKey)
        assertEquals(keyPair.public, deserializedPublicKey)
        keyPair.private.safeDestroy()
    }

    @Test
    fun `test BC EdDSA verify`() {
        val keyPair = generateBCEdDSAKeyPair()
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
    fun `BC and i2p interop`() {
        val keyPair = generateBCEdDSAKeyPair()
        val i2pPublic = (keyPair.public as BCEdDSAPublicKey).toI2pPublicKey()
        val i2pPrivate = (keyPair.private as BCEdDSAPrivateKey).toI2pPrivateKey()
        val i2pKeyPair = KeyPair(i2pPublic, i2pPrivate)
        val bcPublic = (i2pPublic as EdDSAPublicKey).toBCPublicKey()
        val bcPrivate = (i2pPrivate as EdDSAPrivateKey).toBCPrivateKey()
        assertEquals(keyPair.public, bcPublic)
        assertEquals(keyPair.private, bcPrivate)
        val message = "1234567890".toByteArray(Charsets.UTF_8)
        val sig1 = keyPair.sign(message)
        assertEquals(keyPair.public, sig1.publicKey)
        assertEquals("Ed25519", sig1.signatureAlgorithm)
        val sig2 = i2pKeyPair.sign(message)
        assertEquals(i2pKeyPair.public, sig2.publicKey)
        assertEquals("NONEwithEdDSA", sig2.signatureAlgorithm)
        assertArrayEquals(sig1.signature, sig2.signature)
        sig1.verify(message)
        sig2.verify(message)
        val swapped1 = sig1.toDigitalSignature().toDigitalSignatureAndKey(i2pKeyPair.public)
        swapped1.verify(message)
        val swapped2 = sig2.toDigitalSignature().toDigitalSignatureAndKey(keyPair.public)
        swapped2.verify(message)
        keyPair.private.safeDestroy()
        bcPrivate.safeDestroy()
        i2pPrivate.safeDestroy()
    }

}