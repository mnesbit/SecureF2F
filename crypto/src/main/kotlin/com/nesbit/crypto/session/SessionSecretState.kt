package com.nesbit.crypto.session

import com.nesbit.avro.serialize
import com.nesbit.crypto.ChaCha20Poly1305
import com.nesbit.crypto.concatByteArrays
import com.nesbit.crypto.getSharedDHSecret
import com.nesbit.crypto.splitByteArrays
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.security.KeyPair

class SessionSecretState(initiatorInit: InitiatorSessionParams,
                         responderInit: ResponderSessionParams,
                         dhKeys: KeyPair) {
    companion object {
        const val NONCE_SIZE = 16
        val HKDF_SALT = "LinkProto".toByteArray(Charsets.UTF_8)
        val REQUEST_KEY_BYTES = ChaCha20Poly1305.CHACHA_KEY_SIZE_BYTES
        val REQUEST_IV_BYTES = ChaCha20Poly1305.CHACHA_NONCE_SIZE_BYTES
        val REQUEST_MAC_KEY_BYTES = 32
        val RESPONSE_KEY_BYTES = ChaCha20Poly1305.CHACHA_KEY_SIZE_BYTES
        val RESPONSE_IV_BYTES = ChaCha20Poly1305.CHACHA_NONCE_SIZE_BYTES
        val RESPONSE_MAC_KEY_BYTES = 32
        val SESSION_KEY_BYTES = 32
        val TOTAL_KEY_BYTES = REQUEST_KEY_BYTES +
                REQUEST_IV_BYTES +
                REQUEST_MAC_KEY_BYTES +
                RESPONSE_KEY_BYTES +
                RESPONSE_IV_BYTES +
                RESPONSE_MAC_KEY_BYTES +
                SESSION_KEY_BYTES
    }

    val dhSharedValue: ByteArray
    val requestEncParams: ParametersWithIV
    val requestMACKey: ByteArray
    val responseEncParams: ParametersWithIV
    val responseMACKey: ByteArray
    val sessionRootKey: ByteArray

    init {
        dhSharedValue = calculateSharedDHSecret(initiatorInit, dhKeys, responderInit)

        val hkdfKey = calculateHKDFBytes(initiatorInit, responderInit)
        val splits = hkdfKey.splitByteArrays(REQUEST_KEY_BYTES,
                REQUEST_IV_BYTES,
                REQUEST_MAC_KEY_BYTES,
                RESPONSE_KEY_BYTES,
                RESPONSE_IV_BYTES,
                RESPONSE_MAC_KEY_BYTES,
                SESSION_KEY_BYTES)

        requestEncParams = ParametersWithIV(KeyParameter(splits[0]), splits[1])
        requestMACKey = splits[2]

        responseEncParams = ParametersWithIV(KeyParameter(splits[3]), splits[4])
        responseMACKey = splits[5]

        sessionRootKey = splits[6]
    }

    private fun calculateHKDFBytes(initiatorInit: InitiatorSessionParams, responderInit: ResponderSessionParams): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        val context = concatByteArrays(initiatorInit.serialize(), responderInit.serialize())
        hkdf.init(HKDFParameters(dhSharedValue, HKDF_SALT, context))
        val hkdfKey = ByteArray(TOTAL_KEY_BYTES)
        hkdf.generateBytes(hkdfKey, 0, hkdfKey.size)
        return hkdfKey
    }

    private fun calculateSharedDHSecret(initiatorInit: InitiatorSessionParams, dhKeys: KeyPair, responderInit: ResponderSessionParams): ByteArray {
        return if (initiatorInit.initiatorDHPublicKey == dhKeys.public) {
            getSharedDHSecret(dhKeys, responderInit.responderDHPublicKey)
        } else {
            getSharedDHSecret(dhKeys, initiatorInit.initiatorDHPublicKey)
        }
    }
}