package com.nesbit.crypto

import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.util.Arrays
import org.bouncycastle.util.Pack
import javax.crypto.AEADBadTagException

object ChaCha20Poly1305 {
    const val POLY1305_KEY_SIZE = 32
    const val POLY1305_BLOCK_SIZE = 16
    const val POLY1305_TAG_SIZE = 16
    const val CHACHA_KEY_SIZE_BYTES = 32
    const val CHACHA_NONCE_SIZE_BYTES = 12

    private fun createPolyMAC(macKey: KeyParameter, additionalData: ByteArray?, ciphertext: ByteArray): ByteArray {
        val poly = Poly1305()
        poly.init(macKey)

        if (additionalData != null) {
            poly.update(additionalData, 0, additionalData.size)
            if (additionalData.size % POLY1305_BLOCK_SIZE != 0) {
                val round = POLY1305_BLOCK_SIZE - additionalData.size % POLY1305_BLOCK_SIZE
                poly.update(ByteArray(round), 0, round)
            }
        }

        poly.update(ciphertext, 0, ciphertext.size)
        if (ciphertext.size % POLY1305_BLOCK_SIZE != 0) {
            val round = POLY1305_BLOCK_SIZE - ciphertext.size % POLY1305_BLOCK_SIZE
            poly.update(ByteArray(round), 0, round)
        }

        //additional data length
        val additionalDataLength: ByteArray = if (additionalData != null) {
            Pack.longToLittleEndian(additionalData.size.toLong())
        } else {
            ByteArray(8)
        }
        poly.update(additionalDataLength, 0, 8)
        val ciphertextLength = Pack.longToLittleEndian(ciphertext.size.toLong())
        poly.update(ciphertextLength, 0, 8)

        val calculatedMAC = ByteArray(poly.macSize)
        poly.doFinal(calculatedMAC, 0)
        return calculatedMAC
    }

    private fun initRecordMAC(cipher: ChaCha7539Engine): KeyParameter {
        val firstBlock = ByteArray(64)
        cipher.processBytes(firstBlock, 0, firstBlock.size, firstBlock, 0)
        // N.B. All versions I find on the internet do a swap operation here, but that leads to results that don't match the RFC7539 test vectors
        return KeyParameter(firstBlock, 0, POLY1305_KEY_SIZE)
    }

    class Encode(parameters: ParametersWithIV) {
        private val encryptCipher = ChaCha7539Engine().apply {
            require((parameters.parameters as KeyParameter).key.size == CHACHA_KEY_SIZE_BYTES) { "Invalid key size" }
            require(parameters.iv.size == CHACHA_NONCE_SIZE_BYTES) { "Invalid nonce size" }
            init(true, parameters)
        }

        fun encodeCiphertext(plaintext: ByteArray, additionalData: ByteArray? = null): ByteArray {
            val macKey = initRecordMAC(encryptCipher)

            val ciphertext = ByteArray(plaintext.size)
            encryptCipher.processBytes(plaintext, 0, plaintext.size, ciphertext, 0)

            val calculatedMAC = createPolyMAC(macKey, additionalData, ciphertext)

            val ret = ByteArray(ciphertext.size + POLY1305_TAG_SIZE)
            System.arraycopy(ciphertext, 0, ret, 0, ciphertext.size)
            System.arraycopy(calculatedMAC, 0, ret, ciphertext.size, POLY1305_TAG_SIZE)
            return ret
        }
    }

    class Decode(parameters: ParametersWithIV) {
        private val decryptCipher = ChaCha7539Engine().apply {
            require((parameters.parameters as KeyParameter).key.size == CHACHA_KEY_SIZE_BYTES) { "Invalid key size" }
            require(parameters.iv.size == CHACHA_NONCE_SIZE_BYTES) { "Invalid nonce size" }
            init(false, parameters)
        }

        fun decodeCiphertext(ciphertextAndTag: ByteArray, additionalData: ByteArray? = null): ByteArray {
            val macKey = initRecordMAC(decryptCipher)

            val ciphertext = ciphertextAndTag.copyOf(ciphertextAndTag.size - POLY1305_TAG_SIZE)
            val receivedMAC = ciphertextAndTag.copyOfRange(ciphertextAndTag.size - POLY1305_TAG_SIZE, ciphertextAndTag.size)

            val calculatedMAC = createPolyMAC(macKey, additionalData, ciphertext)
            if (!Arrays.constantTimeAreEqual(calculatedMAC, receivedMAC)) {
                throw AEADBadTagException("Invalid Tag")
            }

            val output = ByteArray(ciphertext.size)
            decryptCipher.processBytes(ciphertext, 0, ciphertext.size, output, 0)

            return output
        }
    }
}