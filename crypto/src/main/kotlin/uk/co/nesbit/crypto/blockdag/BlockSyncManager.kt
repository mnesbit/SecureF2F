package uk.co.nesbit.crypto.blockdag

import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.SecureHash

interface BlockSyncManager {
    val memberService: MemberService
    val blockStore: BlockStore
    val signingService: (SecureHash, ByteArray) -> DigitalSignature

    fun createBlock(data: ByteArray): Block
    fun getSyncMessage(peer: SecureHash): BlockSyncMessage
    fun processSyncMessage(message: BlockSyncMessage)
}