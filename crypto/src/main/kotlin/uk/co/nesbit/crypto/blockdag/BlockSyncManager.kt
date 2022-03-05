package uk.co.nesbit.crypto.blockdag

import uk.co.nesbit.crypto.DigitalSignatureAndKey
import uk.co.nesbit.crypto.SecureHash

interface BlockSyncManager {
    var self: SecureHash
    val memberService: MemberService
    val blockStore: BlockStore
    val signingService: (SecureHash, ByteArray) -> DigitalSignatureAndKey

    fun createBlock(data: ByteArray): Block
    fun getSyncMessage(): Pair<SecureHash, BlockSyncMessage>
    fun getSyncMessage(peer: SecureHash): BlockSyncMessage
    fun processSyncMessage(message: BlockSyncMessage)
}