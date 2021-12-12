package uk.co.nesbit.crypto.blockdag

import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.SecureHash

interface BlockSyncManager {
    val memberService: MemberService
    val blockStore: BlockStore

    fun getSyncMessage(peer: SecureHash, signingService: (SecureHash, ByteArray) -> DigitalSignature): BlockSyncMessage
    fun processSyncMessage(message: BlockSyncMessage)
}