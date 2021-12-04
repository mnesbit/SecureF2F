package uk.co.nesbit.crypto.blockdag

interface BlockSyncManager {
    val memberService: MemberService
    val blockStore: BlockStore

}