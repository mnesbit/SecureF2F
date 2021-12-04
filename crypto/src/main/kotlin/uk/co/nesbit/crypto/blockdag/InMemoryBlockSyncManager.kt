package uk.co.nesbit.crypto.blockdag

class InMemoryBlockSyncManager(
    override val memberService: MemberService,
    override val blockStore: BlockStore
) : BlockSyncManager {
}