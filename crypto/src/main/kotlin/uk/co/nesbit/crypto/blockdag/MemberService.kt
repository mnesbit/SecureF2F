package uk.co.nesbit.crypto.blockdag

import uk.co.nesbit.crypto.SecureHash
import java.security.PublicKey

interface MemberService {
    fun getMembers(): List<SecureHash>
    fun getMemberKey(id: SecureHash): PublicKey?
    fun addMember(key: PublicKey): SecureHash
}