package uk.co.nesbit.crypto.blockdag

import uk.co.nesbit.crypto.SecureHash
import java.security.PublicKey

interface MemberService {
    fun getMemberKey(id: SecureHash): PublicKey?
    fun addMember(key: PublicKey): SecureHash
}