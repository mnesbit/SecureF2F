package uk.co.nesbit.crypto.blockdag

import uk.co.nesbit.crypto.SecureHash
import java.security.PublicKey

interface MemberService {
    val members: Set<SecureHash>
    fun getMemberKey(id: SecureHash): PublicKey?
}