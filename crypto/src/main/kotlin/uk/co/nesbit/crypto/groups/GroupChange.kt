package uk.co.nesbit.crypto.groups

import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.crypto.SecureHash

interface GroupChange : AvroConvertible {
    val sponsorKeyId: SecureHash
    fun verify(groupInfo: GroupInfo)
    fun apply(groupInfo: GroupInfo): GroupInfo
}