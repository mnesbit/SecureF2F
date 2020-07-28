package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.crypto.toByteArray

class NetworkAddressInfo(
        val identity: VersionedIdentity,
        val treeAddress1: List<SecureHash>,
        val treeAddress2: List<SecureHash>,
        val treeAddress3: List<SecureHash>
) : AvroConvertible {
    constructor(networkAddressInfoRecord: GenericRecord) :
            this(
                    networkAddressInfoRecord.getTyped("identity"),
                    networkAddressInfoRecord.getObjectArray("treeAddress1", ::SecureHash),
                    networkAddressInfoRecord.getObjectArray("treeAddress2", ::SecureHash),
                    networkAddressInfoRecord.getObjectArray("treeAddress3", ::SecureHash)
            )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val networkAddressInfoSchema: Schema = Schema.Parser()
                .addTypes(
                        mapOf(
                                SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                                VersionedIdentity.versionedIdentitySchema.fullName to VersionedIdentity.versionedIdentitySchema
                        )
                )
                .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/networkaddressinfo.avsc"))

        fun deserialize(bytes: ByteArray): NetworkAddressInfo {
            val networkAddressInfoRecord = networkAddressInfoSchema.deserialize(bytes)
            return NetworkAddressInfo(networkAddressInfoRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val networkAddressInfoRecord = GenericData.Record(networkAddressInfoSchema)
        networkAddressInfoRecord.putTyped("identity", identity)
        networkAddressInfoRecord.putObjectArray("treeAddress1", treeAddress1)
        networkAddressInfoRecord.putObjectArray("treeAddress2", treeAddress2)
        networkAddressInfoRecord.putObjectArray("treeAddress3", treeAddress3)
        return networkAddressInfoRecord
    }

    val roots: List<SecureHash> by lazy(LazyThreadSafetyMode.PUBLICATION) {
        listOf(treeAddress1.first(), treeAddress2.first(), treeAddress3.first())
    }

    val paths: List<List<SecureHash>> by lazy(LazyThreadSafetyMode.PUBLICATION) {
        listOf(treeAddress1, treeAddress2, treeAddress3)
    }

    val depths: List<Int> by lazy(LazyThreadSafetyMode.PUBLICATION) {
        listOf(treeAddress1.size, treeAddress2.size, treeAddress3.size)
    }

    private fun verifyPath(path: List<SecureHash>, index: Int) {
        require(path.isNotEmpty() && path.last() == identity.id) {
            "Address invalid"
        }
        val uniqueIds = path.toSet()
        require(uniqueIds.size == path.size) {
            "No circular paths allowed"
        }
        val minHash = uniqueIds.minBy { SecureHash.secureHash(concatByteArrays(index.toByteArray(), it.bytes)) }
        require(path.first() == minHash) {
            "root should always be lowest hash in chain"
        }
    }

    fun verify() {
        verifyPath(treeAddress1, 0)
        verifyPath(treeAddress2, 1)
        verifyPath(treeAddress3, 2)
    }

    fun greedyDist(other: NetworkAddressInfo): Int = minOf(
            greedyDist(treeAddress1, other.treeAddress1),
            greedyDist(treeAddress2, other.treeAddress2),
            greedyDist(treeAddress3, other.treeAddress3)
    )

    private fun greedyDist(
            self: List<SecureHash>,
            other: List<SecureHash>
    ): Int {
        if (self.first() != other.first()) {
            return Int.MAX_VALUE
        }
        var prefixLength = 0
        while (prefixLength < self.size
                && prefixLength < other.size
                && self[prefixLength] == other[prefixLength]
        ) {
            ++prefixLength
        }
        return self.size + other.size - 2 * prefixLength
    }

    override fun toString(): String {
        return identity.id.toString()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as NetworkAddressInfo

        if (identity != other.identity) return false
        if (treeAddress1 != other.treeAddress1) return false
        if (treeAddress2 != other.treeAddress2) return false
        if (treeAddress3 != other.treeAddress3) return false

        return true
    }

    override fun hashCode(): Int {
        var result = identity.hashCode()
        result = 31 * result + treeAddress1.hashCode()
        result = 31 * result + treeAddress2.hashCode()
        result = 31 * result + treeAddress3.hashCode()
        return result
    }

}