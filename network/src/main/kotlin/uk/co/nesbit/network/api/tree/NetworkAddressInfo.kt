package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.VersionedIdentity

class NetworkAddressInfo(val identity: VersionedIdentity, val treeAddress: List<SecureHash>) : AvroConvertible {
    constructor(networkAddressInfoRecord: GenericRecord) :
            this(
                networkAddressInfoRecord.getTyped("identity"),
                networkAddressInfoRecord.getObjectArray("treeAddress", ::SecureHash)
            )

    init {
        require(treeAddress.isNotEmpty() && treeAddress.last() == identity.id) {
            "Address invalid"
        }
    }

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
        networkAddressInfoRecord.putObjectArray("treeAddress", treeAddress)
        return networkAddressInfoRecord
    }

    fun greedyDist(other: NetworkAddressInfo): Int = greedyDist(other.treeAddress)

    fun greedyDist(
        other: List<SecureHash>
    ): Int {
        var prefixLength = 0
        while (prefixLength < treeAddress.size
            && prefixLength < other.size
            && treeAddress[prefixLength] == other[prefixLength]
        ) {
            ++prefixLength
        }
        return treeAddress.size + other.size - 2 * prefixLength
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as NetworkAddressInfo

        if (identity != other.identity) return false
        if (treeAddress != other.treeAddress) return false

        return true
    }

    override fun hashCode(): Int {
        var result = identity.hashCode()
        result = 31 * result + treeAddress.hashCode()
        return result
    }
}