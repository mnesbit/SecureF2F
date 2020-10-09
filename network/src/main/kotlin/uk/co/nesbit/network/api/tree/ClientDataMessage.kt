package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.network.api.Message

class ClientDataMessage(
    val source: NetworkAddressInfo,
    val sessionId: Long,
    val seqNo: Int,
    val ackSeqNo: Int,
    val selectiveAck: Int,
    val receiveWindowSize: Int,
    val payload: ByteArray
) : Message {
    constructor(clientDataMessageRecord: GenericRecord) : this(
        clientDataMessageRecord.getTyped("source"),
        clientDataMessageRecord.getTyped("sessionId"),
        clientDataMessageRecord.getTyped("seqNo"),
        clientDataMessageRecord.getTyped("ackSeqNo"),
        clientDataMessageRecord.getTyped("selectiveAck"),
        clientDataMessageRecord.getTyped("receiveWindowSize"),
        clientDataMessageRecord.getTyped("payload")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val clientDataMessageSchema: Schema = Schema.Parser()
            .addTypes(mapOf(NetworkAddressInfo.networkAddressInfoSchema.name to NetworkAddressInfo.networkAddressInfoSchema))
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/clientdatamessage.avsc"))

        fun deserialize(bytes: ByteArray): ClientDataMessage {
            val clientDataMessageRecord = clientDataMessageSchema.deserialize(bytes)
            return ClientDataMessage(clientDataMessageRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val clientDataMessageRecord = GenericData.Record(clientDataMessageSchema)
        clientDataMessageRecord.putTyped("source", source)
        clientDataMessageRecord.putTyped("sessionId", sessionId)
        clientDataMessageRecord.putTyped("seqNo", seqNo)
        clientDataMessageRecord.putTyped("ackSeqNo", ackSeqNo)
        clientDataMessageRecord.putTyped("selectiveAck", selectiveAck)
        clientDataMessageRecord.putTyped("receiveWindowSize", receiveWindowSize)
        clientDataMessageRecord.putTyped("payload", payload)
        return clientDataMessageRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ClientDataMessage

        if (source != other.source) return false
        if (sessionId != other.sessionId) return false
        if (seqNo != other.seqNo) return false
        if (ackSeqNo != other.ackSeqNo) return false
        if (selectiveAck != other.selectiveAck) return false
        if (receiveWindowSize != other.receiveWindowSize) return false
        if (!payload.contentEquals(other.payload)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = source.hashCode()
        result = 31 * result + sessionId.hashCode()
        result = 31 * result + seqNo
        result = 31 * result + ackSeqNo
        result = 31 * result + selectiveAck
        result = 31 * result + receiveWindowSize
        result = 31 * result + payload.contentHashCode()
        return result
    }

}