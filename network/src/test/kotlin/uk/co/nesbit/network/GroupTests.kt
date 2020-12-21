package uk.co.nesbit.network

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.network.api.groups.*
import uk.co.nesbit.network.services.KeyServiceImpl
import java.time.Clock
import java.time.Instant

class GroupTests {
    @Test
    fun `serialise group test`() {
        val keyService = KeyServiceImpl(maxVersion = 16)
        val key1 = keyService.generateSigningKey()
        val key2 = keyService.generateSigningKey()
        val dh1 = keyService.generateDhKey()
        val dh2 = keyService.generateDhKey()
        val member1 = GroupMemberInfo(
            "Alice",
            keyService.getSigningKey(key1),
            Instant.parse("2020-12-10T15:55:00Z"),
            1,
            key1,
            GroupMemberRole.ADMIN,
            mapOf("stuff" to "thing", "bits" to "pieces"),
            listOf(
                HistoricKeyInfo(
                    keyService.getSigningKey(key2),
                    Instant.parse("2020-12-01T13:10:00Z"),
                    Instant.parse("2020-12-10T15:50:00Z")
                )
            ),
            keyService.getDhKey(dh1),
            SecureHash.secureHash("1")
        )
        val member2 = GroupMemberInfo(
            "Bob",
            keyService.getSigningKey(key2),
            Instant.parse("2020-12-10T15:55:00Z"),
            2,
            key1,
            GroupMemberRole.ORDINARY,
            mapOf("stuff" to "thing2", "bits" to "pieces2", "other" to "info"),
            emptyList(),
            keyService.getDhKey(dh2),
            SecureHash.secureHash("1")
        )
        val groupInfo = GroupInfo(
            SecureHash.secureHash("group1"),
            "my group",
            5,
            listOf(member1, member2),
            mapOf("key1" to "value"),
            SecureHash.secureHash("state1")
        )
        val serialised = groupInfo.serialize()
        val deserialised = GroupInfo.deserialize(serialised)
        assertEquals(groupInfo, deserialised)
    }

    @Test
    fun `invite serialisation test`() {
        val keyService = KeyServiceImpl(maxVersion = 16)
        val key1 = keyService.generateSigningKey()
        val key2 = keyService.generateSigningKey()
        val dh1 = keyService.generateDhKey()
        val member1 = GroupMemberInfo(
            "Alice",
            keyService.getSigningKey(key1),
            Instant.parse("2020-12-10T15:55:00Z"),
            1,
            key1,
            GroupMemberRole.ADMIN,
            mapOf("stuff" to "thing", "bits" to "pieces"),
            listOf(
                HistoricKeyInfo(
                    keyService.getSigningKey(key2),
                    Instant.parse("2020-12-01T13:10:00Z"),
                    Instant.parse("2020-12-10T15:50:00Z")
                )
            ),
            keyService.getDhKey(dh1),
            SecureHash.secureHash("1")
        )
        val groupInfo = GroupInfo(
            SecureHash.secureHash("group1"),
            "my group",
            5,
            listOf(member1),
            mapOf("key1" to "value"),
            SecureHash.secureHash("state1")
        )
        val invite = GroupInviteToken.createInvite(
            groupInfo,
            Instant.parse("2020-12-15T12:10:00Z"),
            member1.memberKeyId,
            keyService
        )
        val serialised = invite.serialize()
        val deserialised = GroupInviteToken.deserialize(serialised)
        assertEquals(invite, deserialised)
        val jsonSerialised = invite.toJSON()
        val deserialisedJSON = GroupInviteToken.deserializedJSON(jsonSerialised)
        assertEquals(invite, deserialisedJSON)
        val address2 = keyService.generateNetworkID("pub2")
        val key = keyService.generateSigningKey()
        val joinRequest = GroupMemberJoin.createJoinRequest(
            invite,
            "Bob",
            key,
            address2,
            keyService
        )
        val serialisedRequest = joinRequest.serialize()
        val deserialisedRequest = GroupMemberJoin.deserialize(serialisedRequest)
        assertEquals(joinRequest, deserialisedRequest)
        val addRequest = GroupMemberAdd.createMemberAdd(
            groupInfo,
            deserialisedRequest,
            Instant.parse("2020-12-15T12:08:00Z"),
            GroupMemberRole.ORDINARY,
            mapOf("thing" to "that"),
            keyService
        )
        val serializedAdd = addRequest.serialize()
        val deserializedAdd = GroupMemberAdd.deserialize(serializedAdd)
        assertEquals(addRequest, deserializedAdd)
        deserializedAdd.verify(groupInfo)
        val newGroup = groupInfo.applyMemberAdd(deserializedAdd)
        assertEquals(2, newGroup.members.size)
    }

    @Test
    fun `remove serialisation test`() {
        val keyService = KeyServiceImpl(maxVersion = 16)
        val key1 = keyService.generateSigningKey()
        val key2 = keyService.generateSigningKey()
        val dh1 = keyService.generateDhKey()
        val dh2 = keyService.generateDhKey()
        val member1 = GroupMemberInfo(
            "Alice",
            keyService.getSigningKey(key1),
            Instant.parse("2020-12-10T15:55:00Z"),
            1,
            key1,
            GroupMemberRole.ADMIN,
            mapOf("stuff" to "thing", "bits" to "pieces"),
            listOf(
                HistoricKeyInfo(
                    keyService.getSigningKey(key2),
                    Instant.parse("2020-12-01T13:10:00Z"),
                    Instant.parse("2020-12-10T15:50:00Z")
                )
            ),
            keyService.getDhKey(dh1),
            SecureHash.secureHash("1")
        )
        val member2 = GroupMemberInfo(
            "Bob",
            keyService.getSigningKey(key2),
            Instant.parse("2020-12-10T15:55:00Z"),
            2,
            key1,
            GroupMemberRole.ORDINARY,
            mapOf("stuff" to "thing2", "bits" to "pieces2", "other" to "info"),
            emptyList(),
            keyService.getDhKey(dh2),
            SecureHash.secureHash("1")
        )
        val groupInfo = GroupInfo(
            SecureHash.secureHash("group1"),
            "my group",
            5,
            listOf(member1, member2),
            mapOf("key1" to "value"),
            SecureHash.secureHash("state1")
        )
        val newDhKey = keyService.generateDhKey()
        val removeRequest = GroupMemberRemove.createRemoveRequest(
            groupInfo,
            member2.memberKeyId,
            member1.sponsor,
            newDhKey,
            keyService
        )
        val serialised = removeRequest.serialize()
        val deserialised = GroupMemberRemove.deserialize(serialised)
        assertEquals(removeRequest, deserialised)
        deserialised.verify(groupInfo)
    }

    @Test
    fun `modify serialisation test`() {
        val keyService = KeyServiceImpl(maxVersion = 16)
        val key1 = keyService.generateSigningKey()
        val key2 = keyService.generateSigningKey()
        val dh1 = keyService.generateDhKey()
        val dh2 = keyService.generateDhKey()
        val member1 = GroupMemberInfo(
            "Alice",
            keyService.getSigningKey(key1),
            Instant.parse("2020-12-10T15:55:00Z"),
            1,
            key1,
            GroupMemberRole.ADMIN,
            mapOf("stuff" to "thing", "bits" to "pieces"),
            listOf(
                HistoricKeyInfo(
                    keyService.getSigningKey(key2),
                    Instant.parse("2020-12-01T13:10:00Z"),
                    Instant.parse("2020-12-10T15:50:00Z")
                )
            ),
            keyService.getDhKey(dh1),
            SecureHash.secureHash("1")
        )
        val member2 = GroupMemberInfo(
            "Bob",
            keyService.getSigningKey(key2),
            Instant.parse("2020-12-10T15:55:00Z"),
            2,
            key1,
            GroupMemberRole.ORDINARY,
            mapOf("stuff" to "thing2", "bits" to "pieces2", "other" to "info"),
            emptyList(),
            keyService.getDhKey(dh2),
            SecureHash.secureHash("1")
        )
        val groupInfo = GroupInfo(
            SecureHash.secureHash("group1"),
            "my group",
            5,
            listOf(member1, member2),
            mapOf("key1" to "value"),
            SecureHash.secureHash("state1")
        )
        val newSigningKey = keyService.generateSigningKey()
        val now = Instant.parse("2020-12-10T17:55:00Z")
        val newHistoricKeys = member1.historicKeys + HistoricKeyInfo(member1.memberKey, member1.keyIssued, now)
        val keyChanged = member1.copy(
            memberKey = keyService.getSigningKey(newSigningKey),
            keyIssued = now,
            historicKeys = newHistoricKeys
        )
        val keyChange = GroupMemberModify.createModifyRequest(groupInfo, keyChanged, newSigningKey, keyService)
        val serializedKeyChange = keyChange.serialize()
        val deserializedKeyChange = GroupMemberModify.deserialize(serializedKeyChange)
        assertEquals(keyChange, deserializedKeyChange)
        deserializedKeyChange.verify(groupInfo)
        val newDhKey = keyService.generateDhKey()
        val dhKeyChange = member1.copy(groupDhKey = keyService.getDhKey(newDhKey))
        val dhModifyRequest =
            GroupMemberModify.createModifyRequest(groupInfo, dhKeyChange, dhKeyChange.memberKeyId, keyService)
        val serializedDhKeyChange = dhModifyRequest.serialize()
        val deserializedDhKeyChange = GroupMemberModify.deserialize(serializedDhKeyChange)
        assertEquals(dhModifyRequest, deserializedDhKeyChange)
        deserializedDhKeyChange.verify(groupInfo)
        val newRouteKey = keyService.generateNetworkID()
        val routeChange = member1.copy(routingAddress = newRouteKey)
        val routeModifyRequest =
            GroupMemberModify.createModifyRequest(groupInfo, routeChange, routeChange.memberKeyId, keyService)
        val serializedRouteChange = routeModifyRequest.serialize()
        val deserializedRouteChange = GroupMemberModify.deserialize(serializedRouteChange)
        assertEquals(routeModifyRequest, deserializedRouteChange)
        deserializedRouteChange.verify(groupInfo)
        val newMember2Role = member2.copy(role = GroupMemberRole.REVOKED)
        val newMemberRoleChange =
            GroupMemberModify.createModifyRequest(groupInfo, newMember2Role, member1.memberKeyId, keyService)
        val serializedMemberRoleChange = newMemberRoleChange.serialize()
        val deserializedMemberRoleChange = GroupMemberModify.deserialize(serializedMemberRoleChange)
        assertEquals(newMemberRoleChange, deserializedMemberRoleChange)
        deserializedMemberRoleChange.verify(groupInfo)
        val extraInfoChange = member2.copy(otherInfo = mapOf("A" to "B"))
        val infoChange =
            GroupMemberModify.createModifyRequest(groupInfo, extraInfoChange, member1.memberKeyId, keyService)
        val serializedInfoChange = infoChange.serialize()
        val deserializedInfoChange = GroupMemberModify.deserialize(serializedInfoChange)
        assertEquals(infoChange, deserializedInfoChange)
        deserializedInfoChange.verify(groupInfo)
    }

    @Test
    fun `group evolution`() {
        val keyService = KeyServiceImpl(maxVersion = 16)
        val aliceNetworkKey = keyService.generateNetworkID("Alice")
        val startTime = Clock.systemUTC().instant()
        val initialGroup = GroupInfo.createInitialGroup(
            "Group 1",
            mapOf("Group Item" to "Stuff"),
            "ALICE",
            mapOf("Member Item" to "Thing1"),
            aliceNetworkKey,
            startTime,
            keyService
        )
        assertEquals(listOf("ALICE"), initialGroup.members.map { it.memberName })
        val aliceId = initialGroup.members.first().memberKeyId
        val inviteExpireTime = startTime.plusSeconds(120L)
        val bobInvite = GroupInviteToken.createInvite(
            initialGroup,
            inviteExpireTime,
            aliceId,
            keyService
        )
        val bobAddress = keyService.generateNetworkID("BOB")
        val bobGroupKey = keyService.generateSigningKey()
        val bobJoin = GroupMemberJoin.createJoinRequest(
            bobInvite,
            "BOB",
            bobGroupKey,
            bobAddress,
            keyService
        )
        val joinTime = startTime.plusSeconds(10L)
        val bobAdd = GroupMemberAdd.createMemberAdd(
            initialGroup,
            bobJoin,
            joinTime,
            GroupMemberRole.ORDINARY,
            mapOf("Member Item" to "Thing2"),
            keyService
        )
        val aliceBobGroup = initialGroup.applyMemberAdd(bobAdd)
        assertEquals(listOf("ALICE", "BOB"), aliceBobGroup.members.map { it.memberName })
        val welcome = GroupMemberWelcome(aliceBobGroup, ByteArray(32) { it.toByte() })
        val serializedWelcome = welcome.serialize()
        val deserializedWelcome = GroupMemberWelcome.deserialize(serializedWelcome)
        assertEquals(welcome, deserializedWelcome)
        val invite2ExpireTime = joinTime.plusSeconds(120L)
        val charlesInvite = GroupInviteToken.createInvite(
            aliceBobGroup,
            invite2ExpireTime,
            aliceId,
            keyService
        )
        val charlesAddress = keyService.generateNetworkID("CHARLES")
        val charlesGroupKey = keyService.generateSigningKey()
        val charlesJoin = GroupMemberJoin.createJoinRequest(
            charlesInvite,
            "CHARLES",
            charlesGroupKey,
            charlesAddress,
            keyService
        )
        val joinTime2 = joinTime.plusSeconds(10L)
        val charlesAdd = GroupMemberAdd.createMemberAdd(
            aliceBobGroup, charlesJoin,
            joinTime2,
            GroupMemberRole.ORDINARY,
            mapOf("Member Item" to "Cat"), keyService
        )
        val aliceBobCharlesGroup = aliceBobGroup.applyMemberAdd(charlesAdd)
        assertEquals(listOf("ALICE", "BOB", "CHARLES"), aliceBobCharlesGroup.members.map { it.memberName })
        val newDhKey = keyService.generateDhKey()
        val removeBob = GroupMemberRemove.createRemoveRequest(
            aliceBobCharlesGroup,
            bobGroupKey,
            aliceId,
            newDhKey,
            keyService
        )
        val aliceCharlesGroup = aliceBobCharlesGroup.applyMemberRemove(removeBob)
        assertEquals(listOf("ALICE", "CHARLES"), aliceCharlesGroup.members.map { it.memberName })
        val newAliceDhKey = keyService.generateDhKey()
        val aliceInfo = aliceCharlesGroup.findMemberByName("ALICE")!!
        val updatedAliceInfo = aliceInfo.copy(groupDhKey = keyService.getDhKey(newAliceDhKey))
        val keyRefreshModify = GroupMemberModify.createModifyRequest(
            aliceCharlesGroup,
            updatedAliceInfo,
            aliceInfo.memberKeyId,
            keyService
        )
        val aliceCharlesGroup2 = aliceCharlesGroup.applyMemberModify(keyRefreshModify)
        assertEquals(listOf("ALICE", "CHARLES"), aliceCharlesGroup2.members.map { it.memberName })
        val charlesInfo = aliceCharlesGroup2.findMemberByName("CHARLES")!!
        val charlesUpgrade = charlesInfo.copy(role = GroupMemberRole.ADMIN)
        val charlesModify = GroupMemberModify.createModifyRequest(
            aliceCharlesGroup2,
            charlesUpgrade,
            aliceId,
            keyService
        )
        val aliceCharlesGroup3 = aliceCharlesGroup2.applyMemberModify(charlesModify)
        assertEquals(listOf("ALICE", "CHARLES"), aliceCharlesGroup3.members.map { it.memberName })
        assertEquals(GroupMemberRole.ADMIN, aliceCharlesGroup3.findMemberByName("CHARLES")!!.role)
    }
}