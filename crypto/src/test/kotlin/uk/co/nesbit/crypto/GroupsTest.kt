package uk.co.nesbit.crypto

import org.junit.jupiter.api.Test
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.groups.*
import java.time.Clock
import java.time.temporal.ChronoUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class GroupsTest {
    @Test
    fun `GroupMemberInfo serialization test`() {
        val key = generateNACLKeyPair()
        val key2 = generateNACLKeyPair()
        val dhKey = generateNACLDHKeyPair()
        val clock = Clock.systemUTC()
        val created = clock.instant().truncatedTo(ChronoUnit.MILLIS)
        val member = GroupMemberInfo(
            "Alice",
            key.public,
            created,
            0,
            key.public.id,
            GroupMemberRole.ADMIN,
            mapOf("Thing" to "1"),
            listOf(HistoricKeyInfo(key2.public, created.minusSeconds(10L), created)),
            dhKey.public,
            SecureHash.secureHash("1234567890")
        )
        val serialized = member.serialize()
        val deserialized = GroupMemberInfo.deserialize(serialized)
        assertEquals(member, deserialized)
    }

    @Test
    fun `GroupInfo serialisation tests`() {
        val groupId = SecureHash.secureHash("1234")
        val aliceKey = generateNACLKeyPair()
        val aliceDhKey = generateNACLDHKeyPair()
        val now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.MILLIS)
        val groupCreate = GroupCreate.createGroupCreate(
            groupId,
            "Group1",
            mapOf("group data" to "Hello"),
            "Alice",
            aliceKey.public,
            aliceDhKey.public,
            SecureHash.secureHash("Alice address"),
            mapOf("alice info" to "1"),
            now
        ) { k, v ->
            assertEquals(aliceKey.public.id, k)
            aliceKey.sign(v)
        }
        val groupInfo = GroupInfo.EmptyGroup.applyGroupChange(groupCreate)
        val serialized = groupInfo.serialize()
        val deserialized = GroupInfo.deserialize(serialized)
        assertEquals(groupInfo, deserialized)
    }

    @Test
    fun `GroupCreate test`() {
        val groupId = SecureHash.secureHash("1234")
        val aliceKey = generateNACLKeyPair()
        val aliceDhKey = generateNACLDHKeyPair()
        val now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.MILLIS)
        val groupCreate = GroupCreate.createGroupCreate(
            groupId,
            "Group1",
            mapOf("group data" to "Hello"),
            "Alice",
            aliceKey.public,
            aliceDhKey.public,
            SecureHash.secureHash("Alice address"),
            mapOf("alice info" to "1"),
            now
        ) { k, v ->
            assertEquals(aliceKey.public.id, k)
            aliceKey.sign(v)
        }
        val serialized = groupCreate.serialize()
        val deserialized = GroupCreate.deserialize(serialized)
        assertEquals(groupCreate, deserialized)
        val change = GroupBlockPayload(groupCreate)
        val serializedChange = change.serialize()
        val deserializedChange = GroupBlockPayload.deserialize(serializedChange)
        assertEquals(change, deserializedChange)
        val initialGroup = GroupInfo.EmptyGroup.applyGroupChange(groupCreate)
        assertEquals(groupCreate.groupId, initialGroup.groupId)
        assertEquals(groupCreate.groupIdentifier, initialGroup.groupIdentifier)
        assertEquals(0, initialGroup.epoch)
        assertEquals(groupCreate.initialMemberName, initialGroup.admins.single().memberName)
        assertEquals(groupCreate.initialMemberKey, initialGroup.admins.single().memberKey)
        assertEquals(groupCreate.initialMemberDhKey, initialGroup.admins.single().groupDhKey)
        assertEquals(groupCreate.initialMemberAddress, initialGroup.admins.single().routingAddress)
    }

    @Test
    fun `GroupMemberAdd test`() {
        val groupId = SecureHash.secureHash("1234")
        val aliceKey = generateNACLKeyPair()
        val aliceDhKey = generateNACLDHKeyPair()
        val now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.MILLIS)
        val groupCreate = GroupCreate.createGroupCreate(
            groupId,
            "Group1",
            mapOf("group data" to "Hello"),
            "Alice",
            aliceKey.public,
            aliceDhKey.public,
            SecureHash.secureHash("Alice address"),
            mapOf("alice info" to "1"),
            now
        ) { k, v ->
            assertEquals(aliceKey.public.id, k)
            aliceKey.sign(v)
        }
        val groupInfo = GroupInfo.EmptyGroup.applyGroupChange(groupCreate)
        val bobKey = generateNACLKeyPair()
        val bobDhKey = generateNACLDHKeyPair()
        val groupAdd = GroupMemberAdd.createMemberAdd(
            groupInfo,
            "Bob",
            bobKey.public,
            bobDhKey.public,
            SecureHash.secureHash("Bob address"),
            groupInfo.findMemberByName("Alice")!!.memberKeyId,
            now.plusSeconds(1L),
            GroupMemberRole.ORDINARY,
            mapOf("Bob info" to "2")
        ) { k, v ->
            assertEquals(k, aliceKey.public.id)
            aliceKey.sign(v)
        }
        val serialized = groupAdd.serialize()
        val deserialized = GroupMemberAdd.deserialize(serialized)
        assertEquals(groupAdd, deserialized)
        val change = GroupBlockPayload(groupAdd)
        val serializedChange = change.serialize()
        val deserializedChange = GroupBlockPayload.deserialize(serializedChange)
        assertEquals(change, deserializedChange)
        val groupInfo2 = groupInfo.applyGroupChange(groupAdd)
        assertEquals("Bob", groupInfo2.findMemberById(bobKey.public.id)!!.memberName)
    }

    @Test
    fun `GroupMemberRemove test`() {
        val groupId = SecureHash.secureHash("1234")
        val aliceKey = generateNACLKeyPair()
        val aliceKeyId = aliceKey.public.id
        val aliceDhKey = generateNACLDHKeyPair()
        val now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.MILLIS)
        val groupCreate = GroupCreate.createGroupCreate(
            groupId,
            "Group1",
            mapOf("group data" to "Hello"),
            "Alice",
            aliceKey.public,
            aliceDhKey.public,
            SecureHash.secureHash("Alice address"),
            mapOf("alice info" to "1"),
            now
        ) { k, v ->
            assertEquals(aliceKey.public.id, k)
            aliceKey.sign(v)
        }
        val groupInfo = GroupInfo.EmptyGroup.applyGroupChange(groupCreate)
        val bobKey = generateNACLKeyPair()
        val bobDhKey = generateNACLDHKeyPair()
        val groupAdd = GroupMemberAdd.createMemberAdd(
            groupInfo,
            "Bob",
            bobKey.public,
            bobDhKey.public,
            SecureHash.secureHash("Bob address"),
            groupInfo.findMemberByName("Alice")!!.memberKeyId,
            now.plusSeconds(1L),
            GroupMemberRole.ORDINARY,
            mapOf("Bob info" to "2")
        ) { k, v ->
            assertEquals(k, aliceKeyId)
            aliceKey.sign(v)
        }
        val groupInfo2 = groupInfo.applyGroupChange(groupAdd)
        val aliceNewDhKey = generateNACLDHKeyPair()
        val groupRemove = GroupMemberRemove.createRemoveRequest(
            groupInfo2,
            groupInfo2.findMemberByName("Bob")!!.memberKeyId,
            groupInfo2.admins.first().memberKeyId,
            aliceNewDhKey.public
        ) { k, v ->
            assertEquals(k, aliceKeyId)
            aliceKey.sign(v)
        }
        val serialized = groupRemove.serialize()
        val deserialized = GroupMemberRemove.deserialize(serialized)
        assertEquals(groupRemove, deserialized)
        val change = GroupBlockPayload(groupRemove)
        val serializedChange = change.serialize()
        val deserializedChange = GroupBlockPayload.deserialize(serializedChange)
        assertEquals(change, deserializedChange)
        val groupInfo3 = groupInfo2.applyGroupChange(groupRemove)
        assertEquals(1, groupInfo3.members.size)
    }

    @Test
    fun `GroupMemberAdminChange test`() {
        val groupId = SecureHash.secureHash("1234")
        val aliceKey = generateNACLKeyPair()
        val aliceDhKey = generateNACLDHKeyPair()
        val now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.MILLIS)
        val groupCreate = GroupCreate.createGroupCreate(
            groupId,
            "Group1",
            mapOf("group data" to "Hello"),
            "Alice",
            aliceKey.public,
            aliceDhKey.public,
            SecureHash.secureHash("Alice address"),
            mapOf("alice info" to "1"),
            now
        ) { k, v ->
            assertEquals(aliceKey.public.id, k)
            aliceKey.sign(v)
        }
        val groupInfo = GroupInfo.EmptyGroup.applyGroupChange(groupCreate)
        val bobKey = generateNACLKeyPair()
        val bobDhKey = generateNACLDHKeyPair()
        val groupAdd = GroupMemberAdd.createMemberAdd(
            groupInfo,
            "Bob",
            bobKey.public,
            bobDhKey.public,
            SecureHash.secureHash("Bob address"),
            groupInfo.findMemberByName("Alice")!!.memberKeyId,
            now.plusSeconds(1L),
            GroupMemberRole.ORDINARY,
            mapOf("Bob info" to "2")
        ) { k, v ->
            assertEquals(k, aliceKey.public.id)
            aliceKey.sign(v)
        }
        val groupInfo2 = groupInfo.applyGroupChange(groupAdd)
        val newExtraInfo = mapOf("new info" to "2")
        val groupAdminChange = GroupMemberAdminChange.createGroupMemberAdminChange(
            groupInfo2,
            bobKey.public.id,
            GroupMemberRole.ADMIN,
            newExtraInfo,
            aliceKey.public.id
        ) { k, v ->
            assertEquals(k, aliceKey.public.id)
            aliceKey.sign(v)
        }
        val serialized = groupAdminChange.serialize()
        val deserialized = GroupMemberAdminChange.deserialize(serialized)
        assertEquals(groupAdminChange, deserialized)
        val change = GroupBlockPayload(groupAdminChange)
        val serializedChange = change.serialize()
        val deserializedChange = GroupBlockPayload.deserialize(serializedChange)
        assertEquals(change, deserializedChange)
        val groupInfo3 = groupInfo2.applyGroupChange(deserialized)
        assertEquals(newExtraInfo, groupInfo3.findMemberByName("Bob")!!.otherInfo)
        assertEquals(GroupMemberRole.ADMIN, groupInfo3.findMemberByName("Bob")!!.role)
    }

    @Test
    fun `GroupModify test`() {
        val groupId = SecureHash.secureHash("1234")
        val aliceKey = generateNACLKeyPair()
        val aliceKeyId = aliceKey.public.id
        val aliceDhKey = generateNACLDHKeyPair()
        val now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.MILLIS)
        val groupCreate = GroupCreate.createGroupCreate(
            groupId,
            "Group1",
            mapOf("group data" to "Hello"),
            "Alice",
            aliceKey.public,
            aliceDhKey.public,
            SecureHash.secureHash("Alice address"),
            mapOf("alice info" to "1"),
            now
        ) { k, v ->
            assertEquals(aliceKey.public.id, k)
            aliceKey.sign(v)
        }
        val groupInfo = GroupInfo.EmptyGroup.applyGroupChange(groupCreate)
        val newExtraInfo = mapOf("Info2" to "2")
        val groupModify = GroupModify.createModify(
            newExtraInfo,
            aliceKeyId
        ) { k, v ->
            assertEquals(k, aliceKeyId)
            aliceKey.sign(v)
        }
        val serialized = groupModify.serialize()
        val deserialized = GroupModify.deserialize(serialized)
        assertEquals(groupModify, deserialized)
        val change = GroupBlockPayload(groupModify)
        val serializedChange = change.serialize()
        val deserializedChange = GroupBlockPayload.deserialize(serializedChange)
        assertEquals(change, deserializedChange)
        val groupInfo2 = groupInfo.applyGroupChange(deserialized)
        assertEquals(newExtraInfo, groupInfo2.groupInfo)
    }

    @Test
    fun `GroupMemberSetAddress test`() {
        val groupId = SecureHash.secureHash("1234")
        val aliceKey = generateNACLKeyPair()
        val aliceKeyId = aliceKey.public.id
        val aliceDhKey = generateNACLDHKeyPair()
        val now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.MILLIS)
        val groupCreate = GroupCreate.createGroupCreate(
            groupId,
            "Group1",
            mapOf("group data" to "Hello"),
            "Alice",
            aliceKey.public,
            aliceDhKey.public,
            SecureHash.secureHash("Alice address"),
            mapOf("alice info" to "1"),
            now
        ) { k, v ->
            assertEquals(aliceKey.public.id, k)
            aliceKey.sign(v)
        }
        val groupInfo = GroupInfo.EmptyGroup.applyGroupChange(groupCreate)
        val newAddress = SecureHash.secureHash("new address")
        val groupMemberSetAddress = GroupMemberAddressChange.createGroupMemberAddressChange(
            groupInfo,
            aliceKeyId,
            newAddress
        ) { k, v ->
            assertEquals(aliceKey.public.id, k)
            aliceKey.sign(v)
        }
        val serialized = groupMemberSetAddress.serialize()
        val deserialized = GroupMemberAddressChange.deserialize(serialized)
        assertEquals(groupMemberSetAddress, deserialized)
        val change = GroupBlockPayload(groupMemberSetAddress)
        val serializedChange = change.serialize()
        val deserializedChange = GroupBlockPayload.deserialize(serializedChange)
        assertEquals(change, deserializedChange)
        val groupInfo2 = groupInfo.applyGroupChange(deserialized)
        assertEquals(newAddress, groupInfo2.findMemberByName("Alice")!!.routingAddress)
    }

    @Test
    fun `GroupMemberRotateKeys test`() {
        val groupId = SecureHash.secureHash("1234")
        val aliceKey = generateNACLKeyPair()
        val aliceKeyId = aliceKey.public.id
        val aliceDhKey = generateNACLDHKeyPair()
        val now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.MILLIS)
        val groupCreate = GroupCreate.createGroupCreate(
            groupId,
            "Group1",
            mapOf("group data" to "Hello"),
            "Alice",
            aliceKey.public,
            aliceDhKey.public,
            SecureHash.secureHash("Alice address"),
            mapOf("alice info" to "1"),
            now
        ) { k, v ->
            assertEquals(aliceKey.public.id, k)
            aliceKey.sign(v)
        }
        val groupInfo = GroupInfo.EmptyGroup.applyGroupChange(groupCreate)
        val newDhKey = generateNACLDHKeyPair()
        val groupMemberRotate1 = GroupMemberKeyRotate.createGroupMemberKeyRotate(
            groupInfo,
            aliceKeyId,
            false,
            newDhKey.public,
            Clock.systemUTC().instant()
        ) { k, v ->
            assertEquals(aliceKey.public.id, k)
            aliceKey.sign(v)
        }
        val serialized = groupMemberRotate1.serialize()
        val deserialized = GroupMemberKeyRotate.deserialize(serialized)
        assertEquals(groupMemberRotate1, deserialized)
        val change = GroupBlockPayload(groupMemberRotate1)
        val serializedChange = change.serialize()
        val deserializedChange = GroupBlockPayload.deserialize(serializedChange)
        assertEquals(change, deserializedChange)
        val groupInfo2 = groupInfo.applyGroupChange(deserialized)
        assertEquals(newDhKey.public, groupInfo2.findMemberByName("Alice")!!.groupDhKey)
        val newKey = generateNACLKeyPair()
        val groupMemberRotate2 = GroupMemberKeyRotate.createGroupMemberKeyRotate(
            groupInfo2,
            aliceKeyId,
            true,
            newKey.public,
            Clock.systemUTC().instant()
        ) { k, v ->
            if (k == aliceKeyId) {
                aliceKey.sign(v)
            } else if (k == newKey.public.id) {
                newKey.sign(v)
            } else throw IllegalArgumentException("Incorrect key")
        }
        val serialized2 = groupMemberRotate2.serialize()
        val deserialized2 = GroupMemberKeyRotate.deserialize(serialized2)
        assertEquals(groupMemberRotate2, deserialized2)
        val change2 = GroupBlockPayload(groupMemberRotate2)
        val serializedChange2 = change2.serialize()
        val deserializedChange2 = GroupBlockPayload.deserialize(serializedChange2)
        assertEquals(change2, deserializedChange2)
        val groupInfo3 = groupInfo2.applyGroupChange(deserialized2)
        assertEquals(newKey.public, groupInfo3.findMemberByName("Alice")!!.memberKey)
        assertEquals(1, groupInfo3.findMemberByName("Alice")!!.historicKeys.count { it.key == aliceKey.public })
    }

    @Test
    fun `GroupMerge serialization test`() {
        val aliceKey = generateNACLKeyPair()
        val aliceKeyId = aliceKey.public.id
        val groupMerge = GroupMerge.createGroupMerge(
            setOf(
                SecureHash.secureHash("1"),
                SecureHash.secureHash("2")
            ),
            aliceKeyId
        ) { k, v ->
            assertEquals(k, aliceKeyId)
            aliceKey.sign(v)
        }
        val serialized = groupMerge.serialize()
        val deserialized = GroupMerge.deserialize(serialized)
        assertEquals(groupMerge, deserialized)
        val change = GroupBlockPayload(groupMerge)
        val serializedChange = change.serialize()
        val deserializedChange = GroupBlockPayload.deserialize(serializedChange)
        assertEquals(change, deserializedChange)
    }

    @Test
    fun `GroupManager test`() {
        val network = mutableMapOf<SecureHash, GroupManager>()
        val aliceAddress = SecureHash.secureHash("Addr1")
        val groupManagerAlice: GroupManager = GroupManagerImpl.createGroup(
            "Group 1",
            mapOf("Group info" to "A"),
            "Alice",
            aliceAddress,
            mapOf("Member Info" to "1"),
            Clock.systemUTC().instant()
        )
        network[aliceAddress] = groupManagerAlice
        val aliceInfo = groupManagerAlice.groupInfo.findMemberByName("Alice")!!
        val bobKeyManager = InMemoryGroupKeyService()
        val bobKey = bobKeyManager.generateSigningKey()
        val bobDhKey = bobKeyManager.generateDhKey()
        val bobAddress = SecureHash.secureHash("Addr2")
        val bobDetails = InitialMemberDetails(
            "Bob",
            bobKeyManager.getSigningKey(bobKey),
            bobKeyManager.getDhKey(bobDhKey),
            bobAddress
        )
        val groupManagerBob: GroupManager = GroupManagerImpl.joinGroup(
            bobKeyManager,
            bobDetails,
            aliceInfo.memberKey,
            aliceInfo.routingAddress
        )
        network[bobAddress] = groupManagerBob
        groupManagerAlice.addMember(
            bobDetails,
            GroupMemberRole.ORDINARY,
            mapOf("Member Info" to "2"),
            Clock.systemUTC().instant()
        )
        for (round in 0 until 5) {
            for (node in network.values) {
                val (target, message) = node.groupMessageToSend()!!
                val targetNode = network[target]
                println("${node.self}->${targetNode?.self} ${message.heads.size} ${message.blocks.size}")
                targetNode?.processGroupMessage(message)
            }
        }
        val charlesKeyManager = InMemoryGroupKeyService()
        val charlesKey = charlesKeyManager.generateSigningKey()
        val charlesDhKey = charlesKeyManager.generateDhKey()
        val charlesAddress = SecureHash.secureHash("Addr3")
        val charlesDetails = InitialMemberDetails(
            "Charles",
            charlesKeyManager.getSigningKey(charlesKey),
            charlesKeyManager.getDhKey(charlesDhKey),
            charlesAddress
        )
        val groupManagerCharles: GroupManager = GroupManagerImpl.joinGroup(
            charlesKeyManager,
            charlesDetails,
            aliceInfo.memberKey,
            aliceInfo.routingAddress
        )
        network[charlesAddress] = groupManagerCharles
        groupManagerAlice.addMember(
            charlesDetails,
            GroupMemberRole.ORDINARY,
            mapOf("Member Info" to "3"),
            Clock.systemUTC().instant()
        )
        for (round in 0 until 5) {
            for (node in network.values) {
                val (target, message) = node.groupMessageToSend()!!
                val targetNode = network[target]
                println("${node.self}->${targetNode?.self} ${message.heads.size} ${message.blocks.size}")
                targetNode?.processGroupMessage(message)
            }
        }
        for (manager in network.values) {
            assertEquals(3, manager.groupInfo.members.size)
            assertEquals(groupManagerAlice.groupInfo, manager.groupInfo)
        }
    }

    enum class ActionType {
        NoOp,
        AddMember,
        ModifyGroupInfo,
        RemoveMember,
        FlipMemberRole,
        ModifyMemberInfo,
        RotateKey,
        RotateDhKey,
        ChangeAddress
    }

    private data class GroupAction(
        val sponsorName: String,
        val memberName: String,
        val action: ActionType,
        val parallelChange: Boolean = false,
        val expectThrows: Boolean = false
    )

    private fun groupActionRunner(actions: List<GroupAction>): Map<String, GroupInfo> {
        val network = mutableMapOf<SecureHash, GroupManager>()
        var addrCounter = 0
        var memberCounter = 0
        val keyManager = InMemoryGroupKeyService()
        val initialAddress = SecureHash.secureHash("Addr${++addrCounter}")
        val groupManager1: GroupManager = GroupManagerImpl.createGroup(
            "Group 1",
            mapOf("Group info" to "A"),
            "member$memberCounter",
            initialAddress,
            mapOf("Member Info" to "${++memberCounter}"),
            Clock.systemUTC().instant()
        )
        network[initialAddress] = groupManager1
        for (action in actions) {
            val sponsor = network.values.first { it.self == action.sponsorName }
            val sponsorInfo = sponsor.groupInfo.findMemberByName(action.sponsorName)!!
            try {
                when (action.action) {
                    ActionType.NoOp -> {
                        // do nothing
                    }
                    ActionType.AddMember -> {
                        val addMemberName = "member$memberCounter"
                        assertEquals(action.memberName, addMemberName)
                        val addKey = keyManager.generateSigningKey()
                        val addDhKey = keyManager.generateDhKey()
                        val addAddress = SecureHash.secureHash("Addr${++addrCounter}")
                        val addDetails = InitialMemberDetails(
                            addMemberName,
                            keyManager.getSigningKey(addKey),
                            keyManager.getDhKey(addDhKey),
                            addAddress
                        )
                        sponsor.addMember(
                            addDetails,
                            GroupMemberRole.ORDINARY,
                            mapOf("Member Info" to "${++memberCounter}"),
                            Clock.systemUTC().instant()
                        )
                        val newGroupManager: GroupManager = GroupManagerImpl.joinGroup(
                            keyManager,
                            addDetails,
                            sponsorInfo.memberKey,
                            sponsorInfo.routingAddress
                        )
                        network[addAddress] = newGroupManager
                    }
                    ActionType.RemoveMember -> {
                        val deleteTarget = sponsor.groupInfo.members.single { it.memberName == action.memberName }
                        sponsor.deleteMember(deleteTarget.memberKeyId)
                    }
                    ActionType.ModifyGroupInfo -> {
                        sponsor.changeGroupInfo(mapOf("Group info" to "${++memberCounter}"))
                    }
                    ActionType.FlipMemberRole -> {
                        val changeTarget = sponsor.groupInfo.members.single { it.memberName == action.memberName }
                        val newRole =
                            if (changeTarget.role == GroupMemberRole.ADMIN) GroupMemberRole.ORDINARY else GroupMemberRole.ADMIN
                        sponsor.changeMemberRole(changeTarget.memberKeyId, newRole)
                    }
                    ActionType.ModifyMemberInfo -> {
                        val changeTarget = sponsor.groupInfo.members.single { it.memberName == action.memberName }
                        sponsor.changeMemberInfo(changeTarget.memberKeyId, mapOf("Member Info" to "${++memberCounter}"))
                    }
                    ActionType.RotateDhKey -> {
                        assertEquals(action.sponsorName, action.memberName)
                        sponsor.rotateDhKey()
                    }
                    ActionType.RotateKey -> {
                        assertEquals(action.sponsorName, action.memberName)
                        sponsor.rotateKey(Clock.systemUTC().instant())
                    }
                    ActionType.ChangeAddress -> {
                        assertEquals(action.sponsorName, action.memberName)
                        val newAddress = SecureHash.secureHash("Addr${++addrCounter}")
                        network.remove(sponsorInfo.routingAddress)
                        sponsor.setNewAddress(newAddress)
                        network[newAddress] = sponsor
                    }
                }
            } catch (ex: Exception) {
                if (action.expectThrows) {
                    println("As expected failed with: ${ex.message}")
                } else {
                    throw ex
                }
            }
            if (!action.parallelChange) {
                for (i in 0 until 5) {
                    for (node in network.values) {
                        val targetAndMessage = node.groupMessageToSend()
                        if (targetAndMessage != null) {
                            val targetNode = network[targetAndMessage.first]
                            println("${node.self}->${targetNode?.self} ${targetAndMessage.second.heads.size} ${targetAndMessage.second.blocks.size}")
                            targetNode?.processGroupMessage(targetAndMessage.second)
                        }
                    }
                }
            }
        }
        for (i in 0 until 5) {
            for (node in network.values) {
                val targetAndMessage = node.groupMessageToSend()
                if (targetAndMessage != null) {
                    val targetNode = network[targetAndMessage.first]
                    println("${node.self}->${targetNode?.self} ${targetAndMessage.second.heads.size} ${targetAndMessage.second.blocks.size}")
                    targetNode?.processGroupMessage(targetAndMessage.second)
                }
            }
        }
        return network.values.associate { Pair(it.self, it.groupInfo) }
    }

    @Test
    fun `GroupManager add and remove`() {
        val actionList = listOf(
            GroupAction("member0", "member1", ActionType.AddMember),
            GroupAction("member0", "member2", ActionType.AddMember),
            GroupAction("member0", "member1", ActionType.RemoveMember),
        )
        val results = groupActionRunner(actionList)
        assertEquals(3, results.size)
        assertEquals(results["member0"], results["member2"])
        assertNotEquals(results["member0"], results["member1"])
    }

    @Test
    fun `GroupManager add and remove many`() {
        val actionList = listOf(
            GroupAction("member0", "member1", ActionType.AddMember),
            GroupAction("member0", "member2", ActionType.AddMember),
            GroupAction("member0", "member3", ActionType.AddMember),
            GroupAction("member0", "member4", ActionType.AddMember),
            GroupAction("member0", "member1", ActionType.RemoveMember),
            GroupAction("member0", "member5", ActionType.AddMember),
            GroupAction("member0", "member2", ActionType.RemoveMember),
        )
        val results = groupActionRunner(actionList)
        assertEquals(6, results.size)
        assertEquals(results["member0"], results["member3"])
        assertEquals(results["member0"], results["member4"])
        assertEquals(results["member0"], results["member5"])
        assertNotEquals(results["member0"], results["member1"])
        assertNotEquals(results["member0"], results["member2"])
    }

    @Test
    fun `GroupManager add from two admins`() {
        val actionList = listOf(
            GroupAction("member0", "member1", ActionType.AddMember),
            GroupAction("member0", "member2", ActionType.AddMember),
            GroupAction("member0", "member2", ActionType.FlipMemberRole),
            GroupAction("member2", "member3", ActionType.AddMember),
        )
        val results = groupActionRunner(actionList)
        assertEquals(4, results.size)
        assertEquals(results["member0"], results["member1"])
        assertEquals(results["member0"], results["member2"])
        assertEquals(results["member0"], results["member3"])
    }

    @Test
    fun `GroupManager add and remove with causal child`() {
        val actionList = listOf(
            GroupAction("member0", "member1", ActionType.AddMember),
            GroupAction("member0", "member2", ActionType.AddMember),
            GroupAction("member0", "member2", ActionType.FlipMemberRole),
            GroupAction("member2", "member3", ActionType.AddMember),
            GroupAction("member0", "member2", ActionType.RemoveMember),
        )
        val results = groupActionRunner(actionList)
        assertEquals(4, results.size)
        assertEquals(results["member0"], results["member1"])
        assertNotEquals(results["member0"], results["member2"])
        assertEquals(results["member0"], results["member3"])
    }

    @Test
    fun `GroupManager add and remove with clashing child`() {
        val actionList = listOf(
            GroupAction("member0", "member1", ActionType.AddMember),
            GroupAction("member0", "member2", ActionType.AddMember),
            GroupAction("member0", "member2", ActionType.FlipMemberRole),
            GroupAction("member2", "member3", ActionType.AddMember, parallelChange = true),
            GroupAction("member0", "member2", ActionType.RemoveMember, parallelChange = true),
            GroupAction("member0", "member0", ActionType.ModifyGroupInfo)
        )
        val results = groupActionRunner(actionList)
        assertEquals(4, results.size)
        assertEquals(results["member0"], results["member1"])
        assertNotEquals(results["member0"], results["member2"])
        assertNotEquals(results["member0"], results["member3"])
    }

    @Test
    fun `GroupManager key rotate`() {
        val actionList = listOf(
            GroupAction("member0", "member1", ActionType.AddMember),
            GroupAction("member0", "member0", ActionType.RotateKey),
            GroupAction("member1", "member1", ActionType.RotateKey),
        )
        val results = groupActionRunner(actionList)
        assertEquals(2, results.size)
        assertEquals(results["member0"], results["member1"])
    }

    @Test
    fun `GroupManager key rotate 2`() {
        val actionList = listOf(
            GroupAction("member0", "member1", ActionType.AddMember),
            GroupAction("member0", "member0", ActionType.RotateKey),
            GroupAction("member0", "member2", ActionType.AddMember),
            GroupAction("member1", "member1", ActionType.RotateKey),
        )
        val results = groupActionRunner(actionList)
        assertEquals(3, results.size)
        assertEquals(results["member0"], results["member1"])
        assertEquals(results["member0"], results["member2"])
    }

    @Test
    fun `GroupManager DhKey rotate`() {
        val actionList = listOf(
            GroupAction("member0", "member1", ActionType.AddMember),
            GroupAction("member0", "member0", ActionType.RotateDhKey),
            GroupAction("member0", "member2", ActionType.AddMember),
            GroupAction("member1", "member1", ActionType.RotateDhKey),
        )
        val results = groupActionRunner(actionList)
        assertEquals(3, results.size)
        assertEquals(results["member0"], results["member1"])
        assertEquals(results["member0"], results["member2"])
    }

    @Test
    fun `GroupManager address changes`() {
        val actionList = listOf(
            GroupAction("member0", "member1", ActionType.AddMember),
            GroupAction("member0", "member2", ActionType.AddMember),
            GroupAction("member0", "member0", ActionType.ChangeAddress),
            GroupAction("member0", "member3", ActionType.AddMember),
            GroupAction("member2", "member2", ActionType.ChangeAddress),
        )
        val results = groupActionRunner(actionList)
        assertEquals(4, results.size)
        assertEquals(results["member0"], results["member1"])
        assertEquals(results["member0"], results["member2"])
        assertEquals(results["member0"], results["member3"])
    }

    @Test
    fun `GroupManager info changes`() {
        val actionList = listOf(
            GroupAction("member0", "member1", ActionType.AddMember),
            GroupAction("member0", "member2", ActionType.AddMember),
            GroupAction("member0", "member0", ActionType.ModifyGroupInfo),
            GroupAction("member0", "member1", ActionType.ModifyMemberInfo),
        )
        val results = groupActionRunner(actionList)
        assertEquals(3, results.size)
        assertEquals(results["member0"], results["member1"])
        assertEquals(results["member0"], results["member2"])
        assertEquals("4", results["member0"]!!.groupInfo["Group info"])
        assertEquals("5", results["member0"]!!.findMemberByName("member1")!!.otherInfo["Member Info"])
    }

    @Test
    fun `GroupManager no escalation`() {
        val actionList = listOf(
            GroupAction("member0", "member1", ActionType.AddMember),
            GroupAction("member0", "member2", ActionType.AddMember),
            GroupAction("member0", "member2", ActionType.FlipMemberRole),
            GroupAction("member2", "member1", ActionType.FlipMemberRole),
            GroupAction("member1", "member3", ActionType.AddMember),
            GroupAction("member1", "member0", ActionType.FlipMemberRole, expectThrows = true),
            GroupAction("member1", "member2", ActionType.FlipMemberRole, expectThrows = true),
            GroupAction("member2", "member1", ActionType.FlipMemberRole),
            GroupAction("member2", "member1", ActionType.FlipMemberRole),
            GroupAction("member2", "member0", ActionType.FlipMemberRole, expectThrows = true),
            GroupAction("member2", "member2", ActionType.FlipMemberRole),
            GroupAction("member2", "member2", ActionType.FlipMemberRole, expectThrows = true),
        )
        val results = groupActionRunner(actionList)
        assertEquals(4, results.size)
        assertEquals(results["member0"], results["member1"])
        assertEquals(results["member0"], results["member2"])
        assertEquals(results["member0"], results["member3"])
        assertEquals(GroupMemberRole.ADMIN, results["member0"]!!.findMemberByName("member0")!!.role)
        assertEquals(GroupMemberRole.ADMIN, results["member0"]!!.findMemberByName("member1")!!.role)
        assertEquals(GroupMemberRole.ORDINARY, results["member0"]!!.findMemberByName("member2")!!.role)
        assertEquals(GroupMemberRole.ORDINARY, results["member0"]!!.findMemberByName("member3")!!.role)
    }
}