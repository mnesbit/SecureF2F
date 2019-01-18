package uk.co.nesbit.network.api

interface Message

data class RoutedMessage(val path: List<Address>, val payload: Message) : Message
