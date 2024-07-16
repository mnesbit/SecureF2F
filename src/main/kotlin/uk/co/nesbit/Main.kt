package uk.co.nesbit

import picocli.CommandLine
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    val commandLine = CommandLine(NetworkDriver())
    commandLine.setCaseInsensitiveEnumValuesAllowed(true)
    val exitCode = commandLine.execute(*args)
    exitProcess(exitCode)
}


