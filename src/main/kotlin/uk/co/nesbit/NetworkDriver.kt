package uk.co.nesbit

import com.typesafe.config.ConfigFactory
import picocli.CommandLine
import uk.co.nesbit.simpleactor.ActorSystem
import java.util.concurrent.Callable
import java.util.concurrent.Semaphore

@CommandLine.Command(
    name = "",
    sortOptions = false,
    showDefaultValues = true,
    mixinStandardHelpOptions = true,
    version = ["v1.0"]
)
class NetworkDriver : Callable<Int> {
    @CommandLine.Option(
        names = ["-n", "--size"],
        description = ["Set network initial size"],
        defaultValue = "1000"
    )
    var networkSize: Int = 0

    @CommandLine.Option(
        names = ["-t", "--transport"],
        description = [
            "Set the peer-to-peer transport substrate.",
            "Valid values: \${COMPLETION-CANDIDATES}",
        ],
        defaultValue = "Memory"
    )
    lateinit var transportMode: TransportMode

    @CommandLine.Option(
        names = ["-g", "--generator"],
        description = [
            "Set the graph generation algorithm.",
            "Valid values: \${COMPLETION-CANDIDATES}",
            "MinimumDegree - Nodes are added sequentially with minDegree edges to uniform random previous nodes",
            "BarabasiAlbert - Nodes are linked according to the Barabási-Albert scale free model",
            "Linear - Nodes are added in a line, mostly for testing code",
            "ASNetwork - Nodes are mapped as per the AS internet core on January 02 2000 taken from https://snap.stanford.edu/data/as-733.html"
        ],
        defaultValue = "MinimumDegree"
    )
    lateinit var networkGenerator: NetworkGenerator

    @CommandLine.Option(
        names = ["-d", "--degree"],
        description = ["minimum node degree"],
        defaultValue = "3"
    )
    var minDegree: Int = 3

    class DHTOptions {
        @CommandLine.Option(
            names = ["--dht"],
            description = ["run experiment on DHT storage and retrieval"],
            required = true
        )
        var runDHT = false

        @CommandLine.Option(
            names = ["-p", "--dhtPasses"],
            description = ["poll DHT until <dhtPasses> consecutive successes"],
            required = false,
            defaultValue = "10"
        )
        var dhtPasses: Int = 10
    }

    @CommandLine.ArgGroup(exclusive = false, multiplicity = "0..1", heading = "DHT experiments%n")
    var dhtGroup: DHTOptions? = null


    class StreamOptions {
        @CommandLine.Option(
            names = ["--stream"],
            description = ["run experiment to setup a stream between nodes and send messages"],
            required = true
        )
        var runStream = false

        @CommandLine.Option(
            names = ["-o", "--openAttempts"],
            description = ["Allow <openAttempts> attempts to open the stream route"],
            required = false,
            defaultValue = "10"
        )
        var openAttempts: Int = 10

        @CommandLine.Option(
            names = ["-m", "--messageCount"],
            description = ["Send <messageCount> messages down the stream before closing"],
            required = false,
            defaultValue = "2000"
        )
        var messages: Int = 2000
    }

    @CommandLine.ArgGroup(exclusive = false, multiplicity = "0..1", heading = "Stream Experiments%n")
    var streamGroup: StreamOptions? = null

    override fun call(): Int {
        println("Hello")
        println("Network Initial size $networkSize")
        println("Transport mode $transportMode")
        println("Network generator $networkGenerator")
        println("Minimum degree $minDegree")
        val networkGraph = TopologyBuilder.createNetwork(
            networkGenerator,
            minDegree,
            networkSize
        )
        val conf = ConfigFactory.load()
        val actorSystem = ActorSystem.create("f2f", conf)
        val simNetwork = TransportBuilder.createNetwork(transportMode, actorSystem, networkGraph)
        if (dhtGroup?.runDHT == true) {
            println("Run DHT experiment. Require ${dhtGroup?.dhtPasses} successive passes")
            Experiments.pollDht(simNetwork, actorSystem, dhtGroup!!.dhtPasses)
        }
        if (streamGroup?.runStream == true) {
            println("Run Stream experiment. Allow ${streamGroup?.openAttempts} open attempts and send ${streamGroup?.messages} messages")
            Experiments.createStream(simNetwork, actorSystem, streamGroup!!.openAttempts, streamGroup!!.messages)
        }
        if (!(dhtGroup != null || streamGroup != null)) {
            println("Run network until CTRL-C")
            val wait = Semaphore(0)
            Runtime.getRuntime().addShutdownHook(Thread {
                wait.release()
            })
            wait.acquire()
        }
        actorSystem.stop()
        println("bye")
        return 0
    }
}