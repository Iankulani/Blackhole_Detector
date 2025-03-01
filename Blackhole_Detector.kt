import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.regex.Pattern

// Function to ping the provided IP address
fun pingIp(ipAddress: String): Boolean {
    return try {
        // For Linux or macOS, use "-c" for count; for Windows use "-n"
        val command = if (System.getProperty("os.name").startsWith("Windows")) {
            arrayOf("ping", "-n", "1", ipAddress)
        } else {
            arrayOf("ping", "-c", "1", ipAddress)
        }

        // Execute the command
        val process = ProcessBuilder(*command).start()

        // Read the process output
        val reader = BufferedReader(InputStreamReader(process.inputStream))
        val output = reader.readText()
        val exitCode = process.waitFor()

        // Check if the exit code is 0 (ping success)
        exitCode == 0
    } catch (e: Exception) {
        println("Error pinging IP: ${e.message}")
        false
    }
}

// Function to check if the IP address is associated with a blackhole attack
fun checkBlackhole(ipAddress: String): Boolean {
    println("Checking IP address: $ipAddress")

    // Attempt to ping the IP address
    val reachable = pingIp(ipAddress)

    if (!reachable) {
        println("IP address $ipAddress is not reachable. This could indicate a blackhole attack or routing issues.")
        return true
    } else {
        println("IP address $ipAddress is reachable. No blackhole detected.")
        return false
    }
}

// Function to validate the format of the IP address
fun validateIp(ipAddress: String): Boolean {
    val pattern = Pattern.compile(
        "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
        "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
        "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
        "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    return pattern.matcher(ipAddress).matches()
}

fun main() {
    println("Welcome to the Blackhole Detection Tool.")
    println("This tool checks if an IP address may be associated with a Blackhole or Sinkhole attack.")

    while (true) {
        // Prompt user to input an IP address
        print("Enter the IP address to check (or 'exit' to quit): ")
        val ipAddress = readLine()?.trim()

        if (ipAddress.equals("exit", ignoreCase = true)) {
            println("Exiting the tool. Goodbye!")
            break
        }

        // Validate IP address format
        if (ipAddress != null && validateIp(ipAddress)) {
            println("Validating IP address: $ipAddress")
            if (checkBlackhole(ipAddress)) {
                println("Warning: IP address $ipAddress may be associated with a Blackhole attack!")
            } else {
                println("IP address $ipAddress is likely safe.")
            }
        } else {
            println("Invalid IP address format: $ipAddress. Please try again.")
        }
    }
}
