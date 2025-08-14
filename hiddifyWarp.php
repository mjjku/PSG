<?php

declare(strict_types=1);

/**
 * This script generates a Cloudflare WARP profile with randomized endpoints
 * for use in compatible client applications.
 */

// --- Setup ---
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

// --- Configuration Constants ---
// By using constants, the configuration is clean, clear, and separate from the logic.
const OUTPUT_FILE = __DIR__ . '/subscriptions/warp/config';

const IP_RANGES = [
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
];

const PORTS = [
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 384, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
];

const ICON_GREEN = '🟢';
const ICON_BLUE = '🔵';

// #############################################################################
// Helper Functions
// #############################################################################

/**
 * Generates a random IP address from a given /24 subnet.
 *
 * @param string $subnet (e.g., "162.159.192.0/24")
 * @return string A random IP within that subnet.
 */
function generateRandomIpFromSubnet(string $subnet): string
{
    // Get the base of the IP (e.g., "162.159.192.")
    $ipBase = substr($subnet, 0, strrpos($subnet, '.') + 1);
    
    // **Security**: Use cryptographically secure random number generator.
    $randomOctet = random_int(1, 254); // 0 and 255 are often reserved
    
    return $ipBase . $randomOctet;
}

/**
 * Generates a standard profile header.
 *
 * @param string $profileName The title of the profile.
 * @return string The formatted header.
 */
function generateProfileHeader(string $profileName): string
{
    $base64Name = base64_encode($profileName);
    // Using a HEREDOC is much cleaner for multi-line strings.
    return <<<HEADER
#profile-title: base64:{$base64Name}
#profile-update-interval: 1
#subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
#support-url: https://t.me/yebekhe
#profile-web-page-url: https://github.com/yasi-python/PSG

HEADER;
}

// #############################################################################
// Main Script Logic
// #############################################################################

echo "Generating new WARP configuration..." . PHP_EOL;

// 1. Select Random Components
// **Readability & Robustness**: No more magic numbers. This works even if you change the size of the arrays.
$randomRangeKeys = array_rand(IP_RANGES, 2);
$chosenSubnet1 = IP_RANGES[$randomRangeKeys[0]];
$chosenSubnet2 = IP_RANGES[$randomRangeKeys[1]];

$chosenIp1 = generateRandomIpFromSubnet($chosenSubnet1);
$chosenIp2 = generateRandomIpFromSubnet($chosenSubnet2);
$chosenPort = PORTS[array_rand(PORTS)];

// 2. Build the Configuration Links
// **Readability**: Using sprintf makes the structure of the final string much clearer than concatenation.
$linkTemplate = 'warp://%s:%d?ifp=5-10#WiW-%s&&detour=warp://%s:%d?ifp=5-10#WARP-%s';

$profileConfigs = [
    sprintf($linkTemplate, $chosenIp1, $chosenPort, ICON_GREEN, $chosenIp2, $chosenPort, ICON_GREEN),
    sprintf($linkTemplate, $chosenIp2, $chosenPort, ICON_BLUE, $chosenIp1, $chosenPort, ICON_BLUE),
];

// 3. Assemble the Final Profile
$profileHeader = generateProfileHeader("PSG | WARP");
$profileOutput = $profileHeader . implode("\n", $profileConfigs);

// 4. Write to File
// **Robustness**: Ensure the output directory exists before trying to write to it.
$outputDirectory = dirname(OUTPUT_FILE);
if (!is_dir($outputDirectory)) {
    mkdir($outputDirectory, 0775, true);
    echo "Created missing directory: {$outputDirectory}" . PHP_EOL;
}

file_put_contents(OUTPUT_FILE, $profileOutput);

echo "WARP configuration created successfully at: " . OUTPUT_FILE . PHP_EOL;
