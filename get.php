<?php

declare(strict_types=1);

/**
 * Stage 2: Config Extractor (Refactored for Performance + Summary)
 * - Reads channel data and cached HTML from Stage 1.
 * - Extracts proxy configs from both cached HTML files AND the remote private_configs.json.
 * - Processes, enriches, and saves the final subscription files using a "Process Once, Use Many" strategy.
 * - Uses a persistent cache for IP geolocation to reduce network lookups.
 * - Removes channels from channelsAssets.json if they no longer provide valid configs.
 * - Generates a summary.json file with statistics about the run.
 */

// --- Setup ---
ini_set("display_errors", "1");
ini_set("display_startup_errors", "1");
error_reporting(E_ALL);

require "functions.php";

// --- Configuration Constants ---
const ASSETS_FILE = __DIR__ . "/channelsData/channelsAssets.json";
const HTML_CACHE_DIR = __DIR__ . "/channelsData/html_cache";
const OUTPUT_DIR = __DIR__ . "/subscriptions";
const LOCATION_DIR = OUTPUT_DIR . "/location";
const CHANNEL_SUBS_DIR = OUTPUT_DIR . "/channel";
const FINAL_CONFIG_FILE = __DIR__ . "/config.txt";
const IP_CACHE_FILE = __DIR__ . "/channelsData/ip_info_cache.json";
// SUMMARY: Define the path for the new summary file.
const SUMMARY_FILE = OUTPUT_DIR . "/summary.json";

// --- Limits for different outputs ---
const CONFIGS_FOR_MAIN_AGGREGATE = 15;
const CONFIGS_FOR_CHANNEL_SUBS = 40;

const PRIVATE_CONFIGS_URL = "https://raw.githubusercontent.com/yasi-python/PSGP/main/private_configs.json";

/**
 * Processes a single raw config string and enriches it with metadata.
 * @param string $config The raw config string.
 * @param string $source The source channel name.
 * @param int $key The original index of the config.
 * @param array &$ipInfoCache A reference to the IP information cache.
 * @return array|null The enriched config and its metadata, or null if invalid.
 */
function processAndEnrichConfig(
    string $config,
    string $source,
    int $key,
    array &$ipInfoCache
): ?array {
    static $configFields = [
        "vmess" => ["ip" => "add", "name" => "ps"],
        "vless" => ["ip" => "hostname", "name" => "hash"],
        "trojan" => ["ip" => "hostname", "name" => "hash"],
        "tuic" => ["ip" => "hostname", "name" => "hash"],
        "hy2" => ["ip" => "hostname", "name" => "hash"],
        "ss" => ["ip" => "server_address", "name" => "name"],
    ];

    $config = explode("<", $config, 2)[0];
    if (!is_valid($config)) {
        return null;
    }
    $type = detect_type($config);
    if ($type === null || !isset($configFields[$type])) {
        return null;
    }
    $decodedConfig = configParse($config);
    if ($decodedConfig === null) {
        return null;
    }
    if ($type === "ss" && (empty($decodedConfig["encryption_method"]) || empty($decodedConfig["password"]))) {
        return null;
    }

    $ipField = $configFields[$type]["ip"];
    $ipOrHost = $decodedConfig[$ipField] ?? null;
    if ($ipOrHost === null) {
        return null;
    }

    if (!isset($ipInfoCache[$ipOrHost])) {
        $info = ip_info($ipOrHost);
        $ipInfoCache[$ipOrHost] = $info ? $info->country : "XX";
    }
    $countryCode = $ipInfoCache[$ipOrHost];

    $flag = $countryCode === "XX" ? "❔" : ($countryCode === "CF" ? "🚩" : getFlags($countryCode));
    $securityEmoji = isEncrypted($config) ? '🔒' : '🔓';
    $newName = sprintf(
        '%s %s | %s %s | @%s [%d]',
        $flag, $countryCode, $securityEmoji, strtoupper($type), $source, $key + 1
    );
    $decodedConfig[$configFields[$type]["name"]] = $newName;
    $encodedConfig = reparseConfig($decodedConfig, $type);
    if ($encodedConfig === null) {
        return null;
    }
    $finalConfigString = str_replace("amp%3B", "", $encodedConfig);

    return [
        'config' => $finalConfigString,
        'country' => $countryCode,
        'source' => $source,
        // SUMMARY: Also return the protocol type for statistics.
        'type' => $type,
    ];
}

// --- 1. Load Source Data and Sanity Check ---
echo "--- STAGE 2: CONFIG EXTRACTOR ---" . PHP_EOL;
echo "1. Loading source list from assets file..." . PHP_EOL;

if (!file_exists(ASSETS_FILE)) {
    die("Error: channelsAssets.json not found. Please run the assets script first." . PHP_EOL);
}
if (!is_dir(HTML_CACHE_DIR)) {
    echo "Warning: HTML cache directory not found. Will only process subscription-based channels if any." . PHP_EOL;
}

$sourcesArray = json_decode(file_get_contents(ASSETS_FILE), true);
if (json_last_error() !== JSON_ERROR_NONE) {
    die("Error: Invalid JSON in assets file." . PHP_EOL);
}

// --- 2. Extract Configs from Cached HTML Files ---
echo "\n2. Extracting configs from local HTML cache..." . PHP_EOL;
$configsList = [];
$totalSources = count($sourcesArray);
$sourceCounter = 0;

foreach ($sourcesArray as $source => $sourceData) {
    print_progress(++$sourceCounter, $totalSources, "Extracting (HTML):");
    if (isset($sourceData["subscription_url"])) continue;
    $htmlFile = HTML_CACHE_DIR . "/" . $source . ".html";
    if (file_exists($htmlFile)) {
        $htmlContent = file_get_contents($htmlFile);
        if (!empty($htmlContent)) {
            $extractedLinks = extractLinksByType($htmlContent);
            if (!empty($extractedLinks)) {
                $configsList[$source] = array_values(array_unique($extractedLinks));
            }
        }
    }
}
echo PHP_EOL . "HTML extraction complete. Found configs from " . count($configsList) . " sources." . PHP_EOL;

// --- 2.5. Integrate configs from the remote private_configs.json file ---
echo "\n2.5. Integrating configs from private source..." . PHP_EOL;
$privateConfigsJson = @file_get_contents(PRIVATE_CONFIGS_URL);
if ($privateConfigsJson !== false) {
    $privateConfigsData = json_decode($privateConfigsJson, true);
    if (json_last_error() === JSON_ERROR_NONE) {
        echo "  - Successfully fetched private configs. Merging..." . PHP_EOL;
        foreach ($privateConfigsData as $source => $configs) {
            if (empty($configs) || !is_array($configs)) continue;
            if (isset($configsList[$source])) {
                $configsList[$source] = array_values(array_unique(array_merge($configsList[$source], $configs)));
            } else {
                $configsList[$source] = $configs;
            }
        }
    } else {
        echo "  - WARNING: The fetched private_configs.json is not valid JSON. Skipping." . PHP_EOL;
    }
} else {
    echo "  - WARNING: Could not fetch private_configs.json. Skipping this integration." . PHP_EOL;
}

// --- 3. Process All Configs Once and Store in a Master List ---
echo "\n3. Processing all found configs (max " . CONFIGS_FOR_CHANNEL_SUBS . " per source)..." . PHP_EOL;

$ipInfoCache = file_exists(IP_CACHE_FILE) ? json_decode(file_get_contents(IP_CACHE_FILE), true) : [];
$allProcessedConfigs = [];
$sourcesWithValidConfigs = [];

// SUMMARY: Initialize stats counters.
$stats = [
    'total_extracted_raw' => 0,
    'protocol_counts' => [],
];
foreach ($configsList as $configs) {
    $stats['total_extracted_raw'] += count($configs);
}

$totalConfigsToProcess = 0;
foreach ($configsList as $configs) {
    $totalConfigsToProcess += min(count($configs), CONFIGS_FOR_CHANNEL_SUBS);
}
$processedCount = 0;

foreach ($configsList as $source => $configs) {
    $configsToProcess = array_slice($configs, -CONFIGS_FOR_CHANNEL_SUBS);
    $key_offset = count($configs) - count($configsToProcess);

    foreach ($configsToProcess as $key => $config) {
        print_progress(++$processedCount, $totalConfigsToProcess, "Processing:");
        $processedData = processAndEnrichConfig($config, $source, $key + $key_offset, $ipInfoCache);

        if ($processedData !== null) {
            $allProcessedConfigs[] = $processedData;
            $sourcesWithValidConfigs[$source] = true;

            // SUMMARY: Tally the protocol counts.
            $protocol = $processedData['type'];
            $stats['protocol_counts'][$protocol] = ($stats['protocol_counts'][$protocol] ?? 0) + 1;
        }
    }
}
echo PHP_EOL . "Processing complete. Found " . count($allProcessedConfigs) . " valid configs in total." . PHP_EOL;

// --- 4. Write All Subscription Files from the Processed Master List ---
echo "\n4. Writing all subscription files..." . PHP_EOL;

if (is_dir(OUTPUT_DIR)) deleteFolder(OUTPUT_DIR);
mkdir(LOCATION_DIR . "/normal", 0775, true);
mkdir(LOCATION_DIR . "/base64", 0775, true);
mkdir(CHANNEL_SUBS_DIR . "/normal", 0775, true);
mkdir(CHANNEL_SUBS_DIR . "/base64", 0775, true);

$mainAggregateConfigs = [];
$locationBased = [];
$channelBased = [];

$groupedBySource = [];
foreach ($allProcessedConfigs as $procConf) {
    $groupedBySource[$procConf['source']][] = $procConf['config'];
}

foreach ($groupedBySource as $source => $s_configs) {
    $mainAggregateSlice = array_slice($s_configs, -CONFIGS_FOR_MAIN_AGGREGATE);
    $mainAggregateConfigs = array_merge($mainAggregateConfigs, $mainAggregateSlice);
    $channelBased[$source] = $s_configs;
}

foreach ($allProcessedConfigs as $procConf) {
    if (in_array($procConf['config'], $mainAggregateConfigs)) {
        $locationBased[$procConf['country']][] = $procConf['config'];
    }
}

echo "  - Writing main and location files..." . PHP_EOL;
file_put_contents(FINAL_CONFIG_FILE, implode(PHP_EOL, $mainAggregateConfigs));
foreach ($locationBased as $location => $configs) {
    if (empty(trim($location))) continue;
    $plainText = implode(PHP_EOL, $configs);
    file_put_contents(LOCATION_DIR . "/normal/" . $location, $plainText);
    file_put_contents(LOCATION_DIR . "/base64/" . $location, base64_encode($plainText));
}
echo "    Done." . PHP_EOL;

echo "  - Writing channel-specific files..." . PHP_EOL;
foreach ($channelBased as $source => $configs) {
    $plainText = implode(PHP_EOL, $configs);
    $fileName = preg_replace("/[^a-zA-Z0-9_-]/", "", $source);
    file_put_contents(CHANNEL_SUBS_DIR . "/normal/" . $fileName, $plainText);
    file_put_contents(CHANNEL_SUBS_DIR . "/base64/" . $fileName, base64_encode($plainText));
}
echo "    Done." . PHP_EOL;

// --- 5. Clean up channelsAssets.json ---
echo "\n5. Cleaning up channelsAssets.json..." . PHP_EOL;
$originalSourceCount = count($sourcesArray);
$updatedSourcesArray = array_filter(
    $sourcesArray,
    function ($sourceData, $key) use ($sourcesWithValidConfigs) {
        if (isset($sourceData["subscription_url"])) return true;
        return isset($sourcesWithValidConfigs[$key]);
    },
    ARRAY_FILTER_USE_BOTH
);
$finalSourceCount = count($updatedSourcesArray);
$removedCount = $originalSourceCount - $finalSourceCount;
if ($removedCount > 0) {
    echo "Removed $removedCount source(s) that had no valid configs and were not subscription links." . PHP_EOL;
    file_put_contents(ASSETS_FILE, json_encode($updatedSourcesArray, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
} else {
    echo "No sources needed to be removed." . PHP_EOL;
}

// --- 6. Save Caches and Generate Summary ---

// Save the IP cache
echo "\n6. Saving IP information cache to disk..." . PHP_EOL;
file_put_contents(IP_CACHE_FILE, json_encode($ipInfoCache, JSON_PRETTY_PRINT));
echo "Cache saved." . PHP_EOL;

// SUMMARY: Assemble and write the summary file.
echo "\n7. Generating summary file..." . PHP_EOL;

// Get country distribution by directly counting countries from the master list.
$allCountryCodes = array_column($allProcessedConfigs, 'country');
$countryDistribution = array_count_values($allCountryCodes);
arsort($countryDistribution);

$summaryData = [
    'meta' => [
        'last_updated' => date('c'), // ISO 8601 format
        'author' => 'yasi-python/PSG',
    ],
    'sources' => [
        'total_from_assets' => $originalSourceCount,
        'had_configs_extracted' => count($configsList),
        'had_valid_configs' => count($sourcesWithValidConfigs),
        'removed_in_cleanup' => $removedCount,
    ],
    'configs' => [
        'total_extracted_raw' => $stats['total_extracted_raw'],
        'total_valid_processed' => count($allProcessedConfigs),
        'breakdown_by_protocol' => $stats['protocol_counts'],
    ],
    'outputs' => [
        'main_aggregate_size' => count($mainAggregateConfigs),
        'location_files_created' => count($locationBased),
        'channel_files_created' => count($channelBased),
        'country_distribution' => $countryDistribution,
    ],
];

file_put_contents(SUMMARY_FILE, json_encode($summaryData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
echo "Summary file generated at: " . SUMMARY_FILE . PHP_EOL;

echo "\nDone! All files have been generated successfully." . PHP_EOL;
