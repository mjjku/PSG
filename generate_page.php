<?php

declare(strict_types=1);

/**
 * Proxy Subscription Generator (PSG) Page Builder
 *
 * Scans subscription directories and generates a modern, fully functional index.html.
 * This script includes a "Simple Mode" for basic users and an advanced
 * "Subscription Composer" for power users, powered by client-side JavaScript.
 */

// --- Configuration ---
define("PROJECT_ROOT", __DIR__);
define(
    "GITHUB_REPO_URL",
    "https://raw.githubusercontent.com/yasi-python/PSG/main"
);
define("OUTPUT_HTML_FILE", PROJECT_ROOT . "/index.html");
define("SCAN_DIRECTORIES", [
    "Standard" => PROJECT_ROOT . "/subscriptions",
    "Lite" => PROJECT_ROOT . "/lite/subscriptions",
    "Channels" => PROJECT_ROOT . "/subscriptions/channels",
]);

function get_client_info(): array
{
    // This function remains unchanged.
    return [
        "clash" => [
            "windows" => [
                [
                    "name" => "Clash Verge (Rev) - x64 Installer",
                    "url" =>
                        "https://github.com/clash-verge-rev/clash-verge-rev/releases/latest/download/Clash.Verge_1.6.8_x64-setup.exe",
                ],
                [
                    "name" => "Clash Verge (Rev) - ARM64 Installer",
                    "url" =>
                        "https://github.com/clash-verge-rev/clash-verge-rev/releases/latest/download/Clash.Verge_1.6.8_arm64-setup.msi",
                ],
            ],
            "macos" => [
                [
                    "name" => "Clash Verge (Rev) - Apple Silicon",
                    "url" =>
                        "https://github.com/clash-verge-rev/clash-verge-rev/releases/latest/download/Clash.Verge_1.6.8_aarch64.dmg",
                ],
                [
                    "name" => "ClashX - Universal",
                    "url" =>
                        "https://github.com/yichengchen/clashX/releases/latest/download/ClashX.dmg",
                ],
            ],
            "android" => [
                [
                    "name" => "Clash for Android (CFA) - arm64-v8a",
                    "url" =>
                        "https://github.com/Kr328/ClashForAndroid/releases/latest/download/cfa-2.5.12-premium-arm64-v8a-release.apk",
                ],
            ],
            "ios" => [
                [
                    "name" => "Stash (Recommended for Clash)",
                    "url" => "https://apps.apple.com/us/app/stash/id1596063349",
                ],
            ],
            "linux" => [
                [
                    "name" => "Clash Verge (Rev) - amd64 (.deb)",
                    "url" =>
                        "https://github.com/clash-verge-rev/clash-verge-rev/releases/latest/download/clash-verge_1.6.8_amd64.deb",
                ],
            ],
        ],
        "meta" => [
            "windows" => [
                [
                    "name" => "Clash Verge (Rev) - x64 Installer",
                    "url" =>
                        "https://github.com/clash-verge-rev/clash-verge-rev/releases/latest/download/Clash.Verge_1.6.8_x64-setup.exe",
                ],
            ],
            "macos" => [
                [
                    "name" => "Clash Verge (Rev) - Apple Silicon",
                    "url" =>
                        "https://github.com/clash-verge-rev/clash-verge-rev/releases/latest/download/Clash.Verge_1.6.8_aarch64.dmg",
                ],
            ],
            "android" => [
                [
                    "name" => "Clash for Android (CFA) - arm64-v8a",
                    "url" =>
                        "https://github.com/Kr328/ClashForAndroid/releases/latest/download/cfa-2.5.12-premium-arm64-v8a-release.apk",
                ],
            ],
            "ios" => [
                [
                    "name" => "Stash (Recommended for Clash Meta)",
                    "url" => "https://apps.apple.com/us/app/stash/id1596063349",
                ],
            ],
            "linux" => [
                [
                    "name" => "Clash Verge (Rev) - amd64 (.deb)",
                    "url" =>
                        "https://github.com/clash-verge-rev/clash-verge-rev/releases/latest/download/clash-verge_1.6.8_amd64.deb",
                ],
            ],
        ],
        "location" => [
            "windows" => [
                [
                    "name" => "v2rayN (with Xray core)",
                    "url" =>
                        "https://github.com/2dust/v2rayN/releases/latest/download/v2rayN-With-Core.zip",
                ],
            ],
            "android" => [
                [
                    "name" => "v2rayNG - arm64-v8a",
                    "url" =>
                        "https://github.com/2dust/v2rayNG/releases/latest/download/v2rayNG_1.8.19_arm64-v8a.apk",
                ],
            ],
            "ios" => [
                [
                    "name" => "Shadowrocket (Classic Choice)",
                    "url" =>
                        "https://apps.apple.com/us/app/shadowrocket/id932747118",
                ],
            ],
        ],
        "singbox" => [
            "windows" => [
                [
                    "name" => "Hiddify-Next - x64 Installer",
                    "url" =>
                        "https://github.com/hiddify/hiddify-next/releases/latest/download/Hiddify-Windows-x64-Setup.exe",
                ],
            ],
            "macos" => [
                [
                    "name" => "Hiddify-Next - Universal",
                    "url" =>
                        "https://github.com/hiddify/hiddify-next/releases/latest/download/Hiddify-MacOS.dmg",
                ],
            ],
            "android" => [
                [
                    "name" => "Hiddify-Next - Universal",
                    "url" =>
                        "https://github.com/hiddify/hiddify-next/releases/latest/download/Hiddify-Android-universal.apk",
                ],
            ],
            "ios" => [
                [
                    "name" => "Streisand (Recommended for Sing-Box)",
                    "url" =>
                        "https://apps.apple.com/us/app/streisand/id6450534064",
                ],
            ],
            "linux" => [
                [
                    "name" => "Hiddify-Next - x64 (.AppImage)",
                    "url" =>
                        "https://github.com/hiddify/hiddify-next/releases/latest/download/Hiddify-Linux-x64.AppImage",
                ],
            ],
        ],
        "surfboard" => [
            "android" => [
                [
                    "name" => "Surfboard (Google Play)",
                    "url" =>
                        "https://play.google.com/store/apps/details?id=com.getsurfboard",
                ],
            ],
        ],
        "xray" => [
            "windows" => [
                [
                    "name" => "v2rayN (with Xray core)",
                    "url" =>
                        "https://github.com/2dust/v2rayN/releases/latest/download/v2rayN-With-Core.zip",
                ],
            ],
            "android" => [
                [
                    "name" => "v2rayNG - arm64-v8a",
                    "url" =>
                        "https://github.com/2dust/v2rayNG/releases/latest/download/v2rayNG_1.8.19_arm64-v8a.apk",
                ],
            ],
            "ios" => [
                [
                    "name" => "Shadowrocket (Classic Choice)",
                    "url" =>
                        "https://apps.apple.com/us/app/shadowrocket/id932747118",
                ],
            ],
        ],
        "channel" => [
            "windows" => [
                [
                    "name" => "v2rayN (with Xray core)",
                    "url" =>
                        "https://github.com/2dust/v2rayN/releases/latest/download/v2rayN-With-Core.zip",
                ],
            ],
            "android" => [
                [
                    "name" => "v2rayNG - arm64-v8a",
                    "url" =>
                        "https://github.com/2dust/v2rayNG/releases/latest/download/v2rayNG_1.8.19_arm64-v8a.apk",
                ],
            ],
            "ios" => [
                [
                    "name" => "Shadowrocket (Classic Choice)",
                    "url" =>
                        "https://apps.apple.com/us/app/shadowrocket/id932747118",
                ],
            ],
        ],
    ];
}
function scan_directory(string $dir): array
{
    // This function remains unchanged.
    if (!is_dir($dir)) {
        return [];
    }
    $files = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(
            $dir,
            RecursiveDirectoryIterator::SKIP_DOTS
        ),
        RecursiveIteratorIterator::SELF_FIRST
    );
    $ignoreExtensions = ["php", "md", "ini", "txt", "log", "conf"];
    foreach ($iterator as $file) {
        if (
            $file->isFile() &&
            !in_array(strtolower($file->getExtension()), $ignoreExtensions)
        ) {
            $relativePath = str_replace(
                PROJECT_ROOT . DIRECTORY_SEPARATOR,
                "",
                $file->getRealPath()
            );
            $files[] = str_replace(DIRECTORY_SEPARATOR, "/", $relativePath);
        }
    }
    return $files;
}

function process_files_to_structure(array $files_by_category): array
{
    // This function remains unchanged.
    $structure = [];
    foreach (SCAN_DIRECTORIES as $category_key => $category_dir_path) {
        $base_dir_relative = ltrim(
            str_replace(PROJECT_ROOT, "", $category_dir_path),
            DIRECTORY_SEPARATOR
        );
        $base_dir_relative = str_replace(
            DIRECTORY_SEPARATOR,
            "/",
            $base_dir_relative
        );

        if (!isset($files_by_category[$category_key])) {
            continue;
        }

        foreach ($files_by_category[$category_key] as $path) {
            $relative_path_from_base = str_replace(
                $base_dir_relative . "/",
                "",
                $path
            );
            $path_for_parsing = $relative_path_from_base;

            if (
                strpos($path_for_parsing, "xray/") === 0 ||
                strpos($path_for_parsing, "channel/") === 0 ||
                strpos($path_for_parsing, "location/") === 0
            ) {
                $parts = explode("/", $path_for_parsing, 3);
                $type_prefix = $parts[0];

                if (count($parts) < 3 || $parts[1] !== "base64") {
                    continue;
                }
                $path_for_parsing = $type_prefix . "/" . $parts[2];
            }

            $parts = explode("/", $path_for_parsing);
            if (count($parts) < 2) {
                continue;
            }

            $type = array_shift($parts);
            $remaining_path = implode("/", $parts);
            $name = preg_replace('/\\.[^.\\/]+$/', "", $remaining_path);

            $url = GITHUB_REPO_URL . "/" . $path;

            $structure[$category_key][$type][$name] = $url;
        }
    }

    foreach ($structure as &$categories) {
        ksort($categories);
        foreach ($categories as &$elements) {
            ksort($elements);
        }
    }
    ksort($structure);

    return $structure;
}

/**
 * Generates the complete HTML content for the PSG page.
 */
function generate_full_html(
    array $structured_data,
    array $client_info_data,
    string $generation_timestamp
): string {
    $json_structured_data = json_encode(
        $structured_data,
        JSON_UNESCAPED_SLASHES
    );
    $json_client_info_data = json_encode(
        $client_info_data,
        JSON_UNESCAPED_SLASHES
    );

    // The entire HTML template with dark mode support is now here.
    $html_template = <<<'HTML'
<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Subscription Generator (PSG)</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/js-yaml@4.1.0/dist/js-yaml.min.js"></script>
    <script>
      tailwind.config = {
        darkMode: 'class', // Enable dark mode
        theme: {
          extend: {
            fontFamily: {
              sans: ['Inter', 'sans-serif'],
            },
          }
        }
      }
    </script>
    
    <style>
        body { font-family: 'Inter', sans-serif; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; }
        .composer-list::-webkit-scrollbar { width: 5px; }
        .composer-list::-webkit-scrollbar-track { background: #f1f5f9; }
        .composer-list::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 10px; }
        .composer-list::-webkit-scrollbar-thumb:hover { background: #94a3b8; }
        
        html.dark .composer-list::-webkit-scrollbar-track { background: #1e293b; } /* slate-800 */
        html.dark .composer-list::-webkit-scrollbar-thumb { background: #475569; } /* slate-600 */
        html.dark .composer-list::-webkit-scrollbar-thumb:hover { background: #64748b; } /* slate-500 */

        .mode-btn.text-indigo-600 { color: #4f46e5; }
        html.dark .mode-btn.text-indigo-600 { color: #818cf8; } /* indigo-400 */

	    .step-container.active {
            opacity: 1;
            border-color: #4f46e5; /* indigo-500 */
        }
        .step-container.active .step-icon {
            background-color: #4338ca; /* indigo-700 */
        }
	    details[open] > summary .lucide-chevron-down {
            transform: rotate(180deg);
        }
        .composer-step.active {
            opacity: 1;
            border-color: #4f46e5; /* indigo-500 */
        }
        .composer-step.active .step-icon {
            background-color: #4338ca; /* indigo-700 */
        }
    </style>
</head>
<body class="bg-slate-50 dark:bg-slate-900 text-slate-800 dark:text-slate-300 leading-relaxed transition-colors duration-300">
    <div class="container max-w-6xl mx-auto px-4 py-8">
            <!-- START: New Section for Flag and Hashtags -->
        <div class="flex flex-col sm:flex-row justify-center items-center gap-4 mb-6 text-center">
            <!-- Flag Image -->
                <img src="https://static.wixstatic.com/media/fbe150_de0ae4fc01c348d59b8d27f34a4fbeb5~mv2.png/v1/fill/w_503,h_288,al_c,q_85,enc_auto/Untitled%20design%20(8).png" alt="Lion and Sun Flag of Iran" class="h-10 sm:h-12 w-auto transition-transform hover:scale-105">

            <!-- Hashtags Container -->
            <div class="flex flex-wrap justify-center gap-2">
                <span class="bg-green-100 text-green-800 text-sm font-semibold px-3 py-1.5 rounded-full dark:bg-green-900 dark:text-green-300">#همکاری_ملی</span>
                <span class="bg-yellow-100 text-yellow-800 text-sm font-semibold px-3 py-1.5 rounded-full dark:bg-yellow-900 dark:text-yellow-300">#جاویدشاه</span>
                <span class="bg-sky-100 text-sky-800 text-sm font-semibold px-3 py-1.5 rounded-full dark:bg-sky-900 dark:text-sky-300">#KingRezaPahlavi</span>
            </div>
        </div>
        <!-- END: New Section for Flag and Hashtags -->
        <!-- Main Header -->
        <header class="flex justify-between items-center mb-10">
            <div class="text-left">
                <h1 class="text-2xl sm:text-3xl lg:text-4xl font-bold tracking-tight text-slate-900 dark:text-slate-100 mb-0">Proxy Subscription Generator</h1>
                <p class="text-base sm:text-lg text-slate-500 dark:text-slate-400 mt-2">Your central hub for proxy subscriptions.</p>
            </div>
            <!-- Dark Mode Toggle -->
            <div class="flex-shrink-0">
                <button id="theme-toggle" type="button" class="text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 focus:outline-none focus:ring-4 focus:ring-slate-200 dark:focus:ring-slate-700 rounded-lg text-sm p-2.5">
                    <i id="theme-toggle-dark-icon" class="hidden w-5 h-5" data-lucide="moon"></i>
                    <i id="theme-toggle-light-icon" class="hidden w-5 h-5" data-lucide="sun"></i>
                </button>
            </div>
        </header>

        <main>
            <!-- Main Control Panel -->
            <div class="bg-white dark:bg-slate-800/50 dark:backdrop-blur-sm rounded-xl p-4 sm:p-6 lg:p-8 shadow-lg border border-slate-200 dark:border-slate-700 mb-8 sm:mb-10">
                
                <!-- NEW: Segmented Control Navigation -->
                <div class="relative w-full max-w-lg mx-auto mb-8 p-1.5 bg-slate-100 dark:bg-slate-700/50 rounded-xl flex items-center">
                    <!-- The sliding background for the active state -->
                    <div id="mode-slider" class="absolute top-1.5 left-1.5 h-[calc(100%-12px)] w-1/4 bg-white dark:bg-slate-800 rounded-lg shadow-md transition-all duration-300 ease-in-out"></div>
                
                    <!-- The buttons. Notice the added data-id attribute -->
                    <button data-id="simple" class="mode-btn flex-1 relative z-10 text-center px-2 py-2 text-sm font-semibold text-slate-700 dark:text-slate-300 transition-colors">🤌🏻 Simple</button>
                    <button data-id="composer" class="mode-btn flex-1 relative z-10 text-center px-2 py-2 text-sm font-semibold text-slate-700 dark:text-slate-300 transition-colors">✨ Composer</button>
                    <button data-id="splitter" class="mode-btn flex-1 relative z-10 text-center px-2 py-2 text-sm font-semibold text-slate-700 dark:text-slate-300 transition-colors">✂️ Splitter</button>
                    <button data-id="compiler" class="mode-btn flex-1 relative z-10 text-center px-2 py-2 text-sm font-semibold text-slate-700 dark:text-slate-300 transition-colors">🔄 Compiler</button>
                </div>

                <!-- Container for "Simple Mode" -->
<div id="simpleModeContainer">
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 text-center">

        <!-- Step 1: Choose Subscription Category -->
        <div id="step1" class="step-container bg-white dark:bg-slate-800 p-6 rounded-lg border-2 border-indigo-500 dark:border-indigo-500 shadow-lg">
            <div class="flex items-center justify-center w-12 h-12 bg-indigo-600 text-white rounded-full mx-auto mb-4">
                <span class="text-xl font-bold">1</span>
            </div>
            <h3 class="text-lg font-semibold text-slate-800 dark:text-slate-200 mb-1">Choose Category</h3>
            <p class="text-sm text-slate-500 dark:text-slate-400 mb-4">What kind of subscription do you need?</p>
            <select id="configType" class="block w-full rounded-md border-slate-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2.5 bg-slate-50 dark:bg-slate-700 text-slate-800 dark:text-slate-200 dark:border-slate-600"></select>
        </div>

        <!-- Step 2: Choose Client/Core -->
        <div id="step2" class="step-container bg-white dark:bg-slate-800 p-6 rounded-lg border-2 border-slate-200 dark:border-slate-700 transition-opacity duration-300 opacity-50">
             <div class="flex items-center justify-center w-12 h-12 bg-slate-400 text-white rounded-full mx-auto mb-4 step-icon">
                <span class="text-xl font-bold">2</span>
            </div>
            <h3 class="text-lg font-semibold text-slate-800 dark:text-slate-200 mb-1">Select Your App</h3>
            <p class="text-sm text-slate-500 dark:text-slate-400 mb-4">Which app or software will you use?</p>
            <select id="ipType" class="block w-full rounded-md border-slate-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2.5 bg-slate-50 dark:bg-slate-700 text-slate-800 dark:text-slate-200 dark:border-slate-600" disabled></select>
        </div>

        <!-- Step 3: Find & Select Subscription -->
        <div id="step3" class="step-container bg-white dark:bg-slate-800 p-6 rounded-lg border-2 border-slate-200 dark:border-slate-700 transition-opacity duration-300 opacity-50">
             <div class="flex items-center justify-center w-12 h-12 bg-slate-400 text-white rounded-full mx-auto mb-4 step-icon">
                <span class="text-xl font-bold">3</span>
            </div>
            <h3 class="text-lg font-semibold text-slate-800 dark:text-slate-200 mb-1">Find Your Link</h3>
            <p class="text-sm text-slate-500 dark:text-slate-400 mb-4">Search for a specific subscription.</p>
            <input type="search" id="searchBar" placeholder="Filter subscriptions..." class="block w-full rounded-md border-slate-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2 mb-2 bg-slate-50 dark:bg-slate-700 text-slate-800 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-500 dark:border-slate-600" disabled>
            <select id="otherElement" class="block w-full rounded-md border-slate-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2.5 bg-slate-50 dark:bg-slate-700 text-slate-800 dark:text-slate-200 dark:border-slate-600" disabled></select>
        </div>

    </div>
</div>

                <!-- Container for "Subscription Composer Mode" -->
<div id="composerModeContainer" class="hidden">
    <div class="space-y-4 max-w-4xl mx-auto">
        <p class="text-center text-slate-600 dark:text-slate-400 mb-6">Create a custom subscription by mixing and matching from multiple sources.</p>

        <!-- Step 1: Select Sources -->
        <div class="composer-step bg-white dark:bg-slate-800 p-6 rounded-lg border-2 border-indigo-500 shadow-lg">
            <details open>
                <summary class="flex items-center justify-between cursor-pointer list-none">
                    <div class="flex items-center gap-4">
                        <div class="flex items-center justify-center w-10 h-10 bg-indigo-600 text-white rounded-full flex-shrink-0">
                            <span class="text-lg font-bold">1</span>
                        </div>
                        <div>
                            <h3 class="text-lg font-semibold text-slate-800 dark:text-slate-200">Select Sources</h3>
                            <p class="text-sm text-slate-500 dark:text-slate-400">Choose one or more lists to combine.</p>
                        </div>
                    </div>
                    <i data-lucide="chevron-down" class="lucide-chevron-down transition-transform duration-300"></i>
                </summary>
                <div class="mt-6 border-t border-slate-200 dark:border-slate-700 pt-6">
                    <div id="composerSourceList">
    <!-- Categorized source lists will be generated here -->
</div>
                </div>
            </details>
        </div>

        <!-- Step 2: Filter & Refine (Initially disabled) -->
        <div id="composerStep2" class="composer-step bg-white dark:bg-slate-800 p-6 rounded-lg border-2 border-slate-200 dark:border-slate-700 transition-opacity duration-300 opacity-50">
             <details>
                <summary class="flex items-center justify-between cursor-pointer list-none">
                    <div class="flex items-center gap-4">
                        <div class="flex items-center justify-center w-10 h-10 bg-slate-400 text-white rounded-full flex-shrink-0 step-icon">
                            <span class="text-lg font-bold">2</span>
                        </div>
                        <div>
                            <h3 class="text-lg font-semibold text-slate-800 dark:text-slate-200">Filter & Refine (Optional)</h3>
                            <p class="text-sm text-slate-500 dark:text-slate-400">Narrow down the results.</p>
                        </div>
                    </div>
                    <i data-lucide="chevron-down" class="lucide-chevron-down transition-transform duration-300"></i>
                </summary>
                <div class="mt-6 border-t border-slate-200 dark:border-slate-700 pt-6 space-y-6">
                    <div>
                        <label for="filterCountry" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Filter by Country Code</label>
                        <input type="text" id="filterCountry" placeholder="e.g. DE,US,JP (comma-separated)" class="block w-full rounded-md border-slate-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2.5 bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-500 dark:border-slate-600">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Filter by Protocol</label>
                        <div id="composerProtocolFilters" class="grid grid-cols-2 sm:grid-cols-3 gap-2">
                            <!-- Protocol checkboxes will be inserted here -->
                        </div>
                    </div>
                    <div>
                        <label for="nodeLimit" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Max Nodes in Final Subscription</label>
                        <input type="number" id="nodeLimit" value="50" min="1" max="500" class="block w-full rounded-md border-slate-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2.5 bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-200 dark:border-slate-600">
                    </div>
                </div>
            </details>
        </div>

        <!-- Step 3: Generate Output (Initially disabled) -->
        <div id="composerStep3" class="composer-step bg-white dark:bg-slate-800 p-6 rounded-lg border-2 border-slate-200 dark:border-slate-700 transition-opacity duration-300 opacity-50">
            <details>
                <summary class="flex items-center justify-between cursor-pointer list-none">
                    <div class="flex items-center gap-4">
                        <div class="flex items-center justify-center w-10 h-10 bg-slate-400 text-white rounded-full flex-shrink-0 step-icon">
                            <span class="text-lg font-bold">3</span>
                        </div>
                        <div>
                            <h3 class="text-lg font-semibold text-slate-800 dark:text-slate-200">Generate Output</h3>
                            <p class="text-sm text-slate-500 dark:text-slate-400">Choose your final format and create the link.</p>
                        </div>
                    </div>
                    <i data-lucide="chevron-down" class="lucide-chevron-down transition-transform duration-300"></i>
                </summary>
                <div class="mt-6 border-t border-slate-200 dark:border-slate-700 pt-6 space-y-6">
                    <div>
                        <label for="composerTargetClient" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Target Client Format</label>
                        <select id="composerTargetClient" class="block w-full rounded-md border-slate-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2.5 bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-200 dark:border-slate-600">
                            <option value="clash">Clash / Meta</option>
                            <option value="singbox">Sing-box / Hiddify</option>
                            <option value="base64">Base64 (for v2rayN, etc.)</option>
                        </select>
                    </div>
                    <button id="generateCompositionButton" class="w-full flex items-center justify-center gap-2 bg-emerald-600 text-white px-4 py-3 rounded-md hover:bg-emerald-700 transition-colors duration-200 disabled:bg-emerald-300 disabled:cursor-not-allowed">
                        <i data-lucide="git-merge" class="w-5 h-5"></i>
                        <span id="generateCompositionButtonText" class="font-semibold">Generate Composed Subscription</span>
                    </button>
                </div>
            </details>
        </div>
    </div>
</div>

                <!-- Container for "Subscription Splitter Mode" -->
                <div id="splitterModeContainer" class="hidden">
                    <div class="space-y-6 max-w-2xl mx-auto">
                        <p class="text-center text-slate-600 dark:text-slate-400">Paste any large subscription link (from here or anywhere else) to split it into smaller, more manageable lists.</p>
                        
                        <!-- Step 1: Input -->
<div>
    <label for="splitterUrlInput" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Subscription URL or Raw Text:</label>
    <textarea id="splitterUrlInput" rows="4" class="block w-full rounded-md border-slate-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2.5 bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-500 font-mono dark:border-slate-600" placeholder="Paste URL, Base64 text, or a list of configs here..."></textarea>
</div>

                        <!-- Step 2: Options -->
                        <div>
                            <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Splitting Strategy:</label>
                            <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                                <div>
                                    <input type="radio" name="split_strategy" id="split_by_country" value="country" class="hidden peer" checked>
                                    <label for="split_by_country" class="block text-center p-4 rounded-lg border border-slate-300 dark:border-slate-600 cursor-pointer peer-checked:border-indigo-600 peer-checked:ring-2 peer-checked:ring-indigo-500 peer-checked:text-indigo-600 dark:peer-checked:text-indigo-400">
                                        <i data-lucide="map-pinned" class="mx-auto h-6 w-6 mb-1"></i>
                                        <span class="font-semibold">By Country</span>
                                    </label>
                                </div>
                                <div>
                                    <input type="radio" name="split_strategy" id="split_by_protocol" value="protocol" class="hidden peer">
                                    <label for="split_by_protocol" class="block text-center p-4 rounded-lg border border-slate-300 dark:border-slate-600 cursor-pointer peer-checked:border-indigo-600 peer-checked:ring-2 peer-checked:ring-indigo-500 peer-checked:text-indigo-600 dark:peer-checked:text-indigo-400">
                                        <i data-lucide="file-cog" class="mx-auto h-6 w-6 mb-1"></i>
                                        <span class="font-semibold">By Protocol</span>
                                    </label>
                                </div>
                                <div>
                                    <input type="radio" name="split_strategy" id="split_by_chunk" value="chunk" class="hidden peer">
                                    <label for="split_by_chunk" class="block text-center p-4 rounded-lg border border-slate-300 dark:border-slate-600 cursor-pointer peer-checked:border-indigo-600 peer-checked:ring-2 peer-checked:ring-indigo-500 peer-checked:text-indigo-600 dark:peer-checked:text-indigo-400">
                                        <i data-lucide="grip" class="mx-auto h-6 w-6 mb-1"></i>
                                        <span class="font-semibold">By Chunks</span>
                                    </label>
                                </div>
                            </div>
                            <div id="chunkSizeContainer" class="hidden mt-4">
                                <label for="chunkSizeInput" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Nodes per chunk:</label>
                                <input type="number" id="chunkSizeInput" value="50" min="5" class="block w-full max-w-xs mx-auto rounded-md border-slate-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2.5 bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-200 dark:border-slate-600">
                            </div>
                        </div>

                        <!-- Step 3: Action -->
                        <button id="splitSubscriptionButton" class="w-full flex items-center justify-center gap-2 bg-purple-600 text-white px-4 py-3 rounded-md hover:bg-purple-700 transition-colors duration-200 disabled:bg-purple-300">
                            <i data-lucide="scissors" class="w-5 h-5"></i>
                            <span id="splitButtonText" class="font-semibold">Split Subscription</span>
                        </button>
                    </div>

                    <!-- Splitter Result Area -->
                    <div id="splitterResultArea" class="hidden mt-8 pt-6 border-t border-slate-200 dark:border-slate-700">
                        <h3 class="text-lg sm:text-xl font-semibold text-slate-800 dark:text-slate-200 mb-4 text-center">Your Split Subscriptions:</h3>
                        <div id="splitterResultList" class="space-y-3 max-w-2xl mx-auto">
                            <!-- Results will be injected here -->
                        </div>
                    </div>
                </div>

                <!-- Container for "Proxy Converter Mode" -->
<div id="compilerModeContainer" class="hidden">
    <div class="space-y-8">
        <p class="text-center text-slate-600 dark:text-slate-400">Automatically convert any subscription or config file from one format to another.</p>
        
        <!-- Main Conversion Flow UI -->
        <div class="grid grid-cols-1 md:grid-cols-[2fr_auto_2fr] items-center gap-6">
            <!-- Panel 1: Input -->
            <div class="w-full">
                <div class="flex justify-between items-center mb-2">
                    <label for="compilerInputText" class="block text-sm font-medium text-slate-700 dark:text-slate-300">Input (URL or Raw Config)</label>
                    <span id="detectedFormatBadge" class="text-xs font-semibold px-2 py-1 rounded-full bg-slate-200 dark:bg-slate-600 text-slate-600 dark:text-slate-300 transition-all">Auto-Detect</span>
                </div>
                <textarea id="compilerInputText" rows="8" class="block w-full rounded-md border-slate-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2.5 bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-500 font-mono dark:border-slate-600" placeholder="Paste anything here..."></textarea>
            </div>
            
            <!-- Arrow Separator -->
            <div class="text-center">
                <i data-lucide="arrow-right-circle" class="h-8 w-8 text-slate-400 dark:text-slate-500"></i>
            </div>
            
            <!-- Panel 2: Output -->
            <div class="w-full">
                <label for="compilerOutputFormat" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Output Format</label>
                <select id="compilerOutputFormat" class="block w-full rounded-md border-slate-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2.5 bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-200 dark:border-slate-600">
                    <option value="base64" selected>Base64 URI List</option>
                    <option value="clash">Clash Profile (YAML)</option>
                    <option value="singbox">Sing-box Profile (JSON)</option>
                </select>
            </div>
        </div>
        
        <!-- Action Button -->
        <button id="convertButton" class="w-full flex items-center justify-center gap-2 bg-blue-600 text-white px-4 py-3 rounded-md hover:bg-blue-700 transition-colors duration-200 disabled:bg-blue-300">
            <i data-lucide="refresh-cw" class="w-5 h-5"></i>
            <span id="convertButtonText" class="font-semibold">Convert</span>
        </button>
    </div>
    <!-- The result area div remains the same -->
    <div id="compilerResultArea" class="hidden mt-8 pt-6 border-t border-slate-200 dark:border-slate-700">
        <h3 class="text-lg sm:text-xl font-semibold text-slate-800 dark:text-slate-200 mb-2">Conversion Complete:</h3>
        <p id="compilerResultTitle" class="text-sm text-slate-500 dark:text-slate-400 mb-4"></p>
        <textarea id="compilerResultText" readonly class="w-full h-64 font-mono text-xs bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg p-3 outline-none resize-vertical"></textarea>
        <div class="grid grid-cols-3 items-center gap-2 mt-2">
           <button id="copyConvertedButton" class="flex items-center justify-center gap-2 bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 transition-colors duration-200">
               <i data-lucide="copy"></i> Copy
           </button>
           <button id="downloadConvertedButton" class="flex items-center justify-center gap-2 bg-slate-600 text-white px-4 py-2 rounded-md hover:bg-slate-700 transition-colors duration-200">
               <i data-lucide="download"></i> Download
           </button>
           <button id="shareConvertedButton" class="flex items-center justify-center gap-2 bg-teal-600 text-white px-4 py-2 rounded-md hover:bg-teal-700 transition-colors duration-200">
                <i data-lucide="share-2"></i> Share
            </button>
        </div>
    </div>
</div>

                <!-- Result Area for Simple Mode -->
                <div id="resultArea" class="hidden bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 sm:p-6 border border-slate-200 dark:border-slate-700 mt-6">
                    <div class="grid grid-cols-1 lg:grid-cols-2 gap-x-8 gap-y-8 items-start">
                        <div id="subscription-details-container" class="hidden">
                            <h3 class="text-lg sm:text-xl font-semibold text-slate-800 dark:text-slate-200 mb-4">Your Subscription Link:</h3>
                            <div class="flex items-center mb-4">
                                <input type="text" id="subscriptionUrl" readonly class="flex-grow font-mono text-xs sm:text-sm py-2.5 px-3 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-l-lg outline-none whitespace-nowrap overflow-hidden text-ellipsis" />
                                <button id="copyButton" class="flex-shrink-0 flex items-center justify-center w-11 h-11 bg-indigo-50 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-400 border border-l-0 border-indigo-600 dark:border-indigo-500 rounded-r-lg cursor-pointer transition-colors duration-200 hover:bg-indigo-100 dark:hover:bg-indigo-900" title="Copy URL">
                                    <i data-lucide="copy" class="copy-icon w-5 h-5"></i>
                                    <i data-lucide="check" class="check-icon w-5 h-5 hidden"></i>
                                </button>
                            </div>
                            <div class="flex flex-col sm:flex-row items-center justify-center sm:justify-start gap-4">
                                <div id="qrcode" class="p-2 bg-white border border-slate-300 rounded-lg shadow-inner"></div>
                                <button id="analyzeButton" class="w-full sm:w-auto flex-grow flex items-center justify-center gap-2 bg-blue-600 text-white px-4 py-3 rounded-md hover:bg-blue-700 transition-colors duration-200">
                                    <i data-lucide="bar-chart-3" class="w-5 h-5"></i>
                                    <span class="font-semibold">Analyze Subscription DNA</span>
                                </button>
                            </div>
                        </div>
                        <div id="client-info-container">
                           <h3 class="text-lg sm:text-xl font-semibold text-slate-800 dark:text-slate-200 mb-2">Compatible Clients:</h3>
                           <div id="client-info-list" class="space-y-5"></div>
                        </div>
                    </div>
                </div>
                
                <!-- Result Area for Composer Mode -->
                <div id="composerResultArea" class="hidden bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 sm:p-6 border border-slate-200 dark:border-slate-700 mt-6">
                    <h3 class="text-lg sm:text-xl font-semibold text-slate-800 dark:text-slate-200 mb-4">Your Composed Subscription:</h3>
                     <div class="grid grid-cols-1 gap-y-8 items-start">
                        <div>
                             <textarea id="composedResultText" readonly class="w-full h-48 font-mono text-xs bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg p-3 outline-none resize-vertical"></textarea>
                             <!-- Corrected Layout for Composer Buttons -->
<div class="grid grid-cols-3 items-center gap-2 mt-2">
    <button id="copyComposedButton" class="flex items-center justify-center gap-2 bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 transition-colors duration-200">
        <i data-lucide="copy"></i> Copy
    </button>
    <button id="downloadComposedButton" class="flex items-center justify-center gap-2 bg-slate-600 text-white px-4 py-2 rounded-md hover:bg-slate-700 transition-colors duration-200">
        <i data-lucide="download"></i> Download
    </button>
    <button id="shareComposedButton" class="flex items-center justify-center gap-2 bg-teal-600 text-white px-4 py-2 rounded-md hover:bg-teal-700 transition-colors duration-200">
        <i data-lucide="share-2"></i> Share
    </button>
</div>
                        </div>
                     </div>
                </div>

            </div>
        </main>
        
        <footer class="text-center mt-12 sm:mt-16 py-6 sm:py-8 border-t border-slate-200 dark:border-slate-700">
            <div class="flex flex-col sm:flex-row justify-center items-center gap-y-4 gap-x-6 text-slate-500 dark:text-slate-400 text-sm">
                <p>Created with ❤️ by YEBEKHE</p>
                <div class="flex items-center gap-x-3">
                    <a href="https://t.me/yebekhe" target="_blank" rel="noopener noreferrer" class="hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors" title="Telegram"><i data-lucide="send" class="h-5 w-5"></i></a>
                    <a href="https://x.com/yebekhe" target="_blank" rel="noopener noreferrer" class="hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors" title="X (Twitter)"><i data-lucide="twitter" class="h-5 w-5"></i></a>
                </div>
            </div>
            <p id="lastGenerated" class="text-xs text-slate-400 dark:text-slate-500 mt-4">
    <span id="live-ip-info"></span>
    <span class="mx-2">|</span>
    <span>Last Generated: __TIMESTAMP_PLACEHOLDER__</span>
</p>
        </footer>
    </div>
    
    <div id="messageBox" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50 hidden">
        <div class="bg-white dark:bg-slate-800 rounded-lg p-6 shadow-xl max-w-sm w-full text-center">
            <p id="messageBoxText" class="text-lg font-semibold text-slate-800 dark:text-slate-200 mb-4"></p>
            <button id="messageBoxClose" class="bg-indigo-600 text-white px-5 py-2 rounded-md hover:bg-indigo-700 transition-colors duration-200">OK</button>
        </div>
    </div>
    
    <div id="dnaModal" class="fixed inset-0 bg-black bg-opacity-60 backdrop-blur-sm flex items-center justify-center p-4 z-50 hidden">
        <div id="dnaModalContent" class="bg-white dark:bg-slate-800 rounded-xl p-4 sm:p-6 lg:p-8 shadow-2xl max-w-5xl w-full text-slate-800 dark:text-slate-300 transform transition-all scale-95 opacity-0 overflow-y-auto max-h-[90vh]">
            <div class="flex justify-between items-center mb-6 border-b border-slate-200 dark:border-slate-700 pb-4">
                <div>
                    <h2 class="text-xl sm:text-2xl font-bold text-slate-900 dark:text-slate-100">Subscription DNA</h2>
                    <p id="modalSubscriptionName" class="text-sm text-slate-500 dark:text-slate-400"></p>
                </div>
                <button id="dnaModalCloseButton" class="p-2 rounded-full hover:bg-slate-100 dark:hover:bg-slate-700">
                    <i data-lucide="x" class="w-6 h-6 text-slate-600 dark:text-slate-400"></i>
                </button>
            </div>
            <div id="dnaLoadingState" class="text-center py-10"><p class="flex items-center justify-center gap-2 text-slate-600 dark:text-slate-400"><i data-lucide="loader-2" class="animate-spin w-5 h-5"></i>Analyzing... Please wait.</p></div>
            <div id="dnaResultsContainer" class="hidden grid grid-cols-1 md:grid-cols-2 gap-8">
                <div class="space-y-8">
                    <div><h3 class="font-semibold mb-3 text-center text-slate-700 dark:text-slate-300">Protocol Distribution</h3><div class="max-w-[200px] sm:max-w-[250px] mx-auto relative"><canvas id="protocolChart"></canvas><div id="protocolTotal" class="absolute inset-0 flex items-center justify-center text-center leading-none"><div><span class="text-3xl font-bold text-slate-800 dark:text-slate-200"></span><span class="text-sm text-slate-500 dark:text-slate-400 block">Nodes</span></div></div></div></div>
                    <div><h3 class="font-semibold mb-3 text-center text-slate-700 dark:text-slate-300">Security Profile</h3><div class="max-w-[200px] sm:max-w-[250px] mx-auto"><canvas id="securityChart"></canvas></div></div>
                </div>
                <div class="space-y-8">
                     <div><h3 class="font-semibold mb-3 text-center text-slate-700 dark:text-slate-300">Top Countries</h3><div id="countryBarChartContainer"><canvas id="countryBarChart"></canvas></div></div>
                     <div><h3 class="font-semibold mb-3 text-center text-slate-700 dark:text-slate-300">Top Transports</h3><div id="transportChartContainer"><canvas id="transportChart"></canvas></div></div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://unpkg.com/lucide@latest"></script>
    <script src="https://cdn.jsdelivr.net/npm/davidshimjs-qrcodejs@0.0.2/qrcode.min.js"></script>
    
    <script>
    document.addEventListener('DOMContentLoaded', () => {
        // --- THEME TOGGLE LOGIC ---
        const themeToggleBtn = document.getElementById('theme-toggle');
        const themeToggleDarkIcon = document.getElementById('theme-toggle-dark-icon');
        const themeToggleLightIcon = document.getElementById('theme-toggle-light-icon');

        const applyTheme = (isDark) => {
            document.documentElement.classList.toggle('dark', isDark);
            themeToggleLightIcon.classList.toggle('hidden', !isDark);
            themeToggleDarkIcon.classList.toggle('hidden', isDark);
        };
        
        const isSystemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        const savedTheme = localStorage.getItem('color-theme');

        if (savedTheme === 'dark' || (!savedTheme && isSystemDark)) {
            applyTheme(true);
        } else {
            applyTheme(false);
        }

        themeToggleBtn.addEventListener('click', () => {
            const isDarkMode = document.documentElement.classList.toggle('dark');
            localStorage.setItem('color-theme', isDarkMode ? 'dark' : 'light');
            applyTheme(isDarkMode);
            updateChartDefaults(); // Update chart colors
            // Force any visible charts to re-render with new defaults
            Object.values(charts).forEach(chart => {
                if (chart) chart.update();
            });
        });

		/**
 * A JavaScript client for the shz.al pastebin API.
 * This class provides methods to interact with all endpoints of the API.
 * @see API Reference: https://shz.al
 */
class ShzAlClient {
  /**
   * Creates an instance of the ShzAlClient.
   * @param {string} [baseURL='https://shz.al'] - The base URL of the API.
   */
  constructor(baseURL = 'https://shz.al') {
    // Ensure the base URL does not have a trailing slash
    this.baseURL = baseURL.endsWith('/') ? baseURL.slice(0, -1) : baseURL;
  }

  /**
   * Handles the response from the fetch API, throwing an error for non-successful status codes.
   * @private
   * @param {Response} response - The response object from a fetch call.
   * @returns {Promise<Response>} - The original response object if it's successful.
   * @throws {Error} If the response status is not ok (e.g., 404, 500).
   */
  async _handleResponse(response) {
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`API Error: ${response.status} ${response.statusText} - ${errorText}`);
    }
    return response;
  }

  /**
   * Fetches the index page.
   * @returns {Promise<string>} A promise that resolves to the HTML content of the index page.
   */
  async getIndexPage() {
    const response = await fetch(this.baseURL);
    await this._handleResponse(response);
    return response.text();
  }

  /**
   * Fetches a paste's content.
   * @param {string} name - The name of the paste.
   * @param {object} [options={}] - Optional parameters for the request.
   * @param {string} [options.ext] - An extension to append to the name (e.g., 'js', 'txt').
   * @param {string} [options.filename] - A filename to append to the path (e.g., 'image.jpg').
   * @param {boolean} [options.asAttachment=false] - If true, set Content-Disposition to 'attachment'.
   * @param {string} [options.mime] - Overrides the inferred MIME type.
   * @param {string} [options.lang] - Specifies a language for syntax highlighting (results in HTML).
   * @returns {Promise<Response>} A promise that resolves to the raw fetch Response object.
   *                               You can then use .text(), .json(), .blob(), etc., to get the content.
   */
  async getPaste(name, options = {}) {
    const { ext, filename, asAttachment, mime, lang } = options;
    let path = `/${name}`;
    if (filename) {
      path += `/${filename}`;
    } else if (ext) {
      path += `.${ext}`;
    }

    const params = new URLSearchParams();
    if (asAttachment) params.set('a', '');
    if (mime) params.set('mime', mime);
    if (lang) params.set('lang', lang);

    const url = `${this.baseURL}${path}${params.toString() ? '?' + params.toString() : ''}`;
    const response = await fetch(url);
    
    return this._handleResponse(response);
  }

  /**
   * Fetches the URL where a short link redirects.
   * @param {string} name - The name of the URL paste.
   * @returns {Promise<string>} A promise that resolves to the final destination URL after redirection.
   */
  async getRedirectUrl(name) {
    const response = await fetch(`${this.baseURL}/u/${name}`);
    await this._handleResponse(response);
    // After following redirects, the response.url will be the final destination.
    return response.url;
  }

  /**
   * Gets the URL to the web page for displaying a paste.
   * This method constructs the URL without making a network request.
   * @param {string} name - The name of the paste.
   * @param {string} [decryptionKey] - The key to decrypt the paste in the browser.
   * @returns {string} The full URL to the display page.
   */
  getDisplayPageUrl(name, decryptionKey = null) {
    let url = `${this.baseURL}/d/${name}`;
    if (decryptionKey) {
      url += `#${decryptionKey}`;
    }
    return url;
  }
  
  /**
   * Fetches the metadata for a given paste.
   * @param {string} name - The name of the paste.
   * @returns {Promise<object>} A promise that resolves to the metadata JSON object.
   */
  async getMetadata(name) {
    const response = await fetch(`${this.baseURL}/m/${name}`);
    await this._handleResponse(response);
    return response.json();
  }

  /**
   * Fetches the rendered HTML from a markdown paste.
   * @param {string} name - The name of the markdown paste.
   * @returns {Promise<string>} A promise that resolves to the rendered HTML.
   */
  async getMarkdownAsHtml(name) {
    const response = await fetch(`${this.baseURL}/a/${name}`);
    await this._handleResponse(response);
    return response.text();
  }

  /**
   * Makes a HEAD request to get headers for a paste without fetching the body.
   * @param {string} name - The name of the paste.
   * @param {object} [options={}] - Same options as getPaste.
   * @returns {Promise<Headers>} A promise that resolves to the Headers object.
   */
  async headPaste(name, options = {}) {
    const { ext, filename, asAttachment, mime, lang } = options;
    let path = `/${name}`;
    if (filename) path += `/${filename}`;
    else if (ext) path += `.${ext}`;

    const params = new URLSearchParams();
    if (asAttachment) params.set('a', '');
    if (mime) params.set('mime', mime);
    if (lang) params.set('lang', lang);

    const url = `${this.baseURL}${path}${params.toString() ? '?' + params.toString() : ''}`;
    const response = await fetch(url, { method: 'HEAD' });
    await this._handleResponse(response);
    return response.headers;
  }

  /**
   * Uploads a new paste.
   * @param {string|Blob|File} content - The content of the paste (text or binary).
   * @param {object} [options={}] - Optional parameters for the upload.
   * @param {string} [options.expiration] - Expiration time (e.g., '300s', '1h', '25d').
   * @param {string} [options.password] - A password to manage the paste.
   * @param {string} [options.name] - A custom name for the paste (will be prefixed with ~).
   * @param {boolean} [options.private=false] - If true, generates a long, private name.
   * @param {string} [options.encryptionScheme] - The client-side encryption scheme used.
   * @param {string} [options.lang] - The language for syntax highlighting.
   * @returns {Promise<object>} A promise that resolves to the API response JSON.
   */
  async uploadPaste(content, options = {}) {
    const { expiration, password, name, isPrivate, encryptionScheme, lang } = options;
    const formData = new FormData();

    // The API expects 'c' for content. If content is a File object, its filename will be used.
    formData.append('c', content);

    if (expiration) formData.append('e', expiration);
    if (password) formData.append('s', password);
    if (name) formData.append('n', name);
    if (isPrivate) formData.append('p', '1');
    if (encryptionScheme) formData.append('encryption-scheme', encryptionScheme);
    if (lang) formData.append('lang', lang);

    const response = await fetch(this.baseURL + '/', {
      method: 'POST',
      body: formData,
    });
    
    await this._handleResponse(response);
    return response.json();
  }

  /**
   * Updates an existing paste.
   * @param {string} name - The name of the paste to update.
   * @param {string} password - The password for the paste.
   * @param {string|Blob|File} content - The new content for the paste.
   * @param {object} [options={}] - Optional parameters for the update.
   * @param {string} [options.expiration] - A new expiration time.
   * @param {string} [options.newPassword] - A new password for the paste.
   * @returns {Promise<object>} A promise that resolves to the API response JSON.
   */
  async updatePaste(name, password, content, options = {}) {
    const { expiration, newPassword } = options;
    const formData = new FormData();
    
    formData.append('c', content);
    if (expiration) formData.append('e', expiration);
    if (newPassword) formData.append('s', newPassword);

    const url = `${this.baseURL}/${name}:${password}`;
    const response = await fetch(url, {
      method: 'PUT',
      body: formData,
    });
    
    await this._handleResponse(response);
    return response.json();
  }

  /**
   * Deletes a paste.
   * @param {string} name - The name of the paste to delete.
   * @param {string} password - The password for the paste.
   * @returns {Promise<string>} A promise that resolves to the confirmation message from the API.
   */
  async deletePaste(name, password) {
    const url = `${this.baseURL}/${name}:${password}`;
    const response = await fetch(url, {
      method: 'DELETE',
    });
    
    await this._handleResponse(response);
    return response.text();
  }

  /**
   * Fetches the web page to edit a paste.
   * NOTE: This is likely for browser use, as it returns an HTML page.
   * @param {string} name - The name of the paste.
   * @param {string} password - The password for the paste.
   * @returns {Promise<string>} A promise that resolves to the HTML content of the edit page.
   */
  async getEditPage(name, password) {
    const url = `${this.baseURL}/${name}:${password}`;
    const response = await fetch(url);
    await this._handleResponse(response);
    return response.text();
  }
}
        // --- DATA (Injected by PHP) ---
        const structuredData = __JSON_DATA_PLACEHOLDER__;
        const clientInfoData = __CLIENT_INFO_PLACEHOLDER__;
        
        // --- DOM REFERENCES ---
        const modeSlider = document.getElementById('mode-slider');
        const modeButtons = document.querySelectorAll('.mode-btn');

        // Simple Mode
        const configTypeSelect = document.getElementById('configType');
        const ipTypeSelect = document.getElementById('ipType');
        const otherElementSelect = document.getElementById('otherElement');
        const searchBar = document.getElementById('searchBar');
        const resultArea = document.getElementById('resultArea');
        const subscriptionUrlInput = document.getElementById('subscriptionUrl');
        const copyButton = document.getElementById('copyButton');
        const qrcodeDiv = document.getElementById('qrcode');
        const clientInfoList = document.getElementById('client-info-list');
        const subscriptionDetailsContainer = document.getElementById('subscription-details-container');
        
        // DNA Modal
        const analyzeButton = document.getElementById('analyzeButton');
        const dnaModal = document.getElementById('dnaModal');
        const dnaModalCloseButton = document.getElementById('dnaModalCloseButton');
        
        // Message Box
        const messageBox = document.getElementById('messageBox');
        const messageBoxText = document.getElementById('messageBoxText');
        const messageBoxClose = document.getElementById('messageBoxClose');
        
        // Mode Containers
        const simpleModeContainer = document.getElementById('simpleModeContainer');
        const composerModeContainer = document.getElementById('composerModeContainer');
        const splitterModeContainer = document.getElementById('splitterModeContainer');
        const compilerModeContainer = document.getElementById('compilerModeContainer');
        
        // Composer Mode
        const composerSourceList = document.getElementById('composerSourceList');
        const composerProtocolFilters = document.getElementById('composerProtocolFilters');
        const generateCompositionButton = document.getElementById('generateCompositionButton');
        const composerResultArea = document.getElementById('composerResultArea');
        const composedResultText = document.getElementById('composedResultText');
        const copyComposedButton = document.getElementById('copyComposedButton');
        const downloadComposedButton = document.getElementById('downloadComposedButton');
	const composerStep2 = document.getElementById('composerStep2');
	const composerStep3 = document.getElementById('composerStep3');
        
        // Splitter Mode
        const splitterUrlInput = document.getElementById('splitterUrlInput');
        const splitSubscriptionButton = document.getElementById('splitSubscriptionButton');
        const splitterResultArea = document.getElementById('splitterResultArea');
        const splitterResultList = document.getElementById('splitterResultList');
        const chunkSizeContainer = document.getElementById('chunkSizeContainer');
        const chunkSizeInput = document.getElementById('chunkSizeInput');

        // Compiler Mode
        const compilerInputFormat = document.getElementById('compilerInputFormat');
        const compilerOutputFormat = document.getElementById('compilerOutputFormat');
        const compilerInputText = document.getElementById('compilerInputText');
        const convertButton = document.getElementById('convertButton');
        const compilerResultArea = document.getElementById('compilerResultArea');
        const compilerResultTitle = document.getElementById('compilerResultTitle');
        const compilerResultText = document.getElementById('compilerResultText');
        const copyConvertedButton = document.getElementById('copyConvertedButton');
        const downloadConvertedButton = document.getElementById('downloadConvertedButton');
	const shareConvertedButton = document.getElementById('shareConvertedButton');
	// --- Add for Compiler Wizard ---
const detectedFormatBadge = document.getElementById('detectedFormatBadge');
let detectedInputFormat = null; // To store the auto-detected format

        let charts = {};

        // --- CHART THEME LOGIC ---
        function updateChartDefaults() {
            const isDark = document.documentElement.classList.contains('dark');
            const gridColor = isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(203, 213, 225, 0.5)';
            const textColor = isDark ? '#cbd5e1' : '#475569';

            Chart.defaults.color = textColor;
            Chart.defaults.borderColor = gridColor;
            Chart.defaults.plugins.legend.labels.color = textColor;
        }

        // --- UTILITY FUNCTIONS ---
	    /**
 * Analyzes a string to detect its configuration format.
 * @param {string} text - The raw input text.
 * @returns {string|null} The detected format ('clash', 'singbox', 'base64', 'uri_list') or null.
 */
function detectInputFormat(text) {
    const trimmedText = text.trim();
    
    // 1. Check for plain URI lists
    if (trimmedText.startsWith('vless://') || trimmedText.startsWith('vmess://') || trimmedText.startsWith('trojan://') || trimmedText.startsWith('ss://')) {
        return 'uri_list';
    }

    // 2. Check for JSON (Sing-box)
    try {
        const parsed = JSON.parse(trimmedText);
        if (parsed && typeof parsed === 'object' && parsed.outbounds) {
            return 'singbox';
        }
    } catch (e) { /* Not JSON */ }

    // 3. Check for YAML (Clash)
    try {
        // A simple heuristic: valid Clash configs usually have 'proxies:'
        if (trimmedText.includes('proxies:') || trimmedText.includes('proxy-groups:')) {
            const parsed = jsyaml.load(trimmedText);
            if (parsed && typeof parsed === 'object') {
                return 'clash';
            }
        }
    } catch (e) { /* Not YAML */ }

    // 4. Check for Base64
    // Must not contain spaces and only valid Base64 chars
    const cleanedText = text.replace(/\s/g, '');
    if (/^[A-Za-z0-9+/=]+$/.test(cleanedText)) {
         try {
            // Final check: does it decode to something that looks like a URI list?
            const decoded = atob(cleanedText);
            if (decoded.includes('://')) {
                return 'base64';
            }
         } catch(e) { /* Not valid Base64 after all */ }
    }

    return null; // Could not determine format
}
/**
 * Uploads content to shz.al and shows the user the shareable URL.
 * @param {string} contentToUpload The text content to upload.
 * @param {HTMLElement} buttonElement The button that was clicked.
 */
async function handleShare(contentToUpload, buttonElement) {
    if (!contentToUpload) {
        showMessageBox('There is nothing to share.');
        return;
    }

    const originalButtonText = buttonElement.innerHTML;
    buttonElement.disabled = true;
    buttonElement.innerHTML = `<i data-lucide="loader-2" class="animate-spin w-5 h-5"></i> Sharing...`;
    lucide.createIcons();

    try {
        const client = new ShzAlClient();
        // Upload as a private paste that expires in 7 days
        const result = await client.uploadPaste(contentToUpload, {
            expiration: '7d',
            isPrivate: true
        });

        // Prompt the user with the URL, which is easy to copy.
        prompt('Share this URL (expires in 7 days):', result.url);

    } catch (error) {
        console.error('Share failed:', error);
        showMessageBox(`Upload failed: ${error.message}`);
    } finally {
        // Restore the button to its original state
        buttonElement.disabled = false;
        buttonElement.innerHTML = originalButtonText;
        lucide.createIcons();
    }
}
        const countryCodeMap = { US: 'United States', SG: 'Singapore', JP: 'Japan', KR: 'S. Korea', DE: 'Germany', NL: 'Netherlands', GB: 'UK', FR: 'France', CA: 'Canada', AU: 'Australia', HK: 'Hong Kong', TW: 'Taiwan', RU: 'Russia', IN: 'India', TR: 'Turkey', IR: 'Iran', AE: 'UAE' };
        function getCountryName(code) { return countryCodeMap[code.toUpperCase()] || code.toUpperCase(); }
        function getFlagEmoji(countryCode) { if (!/^[A-Z]{2}$/.test(countryCode)) return '🏳️'; return String.fromCodePoint(...countryCode.toUpperCase().split('').map(char => 127397 + char.charCodeAt())); }
        function showMessageBox(message) { messageBoxText.textContent = message; messageBox.classList.remove('hidden'); }
        function formatDisplayName(name) {
            let flag = '';
            const countryCodeMatch = name.match(/\[([A-Z]{2})\]|^([A-Z]{2})[-_]|\b([A-Z]{2})\b/);
            if (countryCodeMatch) {
                const code = countryCodeMatch[1] || countryCodeMatch[2] || countryCodeMatch[3];
                if (code) flag = getFlagEmoji(code);
            }
            const specialReplacements = { 'ss': 'SHADOWSOCKS' };
            const uppercaseTypes = ['mix', 'vless', 'vmess', 'trojan', 'ssr', 'ws', 'grpc', 'reality', 'hy2', 'hysteria2', 'tuic', 'xhttp'];
            const parts = name.replace(/\//g, '-').split(/[-_]/).filter(p => p !== '');
            const displayNameParts = parts.map((part) => {
                if (/^[A-Z]{2}$/.test(part)) return part.toUpperCase();
                const lowerPart = part.toLowerCase();
                if (specialReplacements[lowerPart]) return specialReplacements[lowerPart];
                if (uppercaseTypes.includes(lowerPart)) return part.toUpperCase();
                return part.charAt(0).toUpperCase() + part.slice(1).toLowerCase();
            });
            const textName = displayNameParts.join(' ');
            return flag ? `${flag} ${textName.trim()}` : textName.trim();
        }
        /**
         * Fetches a URL, attempting a direct request first and falling back
         * to a CORS proxy if a network error (likely CORS) occurs.
         * @param {string} url The URL to fetch.
         * @returns {Promise<Response>} A promise that resolves with the response.
         */
        async function fetchWithCorsFallback(url) {
            try {
                // First, try a direct fetch.
                const directResponse = await fetch(url);
                return directResponse;
            } catch (error) {
                // A TypeError on fetch is a strong indicator of a CORS issue.
                if (error instanceof TypeError) {
                    console.warn(`Direct fetch for ${url} failed (likely CORS). Retrying with proxy.`);
                    const proxiedUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`;
                    const proxiedResponse = await fetch(proxiedUrl);
                    return proxiedResponse;
                }
                // If it's not a TypeError, it's a different issue, so re-throw it.
                throw error;
            }
        }

        // --- CORE NAVIGATION LOGIC ---
        function switchMode(activeMode) {
            const allModes = {
                simple: { container: simpleModeContainer, index: 0 },
                composer: { container: composerModeContainer, index: 1 },
                splitter: { container: splitterModeContainer, index: 2 },
                compiler: { container: compilerModeContainer, index: 3 }
            };

            // 1. Move the slider
            const activeIndex = allModes[activeMode].index;
            if (modeSlider) {
                modeSlider.style.transform = `translateX(${activeIndex * 100}%)`;
            }

            // 2. Hide all containers and result areas
            Object.values(allModes).forEach(mode => mode.container.classList.add('hidden'));
            resultArea.classList.add('hidden');
            composerResultArea.classList.add('hidden');
            splitterResultArea.classList.add('hidden');
            compilerResultArea.classList.add('hidden');
            
            // 3. Highlight the active button's text
            modeButtons.forEach(btn => btn.classList.remove('text-indigo-600'));
            const activeButton = document.querySelector(`.mode-btn[data-id='${activeMode}']`);
            if(activeButton) {
                activeButton.classList.add('text-indigo-600');
            }

            // 4. Show the active container
            if (allModes[activeMode]) {
                allModes[activeMode].container.classList.remove('hidden');
	        if (activeMode === 'simple' && ipTypeSelect.value) {
                    resultArea.classList.remove('hidden');
                }
            }
        }

        // --- SIMPLE MODE & DNA LOGIC (largely unchanged) ---
        function populateSelect(selectElement, sortedKeys, defaultOptionText) { selectElement.innerHTML = `<option value="">${defaultOptionText}</option>`; sortedKeys.forEach(key => { const option = document.createElement('option'); option.value = key; option.textContent = formatDisplayName(key); selectElement.appendChild(option); }); }
        function resetSelect(selectElement, defaultText) { selectElement.innerHTML = `<option value="">${defaultText}</option>`; selectElement.disabled = true; }
        
        function updateQRCode(element, url) {
            element.innerHTML = '';
            const MAX_QR_CODE_LENGTH = 2500;
            if (!url) return;
            if (url.length > MAX_QR_CODE_LENGTH) {
                element.innerHTML = `<div class="w-[128px] h-[128px] flex items-center justify-center text-center text-xs text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-700 rounded-md p-2">Content is too large for a QR code. Please copy the URL.</div>`;
                return;
            }
            try { new QRCode(element, { text: url, width: 128, height: 128, colorDark: "#000000", colorLight: "#FFFFFF", correctLevel: QRCode.CorrectLevel.H }); } catch (error) { console.error('QR code init failed:', error); }
        }

        function updateClientInfo(coreType) {
            clientInfoList.innerHTML = '';
            const platforms = clientInfoData[coreType];
            if (!platforms || Object.keys(platforms).length === 0) { clientInfoList.closest('#client-info-container').classList.add('hidden'); return; }
            clientInfoList.closest('#client-info-container').classList.remove('hidden');
            Object.entries(platforms).forEach(([platformName, clients]) => {
                if (clients.length > 0) {
                    const platformContainer = document.createElement('div');
                    const titleDiv = document.createElement('div');
                    titleDiv.className = 'flex items-center gap-2 text-sm font-semibold text-slate-600 dark:text-slate-400 mb-2';
                    const iconName = { windows: 'monitor', macos: 'apple', android: 'smartphone', ios: 'tablet', linux: 'terminal' }[platformName.toLowerCase()] || 'box';
                    titleDiv.innerHTML = `<i data-lucide="${iconName}" class="w-4 h-4 text-slate-500 dark:text-slate-400"></i><span>${platformName.charAt(0).toUpperCase() + platformName.slice(1)}</span>`;
                    platformContainer.appendChild(titleDiv);
                    const linksContainer = document.createElement('div');
                    linksContainer.className = 'flex flex-col gap-2';
                    clients.forEach(client => { linksContainer.innerHTML += `<a href="${client.url}" target="_blank" rel="noopener noreferrer" class="flex items-center justify-between p-2.5 bg-slate-100 dark:bg-slate-700 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors duration-200 text-slate-700 dark:text-slate-300 hover:text-indigo-600 dark:hover:text-indigo-400"><span class="font-medium text-sm">${client.name}</span><i data-lucide="download" class="w-4 h-4 text-slate-500 dark:text-slate-400"></i></a>`; });
                    platformContainer.appendChild(linksContainer);
                    clientInfoList.appendChild(platformContainer);
                }
            });
            lucide.createIcons();
        }
        function updateOtherElementOptions() {
            const selectedConfigType = configTypeSelect.value;
            const selectedIpType = ipTypeSelect.value;
            const searchTerm = searchBar.value.toLowerCase();
            
            resetSelect(otherElementSelect, 'Select Subscription');
            subscriptionDetailsContainer.classList.add('hidden');
            
            if (selectedIpType && structuredData[selectedConfigType]?.[selectedIpType]) {
                const allElements = structuredData[selectedConfigType][selectedIpType];
                const filteredAndSortedKeys = Object.keys(allElements)
                    .filter(key => formatDisplayName(key).toLowerCase().includes(searchTerm))
                    .sort((a, b) => a.localeCompare(b));
                    
                populateSelect(otherElementSelect, filteredAndSortedKeys, filteredAndSortedKeys.length > 0 ? 'Select Subscription' : 'No matches found');
                otherElementSelect.disabled = false;
            }
        }
                function getUniversalDna(content, coreType) {
            const dna = { protocols: {}, countries: {}, transports: {}, security: {tls: 0, reality: 0, insecure: 0}, total: 0 };
            
            const processNodeDetails = (protocol, name, transport, security) => {
                if (!protocol || !name) return;
                dna.total++;
                const lowerName = name.toLowerCase();

                // Normalize protocol names
                let normalizedProtocol = protocol.toLowerCase();
                if (normalizedProtocol === 'ss') normalizedProtocol = 'shadowsocks';
                if (normalizedProtocol === 'hysteria2') normalizedProtocol = 'hy2';

                dna.protocols[normalizedProtocol] = (dna.protocols[normalizedProtocol] || 0) + 1;
                
                let normalizedTransport = transport ? transport.toLowerCase() : 'tcp';
                dna.transports[normalizedTransport] = (dna.transports[normalizedTransport] || 0) + 1;
                
                if (security === 'tls') dna.security.tls++;
                else if (security === 'reality') dna.security.reality++;
                else dna.security.insecure++;

                const countryMatch = lowerName.match(/\[([a-z]{2})\]|\b([a-z]{2})\b|([a-z]{2})[-_]/);
                if (countryMatch) {
                    const code = (countryMatch[1] || countryMatch[2] || countryMatch[3]).toUpperCase();
                    dna.countries[code] = (dna.countries[code] || 0) + 1;
                }
            };
            
            try {
                switch (coreType.toLowerCase()) {
                    case 'clash':
                    case 'meta':
                        const parsedYaml = jsyaml.load(content);
                        if (parsedYaml && Array.isArray(parsedYaml.proxies)) {
                            parsedYaml.proxies.forEach(p => {
                                let security = 'insecure';
                                if (p.tls) security = 'tls';
                                if (p['reality-opts']) security = 'reality';
                                processNodeDetails(p.type, p.name, p.network || 'tcp', security);
                            });
                        }
                        break;

                    case 'singbox':
                        const parsedJson = JSON.parse(content);
                        const utilityTypes = ['selector', 'urltest', 'direct', 'block', 'dns'];
                        if (parsedJson && Array.isArray(parsedJson.outbounds)) {
                            parsedJson.outbounds
                                .filter(o => o.type && !utilityTypes.includes(o.type))
                                .forEach(o => {
                                    let security = 'insecure';
                                    if (o.tls?.enabled) {
                                        security = o.tls.reality?.enabled ? 'reality' : 'tls';
                                    }
                                    processNodeDetails(o.type, o.tag, o.transport?.type || 'tcp', security);
                                });
                        }
                        break;
                    
                    case 'xray':
                    case 'location':
                    case 'channel':
                    case 'surfboard': // Surfboard is often base64
                    default: // Fallback for base64 with expanded regex
                        const decoded = atob(content);
                        const vmessRegex = /^vmess:\/\/(.+)$/;
                        const standardRegex = /^(vless|trojan|ss|hy2|tuic|hysteria|hysteria2):\/\/([^@]+@)?([^:?#]+):(\d+)\??([^#]+)?#(.+)$/;

                        decoded.split(/[\n\r]+/).forEach(line => {
                            line = line.trim();
                            if (!line) return;
                            
                            let match;
                            if (match = line.match(vmessRegex)) {
                                try {
                                    const vmessConfig = JSON.parse(atob(match[1]));
                                    processNodeDetails(
                                        'vmess',
                                        vmessConfig.ps || 'vmess_node',
                                        vmessConfig.net || 'tcp',
                                        vmessConfig.tls || 'insecure'
                                    );
                                } catch (e) { /* Malformed vmess, skip */ }
                            } else if (match = line.match(standardRegex)) {
                                const protocol = match[1];
                                const params = new URLSearchParams(match[5] || '');
                                const name = decodeURIComponent(match[6] || `${protocol}_node`);
                                processNodeDetails(
                                    protocol,
                                    name,
                                    params.get('type') || 'tcp',
                                    params.get('security') || 'insecure'
                                );
                            }
                        });
                        break;
                }
            } catch (e) {
                console.error(`Parsing failed for type ${coreType}:`, e);
                throw new Error(`Could not parse subscription. It may be invalid or malformed for the '${coreType}' type.`);
            }
            return dna;
        }

        analyzeButton.addEventListener('click', async () => {
            const url = subscriptionUrlInput.value;
            if (!url) { showMessageBox('Please select a subscription URL first.'); return; }
            
            const modalContent = document.getElementById('dnaModalContent');
            document.getElementById('dnaLoadingState').classList.remove('hidden');
            document.getElementById('dnaResultsContainer').classList.add('hidden');
            document.getElementById('modalSubscriptionName').textContent = `For: ${formatDisplayName(otherElementSelect.value)}`;
            dnaModal.classList.remove('hidden');
            setTimeout(() => modalContent.classList.remove('scale-95', 'opacity-0'), 50);

            try {
                const response = await fetch(url);
                if (!response.ok) throw new Error(`Fetch failed (${response.status})`);
                const content = await response.text();
                const dna = getUniversalDna(content, ipTypeSelect.value);

                if (dna.total === 0) throw new Error('No compatible proxy nodes found to analyze.');
                Object.values(charts).forEach(chart => { if (chart) chart.destroy(); });
                
                charts.protocol = new Chart(document.getElementById('protocolChart'), {
                    type: 'doughnut', data: { labels: Object.keys(dna.protocols), datasets: [{ data: Object.values(dna.protocols), backgroundColor: ['#4f46e5', '#16a34a', '#f97316', '#0ea5e9', '#dc2626', '#d946ef', '#65a30d'], borderWidth: 0 }] },
                    options: { responsive: true, cutout: '70%', plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, padding: 15 }}}}
                });
                document.querySelector('#protocolTotal div span:first-child').textContent = dna.total;

                charts.security = new Chart(document.getElementById('securityChart'), {
                    type: 'doughnut', data: { labels: ['TLS', 'REALITY', 'Insecure'], datasets: [{ data: [dna.security.tls, dna.security.reality, dna.security.insecure], backgroundColor: ['#34d399', '#a78bfa', '#fbbf24'], borderWidth: 0 }] },
                    options: { responsive: true, cutout: '70%', plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, padding: 15 }}}}
                });

                const sortedCountries = Object.entries(dna.countries).sort((a, b) => b[1] - a[1]).slice(0, 7);
                charts.country = new Chart(document.getElementById('countryBarChart'), {
                    type: 'bar', data: { labels: sortedCountries.map(c => `${getFlagEmoji(c[0])} ${getCountryName(c[0])}`), datasets: [{ label: '# Nodes', data: sortedCountries.map(c => c[1]), backgroundColor: '#60a5fa', borderRadius: 4 }] },
                    options: { indexAxis: 'y', responsive: true, plugins: { legend: { display: false } } }
                });

                const sortedTransports = Object.entries(dna.transports).sort((a, b) => b[1] - a[1]).slice(0, 7);
                charts.transport = new Chart(document.getElementById('transportChart'), {
                    type: 'bar', data: { labels: sortedTransports.map(t => t[0]), datasets: [{ label: '# Nodes', data: sortedTransports.map(t => t[1]), backgroundColor: '#f472b6', borderRadius: 4 }] },
                    options: { indexAxis: 'y', responsive: true, plugins: { legend: { display: false } } }
                });
                
                document.getElementById('dnaLoadingState').classList.add('hidden');
                document.getElementById('dnaResultsContainer').classList.remove('hidden');
            } catch (error) {
                const modalContent = document.getElementById('dnaModalContent');
                modalContent.classList.add('scale-95', 'opacity-0');
                setTimeout(() => dnaModal.classList.add('hidden'), 200);
                showMessageBox(`Analysis Failed: ${error.message}`);
            }
        });

        dnaModalCloseButton.addEventListener('click', () => {
            const modalContent = document.getElementById('dnaModalContent');
            modalContent.classList.add('scale-95', 'opacity-0');
            setTimeout(() => dnaModal.classList.add('hidden'), 200);
            Object.values(charts).forEach(chart => { if (chart) chart.destroy(); });
        });

        // --- COMPOSER LOGIC ---
        function populateComposerSources() {
    composerSourceList.innerHTML = ''; // Clear previous content

    // Define the specific sub-folders we want to use from the "Standard" category
    const allowedSubFolders = ['location', 'channel', 'xray'];

    // This object will hold the final, grouped sources
    const curatedGroups = {
        Locations: [],
        Channels: [],
        Types: [] // For the 'xray' folder
    };

    // Only process the "Standard" category from our main data
    const standardCategory = structuredData['Standard'];
    if (standardCategory) {
        Object.entries(standardCategory).forEach(([subFolderName, subscriptions]) => {
            // Check if this sub-folder is one we're allowed to use
            if (allowedSubFolders.includes(subFolderName.toLowerCase())) {
                
                Object.entries(subscriptions).forEach(([name, url]) => {
                    const sourceItem = { name, url };
                    
                    // Sort the item into the correct curated group
                    if (subFolderName === 'location') {
                        curatedGroups.Locations.push(sourceItem);
                    } else if (subFolderName === 'channel') {
                        curatedGroups.Channels.push(sourceItem);
                    } else if (subFolderName === 'xray') {
                        curatedGroups.Types.push(sourceItem);
                    }
                });
            }
        });
    }

    // A helper function to build the HTML for each group
    const buildGroupUI = (title, sources, parentElement) => {
        if (sources.length === 0) {
            return; // Don't build a section if there are no sources for it
        }

        // Sort sources alphabetically within the group
        sources.sort((a, b) => a.name.localeCompare(b.name));
        
        const groupId = title.replace(/[^a-zA-Z0-9]/g, '-'); // e.g., "Main-Types"

        const categoryContainer = document.createElement('div');
        categoryContainer.className = 'mb-6';

        categoryContainer.innerHTML = `
            <div class="flex justify-between items-center mb-3 pb-2 border-b border-slate-200 dark:border-slate-700">
                <label class="font-semibold text-slate-700 dark:text-slate-300">${title}</label>
                <button data-target-list="source-list-${groupId}" class="composer-select-all-btn text-xs font-semibold text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300">Select All</button>
            </div>
            <!-- THIS IS THE SCROLLABLE CONTAINER -->
            <div id="source-list-${groupId}" class="composer-list space-y-2 max-h-40 overflow-y-auto pr-2">
                <!-- Checkboxes will be inserted here -->
            </div>
        `;
        
        const listDiv = categoryContainer.querySelector(`#source-list-${groupId}`);
        sources.forEach(source => {
            const checkboxDiv = document.createElement('div');
            checkboxDiv.className = 'flex items-center';
            checkboxDiv.innerHTML = `
                <input type="checkbox" id="source_${source.url}" data-url="${source.url}" class="composer-source h-4 w-4 rounded border-slate-300 dark:border-slate-500 text-indigo-600 focus:ring-indigo-500">
                <label for="source_${source.url}" class="ml-2 block text-sm text-slate-900 dark:text-slate-300 truncate" title="${source.name}">${formatDisplayName(source.name)}</label>
            `;
            listDiv.appendChild(checkboxDiv);
        });
        
        parentElement.appendChild(categoryContainer);
    };
    
    // Build the UI for each of our curated groups
    buildGroupUI('Locations (by Country)', curatedGroups.Locations, composerSourceList);
    buildGroupUI('Channels (by Provider)', curatedGroups.Channels, composerSourceList);
    buildGroupUI('Types (by Protocol)', curatedGroups.Types, composerSourceList);
    
    // This event listener for the "Select All" buttons remains the same as before,
    // as it is generic enough to handle the new structure.
    composerSourceList.addEventListener('click', (e) => {
        if (e.target.classList.contains('composer-select-all-btn')) {
            const button = e.target;
            const targetListId = button.dataset.targetList;
            const listContainer = document.getElementById(targetListId);
            const checkboxes = listContainer.querySelectorAll('input[type="checkbox"]');
            const isSelectAll = button.textContent === 'Select All';
            
            checkboxes.forEach(cb => {
                if (cb.checked !== isSelectAll) {
                    cb.checked = isSelectAll;
                }
            });
            
            button.textContent = isSelectAll ? 'Deselect All' : 'Select All';
            composerSourceList.dispatchEvent(new Event('change', { bubbles: true }));
        }
    });

    // Protocol Filters section remains unchanged
    const protocols = ['VLESS', 'VMess', 'Trojan', 'Shadowsocks', 'REALITY', 'Hysteria2'];
    composerProtocolFilters.innerHTML = protocols.map(p => `
        <div class="flex items-center">
            <input type="checkbox" id="proto_${p.toLowerCase()}" data-protocol="${p.toLowerCase()}" class="composer-protocol h-4 w-4 rounded border-slate-300 dark:border-slate-500 text-indigo-600 focus:ring-indigo-500">
            <label for="proto_${p.toLowerCase()}" class="ml-2 block text-sm text-slate-900 dark:text-slate-300">${p}</label>
        </div>
    `).join('');
}
        function handleSelectAll(e) {
            const button = e.target;
            const targetId = button.dataset.target;
            const container = document.getElementById(targetId);
            const checkboxes = container.querySelectorAll('input[type="checkbox"]');
            const isSelectAll = button.textContent === 'Select All';
            checkboxes.forEach(cb => cb.checked = isSelectAll);
            button.textContent = isSelectAll ? 'Deselect All' : 'Select All';
        }
        
        // ====================================================================
        // NEW, ROBUST PARSING LOGIC (Directly converted from your PHP)
        // ====================================================================

        /**
         * Parses a configuration link into an object, mirroring the PHP logic.
         * @param {string} uri The configuration link.
         * @returns {object|null} The parsed configuration or null on failure.
         */
        function configParse(uri) {
            try {
                const protocolMatch = uri.match(/^([a-z0-9]+):\/\//);
                if (!protocolMatch) return null;
                const protocol = protocolMatch[1];

                switch (protocol) {
                    case 'vmess': {
                        const b64 = uri.substring(8);
                        const decoded = JSON.parse(atob(b64));
                        decoded.protocol = 'vmess';
                        return decoded;
                    }

                    case 'vless':
                    case 'trojan':
                    case 'tuic':
                    case 'hy2': 
                    case 'hysteria2': {
                        let url;
                        try {
                            url = new URL(uri);
                        } catch (e) {
                            console.warn("Skipping malformed URI:", uri, e.message);
                            return null;
                        }

                        const params = {};
                        url.searchParams.forEach((value, key) => {
                            params[key.toLowerCase()] = value;
                        });

                        const output = {
                            protocol: protocol,
                            username: decodeURIComponent(url.username),
                            hostname: url.hostname,
                            port: parseInt(url.port, 10),
                            params: params,
                            hash: decodeURIComponent(url.hash.substring(1)) || `PSG_${Math.random().toString(36).substring(2, 8)}`,
                        };

                        if (protocol === 'tuic') {
                            output.password = decodeURIComponent(url.password);
                        }
                        return output;
                    }

                    case 'ss': {
                        let url;
                        try {
                           url = new URL(uri);
                        } catch (e) {
                            console.warn("Skipping malformed SS URI:", uri, e.message);
                            return null;
                        }

                        let userInfo = decodeURIComponent(url.username);
                        // Check if the user info part might be base64 encoded
                        try {
                            // A common pattern is base64(method:password)
                            const decodedUserInfo = atob(userInfo);
                            if (decodedUserInfo.includes(':')) {
                                userInfo = decodedUserInfo;
                            }
                        } catch (e) {
                            // Not valid base64, proceed as is
                        }
                        
                        if (!userInfo.includes(':')) return null;

                        const [method, password] = userInfo.split(':', 2);

                        return {
                            protocol: 'ss',
                            encryption_method: method,
                            password: password,
                            hostname: url.hostname,
                            port: parseInt(url.port, 10),
                            hash: decodeURIComponent(url.hash.substring(1)) || `PSG_${Math.random().toString(36).substring(2, 8)}`,
                        };
                    }
                    default:
                        return null;
                }
            } catch (e) {
                console.error("Fatal error parsing config:", uri, e);
                return null;
            }
        }

        function generateBase64Output(nodes) {
            // This function now correctly uses the original URI stored on each node object.
            // The 'allNodes' array stores objects with a 'parsed' property and the original 'uri'.
            const uris = nodes.map(node => node.parsed.uri || node.uri).filter(Boolean);
            return btoa(uris.join('\n'));
        }

        async function generateClashOutput(nodes) {
            const templateURL = 'https://raw.githubusercontent.com/yasi-python/PSG/main/templates/clash.yaml';
            const response = await fetch(templateURL);
            if (!response.ok) throw new Error('Could not fetch Clash template.');
            let templateContent = await response.text();
            
            // 1. Convert all parsed nodes into the correct Clash JSON object format
            const proxyDetails = nodes.map(node => {
                const p = node.parsed;
                let clashNode = null;
                switch(p.protocol) {
                    case 'vmess': clashNode = { type: 'vmess', name: p.ps, server: p.add, port: parseInt(p.port), uuid: p.id, alterId: parseInt(p.aid) || 0, cipher: 'auto', udp: true, network: p.net, 'ws-opts': p.net === 'ws' ? { path: (p.path || '/').split('?')[0], headers: { Host: p.host || p.add } } : undefined }; break;
                    case 'vless': clashNode = { type: 'vless', name: p.hash, server: p.hostname, port: p.port, uuid: p.username, udp: true, network: p.params.type, tls: p.params.security === 'tls' || p.params.security === 'reality', 'client-fingerprint': 'chrome', 'ws-opts': p.params.type === 'ws' ? { path: p.params.path } : undefined, 'reality-opts': p.params.security === 'reality' ? { 'public-key': p.params.pbk, 'short-id': p.params.sid } : undefined, 'servername': p.params.sni }; break;
                    case 'trojan': clashNode = { type: 'trojan', name: p.hash, server: p.hostname, port: p.port, password: p.username, udp: true, sni: p.params.sni }; break;
                    case 'ss': clashNode = { type: 'ss', name: p.hash, server: p.hostname, port: p.port, cipher: p.encryption_method, password: p.password, udp: true }; break;
                }
                // Clean up any undefined properties from the final object
                if (clashNode) {
                    Object.keys(clashNode).forEach(key => clashNode[key] === undefined && delete clashNode[key]);
                }
                return clashNode;
            }).filter(Boolean);

            // 2. Format the proxies section as single-line JSON strings
            const proxiesJSONLines = proxyDetails.map(p => `  - ${JSON.stringify(p)}`).join('\n');

            // 3. Format the proxy names for the proxy-group
            const proxyNamesYAML = proxyDetails.map(p => `      - '${p.name.replace(/'/g, "''")}'`).join('\n'); // Safely quote names

            // 4. Replace placeholders
            templateContent = templateContent.replace('##PROXIES##', proxiesJSONLines);
            templateContent = templateContent.replace('##PROXY_NAMES##', proxyNamesYAML);
            
            return templateContent;
        }
        
        async function generateSingboxOutput(nodes) {
            const templateURL = 'https://raw.githubusercontent.com/yasi-python/PSG/main/templates/structure.json';
            const response = await fetch(templateURL);
            if (!response.ok) throw new Error('Could not fetch Sing-box template.');
            const templateString = await response.text();
            const jsonString = templateString.replace(/\\"|"(?:\\"|[^"])*"|(\/\/.*|\/\*[\s\S]*?\*\/)/g, (m, g) => g ? "" : m);
            const templateJson = JSON.parse(jsonString);

            const ALLOWED_ADVANCED_TRANSPORTS = ['http', 'ws', 'quic', 'grpc', 'httpupgrade'];

            const outbounds = nodes.map(node => {
                const p = node.parsed;
                const transportType = (p.net || p.params?.type || 'tcp').toLowerCase();
                const isTlsEnabled = p.tls === 'tls' || p.params?.security === 'tls' || p.params?.security === 'reality';

                // --- NEW REFINED FILTERING LOGIC ---
                // Keep the node if:
                // 1. It uses an allowed advanced transport.
                // OR
                // 2. Its transport is 'tcp' AND it's using TLS.
                if (p.protocol === 'hy2' || p.protocol === 'hysteria2') {
	            // This is a valid node, do nothing and let it pass the filter.
	        } else if (!ALLOWED_ADVANCED_TRANSPORTS.includes(transportType) && !(transportType === 'tcp' && isTlsEnabled)) {
	            return null; // Discard other plain, unencrypted TCP and unsupported transports.
	        }

                let transport = null;
                // Only create a transport object for the advanced, non-tcp types
                if (transportType !== 'tcp') {
                    transport = { type: transportType };
                    switch (transportType) {
                        case 'ws':
                        case 'http':
                            transport.path = (p.path || p.params?.path || '/').split('?')[0];
                            transport.headers = { Host: p.host || p.params?.host || p.hostname };
                            break;
                        case 'grpc':
                            transport.service_name = p.params?.serviceName || '';
                            break;
                        case 'httpupgrade':
                             transport.path = p.params?.path || '/';
                             transport.headers = { Host: p.params?.host || p.hostname };
                             break;
                    }
                }

                let singboxNode = null;
                const tlsSettings = isTlsEnabled ? { 
                    enabled: true, 
                    server_name: p.sni || p.params?.sni, 
                    reality: p.params?.security === 'reality' ? { enabled: true, public_key: p.params.pbk, short_id: p.params.sid } : undefined 
                } : undefined;

                switch (p.protocol) {
                    case 'vmess': 
                        singboxNode = { tag: p.ps, type: 'vmess', server: p.add, server_port: parseInt(p.port), uuid: p.id, alter_id: parseInt(p.aid), security: 'auto', tls: tlsSettings };
                        break;
                    case 'vless': 
                        singboxNode = { tag: p.hash, type: 'vless', server: p.hostname, server_port: p.port, uuid: p.username, tls: tlsSettings }; 
                        break;
                    case 'trojan': 
                        singboxNode = { tag: p.hash, type: 'trojan', server: p.hostname, server_port: p.port, password: p.username, tls: tlsSettings }; 
                        break;
                    case 'ss':
                        singboxNode = { tag: p.hash, type: 'shadowsocks', server: p.hostname, server_port: p.port, method: p.encryption_method, password: p.password, tls: tlsSettings };
                        break;
	            case 'hy2':
	            case 'hysteria2':
                        singboxNode = { tag: p.hash, type: 'hysteria2', server: p.hostname, server_port: p.port, password: p.username, obfs: p.params.obfs ? { type: p.params.obfs, password: p.params['obfs-password'] || '' } : undefined, tls: { enabled: true, server_name: p.params.sni, insecure: p.params.insecure === '1' || p.params.insecure === 'true' } };
	                if (singboxNode.obfs === undefined) { delete singboxNode.obfs; }
	                break;
                }
                
                if (singboxNode && transport) {
                    singboxNode.transport = transport;
                }
                
                return singboxNode;

            }).filter(Boolean);

            if (outbounds.length === 0) {
                throw new Error("No nodes with supported Sing-box transports (WebSocket, gRPC, TLS, etc.) were found in the source.");
            }

            const urlTestGroup = templateJson.outbounds.find(o => o.tag === 'auto');
            if (urlTestGroup) { urlTestGroup.outbounds = outbounds.map(o => o.tag); }
            templateJson.outbounds.unshift(...outbounds);
            return JSON.stringify(templateJson, null, 2);
        }

        async function handleGenerateComposition() {
            const button = generateCompositionButton;
            const buttonText = document.getElementById('generateCompositionButtonText');
            button.disabled = true;
            buttonText.textContent = 'Generating...';
            composerResultArea.classList.add('hidden');

            const selectedCheckboxes = document.querySelectorAll('.composer-source:checked');
            if (selectedCheckboxes.length === 0) {
                showMessageBox('Please select at least one proxy source.');
                button.disabled = false; buttonText.textContent = 'Generate Composed Subscription'; return;
            }

            const urls = Array.from(selectedCheckboxes).map(cb => cb.dataset.url);
            let allNodes = [];
            const responses = await Promise.allSettled(urls.map(url => fetch(url)));
            
            for (const response of responses) {
                if (response.status === 'fulfilled' && response.value.ok) {
                    try {
                        const decoded = atob(await response.value.text());
                        const uris = decoded.split(/[\n\r]+/).filter(Boolean);
                        uris.forEach(uri => {
                            const parsed = configParse(uri);
                            if (parsed) {
                                const name = parsed.ps || parsed.hash;
                                const countryMatch = name.match(/\[([A-Z]{2})\]|\b([A-Z]{2})\b/i);
                                // The crucial change is to store the original URI here.
                                allNodes.push({
                                    uri: uri, // Store the original URI
                                    parsed: parsed,
                                    protocol: parsed.protocol,
                                    name: name,
                                    country: countryMatch ? (countryMatch[1] || countryMatch[2])?.toUpperCase() : null,
                                });
                            }
                        });
                    } catch (e) { console.warn(`Failed to process source:`, e); }
                }
            }
            
            const countryFilter = document.getElementById('filterCountry').value.toUpperCase().split(',').map(c => c.trim()).filter(Boolean);
            const protocolFilter = Array.from(document.querySelectorAll('.composer-protocol:checked')).map(cb => cb.dataset.protocol);
            let filteredNodes = allNodes;
            if (countryFilter.length > 0) { filteredNodes = filteredNodes.filter(node => node.country && countryFilter.includes(node.country)); }
            if (protocolFilter.length > 0) { filteredNodes = filteredNodes.filter(node => node.protocol && protocolFilter.includes(node.protocol)); }

            filteredNodes.sort(() => 0.5 - Math.random());
            const limit = parseInt(document.getElementById('nodeLimit').value, 10) || 50;
            const finalNodes = filteredNodes.slice(0, limit);

            if (finalNodes.length === 0) {
                showMessageBox('No nodes found matching your criteria. Try different filters or sources.');
                button.disabled = false; buttonText.textContent = 'Generate Composed Subscription'; return;
            }

            const targetClient = document.getElementById('composerTargetClient').value;
            let outputContent = '', fileExtension = 'txt';

            try {
                if (targetClient === 'clash') { outputContent = await generateClashOutput(finalNodes); fileExtension = 'yaml'; }
                else if (targetClient === 'singbox') { outputContent = await generateSingboxOutput(finalNodes); fileExtension = 'json'; }
                else { outputContent = generateBase64Output(finalNodes); }
            } catch (e) {
                showMessageBox(`Error generating config: ${e.message}`);
                console.error(e);
                button.disabled = false; buttonText.textContent = 'Generate Composed Subscription'; return;
            }
            
            composedResultText.value = outputContent;
            composedResultText.setAttribute('data-filename', `PSG-composed-config.${fileExtension}`);
            composerResultArea.classList.remove('hidden');
            button.disabled = false; buttonText.textContent = 'Generate Composed Subscription';
        }

        // --- SUBSCRIPTION SPLITTER LOGIC ---
        document.querySelectorAll('input[name="split_strategy"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                if (e.target.value === 'chunk') {
                    chunkSizeContainer.classList.remove('hidden');
                } else {
                    chunkSizeContainer.classList.add('hidden');
                }
            });
        });

        splitSubscriptionButton.addEventListener('click', async () => {
    const inputText = splitterUrlInput.value.trim();
    if (!inputText) {
        showMessageBox('Please paste a URL or raw subscription text to split.');
        return;
    }

    const button = splitSubscriptionButton;
    const buttonText = document.getElementById('splitButtonText');
    button.disabled = true;
    buttonText.textContent = 'Parsing...';
    splitterResultArea.classList.add('hidden');
    splitterResultList.innerHTML = '';

    try {
        let rawSubscriptionContent = '';

        // Check if inputText is a URL
        const isUrl = inputText.startsWith('http://') || inputText.startsWith('https://');
        if (isUrl) {
            buttonText.textContent = 'Fetching URL...';
            const response = await fetchWithCorsFallback(inputText);
            if (!response.ok) throw new Error(`Fetch failed (${response.status})`);
            rawSubscriptionContent = await response.text();
        } else {
            // If not a URL, the raw text is the inputText itself.
            rawSubscriptionContent = inputText;
        }

        // --- "ENCODE-FIRST" NORMALIZATION LOGIC ---
        let base64Content = '';
        
        // A robust regex to check if the string is likely already Base64.
        const isLikelyBase64 = /^[A-Za-z0-9+/=]+$/.test(rawSubscriptionContent.replace(/\s/g, ''));

        if (isLikelyBase64) {
            // If it already looks like Base64, use it as is (after cleaning whitespace).
            base64Content = rawSubscriptionContent.replace(/\s/g, '');
        } else {
            // If it's not Base64 (i.e., it's a plain text URI list), then we encode it.
            base64Content = btoa(rawSubscriptionContent);
        }
        // --- END OF NORMALIZATION LOGIC ---

        // Now, we can confidently proceed assuming we have valid Base64.
        const decoded = atob(base64Content);
        const uris = decoded.split(/[\n\r]+/).filter(Boolean);

        if (uris.length === 0) {
            throw new Error('No valid proxy URIs could be processed from the input.');
        }

        buttonText.textContent = 'Splitting...';

        const nodes = uris.map(uri => {
            const parsed = configParse(uri);
            return parsed ? { uri, parsed } : null;
        }).filter(Boolean);

        const strategy = document.querySelector('input[name="split_strategy"]:checked').value;
        let groupedNodes = {};

        if (strategy === 'country') {
            nodes.forEach(node => {
                const name = node.parsed.ps || node.parsed.hash || 'Unknown';
                const countryMatch = name.match(/\[([A-Z]{2})\]|\b([A-Z]{2})\b/i);
                const countryCode = countryMatch ? (countryMatch[1] || countryMatch[2]).toUpperCase() : 'Unknown';
                if (!groupedNodes[countryCode]) groupedNodes[countryCode] = [];
                groupedNodes[countryCode].push(node);
            });
        } else if (strategy === 'protocol') {
            nodes.forEach(node => {
                const protocol = node.parsed.protocol || 'unknown';
                if (!groupedNodes[protocol]) groupedNodes[protocol] = [];
                groupedNodes[protocol].push(node);
            });
        } else { // chunk
            const chunkSize = parseInt(chunkSizeInput.value, 10) || 50;
            for (let i = 0; i < nodes.length; i += chunkSize) {
                const chunk = nodes.slice(i, i + chunkSize);
                const chunkName = `Chunk ${Math.floor(i / chunkSize) + 1}`;
                groupedNodes[chunkName] = chunk;
            }
        }

        // Clear previous results before rendering new ones
        splitterResultList.innerHTML = '';

        Object.entries(groupedNodes).sort((a,b) => a[0].localeCompare(b[0])).forEach(([groupName, groupNodes]) => {
            const nodeCount = groupNodes.length;
            const groupBase64Content = btoa(groupNodes.map(n => n.uri).join('\n'));
            
            let displayName = groupName;
            if (strategy === 'country' && groupName !== 'Unknown') {
                displayName = `${getFlagEmoji(groupName)} ${getCountryName(groupName)}`;
            } else if (strategy === 'protocol') {
                displayName = formatDisplayName(groupName);
            }

            const resultItem = document.createElement('div');
            resultItem.className = 'bg-white dark:bg-slate-700/50 border dark:border-slate-600 rounded-lg p-3 flex items-center justify-between';
            resultItem.innerHTML = `
                <div class="font-semibold text-slate-800 dark:text-slate-200">${displayName} <span class="text-sm text-slate-500 dark:text-slate-400 font-normal">(${nodeCount} nodes)</span></div>
                <div class="flex items-center gap-2">
                    <button class="splitter-copy-btn p-2 rounded-md bg-indigo-50 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-400 hover:bg-indigo-100 dark:hover:bg-indigo-800" title="Copy Base64 Content" data-uri="${groupBase64Content}">
                        <i data-lucide="copy" class="h-5 w-5"></i>
                    </button>
                    <button class="splitter-share-btn p-2 rounded-md bg-teal-50 dark:bg-teal-900/50 text-teal-700 dark:text-teal-400 hover:bg-teal-100 dark:hover:bg-teal-800" title="Generate Share Link" data-uri="${groupBase64Content}">
                        <i data-lucide="share-2" class="h-5 w-5"></i>
                    </button>
                    <div class="splitter-qr-btn p-2 rounded-md bg-slate-100 dark:bg-slate-600 hover:bg-slate-200 dark:hover:bg-slate-500" title="Show QR Code">
                        <i data-lucide="qr-code" class="h-5 w-5"></i>
                    </div>
                </div>
            `;
            splitterResultList.appendChild(resultItem);
        });

        splitterResultArea.classList.remove('hidden');

    } catch (error) {
        showMessageBox(`Splitting Failed: ${error.message}`);
    } finally {
        button.disabled = false;
        buttonText.textContent = 'Split Subscription';
        lucide.createIcons();
    }
});

        splitterResultList.addEventListener('click', e => {
            const copyBtn = e.target.closest('.splitter-copy-btn');
            const qrBtn = e.target.closest('.splitter-qr-btn');
			const shareBtn = e.target.closest('.splitter-share-btn');
            if (copyBtn) {
                navigator.clipboard.writeText(copyBtn.dataset.uri).then(() => {
                    showMessageBox('Data URI copied to clipboard!');
                });
            }
			
			if (shareBtn) {
                const content = shareBtn.dataset.uri;
                handleShare(content, shareBtn);
            }

            if (qrBtn) {
                const dataUri = qrBtn.previousElementSibling.previousElementSibling.dataset.uri;
                const MAX_QR_LENGTH = 2500;

                const modalContent = document.getElementById('dnaModalContent');
                const loadingStateDiv = document.getElementById('dnaLoadingState');
                
                loadingStateDiv.innerHTML = `<div class="p-4 bg-white dark:bg-slate-800"><div id="splitterQrCodeContainer" class="flex justify-center"></div></div>`;
                loadingStateDiv.classList.remove('hidden');
                document.getElementById('dnaResultsContainer').classList.add('hidden');
                document.getElementById('modalSubscriptionName').textContent = `QR Code`;
                dnaModal.classList.remove('hidden');
                setTimeout(() => modalContent.classList.remove('scale-95', 'opacity-0'), 50);

                const qrContainer = document.getElementById('splitterQrCodeContainer');

                if (dataUri.length > MAX_QR_LENGTH) {
                    qrContainer.innerHTML = `<div class="h-64 flex items-center justify-center text-center text-lg text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-700 rounded-md p-4">Content is too large for a QR code.</div>`;
                } else {
                    try { new QRCode(qrContainer, { text: dataUri, width: 256, height: 256, colorDark: "#111827", colorLight: "#FFFFFF" }); }
                    catch (e) { qrContainer.innerHTML = `<div class="h-64 flex items-center justify-center text-red-500">Error generating QR Code.</div>`; }
                }
            }
        });

        // --- CROSS-COMPILER LOGIC ---
        convertButton.addEventListener('click', async () => {
    const buttonText = document.getElementById('convertButtonText');
    let inputText = compilerInputText.value.trim();

    if (!inputText) {
        showMessageBox('Please paste a URL or raw config text.');
        return;
    }

    convertButton.disabled = true;
    buttonText.textContent = 'Working...';
    compilerResultArea.classList.add('hidden');

    try {
        let rawContent = '';
        const isUrl = inputText.startsWith('http://') || inputText.startsWith('https://');
        
        // --- FIX: FETCH THE CONTENT BEFORE DETECTION ---
        if (isUrl) {
            buttonText.textContent = 'Fetching URL...';
            const response = await fetchWithCorsFallback(inputText);
            if (!response.ok) throw new Error(`Fetch failed (${response.status})`);
            rawContent = await response.text();
        } else {
            rawContent = inputText;
        }

        // Now, run detection on the ACTUAL content (either from the URL or the textarea)
        const inputFormat = detectInputFormat(rawContent);

        if (!inputFormat) {
            // If detection fails on the content, then it's truly an unknown format.
            throw new Error("Could not determine the format of the provided content.");
        }
        
        // Update the badge with the format of the fetched content
        let badgeText = 'Auto-Detect';
        let badgeClass = 'bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300';
        switch (inputFormat) {
            case 'clash': badgeText = 'Clash (YAML)'; break;
            case 'singbox': badgeText = 'Sing-box (JSON)'; break;
            case 'base64': badgeText = 'Base64'; break;
            case 'uri_list': badgeText = 'URI List'; break;
        }
        detectedFormatBadge.textContent = badgeText;
        detectedFormatBadge.className = `text-xs font-semibold px-2 py-1 rounded-full transition-all ${badgeClass}`;


        buttonText.textContent = 'Parsing...';
        let universalNodes = [];
        let uris = [];

        // --- PARSING LOGIC BASED ON DETECTED FORMAT ---
        switch (inputFormat) {
            case 'base64':
                uris = atob(rawContent.replace(/\s/g, '')).split(/[\n\r]+/).filter(Boolean);
                break;
            case 'uri_list':
                uris = rawContent.split(/[\n\r]+/).filter(Boolean);
                break;
            case 'clash':
                const parsedYaml = jsyaml.load(rawContent);
                if (!parsedYaml.proxies || !Array.isArray(parsedYaml.proxies)) throw new Error('Invalid Clash file: "proxies" array not found.');
                uris = parsedYaml.proxies.map(p => {
                     const name = encodeURIComponent(p.name);
                     return `${p.type}://${p.uuid || p.password || ''}@${p.server}:${p.port}#${name}`;
                });
                break;
            case 'singbox':
                const jsonString = rawContent.replace(/\\"|"(?:\\"|[^"])*"|(\/\/.*|\/\*[\s\S]*?\*\/)/g, (m, g) => g ? "" : m);
                const parsedJson = JSON.parse(jsonString);
                if (!parsedJson.outbounds || !Array.isArray(parsedJson.outbounds)) throw new Error('Invalid Sing-box file: "outbounds" array not found.');
                const utilityTypes = ['selector', 'urltest', 'direct', 'block', 'dns'];
                uris = parsedJson.outbounds
                    .filter(o => o.type && !utilityTypes.includes(o.type))
                    .map(o => {
                         const name = encodeURIComponent(o.tag);
                         return `${o.type}://${o.uuid || o.password || ''}@${o.server}:${o.server_port}#${name}`;
                    });
                break;
        }

        universalNodes = uris.map(uri => ({ uri, parsed: configParse(uri) })).filter(n => n.parsed);
        
        if (universalNodes.length === 0) throw new Error("No compatible proxy nodes could be extracted from the input.");

        buttonText.textContent = 'Compiling...';
        
        const outputFormat = compilerOutputFormat.value;
        let outputContent = '';
        let fileExtension = 'txt';
        
        if (outputFormat === 'base64') { outputContent = generateBase64Output(universalNodes); } 
        else if (outputFormat === 'clash') { outputContent = await generateClashOutput(universalNodes); fileExtension = 'yaml'; } 
        else if (outputFormat === 'singbox') { outputContent = await generateSingboxOutput(universalNodes); fileExtension = 'json'; } 
        
        compilerResultTitle.textContent = `Successfully converted ${universalNodes.length} nodes from ${inputFormat.toUpperCase()} to ${outputFormat.toUpperCase()}.`;
        compilerResultText.value = outputContent;
        downloadConvertedButton.setAttribute('data-filename', `PSG-converted-config.${fileExtension}`);
        compilerResultArea.classList.remove('hidden');

    } catch (error) {
        showMessageBox(`Conversion Failed: ${error.message}`);
        console.error(error);
    } finally {
        convertButton.disabled = false;
        buttonText.textContent = 'Convert';
    }
});

        // --- EVENT LISTENERS ---
        // NEW: Event listener for the segmented control buttons
        modeButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const targetMode = e.currentTarget.dataset.id; // Gets 'simple', 'composer', etc.
                switchMode(targetMode);
            });
        });
	    // =======================================================
// --- GUIDED WIZARD LOGIC FOR SIMPLE MODE ---
// =======================================================
const step1 = document.getElementById('step1');
const step2 = document.getElementById('step2');
const step3 = document.getElementById('step3');

function resetStep(stepElement) {
    stepElement.classList.remove('active');
    stepElement.style.opacity = '0.5';
    stepElement.querySelector('.step-icon')?.classList.replace('bg-indigo-700', 'bg-slate-400');

    // Disable all inputs within this step
    stepElement.querySelectorAll('select, input').forEach(input => {
        if (input.id !== 'configType') { // Don't disable the very first select
            input.disabled = true;
        }
    });
}

function activateStep(stepElement) {
    stepElement.classList.add('active');
    stepElement.style.opacity = '1';
    stepElement.querySelector('.step-icon')?.classList.replace('bg-slate-400', 'bg-indigo-700');
    
    // Enable the primary input of this step
    const primaryInput = stepElement.querySelector('select, input');
    if (primaryInput) {
        primaryInput.disabled = false;
    }
}
	    // =======================================================
// --- GUIDED WIZARD LOGIC FOR COMPOSER MODE ---
// =======================================================

// Helper to activate a composer step
function activateComposerStep(stepElement) {
    stepElement.classList.add('active');
    stepElement.style.opacity = '1';
    const icon = stepElement.querySelector('.step-icon');
    if (icon) {
        icon.classList.replace('bg-slate-400', 'bg-indigo-700');
    }
}

// Listen for any change on the source checkboxes
composerSourceList.addEventListener('change', () => {
    const selectedCheckboxes = composerSourceList.querySelectorAll('.composer-source:checked');
    
    if (selectedCheckboxes.length > 0) {
        // Activate steps 2 and 3 if at least one source is selected
        activateComposerStep(composerStep2);
        activateComposerStep(composerStep3);
    } else {
        // Deactivate if no sources are selected
        composerStep2.classList.remove('active');
        composerStep2.style.opacity = '0.5';
        composerStep2.querySelector('.step-icon')?.classList.replace('bg-indigo-700', 'bg-slate-400');
        composerStep2.querySelector('details').open = false; // Close the details panel

        composerStep3.classList.remove('active');
        composerStep3.style.opacity = '0.5';
        composerStep3.querySelector('.step-icon')?.classList.replace('bg-indigo-700', 'bg-slate-400');
        composerStep3.querySelector('details').open = false; // Close the details panel
    }
});

// --- NEW Event Listeners ---
compilerInputText.addEventListener('input', () => {
    const text = compilerInputText.value;
    detectedInputFormat = detectInputFormat(text);

    let badgeText = 'Auto-Detect';
    let badgeClass = 'bg-slate-200 text-slate-600 dark:bg-slate-600 dark:text-slate-300';

    if (detectedInputFormat) {
        badgeClass = 'bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300';
        switch (detectedInputFormat) {
            case 'clash': badgeText = 'Clash (YAML)'; break;
            case 'singbox': badgeText = 'Sing-box (JSON)'; break;
            case 'base64': badgeText = 'Base64'; break;
            case 'uri_list': badgeText = 'URI List'; break;
        }
    }
    detectedFormatBadge.textContent = badgeText;
    detectedFormatBadge.className = `text-xs font-semibold px-2 py-1 rounded-full transition-all ${badgeClass}`;
});
	    
configTypeSelect.addEventListener('change', () => {
    // Reset steps 2 and 3
    resetStep(step2);
    resetStep(step3);
    resetSelect(ipTypeSelect, 'Select Your App');
    resetSelect(otherElementSelect, 'Select Subscription');
    searchBar.value = '';
    searchBar.disabled = true;
    resultArea.classList.add('hidden');

    if (configTypeSelect.value) {
        // Activate Step 2
        activateStep(step2);
        populateSelect(ipTypeSelect, Object.keys(structuredData[configTypeSelect.value]), 'Select Your App');
    }
});

ipTypeSelect.addEventListener('change', () => {
    // Reset step 3
    resetStep(step3);
    resetSelect(otherElementSelect, 'Select Subscription');
    searchBar.value = '';
    resultArea.classList.add('hidden');

    if (ipTypeSelect.value) {
        // Activate Step 3
        activateStep(step3);
        searchBar.disabled = false;
        otherElementSelect.disabled = false;
        
        // Populate and show client info immediately
        updateClientInfo(ipTypeSelect.value);
        resultArea.classList.remove('hidden');
        subscriptionDetailsContainer.classList.add('hidden'); // Hide URL until a sub is chosen
        updateOtherElementOptions();
    }
});

otherElementSelect.addEventListener('change', () => {
    const url = structuredData[configTypeSelect.value]?.[ipTypeSelect.value]?.[otherElementSelect.value];
    if (url) {
        subscriptionUrlInput.value = url;
        updateQRCode(qrcodeDiv, url);
        subscriptionDetailsContainer.classList.remove('hidden');
    } else {
        subscriptionDetailsContainer.classList.add('hidden');
    }
});

// The search bar listener remains the same, as it's just for filtering
searchBar.addEventListener('input', updateOtherElementOptions);
        searchBar.addEventListener('input', updateOtherElementOptions);
        copyButton.addEventListener('click', () => { navigator.clipboard.writeText(subscriptionUrlInput.value).then(() => { const icon = copyButton.querySelector('.copy-icon'), check = copyButton.querySelector('.check-icon'); icon.classList.add('hidden'); check.classList.remove('hidden'); setTimeout(() => { icon.classList.remove('hidden'); check.classList.add('hidden'); }, 2000); }); });
        messageBoxClose.addEventListener('click', () => messageBox.classList.add('hidden'));
        generateCompositionButton.addEventListener('click', handleGenerateComposition);
        copyComposedButton.addEventListener('click', () => { navigator.clipboard.writeText(composedResultText.value).then(() => showMessageBox('Copied to clipboard!')); });
        downloadComposedButton.addEventListener('click', () => { const blob = new Blob([composedResultText.value], { type: 'text/plain' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = composedResultText.dataset.filename || 'psg-config.txt'; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url); });
        copyConvertedButton.addEventListener('click', () => { navigator.clipboard.writeText(compilerResultText.value).then(() => showMessageBox('Copied to clipboard!')); });
        downloadConvertedButton.addEventListener('click', (e) => { const blob = new Blob([compilerResultText.value], { type: 'text/plain;charset=utf-8' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = e.currentTarget.getAttribute('data-filename') || 'psg-converted.txt'; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url); });
        
        document.getElementById('shareComposedButton').addEventListener('click', (e) => {
            const content = document.getElementById('composedResultText').value;
            handleShare(content, e.currentTarget);
        });
        shareConvertedButton.addEventListener('click', (e) => {
    const content = document.getElementById('compilerResultText').value;
    handleShare(content, e.currentTarget);
});

        // --- INITIALIZATION ---
        populateSelect(configTypeSelect, Object.keys(structuredData), 'Select Config Type');
        configTypeSelect.disabled = false;
        populateComposerSources();
        switchMode('simple'); // Set the initial state to "Simple" mode
        lucide.createIcons();
		updateChartDefaults();
		
    });
    (function() {
    const ipInfoSpan = document.getElementById('live-ip-info');
    if (!ipInfoSpan) return;

    const getFlagEmoji = (countryCode) => {
        if (!/^[A-Z]{2}$/.test(countryCode)) return '🏳️';
        return String.fromCodePoint(...countryCode.toUpperCase().split('').map(char => 127397 + char.charCodeAt()));
    };

    const updateIpAndLocationInfo = async () => {
        ipInfoSpan.innerHTML = `Your Info: <span class="font-semibold">Fetching...</span> ⏳`;

        try {
            const response = await fetch('https://ipinfo.io/json');
            if (!response.ok) {
                throw new Error(`API request failed with status ${response.status}`);
            }
            const data = await response.json();
            
            const flag = getFlagEmoji(data.country);
            const location = [data.city, data.region, data.country].filter(Boolean).join(', ');
            const refreshButton = `<a href="#" id="ip-refresh-btn" title="Refresh Info" class="inline-block text-slate-400 dark:text-slate-500 hover:text-indigo-500 dark:hover:text-indigo-400 hover:rotate-90 transition-transform duration-300 ml-2">[🔄]</a>`;

            ipInfoSpan.innerHTML = `
                Your IP: <span class="font-semibold">${data.ip}</span> 
                (${data.org}) ${flag} ${location}
                ${refreshButton}
            `;

        } catch (e) {
            console.error("Failed to fetch IP info:", e);
            ipInfoSpan.innerHTML = `Your Info: <span class="font-semibold text-red-500">Unavailable</span> ⚠️ <a href="#" id="ip-refresh-btn" title="Refresh Info">[🔄]</a>`;
        }
    };

    // Use a delegated event listener for the refresh button, since it gets re-created
    document.body.addEventListener('click', function(e) {
        if (e.target && e.target.id === 'ip-refresh-btn') {
            e.preventDefault();
            updateIpAndLocationInfo();
        }
    });

    // Run it for the first time when the page loads
    updateIpAndLocationInfo();
})();
    </script>
</body>
</html>
HTML;

    // Inject the JSON data and timestamp into the final HTML
    $final_html = str_replace(
        "__JSON_DATA_PLACEHOLDER__",
        $json_structured_data,
        $html_template
    );
    $final_html = str_replace(
        "__CLIENT_INFO_PLACEHOLDER__",
        $json_client_info_data,
        $final_html
    );
    $final_html = str_replace(
        "__TIMESTAMP_PLACEHOLDER__",
        $generation_timestamp,
        $final_html
    );
    return $final_html;
}

// --- Main Execution ---
echo "Starting PSG page generator..." . PHP_EOL;
$all_files = [];
foreach (SCAN_DIRECTORIES as $category => $dir) {
    if (is_dir($dir)) {
        echo "Scanning directory: {$dir}" . PHP_EOL;
        $all_files[$category] = scan_directory($dir);
    } else {
        echo "Warning: Directory not found, skipping: {$dir}" . PHP_EOL;
    }
}
$file_count = array_sum(array_map("count", $all_files));
if ($file_count === 0) {
    die(
        "Error: No subscription files were found to generate the page. Please check SCAN_DIRECTORIES paths. Exiting." .
            PHP_EOL
    );
}
echo "Found and categorized {$file_count} subscription files." . PHP_EOL;
$structured_data = process_files_to_structure($all_files);
$client_info = get_client_info();
date_default_timezone_set("Asia/Tehran");
$timestamp = date("Y-m-d H:i:s T");
$final_html = generate_full_html($structured_data, $client_info, $timestamp);
file_put_contents(OUTPUT_HTML_FILE, $final_html);
echo "Successfully generated page at: " . realpath(OUTPUT_HTML_FILE) . PHP_EOL;
