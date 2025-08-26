#!/usr/bin/env bash

set -e

# Function to scan main application dependencies
scan_main_dependencies() {
    local target="$1"
    local head_ref="$2"
    
    echo "Security Scanning Started"
    echo "Target: $target"
    echo "PR Branch (code being scanned): $head_ref"

    # Define directories to scan with their specific configurations
    local scan_configs=(
        "code-editor-src::root"
        "remote::subdir_ignore_errors"
        "extensions::subdir_ignore_errors"
        "remote/web::subdir_ignore_errors"
    )
    local scan_results=()
    
    # Scan each directory
    for config in "${scan_configs[@]}"; do
        local dir=$(echo "$config" | cut -d':' -f1)
        local scan_type=$(echo "$config" | cut -d':' -f3)
        
        echo "=== Scanning directory: $dir ==="
        
        # For the first scan (code-editor-src), we need to check the root directory
        # For others, we need to check subdirectories within code-editor-src
        local check_dir
        if [ "$scan_type" = "root" ]; then
            check_dir="$dir"
        else
            check_dir="code-editor-src/$dir"
        fi
        
        # Check if directory exists and has package-lock.json
        if [ ! -d "$check_dir" ]; then
            echo "Warning: Directory $check_dir does not exist, skipping..."
            continue
        fi
        
        if [ ! -f "$check_dir/package-lock.json" ]; then
            echo "Warning: No package-lock.json found in $check_dir, skipping..."
            continue
        fi
        
        # Generate SBOM for this directory
        echo "Generating SBOM for $dir"
        
        # Create a safe filename for the SBOM
        local safe_dir_name=$(echo "$dir" | sed 's/\//_/g')
        local sbom_file="${safe_dir_name}-sbom.json"
        local result_file="${safe_dir_name}-scan-result.json"
        
        # Handle different scan types
        if [ "$scan_type" = "root" ]; then
            # First scan: cd into code-editor-src and run scan there
            echo "Scanning root directory: $dir"
            cd "$dir"
            cyclonedx-npm --omit dev --output-reproducible --spec-version 1.5 -o "$sbom_file"
            
        elif [ "$scan_type" = "subdir_ignore_errors" ]; then
            # Subdirectory scans with npm error handling: cd into directory and add --ignore-npm-errors flag
            # This is to ignore extraneous npm errors that don't affect the security scan
            # This behaviour is same for internal scanning.
            echo "Scanning subdirectory: $dir (ignoring npm errors)"
            cd "$check_dir"
            cyclonedx-npm --omit dev --output-reproducible --spec-version 1.5 --ignore-npm-errors -o "$sbom_file"
        fi
        
        echo "Invoking Inspector's ScanSbom API for $dir"
        aws inspector-scan scan-sbom --sbom "file://$sbom_file" > "$result_file"
        
        # Store the result file path for later analysis
        scan_results+=("$PWD/$result_file")
        
        # Return to root directory for next iteration
        cd - > /dev/null
        
        echo "Completed scan for $dir"
    done
    
    # Store scan results paths in a file for the analyze step
    printf '%s\n' "${scan_results[@]}" > scan_results_paths.txt
}

# Function to generate SBOMs for additional dependencies
generate_additional_sboms() {
    echo "Generating SBOMs for additional dependencies"
    
    # Store current working directory
    local root_dir=$(pwd)
    
    # Create directory for additional SBOMs
    mkdir -p additional-node-js-sboms
    
    # 1. Generate SBOM for @electrovir/oss-attribution-generator
    echo "Generating SBOM for @electrovir/oss-attribution-generator"
    
    # Find the global npm modules directory
    global_npm_dir=$(npm list -g | head -1)
    oss_attribution_dir="$global_npm_dir/node_modules/@electrovir/oss-attribution-generator"
    
    if [ -d "$oss_attribution_dir" ]; then
        echo "Found OSS attribution generator at: $oss_attribution_dir"
        cd "$oss_attribution_dir"
        cyclonedx-npm --omit dev --output-reproducible --spec-version 1.5 -o "$root_dir/additional-node-js-sboms/oss-attribution-generator-sbom.json"
        cd - > /dev/null
        echo "Generated SBOM for OSS attribution generator"
    else
        echo "Error: OSS attribution generator not found at expected location: $oss_attribution_dir"
        exit 1
    fi
    
    # 2. Generate SBOM for Node.js linux-x64 binary
    echo "Generating SBOM for Node.js linux-x64 binary"
    
    # Read Node.js version from .npmrc file
    if [ -f "code-editor-src/remote/.npmrc" ]; then
        NODE_VERSION=$(grep 'target=' code-editor-src/remote/.npmrc | cut -d'"' -f2)
    else
        NODE_VERSION="22.15.1"  # fallback version
    fi
    
    node_x64_dir="nodejs-binaries/node-v$NODE_VERSION-linux-x64"
    if [ -d "$node_x64_dir" ]; then
        echo "Found Node.js x64 binary at: $node_x64_dir"
        syft "$node_x64_dir" -o cyclonedx-json@1.5="$root_dir/additional-node-js-sboms/nodejs-x64-sbom.json"
        echo "Generated SBOM for Node.js x64 binary"
    else
        echo "Error: Node.js x64 binary not found at expected location: $node_x64_dir"
        exit 1
    fi
    
    # 3. Generate SBOM for Node.js linux-arm64 binary
    echo "Generating SBOM for Node.js linux-arm64 binary"
    
    node_arm64_dir="nodejs-binaries/node-v$NODE_VERSION-linux-arm64"
    if [ -d "$node_arm64_dir" ]; then
        echo "Found Node.js ARM64 binary at: $node_arm64_dir"
        syft "$node_arm64_dir" -o cyclonedx-json@1.5="$root_dir/additional-node-js-sboms/nodejs-arm64-sbom.json"
        echo "Generated SBOM for Node.js ARM64 binary"
    else
        echo "Error: Node.js ARM64 binary not found at expected location: $node_arm64_dir"
        exit 1
    fi
    
    # List generated SBOMs
    echo "Generated additional SBOMs:"
    ls -la additional-node-js-sboms/
    
    echo "Additional SBOM generation completed successfully"
}

# Function to scan additional SBOMs using AWS Inspector
scan_additional_sboms() {
    echo "Scanning additional SBOMs with AWS Inspector"
    
    # First, download Node.js binaries
    echo "Downloading Node.js binaries..."
    download_nodejs_binaries
    
    # Then, generate additional SBOMs
    echo "Generating additional SBOMs..."
    generate_additional_sboms
    
    # Create directory for additional scan results
    mkdir -p additional-scan-results
    
    # Check if additional SBOMs directory exists (should exist after generation)
    if [ ! -d "additional-node-js-sboms" ]; then
        echo "Error: additional-node-js-sboms directory not found after generation"
        exit 1
    fi
    
    # Array to store scan result files for later analysis
    local additional_scan_results=()
    
    # Scan each SBOM file in the additional-node-js-sboms directory
    for sbom_file in additional-node-js-sboms/*.json; do
        if [ ! -f "$sbom_file" ]; then
            echo "Warning: No SBOM files found in additional-node-js-sboms directory"
            continue
        fi
        
        # Extract base filename without path and extension
        local base_name=$(basename "$sbom_file" .json)
        local result_file="additional-scan-results/${base_name}-scan-result.json"
        
        echo "Scanning SBOM: $sbom_file"
        echo "Output will be saved to: $result_file"
        
        # Run AWS Inspector scan on the SBOM
        aws inspector-scan scan-sbom --sbom "file://$sbom_file" > "$result_file"
        
        # Store the result file path for later analysis
        additional_scan_results+=("$PWD/$result_file")
        
        echo "Completed scan for $base_name"
    done
    
    # Store additional scan results paths in a file for the analyze step
    printf '%s\n' "${additional_scan_results[@]}" > additional_scan_results_paths.txt
    
    echo "Additional SBOM scanning completed successfully"
    echo "Scan results saved in additional-scan-results/ directory"
    ls -la additional-scan-results/
}

# Function to download Node.js binaries for scanning
download_nodejs_binaries() {
    echo "Downloading Node.js prebuilt binaries for scanning"
    
    # Create directory for Node.js binaries
    mkdir -p nodejs-binaries
    cd nodejs-binaries
    
    # Read Node.js version from .npmrc file
    if [ -f "../code-editor-src/remote/.npmrc" ]; then
        NODE_VERSION=$(grep 'target=' ../code-editor-src/remote/.npmrc | cut -d'"' -f2)
        echo "Found Node.js version $NODE_VERSION in .npmrc"
    else
        NODE_VERSION="22.15.1"  # fallback version
        echo "Using fallback Node.js version $NODE_VERSION"
    fi
    
    # Download Node.js binaries for both architectures
    echo "Downloading Node.js v$NODE_VERSION for linux-x64"
    curl -sSL "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-x64.tar.xz" -o "node-v$NODE_VERSION-linux-x64.tar.xz"
    
    echo "Downloading Node.js v$NODE_VERSION for linux-arm64"
    curl -sSL "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-arm64.tar.xz" -o "node-v$NODE_VERSION-linux-arm64.tar.xz"
    
    # Extract the downloaded files
    echo "Extracting Node.js binaries"
    tar -xf "node-v$NODE_VERSION-linux-x64.tar.xz"
    tar -xf "node-v$NODE_VERSION-linux-arm64.tar.xz"
    
    echo "Node.js binaries downloaded and extracted:"
    ls -la
    
    # Return to root directory
    cd - > /dev/null
    
    echo "Node.js dependencies preparation completed"
}

# Function to analyze SBOM scan results
analyze_sbom_results() {
    local target="$1"
    local results_file="$2"
    
    # Check if results file parameter is provided
    if [ -z "$results_file" ]; then
        echo "Error: Results file path is required as second parameter"
        exit 1
    fi
    
    # Check if scan results paths file exists
    if [ ! -f "$results_file" ]; then
        echo "Error: Scan results paths file '$results_file' not found"
        exit 1
    fi
    
    # Initialize totals
    local total_critical=0
    local total_high=0
    local total_medium=0
    local total_other=0
    local total_low=0
    
    echo "=== SBOM Security Scan Results for $target ==="
    
    # Process each scan result file
    while IFS= read -r result_file; do
        if [ ! -f "$result_file" ]; then
            echo "Warning: Scan result file $result_file not found, skipping..."
            continue
        fi
        
        # Extract directory name from result file path
        local dir_name=$(basename "$result_file" | sed 's/-scan-result\.json$//' | sed 's/_/\//g')
        
        echo ""
        echo "--- Results for $dir_name ---"
        
        # Extract vulnerability counts from this scan result
        local critical=$(jq -r '.sbom.vulnerability_count.critical // 0' "$result_file")
        local high=$(jq -r '.sbom.vulnerability_count.high // 0' "$result_file")
        local medium=$(jq -r '.sbom.vulnerability_count.medium // 0' "$result_file")
        local other=$(jq -r '.sbom.vulnerability_count.other // 0' "$result_file")
        local low=$(jq -r '.sbom.vulnerability_count.low // 0' "$result_file")
        
        echo "Critical: $critical, High: $high, Medium: $medium, Other: $other, Low: $low"
        
        # Add to totals
        total_critical=$((total_critical + critical))
        total_high=$((total_high + high))
        total_medium=$((total_medium + medium))
        total_other=$((total_other + other))
        total_low=$((total_low + low))
        
        # Check for concerning vulnerabilities in this directory
        local dir_concerning=$((critical + high + medium + other))
        if [ $dir_concerning -gt 0 ]; then
            echo "⚠️  Found $dir_concerning concerning vulnerabilities in $dir_name"
        else
            echo "✅ No concerning vulnerabilities in $dir_name"
        fi
        
    done < "$results_file"
    
    echo ""
    echo "=== TOTAL SCAN RESULTS ==="
    echo "Total Critical vulnerabilities: $total_critical"
    echo "Total High vulnerabilities: $total_high"
    echo "Total Medium vulnerabilities: $total_medium"
    echo "Total Other vulnerabilities: $total_other"
    echo "Total Low vulnerabilities: $total_low"
    echo "=================================================="
    
    # Calculate total concerning vulnerabilities (excluding low)
    local total_concerning=$((total_critical + total_high + total_medium + total_other))
    
    if [ $total_concerning -gt 0 ]; then
        echo "❌ Security scan FAILED: Found $total_concerning concerning vulnerabilities across all directories"
        echo "Critical: $total_critical, High: $total_high, Medium: $total_medium, Other: $total_other"
        exit 1
    else
        echo "✅ Security scan PASSED: No concerning vulnerabilities found across all directories"
        echo "Total Low vulnerabilities: $total_low (acceptable)"
    fi
}

# Main function to handle command line arguments
main() {
    case "$1" in
        "scan-main-dependencies")
            scan_main_dependencies "$2" "$3"
            ;;
        "analyze-results")
            analyze_sbom_results "$2" "$3"
            ;;
        "scan-additional-dependencies")
            scan_additional_sboms
            ;;
        *)
            echo "Usage: $0 {scan-main-dependencies|analyze-results|scan-additional-dependencies}"
            echo "  scan-main-dependencies: Generate SBOMs and scan main application dependencies"
            echo "  analyze-results: Analyze SBOM scan results and fail if vulnerabilities found"
            echo "  scan-additional-dependencies: Download, generate SBOMs, and scan additional Node.js dependencies"
            exit 1
            ;;
    esac
}

# Call main function with all arguments
main "$@"