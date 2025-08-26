#!/usr/bin/env bash

set -e

# Function to run the SBOM security scan
run_security_scan() {
    local target="$1"
    local repository="$2"
    local head_ref="$3"
    
    echo "Security Scanning Started"
    echo "Target: $target"
    echo "PR Branch (code being scanned): $head_ref"

    # Define directories to scan
    local scan_dirs=(
        "code-editor-src" 
        "code-editor-src/remote" 
        "code-editor-src/extensions" 
        "code-editor-src/remote/web"
    )
    local scan_results=()
    
    # Scan each directory
    for dir in "${scan_dirs[@]}"; do
        echo "=== Scanning directory: $dir ==="
        
        # Check if directory exists and has package-lock.json
        if [ ! -d "$dir" ]; then
            echo "Warning: Directory $dir does not exist, skipping..."
            continue
        fi
        
        if [ ! -f "$dir/package-lock.json" ]; then
            echo "Warning: No package-lock.json found in $dir, skipping..."
            continue
        fi
        
        # Generate SBOM for this directory
        echo "Generating SBOM for $dir"
        cd "$dir"
        
        # Create a safe filename for the SBOM
        local safe_dir_name=$(echo "$dir" | sed 's/\//_/g')
        local sbom_file="${safe_dir_name}-sbom.json"
        local result_file="${safe_dir_name}-scan-result.json"
        
        # 1.5 Spec Version compatible with Inspector's ScanSbom API
        cyclonedx-npm --omit dev --output-reproducible --spec-version 1.5 -o "$sbom_file"
        
        echo "Invoking Inspector's ScanSbom API for $dir"
        aws inspector-scan scan-sbom --sbom "file://$sbom_file" > "$result_file"
        
        # Store the result file path for later analysis
        scan_results+=("$PWD/$result_file")
        
        # Return to root directory
        cd - > /dev/null
        
        echo "Completed scan for $dir"
    done
    
    # Store scan results paths in a file for the analyze step
    printf '%s\n' "${scan_results[@]}" > scan_results_paths.txt

    echo "Publish success metric for Security Scan"
    aws cloudwatch put-metric-data \
        --namespace "GitHub/Workflows" \
        --metric-name "SecurityScanInvoked" \
        --dimensions "Repository=$repository,Workflow=SecurityScanning,Target=$target" \
        --value 1
}

# Function to analyze SBOM scan results
analyze_sbom_results() {
    local target="$1"
    local repository="$2"
    
    # Check if scan results paths file exists
    if [ ! -f "scan_results_paths.txt" ]; then
        echo "Error: Scan results paths file not found"
        exit 1
    fi
    
    # Initialize totals
    local total_critical=0
    local total_high=0
    local total_medium=0
    local total_other=0
    local total_low=0
    local has_failures=false
    
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
            has_failures=true
            echo "⚠️  Found $dir_concerning concerning vulnerabilities in $dir_name"
        else
            echo "✅ No concerning vulnerabilities in $dir_name"
        fi
        
    done < scan_results_paths.txt
    
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
        
        # Publish failure metric
        aws cloudwatch put-metric-data \
            --namespace "GitHub/Workflows" \
            --metric-name "SecurityScanFailed" \
            --dimensions "Repository=$repository,Workflow=SecurityScanning,Target=$target" \
            --value 1
        
        exit 1
    else
        echo "✅ Security scan PASSED: No concerning vulnerabilities found across all directories"
        echo "Total Low vulnerabilities: $total_low (acceptable)"
        
        # Publish success metric
        aws cloudwatch put-metric-data \
            --namespace "GitHub/Workflows" \
            --metric-name "SecurityScanPassed" \
            --dimensions "Repository=$repository,Workflow=SecurityScanning,Target=$target" \
            --value 1
    fi
}

# Main function to handle command line arguments
main() {
    case "$1" in
        "run-scan")
            run_security_scan "$2" "$3" "$4"
            ;;
        "analyze-results")
            analyze_sbom_results "$2" "$3"
            ;;
        *)
            echo "Usage: $0 {run-scan|analyze-results} <target> <repository> [head_ref]"
            echo "  run-scan: Execute the SBOM security scan"
            echo "  analyze-results: Analyze SBOM scan results and fail if vulnerabilities found"
            exit 1
            ;;
    esac
}

# Call main function with all arguments
main "$@"