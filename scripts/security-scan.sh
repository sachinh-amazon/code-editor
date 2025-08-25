#!/bin/bash

set -e

# Function to run the SBOM security scan
run_security_scan() {
    local target="$1"
    local repository="$2"
    local head_ref="$3"
    
    echo "Security Scanning Started"
    echo "Target: $target"
    echo "PR Branch (code being scanned): $head_ref"

    echo "Generating SBOM"
    cd code-editor-src
    # 1.5 Spec Version compatible with Inspector's ScanSbom API. 
    cyclonedx-npm --omit dev --output-reproducible --spec-version 1.5 -o code-editor-sbom.json
    
    echo "Invoking Inspector's ScanSbom API"
    aws inspector-scan scan-sbom --sbom file://code-editor-sbom.json > sbom_scan_result.json

    echo "Publish success metric for Security Scan"
    aws cloudwatch put-metric-data \
        --namespace "GitHub/Workflows" \
        --metric-name "ScanComplete" \
        --dimensions "Repository=$repository,Workflow=SecurityScanning" \
        --value 1
}

# Function to analyze SBOM scan results
analyze_sbom_results() {
    local target="$1"
    local repository="$2"
    
    cd code-editor-src
    
    # Check if scan results file exists
    if [ ! -f "sbom_scan_result.json" ]; then
        echo "Error: SBOM scan results file not found"
        exit 1
    fi
    
    # Extract vulnerability counts from the scan results
    critical=$(jq -r '.sbom.vulnerability_count.critical // 0' sbom_scan_result.json)
    high=$(jq -r '.sbom.vulnerability_count.high // 0' sbom_scan_result.json)
    medium=$(jq -r '.sbom.vulnerability_count.medium // 0' sbom_scan_result.json)
    other=$(jq -r '.sbom.vulnerability_count.other // 0' sbom_scan_result.json)
    low=$(jq -r '.sbom.vulnerability_count.low // 0' sbom_scan_result.json)
    
    echo "=== SBOM Security Scan Results for $target ==="
    echo "Critical vulnerabilities: $critical"
    echo "High vulnerabilities: $high"
    echo "Medium vulnerabilities: $medium"
    echo "Other vulnerabilities: $other"
    echo "Low vulnerabilities: $low"
    echo "=================================================="
    
    # Calculate total concerning vulnerabilities (excluding low)
    total_concerning=$((critical + high + medium + other))
    
    if [ $total_concerning -gt 0 ]; then
        echo "❌ Security scan FAILED: Found $total_concerning concerning vulnerabilities"
        echo "Critical: $critical, High: $high, Medium: $medium, Other: $other"
        
        # Display detailed vulnerability messages if available
        echo ""
        echo "Vulnerability details:"
        jq -r '.sbom.messages[]? | select(.vulnerability_message or .error_message) | "- \(.purl // "Unknown"): \(.vulnerability_message // .error_message // .info_message)"' sbom_scan_result.json || echo "No detailed messages available"
        
        # Publish failure metric
        aws cloudwatch put-metric-data \
            --namespace "GitHub/Workflows" \
            --metric-name "SecurityScanFailed" \
            --dimensions "Repository=$repository,Workflow=SecurityScanning,Target=$target" \
            --value $total_concerning
        
        exit 1
    else
        echo "✅ Security scan PASSED: No concerning vulnerabilities found"
        echo "Low vulnerabilities: $low (acceptable)"
        
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