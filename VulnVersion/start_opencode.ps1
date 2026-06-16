$ErrorActionPreference = "Stop"

# Get the directory of this script
$scriptDir = $PSScriptRoot

# Path to .env file
$envPath = Join-Path $scriptDir ".env"

if (Test-Path $envPath) {
    Write-Host "Loading environment variables from $envPath"
    Get-Content $envPath | ForEach-Object {
        $line = $_.Trim()
        # Skip empty lines and comments
        if ($line -and -not $line.StartsWith("#")) {
            # Split by first equals sign
            $parts = $line.Split("=", 2)
            if ($parts.Length -eq 2) {
                $name = $parts[0].Trim()
                $val = $parts[1].Trim()
                # Set process-level environment variable
                [System.Environment]::SetEnvironmentVariable($name, $val, "Process")
                # Mask API Key in logs
                if ($name -like "*KEY*") {
                    Write-Host "Loaded: $name = *****"
                } else {
                    Write-Host "Loaded: $name = $val"
                }
            }
        }
    }
} else {
    Write-Warning ".env file not found at $envPath. Starting OpenCode without loading .env."
}

Write-Host "Starting OpenCode Server..."
$opencodeCmd = Get-Command opencode.cmd -ErrorAction SilentlyContinue
if ($opencodeCmd) {
    & $opencodeCmd.Source serve --hostname 127.0.0.1 --port 4096 --print-logs
} else {
    opencode serve --hostname 127.0.0.1 --port 4096 --print-logs
}
