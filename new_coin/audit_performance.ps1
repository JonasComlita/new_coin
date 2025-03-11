# Define the port to listen on
$port = 6000  # Replace with your desired port number
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $port)
$listener.Start()

Write-Host "Listening on port $port..."

try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        $stream = $client.GetStream()
        $reader = [System.IO.StreamReader]::new($stream)
        $writer = [System.IO.StreamWriter]::new($stream)
        $writer.AutoFlush = $true

        # Read data from the client
        $data = $reader.ReadLine()
        Write-Host "Received data: $data"

        # Process the data (log lines)
        $logs = $data -split "`n"

        # Define regex patterns for each metric
        $patterns = @{
            "Key Generation"   = "Generated secure secret in (\d+\.\d+) µs"
            "Secret Retrieval" = "Retrieved peer auth secret in (\d+\.\d+) µs"
            "Authentication"   = "Validated peer auth in (\d+\.\d+) µs"
            "Encryption"       = "Encrypted key for .+ in (\d+\.\d+) ms"
            "Distribution"     = "Distributed finalized key to \d+\/\d+ nodes in (\d+\.\d+) seconds"
            "Initialization"   = "Initialized KeyRotationManager for .+ in (\d+\.\d+) seconds"
        }

        # Initialize results
        $results = @{}
        foreach ($metric in $patterns.Keys) {
            $results[$metric] = @{
                Count  = 0
                Min    = [double]::MaxValue
                Max    = 0
                Sum    = 0
                Values = @()
            }
        }

        # Process logs
        foreach ($line in $logs) {
            foreach ($metric in $patterns.Keys) {
                if ($line -match $patterns[$metric]) {
                    $value = [double]$Matches[1]
                    $results[$metric].Count += 1
                    $results[$metric].Min = [Math]::Min($results[$metric].Min, $value)
                    $results[$metric].Max = [Math]::Max($results[$metric].Max, $value)
                    $results[$metric].Sum += $value
                    $results[$metric].Values += $value
                }
            }
        }

        # Print results with targets
        $targets = @{
            "Key Generation"   = @{ Value = 100; Unit = "µs" }
            "Secret Retrieval" = @{ Value = 50; Unit = "µs" }
            "Authentication"   = @{ Value = 10; Unit = "µs" }
            "Encryption"       = @{ Value = 20; Unit = "ms" }
            "Distribution"     = @{ Value = 1; Unit = "s" }
            "Initialization"   = @{ Value = 1; Unit = "s" }
        }

        Write-Host "Performance Audit Results`n" -ForegroundColor Cyan

        foreach ($metric in $patterns.Keys) {
            $data = $results[$metric]
            if ($data.Count -gt 0) {
                $avg = $data.Sum / $data.Count
                $target = $targets[$metric].Value
                $unit = $targets[$metric].Unit
                
                # Determine if meeting target
                $meetingTarget = if ($avg -le $target) { "`u2713" } else { "`u2717" }
                $color = if ($avg -le $target) { "Green" } else { "Red" }
                
                Write-Host "$metric ($($data.Count) samples):" -ForegroundColor Yellow
                Write-Host "  Average: $($avg.ToString('F2')) $unit - Target: $target $unit $meetingTarget" -ForegroundColor $color
                Write-Host "  Min: $($data.Min.ToString('F2')) $unit, Max: $($data.Max.ToString('F2')) $unit"
            }
            else {
                Write-Host "$metric`: No data found in logs" -ForegroundColor Gray
            }
            Write-Host ""
        }

        # Send a response back to the client
        $writer.WriteLine("Data received and processed")

        # Close the client connection
        $stream.Close()
        $client.Close()
    }
}
finally {
    $listener.Stop()
}