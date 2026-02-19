# ==============================
# SQL Stored Procedure Optimizer
# ==============================
# Steps:
# 1. Connects to SQL Server
# 2. Extracts stored procedure definition
# 3. Executes stored procedure with parameters and captures execution plan
# 4. Runs benchmarks (original vs optimized)
# 5. Sends SP + Plan to AI model for optimization
# 6. Saves:
#    - Original SP
#    - Query Plan
#    - AI Analysis Report
#    - Optimized SP
#    - Benchmark comparison
# ==============================
function OptimizeSPFromDB{
[CmdletBinding()]
param (
    [string]$ServerInstance = "localhost\SQLEXPRESS",
    [string]$Database = "YourDB",
    [string]$StoredProc = "dbo.YourProcedure",
    [string]$Params = "@Param1=1, @Param2='Test'",
    [string]$OutDir = "C:\SP_Optimization",
    [string]$ApiKey = "<YOUR_API_KEY_HERE>"
)

# Ensure output dir
if (-not (Test-Path $OutDir)) {
    New-Item -Path $OutDir -ItemType Directory | Out-Null
}

# -----------------------------
# 1. Extract stored procedure definition
# -----------------------------
$procFile = Join-Path $OutDir "StoredProc.sql"
Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query "
    SELECT OBJECT_DEFINITION(OBJECT_ID('$StoredProc')) AS ProcDefinition
" | ForEach-Object {
    $_.ProcDefinition | Out-File -FilePath $procFile -Encoding UTF8
}
Write-Output "Stored procedure saved: $procFile"

# -----------------------------
# 2. Capture execution plan
# -----------------------------
$query = "SET STATISTICS XML ON; EXEC $StoredProc $Params; SET STATISTICS XML OFF;"
$planFile = Join-Path $OutDir "QueryPlan.xml"

Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $query |
    ForEach-Object {
        if ($_["Microsoft.SqlServer.Management.Smo.ExecutionPlan"]) {
            $_["Microsoft.SqlServer.Management.Smo.ExecutionPlan"].InnerXml |
                Out-File -FilePath $planFile -Encoding UTF8
        }
    }
Write-Output "Execution plan saved: $planFile"

# -----------------------------
# 3. Benchmark (original proc)
# -----------------------------
$benchmarkFile = Join-Path $OutDir "Benchmark_Original.txt"
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query "EXEC $StoredProc $Params"
$stopwatch.Stop()
"Execution Time (ms): $($stopwatch.ElapsedMilliseconds)" |
    Out-File -FilePath $benchmarkFile -Encoding UTF8
Write-Output "Original benchmark saved: $benchmarkFile"

# -----------------------------
# 4. Prepare AI request
# -----------------------------
$spContent   = Get-Content $procFile -Raw
$planContent = Get-Content $planFile -Raw

$prompt = @"
You are a SQL Server optimization expert.
I am providing:

1. Stored procedure definition:
$spContent

2. Execution plan (XML):
$planContent

Tasks:
1. Identify and explain the main performance issues in the stored procedure (parameter sniffing, missing indexes, scans, bad joins, RBAR, etc).
2. Suggest and explain what optimizations should be applied to fix them.
3. Provide the rewritten stored procedure with the new name ${StoredProc}_Optimized.
4. Return your answer in two parts:
   - **Analysis Report** (detailed explanation of faults + optimization steps taken)
   - **Optimized Stored Procedure** (SQL code only)
"@

# -----------------------------
# 5. Send to AI (OpenAI GPT-4o or GPT-5 if enabled)
# -----------------------------
$body = @{
    model = "gpt-4o-mini"   # change to "gpt-5" if available
    messages = @(@{ role = "user"; content = $prompt })
    temperature = 0.2
} | ConvertTo-Json -Depth 4

$response = Invoke-RestMethod `
    -Uri "https://api.openai.com/v1/chat/completions" `
    -Headers @{ "Authorization" = "Bearer $ApiKey"; "Content-Type" = "application/json" } `
    -Method Post -Body $body

$aiOutput = $response.choices[0].message.content

# -----------------------------
# 6. Split AI response
# -----------------------------
if ($aiOutput -match "(?s)Analysis Report(.*)Optimized Stored Procedure(.*)") {
    $analysis = $matches[1].Trim()
    $optimizedSQL = $matches[2].Trim()
} else {
    $analysis = $aiOutput
    $optimizedSQL = "-- AI did not separate analysis and SQL properly"
}

# Save outputs
$analysisFile   = Join-Path $OutDir "Analysis_Report.txt"
$optimizedFile  = Join-Path $OutDir "StoredProc_Optimized.sql"

$analysis     | Out-File -FilePath $analysisFile -Encoding UTF8
$optimizedSQL | Out-File -FilePath $optimizedFile -Encoding UTF8

Write-Output "Analysis report saved: $analysisFile"
Write-Output "Optimized stored procedure saved: $optimizedFile"

# -----------------------------
# 7. Benchmark (optimized proc)
# -----------------------------
$optimizedBenchmarkFile = Join-Path $OutDir "Benchmark_Optimized.txt"

$stopwatch.Restart()
Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query "EXEC ${StoredProc}_Optimized $Params"
$stopwatch.Stop()
"Execution Time (ms): $($stopwatch.ElapsedMilliseconds)" |
    Out-File -FilePath $optimizedBenchmarkFile -Encoding UTF8
Write-Output "Optimized benchmark saved: $optimizedBenchmarkFile"

# -----------------------------
# 8. Compare benchmarks
# -----------------------------
$orig = Get-Content $benchmarkFile -Raw
$opt  = Get-Content $optimizedBenchmarkFile -Raw
$comparisonFile = Join-Path $OutDir "Benchmark_Comparison.txt"
"Original:`n$orig`n`nOptimized:`n$opt" |
    Out-File -FilePath $comparisonFile -Encoding UTF8
Write-Output "Benchmark comparison saved: $comparisonFile"

Write-Output "Optimization workflow complete!"
}
OptimizeSPFromDB -ServerInstance "<ServerName>"  -Database "<DatabaseName>" -StoredProc "dbo.<StoredProcedureName>" -Params "@StartProductID = 749, @CheckDate = '2010-05-26'" -OutDir "<FolderPath>" -ApiKey "sk-proj"
