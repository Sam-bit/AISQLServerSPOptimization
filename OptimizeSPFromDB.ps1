# ============================================================
# SQL Stored Procedure Optimizer
# ============================================================
# Steps:
# 1. Connects to SQL Server
# 2. Extracts stored procedure definition
# 3. Executes stored procedure with parameters and captures execution plan
# 4. Runs benchmarks (original vs optimized)
# 5. Sends SP + Plan to AI model for optimization
#    Supported AI modes:
#      - OpenAI   (ApiKey starting with sk-  or sk-proj-)
#      - GitHub Copilot API  (ApiKey starting with ghp_, ghu_, ghs_, github_pat_, gho_)
#      - No key   (generates a ready-to-paste prompt file instead)
# 6. Saves:
#    - Original SP
#    - Query Plan
#    - AI Analysis Report  (or Prompt.txt when no key)
#    - Optimized SP
#    - Benchmark comparison
# ============================================================

function OptimizeSPFromDB {
    [CmdletBinding()]
    param (
        [string]$ServerInstance = "localhost\SQLEXPRESS",
        [string]$Database       = "YourDB",
        [string]$StoredProc     = "dbo.YourProcedure",
        [string]$Params         = "@Param1=1, @Param2='Test'",
        [string]$OutDir         = "C:\SP_Optimization",
        # Leave blank or omit to enter prompt-only mode (no API call made)
        [string]$ApiKey         = ""
    )

    # -------------------------------------------------------------------------
    # Helper: detect which AI provider owns this key
    # -------------------------------------------------------------------------
    function Get-AIProvider ([string]$key) {
        if     ([string]::IsNullOrWhiteSpace($key))               { return "none"    }
        elseif ($key -match "^(ghp_|ghu_|ghs_|github_pat_|gho_)") { return "copilot" }
        elseif ($key -match "^sk-")                               { return "openai"  }
        else                                                       { return "unknown" }
    }

    # -------------------------------------------------------------------------
    # Helper: call OpenAI chat completions
    # -------------------------------------------------------------------------
    function Invoke-OpenAI ([string]$prompt, [string]$key, [string]$model = "gpt-4o") {
        $body = @{
            model       = $model
            messages    = @(@{ role = "user"; content = $prompt })
            temperature = 0.2
        } | ConvertTo-Json -Depth 4

        $resp = Invoke-RestMethod `
            -Uri     "https://api.openai.com/v1/chat/completions" `
            -Headers @{ "Authorization" = "Bearer $key"; "Content-Type" = "application/json" } `
            -Method  Post `
            -Body    $body

        return $resp.choices[0].message.content
    }

    # -------------------------------------------------------------------------
    # Helper: call GitHub Copilot API  (OpenAI-compatible endpoint)
    #
    # The Copilot API lives at https://api.githubcopilot.com and requires two
    # extra headers that VS Code / JetBrains send automatically:
    #   Copilot-Integration-Id: vscode-chat
    #   Editor-Version:         vscode/1.85.0
    #
    # Supported models (pass via -CopilotModel):
    #   gpt-4o (default)  |  gpt-4o-mini  |  gpt-4  |  o1-preview
    #   o1-mini           |  claude-3.5-sonnet        |  gemini-1.5-pro
    #
    # NOTE: o1 / o1-preview / o1-mini do NOT support a system message or the
    #       temperature parameter — the function handles that automatically.
    # -------------------------------------------------------------------------
    function Invoke-GitHubCopilot ([string]$prompt, [string]$key, [string]$model = "gpt-4o") {

        # o1-series reasoning models have restrictions
        $isO1 = $model -match "^o1"

        $messages = if ($isO1) {
            # o1 models: user message only, no system role
            @(@{ role = "user"; content = $prompt })
        } else {
            @(
                @{ role = "system"; content = "You are a SQL Server performance expert and query optimizer." },
                @{ role = "user";   content = $prompt }
            )
        }

        $bodyHash = @{
            model    = $model
            messages = $messages
        }
        if (-not $isO1) { $bodyHash["temperature"] = 0.2 }

        $body = $bodyHash | ConvertTo-Json -Depth 4

        $resp = Invoke-RestMethod `
            -Uri     "https://api.githubcopilot.com/chat/completions" `
            -Headers @{
                "Authorization"          = "Bearer $key"
                "Content-Type"           = "application/json"
                "Copilot-Integration-Id" = "vscode-chat"
                "Editor-Version"         = "vscode/1.85.0"
            } `
            -Method Post `
            -Body   $body

        return $resp.choices[0].message.content
    }

    # -------------------------------------------------------------------------
    # Helper: build a nicely formatted copy-paste prompt file when no key given
    # -------------------------------------------------------------------------
    function Save-PromptFile ([string]$prompt, [string]$outDir, [string]$procName) {
        $ts          = Get-Date -Format "yyyy-MM-dd HH:mm"
        $promptFile  = Join-Path $outDir "Prompt.txt"
        $instructions = @"
==============================================================
  SQL OPTIMIZER — READY-TO-PASTE PROMPT
  Procedure : $procName
  Generated : $ts
==============================================================

No API key was provided, so no AI call was made.
Copy everything between the dashed lines and paste it into
any of the platforms below:

  ChatGPT   →  https://chat.openai.com         (use GPT-4o)
  Claude    →  https://claude.ai               (use Claude Sonnet)
  Gemini    →  https://gemini.google.com       (use Gemini 1.5 Pro)
  Copilot   →  VS Code › Copilot Chat panel    (paste as a message)
  Perplexity→  https://www.perplexity.ai

To enable automatic AI optimization, re-run with one of:
  -ApiKey "sk-proj-..."          (OpenAI key)
  -ApiKey "ghp_..."              (GitHub Personal Access Token with Copilot scope)

--------------------------------------------------------------
$prompt
--------------------------------------------------------------
"@
        $instructions | Out-File -FilePath $promptFile -Encoding UTF8
        return $promptFile
    }

    # =========================================================================
    # MAIN WORKFLOW
    # =========================================================================

    $provider = Get-AIProvider $ApiKey

    Write-Output ""
    Write-Output "=== SQL Stored Procedure Optimizer ==="
    Write-Output "  Procedure : $StoredProc"
    Write-Output "  Database  : $Database @ $ServerInstance"
    Write-Output "  AI mode   : $(if ($provider -eq 'none') {'prompt-only (no key supplied)'} elseif ($provider -eq 'copilot') {'GitHub Copilot API'} elseif ($provider -eq 'openai') {'OpenAI'} else {'unknown key format — will try OpenAI endpoint'})"
    Write-Output "  Output    : $OutDir"
    Write-Output ""

    # Ensure output directory
    if (-not (Test-Path $OutDir)) {
        New-Item -Path $OutDir -ItemType Directory | Out-Null
    }

    # -------------------------------------------------------------------------
    # 1. Extract stored procedure definition
    # -------------------------------------------------------------------------
    $procFile = Join-Path $OutDir "StoredProc.sql"
    Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query `
        "SELECT OBJECT_DEFINITION(OBJECT_ID('$StoredProc')) AS ProcDefinition" |
        ForEach-Object { $_.ProcDefinition | Out-File -FilePath $procFile -Encoding UTF8 }
    Write-Output "  [1/8] Stored procedure saved: $procFile"

    # -------------------------------------------------------------------------
    # 2. Capture execution plan
    # -------------------------------------------------------------------------
    $planFile = Join-Path $OutDir "QueryPlan.xml"
    $planQuery = "SET STATISTICS XML ON; EXEC $StoredProc $Params; SET STATISTICS XML OFF;"

    Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $planQuery |
        ForEach-Object {
            if ($_["Microsoft.SqlServer.Management.Smo.ExecutionPlan"]) {
                $_["Microsoft.SqlServer.Management.Smo.ExecutionPlan"].InnerXml |
                    Out-File -FilePath $planFile -Encoding UTF8
            }
        }
    Write-Output "  [2/8] Execution plan saved: $planFile"

    # -------------------------------------------------------------------------
    # 3. Benchmark original procedure
    # -------------------------------------------------------------------------
    $benchmarkFile = Join-Path $OutDir "Benchmark_Original.txt"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database `
        -Query "EXEC $StoredProc $Params"
    $sw.Stop()
    $origMs = $sw.ElapsedMilliseconds
    "Procedure  : $StoredProc`nRun type   : original`nElapsed (ms): $origMs" |
        Out-File -FilePath $benchmarkFile -Encoding UTF8
    Write-Output "  [3/8] Original benchmark: ${origMs} ms  →  $benchmarkFile"

    # -------------------------------------------------------------------------
    # 4. Build AI prompt
    # -------------------------------------------------------------------------
    $spContent   = Get-Content $procFile -Raw
    $planContent = Get-Content $planFile -Raw -ErrorAction SilentlyContinue
    if (-not $planContent) { $planContent = "(execution plan not captured)" }

    $prompt = @"
You are a SQL Server performance engineer and query optimizer with 20+ years of experience.

I am providing:

1. Stored procedure definition:
$spContent

2. Execution plan (XML):
$planContent

Tasks:
1. Identify and explain the main performance issues (parameter sniffing, missing indexes,
   table/index scans, bad joins, implicit conversions, RBAR patterns, etc.).
2. Suggest and explain what optimizations should be applied and why.
3. Provide the fully rewritten stored procedure renamed to ${StoredProc}_Optimized.
4. Return your answer in exactly two labelled sections:
   ## Analysis Report
   (detailed explanation of every fault found and every optimization applied)

   ## Optimized Stored Procedure
   (complete runnable SQL only — no extra commentary inside the code block)
"@

    # -------------------------------------------------------------------------
    # 5. Call AI  (or save prompt file if no key)
    # -------------------------------------------------------------------------
    $aiOutput = $null

    switch ($provider) {

        "openai" {
            Write-Output "  [5/8] Calling OpenAI API (gpt-4o)..."
            try {
                $aiOutput = Invoke-OpenAI -prompt $prompt -key $ApiKey -model "gpt-4o"
                Write-Output "  [5/8] OpenAI response received."
            } catch {
                Write-Warning "  OpenAI call failed: $_"
                Write-Warning "  Falling back to prompt-only mode."
                $provider = "none"
            }
        }

        "copilot" {
            # Default to gpt-4o; override by setting $env:GHCP_MODEL before calling
            $copilotModel = if ($env:GHCP_MODEL) { $env:GHCP_MODEL } else { "gpt-4o" }
            Write-Output "  [5/8] Calling GitHub Copilot API (model: $copilotModel)..."
            try {
                $aiOutput = Invoke-GitHubCopilot -prompt $prompt -key $ApiKey -model $copilotModel
                Write-Output "  [5/8] GitHub Copilot response received."
            } catch {
                Write-Warning "  Copilot API call failed: $_"
                Write-Warning "  Falling back to prompt-only mode."
                $provider = "none"
            }
        }

        "unknown" {
            # Unrecognised key format — try OpenAI endpoint and warn
            Write-Warning "  Key format not recognised. Attempting OpenAI endpoint..."
            try {
                $aiOutput = Invoke-OpenAI -prompt $prompt -key $ApiKey -model "gpt-4o"
                Write-Output "  [5/8] Response received."
            } catch {
                Write-Warning "  API call failed: $_"
                $provider = "none"
            }
        }

        "none" {
            # Intentional no-key path — handled below
        }
    }

    # If we ended up with no AI output, save prompt file and exit gracefully
    if ($provider -eq "none" -or -not $aiOutput) {
        Write-Output ""
        Write-Output "  *** No API key supplied (or all API calls failed). ***"
        Write-Output "  *** Generating a ready-to-paste prompt file instead. ***"
        Write-Output ""
        $pf = Save-PromptFile -prompt $prompt -outDir $OutDir -procName $StoredProc
        Write-Output "  [5/8] Prompt file saved: $pf"
        Write-Output ""
        Write-Output "  Copy the prompt from the file above and paste it into ChatGPT,"
        Write-Output "  Claude, Gemini, GitHub Copilot Chat, or any other AI assistant."
        Write-Output ""
        Write-Output "  To enable automatic optimization, re-run with:"
        Write-Output "    -ApiKey 'sk-proj-...'   (OpenAI)"
        Write-Output "    -ApiKey 'ghp_...'       (GitHub Copilot)"
        Write-Output ""
        Write-Output "Workflow complete (prompt-only mode)."
        return
    }

    # -------------------------------------------------------------------------
    # 6. Split AI response into analysis + optimized SQL
    # -------------------------------------------------------------------------
    if ($aiOutput -match "(?si)##\s*Analysis Report\s*(.*?)##\s*Optimized Stored Procedure\s*(.*)") {
        $analysis     = $Matches[1].Trim()
        $optimizedSQL = $Matches[2].Trim()
        # Strip any surrounding ```sql ... ``` fences the AI may have added
        $optimizedSQL = $optimizedSQL -replace "(?si)^```sql\s*", "" -replace "\s*```$", ""
    } else {
        # Fallback: use full response as analysis, flag the SQL section
        $analysis     = $aiOutput
        $optimizedSQL = "-- AI response did not follow the expected section format.`n-- Full response saved in Analysis_Report.txt"
    }

    $analysisFile  = Join-Path $OutDir "Analysis_Report.txt"
    $optimizedFile = Join-Path $OutDir "StoredProc_Optimized.sql"

    $analysis     | Out-File -FilePath $analysisFile  -Encoding UTF8
    $optimizedSQL | Out-File -FilePath $optimizedFile -Encoding UTF8

    Write-Output "  [6/8] Analysis report saved   : $analysisFile"
    Write-Output "  [6/8] Optimized procedure saved: $optimizedFile"

    # -------------------------------------------------------------------------
    # 7. Benchmark optimized procedure
    # -------------------------------------------------------------------------
    $optBenchmarkFile = Join-Path $OutDir "Benchmark_Optimized.txt"
    $sw.Restart()
    try {
        Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database `
            -Query "EXEC ${StoredProc}_Optimized $Params"
        $sw.Stop()
        $optMs = $sw.ElapsedMilliseconds
    } catch {
        $sw.Stop()
        $optMs = -1
        Write-Warning "  Optimized proc benchmark failed (proc may not be deployed yet): $_"
    }

    "Procedure  : ${StoredProc}_Optimized`nRun type   : optimized`nElapsed (ms): $optMs" |
        Out-File -FilePath $optBenchmarkFile -Encoding UTF8
    Write-Output "  [7/8] Optimized benchmark: ${optMs} ms  →  $optBenchmarkFile"

    # -------------------------------------------------------------------------
    # 8. Compare benchmarks
    # -------------------------------------------------------------------------
    $compFile = Join-Path $OutDir "Benchmark_Comparison.txt"

    $saved   = if ($optMs -ge 0) { $origMs - $optMs } else { "N/A" }
    $pctImp  = if ($optMs -ge 0 -and $origMs -gt 0) {
                   "{0:N1}" -f (($origMs - $optMs) / $origMs * 100)
               } else { "N/A" }
    $speedup = if ($optMs -gt 0) { "{0:N2}" -f ($origMs / $optMs) } else { "N/A" }

    @"
============================================================
  BENCHMARK COMPARISON
============================================================
  Procedure  : $StoredProc
  Generated  : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  AI Provider: $provider
------------------------------------------------------------
  Original execution time  : $origMs ms
  Optimized execution time : $(if ($optMs -ge 0) {"$optMs ms"} else {"not measured"})
------------------------------------------------------------
  Time saved               : $saved ms
  Improvement              : $pctImp %
  Speedup factor           : ${speedup}x
============================================================
"@ | Out-File -FilePath $compFile -Encoding UTF8

    Write-Output "  [8/8] Benchmark comparison saved: $compFile"
    Write-Output ""
    Write-Output "=== Optimization workflow complete! ==="
    Write-Output "  Original  : $origMs ms"
    if ($optMs -ge 0) {
        Write-Output "  Optimized : $optMs ms  ($pctImp% improvement, ${speedup}x faster)"
    }
    Write-Output "  Output dir: $OutDir"
    Write-Output ""
}

# ============================================================
# EXAMPLE CALLS
# ============================================================

# --- OpenAI (GPT-4o) ---
# OptimizeSPFromDB `
#     -ServerInstance "localhost\SQLEXPRESS" `
#     -Database       "AdventureWorks" `
#     -StoredProc     "dbo.uspGetBillOfMaterials" `
#     -Params         "@StartProductID = 749, @CheckDate = '2010-05-26'" `
#     -OutDir         "C:\SP_Optimization" `
#     -ApiKey         "sk-proj-..."

# --- GitHub Copilot API ---
# $env:GHCP_MODEL = "gpt-4o"   # optional — default is gpt-4o
#                               # other options: gpt-4o-mini | gpt-4 | o1-preview
#                               #                o1-mini | claude-3.5-sonnet | gemini-1.5-pro
# OptimizeSPFromDB `
#     -ServerInstance "localhost\SQLEXPRESS" `
#     -Database       "AdventureWorks" `
#     -StoredProc     "dbo.uspGetBillOfMaterials" `
#     -Params         "@StartProductID = 749, @CheckDate = '2010-05-26'" `
#     -OutDir         "C:\SP_Optimization" `
#     -ApiKey         "ghp_..."    # GitHub PAT with Copilot scope

# --- No key — generates Prompt.txt for manual copy-paste ---
OptimizeSPFromDB `
    -ServerInstance "<ServerName>" `
    -Database       "<DatabaseName>" `
    -StoredProc     "dbo.<StoredProcedureName>" `
    -Params         "@StartProductID = 749, @CheckDate = '2010-05-26'" `
    -OutDir         "<FolderPath>"
    # -ApiKey not supplied → prompt-only mode
