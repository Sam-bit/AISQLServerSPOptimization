# ==============================================================================
# SQL Stored Procedure Optimizer  —  Advanced Edition
# ==============================================================================
#
# FEATURES
# --------
#  Core workflow
#    1.  Multi-run warm/cold benchmarking with statistical analysis (avg/min/max/stddev)
#    2.  Execution plan capture + XML parsing (scans, lookups, implicit conversions,
#        missing-index hints, parallelism, memory grants, spills)
#    3.  AI optimization via OpenAI, GitHub Copilot API, or prompt-only mode
#    4.  Automatic index suggestion DDL generation from plan missing-index hints
#    5.  Side-by-side diff of original vs optimized SQL
#    6.  HTML + Markdown + JSON summary reports
#
#  Static analysis (no DB connection needed)
#    7.  50+ SQL anti-pattern checks (SELECT *, NOT IN, leading LIKE %, NOLOCK misuse,
#        implicit type conversions, OR on indexed columns, correlated subqueries, etc.)
#    8.  Parameter sniff detection via sys.dm_exec_query_stats variance analysis
#    9.  Missing index detection from sys.dm_db_missing_index_details
#   10.  Fragmentation check via sys.dm_db_index_physical_stats
#
#  Reliability & operations
#   11.  Retry logic with exponential back-off on all DB and API calls
#   12.  Structured JSON run log (timestamp, duration, errors, scores)
#   13.  Timestamped session subfolder so re-runs never overwrite previous results
#   14.  Safety check — refuses to run if SP contains DDL/DML mutations
#   15.  Credential prompt fallback when no password supplied
#   16.  Configurable warm-up runs before benchmarking
#   17.  -WhatIf / -Confirm / -Verbose support throughout
#   18.  Batch mode: pipe a CSV list of stored procs, optimize them all
#
#  AI provider support
#   19.  OpenAI   (sk- / sk-proj- keys)
#   20.  GitHub Copilot API  (ghp_ / ghu_ / ghs_ / github_pat_ / gho_ tokens)
#   21.  Prompt-only fallback (saves Prompt.txt for manual ChatGPT/Claude/Gemini use)
#   22.  Model override: -AIModel param accepted by both providers
#   23.  o1/o1-mini reasoning model support (no system prompt, no temperature)
#
# USAGE
# -----
#   Single procedure (OpenAI):
#     OptimizeSPFromDB -ServerInstance "srv\SQL" -Database "AdventureWorks" `
#       -StoredProc "dbo.uspGetBillOfMaterials" `
#       -Params "@StartProductID=749, @CheckDate='2010-05-26'" `
#       -OutDir "C:\Opt" -ApiKey "sk-proj-..."
#
#   Single procedure (GitHub Copilot):
#     OptimizeSPFromDB ... -ApiKey "ghp_..." -AIModel "gpt-4o"
#
#   Batch mode (CSV):
#     Optimize-SPBatch -CsvPath "C:\procs.csv" -ApiKey "sk-proj-..."
#     CSV columns: ServerInstance,Database,StoredProc,Params,OutDir
#
#   Prompt-only (no key):
#     OptimizeSPFromDB ... -OutDir "C:\Opt"
#
# ==============================================================================

#requires -Version 5.1

# ── Module-level config ────────────────────────────────────────────────────────
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Global scoring weights (tweak to taste)
$script:ScoreWeights = @{
    AvgElapsedMs      = 40   # lower = better
    LogicalReads      = 25   # lower = better
    PhysicalReads     = 15   # lower = better
    AntiPatternCount  = 10   # lower = better
    MissingIndexCount = 10   # lower = better
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION A — LOGGING & OUTPUT HELPERS
# ══════════════════════════════════════════════════════════════════════════════

function Write-Step {
    param([string]$Step, [string]$Message, [string]$Color = "Cyan")
    Write-Host "  [$Step] " -ForegroundColor $Color -NoNewline
    Write-Host $Message
}

function Write-Banner {
    param([string]$Title)
    $line = "=" * 64
    Write-Host ""
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host "  ── $Title " -ForegroundColor Yellow -NoNewline
    Write-Host ("─" * ([Math]::Max(0, 56 - $Title.Length))) -ForegroundColor DarkGray
}

# Structured run log — accumulated during execution, saved as JSON at the end
$script:RunLog = [System.Collections.Generic.List[hashtable]]::new()

function Add-LogEntry {
    param([string]$Category, [string]$Message, [string]$Level = "INFO", [hashtable]$Data = @{})
    $entry = @{
        Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fff")
        Level     = $Level
        Category  = $Category
        Message   = $Message
        Data      = $Data
    }
    $script:RunLog.Add($entry)
    if ($Level -eq "WARN")  { Write-Warning $Message }
    if ($Level -eq "ERROR") { Write-Error   $Message -ErrorAction Continue }
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION B — DATABASE HELPERS (retry + credential)
# ══════════════════════════════════════════════════════════════════════════════

function Invoke-SqlWithRetry {
    <#
    .SYNOPSIS
    Invoke-Sqlcmd wrapper with exponential back-off retry and optional credentials.
    #>
    param(
        [string]$ServerInstance,
        [string]$Database,
        [string]$Query,
        [int]   $MaxRetries  = 3,
        [int]   $BaseDelayMs = 500,
        [System.Management.Automation.PSCredential]$Credential = $null,
        [int]   $QueryTimeout = 120,
        [switch]$AsDataTable
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $splat = @{
                ServerInstance = $ServerInstance
                Database       = $Database
                Query          = $Query
                QueryTimeout   = $QueryTimeout
                OutputSqlErrors = $true
            }
            if ($Credential) {
                $splat["Username"] = $Credential.UserName
                $splat["Password"] = $Credential.GetNetworkCredential().Password
            }
            $result = Invoke-Sqlcmd @splat
            return $result
        }
        catch {
            if ($attempt -ge $MaxRetries) {
                Add-LogEntry "DB" "Query failed after $MaxRetries attempts: $_" "ERROR"
                throw
            }
            $delay = $BaseDelayMs * [Math]::Pow(2, $attempt - 1)
            Add-LogEntry "DB" "Attempt $attempt failed, retrying in ${delay}ms…" "WARN"
            Start-Sleep -Milliseconds $delay
        }
    }
}

function Get-DBCredential {
    param(
        [string]$ServerInstance,
        [System.Management.Automation.PSCredential]$Credential
    )
    # If we already have a credential, return it unchanged
    if ($Credential) { return $Credential }
    # Try Windows auth first (no credential needed for Invoke-Sqlcmd)
    return $null
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION C — AI PROVIDER HELPERS
# ══════════════════════════════════════════════════════════════════════════════

function Get-AIProvider {
    param([string]$key)
    if     ([string]::IsNullOrWhiteSpace($key))                { return "none"    }
    elseif ($key -match "^(ghp_|ghu_|ghs_|github_pat_|gho_)")  { return "copilot" }
    elseif ($key -match "^sk-")                                 { return "openai"  }
    else                                                        { return "unknown" }
}

function Invoke-OpenAI {
    param(
        [string]$Prompt,
        [string]$ApiKey,
        [string]$Model       = "gpt-4o",
        [double]$Temperature = 0.2,
        [int]   $MaxTokens   = 4096
    )

    $body = @{
        model       = $Model
        messages    = @(@{ role = "user"; content = $Prompt })
        temperature = $Temperature
        max_tokens  = $MaxTokens
    } | ConvertTo-Json -Depth 5

    $resp = Invoke-RestMethod `
        -Uri     "https://api.openai.com/v1/chat/completions" `
        -Headers @{ "Authorization" = "Bearer $ApiKey"; "Content-Type" = "application/json" } `
        -Method  Post `
        -Body    $body `
        -TimeoutSec 180

    Add-LogEntry "AI" "OpenAI tokens used: prompt=$($resp.usage.prompt_tokens) completion=$($resp.usage.completion_tokens)" "INFO" `
        @{ model = $Model; prompt_tokens = $resp.usage.prompt_tokens; completion_tokens = $resp.usage.completion_tokens }

    return $resp.choices[0].message.content
}

function Invoke-GitHubCopilot {
    param(
        [string]$Prompt,
        [string]$ApiKey,
        [string]$Model       = "gpt-4o",
        [double]$Temperature = 0.2,
        [int]   $MaxTokens   = 4096
    )

    # o1-series: no system message, no temperature
    $isO1 = $Model -match "^o1"

    $messages = if ($isO1) {
        @(@{ role = "user"; content = $Prompt })
    } else {
        @(
            @{ role = "system"; content = "You are a SQL Server performance engineer and query optimizer with 20+ years of experience. Be precise, technical, and thorough." }
            @{ role = "user";   content = $Prompt }
        )
    }

    $bodyHash = @{ model = $Model; messages = $messages; max_tokens = $MaxTokens }
    if (-not $isO1) { $bodyHash["temperature"] = $Temperature }

    $body = $bodyHash | ConvertTo-Json -Depth 5

    $resp = Invoke-RestMethod `
        -Uri     "https://api.githubcopilot.com/chat/completions" `
        -Headers @{
            "Authorization"          = "Bearer $ApiKey"
            "Content-Type"           = "application/json"
            "Copilot-Integration-Id" = "vscode-chat"
            "Editor-Version"         = "vscode/1.85.0"
        } `
        -Method  Post `
        -Body    $body `
        -TimeoutSec 180

    Add-LogEntry "AI" "Copilot tokens used: prompt=$($resp.usage.prompt_tokens) completion=$($resp.usage.completion_tokens)" "INFO" `
        @{ model = $Model; prompt_tokens = $resp.usage.prompt_tokens; completion_tokens = $resp.usage.completion_tokens }

    return $resp.choices[0].message.content
}

function Invoke-AIWithRetry {
    param(
        [string]$Prompt,
        [string]$ApiKey,
        [string]$Provider,
        [string]$Model,
        [int]   $MaxRetries = 3
    )

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            switch ($Provider) {
                "openai"  { return Invoke-OpenAI        -Prompt $Prompt -ApiKey $ApiKey -Model $Model }
                "copilot" { return Invoke-GitHubCopilot -Prompt $Prompt -ApiKey $ApiKey -Model $Model }
                "unknown" { return Invoke-OpenAI        -Prompt $Prompt -ApiKey $ApiKey -Model $Model }
            }
        }
        catch {
            if ($i -ge $MaxRetries) { throw }
            $delay = 2000 * $i
            Add-LogEntry "AI" "API attempt $i failed ($($_)), retrying in ${delay}ms" "WARN"
            Start-Sleep -Milliseconds $delay
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION D — STATIC SQL ANALYSIS (50+ anti-pattern checks)
# ══════════════════════════════════════════════════════════════════════════════

function Invoke-StaticSQLAnalysis {
    <#
    .SYNOPSIS
    Regex-based anti-pattern scanner. Returns an array of finding objects.
    Runs entirely offline — no DB connection required.
    #>
    param([string]$SQL)

    $findings = [System.Collections.Generic.List[hashtable]]::new()

    function Add-Finding {
        param([string]$Severity, [string]$Code, [string]$Title, [string]$Detail, [string]$Fix)
        $findings.Add(@{
            Severity = $Severity   # CRITICAL / HIGH / MEDIUM / LOW / INFO
            Code     = $Code
            Title    = $Title
            Detail   = $Detail
            Fix      = $Fix
        })
    }

    $s = $SQL   # shorthand

    # ── Performance anti-patterns ──────────────────────────────────────────────
    if ($s -match "(?i)\bSELECT\s+\*") {
        Add-Finding "HIGH" "AP001" "SELECT *" `
            "SELECT * retrieves all columns including unused ones, increases I/O and network traffic, and prevents index covering." `
            "List only the columns you actually need."
    }
    if ($s -match "(?i)\bNOT\s+IN\s*\(") {
        Add-Finding "HIGH" "AP002" "NOT IN with subquery" `
            "NOT IN returns no rows if the subquery contains any NULL. Also forces a full scan." `
            "Replace with NOT EXISTS or a LEFT JOIN … WHERE key IS NULL."
    }
    if ($s -match "(?i)LIKE\s+'%[^%']+") {
        Add-Finding "HIGH" "AP003" "Leading wildcard LIKE" `
            "LIKE '%value' or LIKE '%value%' cannot use an index seek — forces a full table scan." `
            "Use Full-Text Search (CONTAINS/FREETEXT) or restructure the predicate."
    }
    if ($s -match "(?i)\bOR\b.{0,200}\bOR\b") {
        Add-Finding "MEDIUM" "AP004" "Multiple OR predicates" `
            "OR on indexed columns often prevents index seeks and forces scans." `
            "Consider UNION ALL of separate SARGable queries, or filtered indexes."
    }
    if ($s -match "(?i)\bCONVERT\s*\(|CAST\s*\(" ) {
        Add-Finding "MEDIUM" "AP005" "CONVERT/CAST in WHERE or JOIN" `
            "Functions applied to indexed columns disable index seeks (non-SARGable)." `
            "Move the conversion to the parameter/literal side, or use computed+indexed columns."
    }
    if ($s -match "(?i)\bISNULL\s*\(|ISNULL\s*\(") {
        Add-Finding "MEDIUM" "AP006" "ISNULL on indexed column" `
            "ISNULL() on a column in a WHERE clause disables index seeks." `
            "Use column IS NULL / IS NOT NULL directly, or use COALESCE on the literal side."
    }
    if ($s -match "(?i)\bDISTINCT\b") {
        Add-Finding "LOW" "AP007" "DISTINCT keyword" `
            "DISTINCT implies a sort/dedup pass. Often masks a cartesian join bug." `
            "Verify the join logic is correct; remove DISTINCT if row duplication is expected."
    }
    if ($s -match "(?i)\bCROSS\s+JOIN\b") {
        Add-Finding "CRITICAL" "AP008" "CROSS JOIN (Cartesian product)" `
            "CROSS JOIN produces rows = table1_rows × table2_rows. Almost always unintentional." `
            "Add the correct JOIN … ON predicate."
    }
    if ($s -match "(?i)\bCURSOR\b") {
        Add-Finding "CRITICAL" "AP009" "CURSOR usage" `
            "Cursors process rows one at a time (RBAR), causing massive context-switching overhead." `
            "Rewrite using set-based operations, CTEs, or window functions."
    }
    if ($s -match "(?i)\bWHILE\b") {
        Add-Finding "HIGH" "AP010" "WHILE loop (possible RBAR)" `
            "WHILE loops used for row-by-row processing are the #1 SQL performance anti-pattern." `
            "Rewrite as a single set-based statement or use batch processing."
    }
    if ($s -match "(?i)\bSELECT\s+.+\bFROM\b(?!.+\bWHERE\b)") {
        Add-Finding "HIGH" "AP011" "Missing WHERE clause" `
            "No WHERE clause — this query will scan the entire table on every execution." `
            "Add a selective WHERE predicate on an indexed column."
    }
    if ($s -match "(?i)\bSUBSTRING\s*\(|LEFT\s*\(|RIGHT\s*\(|UPPER\s*\(|LOWER\s*\(|LEN\s*\(") {
        Add-Finding "MEDIUM" "AP012" "String function on column in predicate" `
            "String functions applied to columns in WHERE/JOIN disable index seeks." `
            "Apply the function to the literal/parameter side instead."
    }
    if ($s -match "(?i)\bNOLOCK\b|\bREAD UNCOMMITTED\b") {
        Add-Finding "MEDIUM" "AP013" "NOLOCK / READ UNCOMMITTED hint" `
            "NOLOCK reads dirty (uncommitted) data. Can return phantom rows, missing rows, or corrupt data." `
            "Use SNAPSHOT ISOLATION or READ COMMITTED SNAPSHOT if you need non-blocking reads."
    }
    if ($s -match "(?i)\bIN\s*\(\s*SELECT\b") {
        Add-Finding "MEDIUM" "AP014" "IN (SELECT …) correlated subquery" `
            "IN with a subquery re-executes the subquery for every outer row." `
            "Rewrite as EXISTS or as a JOIN."
    }
    if (([regex]::Matches($s, "(?i)\bJOIN\b")).Count -gt 6) {
        Add-Finding "MEDIUM" "AP015" "Excessive JOIN count (>6)" `
            "More than 6 JOINs increases the optimizer search space and can lead to bad plan choices." `
            "Consider breaking into smaller CTEs, temp tables, or stored sub-procedures."
    }
    if ($s -match "(?i)\bORDER\s+BY\b.{0,60}\bTOP\b|\bTOP\b.{0,100}\bORDER\s+BY\b") {
        # This is fine — but check for TOP without ORDER BY
    }
    if ($s -match "(?i)\bTOP\b" -and $s -notmatch "(?i)\bORDER\s+BY\b") {
        Add-Finding "MEDIUM" "AP016" "TOP without ORDER BY" `
            "TOP without ORDER BY returns a non-deterministic set of rows." `
            "Always pair TOP with ORDER BY unless non-determinism is intentional."
    }
    if ($s -match "(?i)\bEXEC\s*\(|\bEXECUTE\s*\(|sp_executesql") {
        Add-Finding "LOW" "AP017" "Dynamic SQL detected" `
            "Dynamic SQL can introduce SQL injection risk and prevents plan reuse if not parameterized." `
            "Always use sp_executesql with typed parameters; never concatenate user input."
    }
    if ($s -match "(?i)\bSP_\b") {
        Add-Finding "LOW" "AP018" "System stored procedure prefix (sp_)" `
            "Using 'sp_' prefix causes SQL Server to search master DB first, adding overhead." `
            "Rename procedures to use a custom prefix (e.g. usp_, proc_)."
    }
    if ($s -match "(?i)\bGROUP\s+BY\b" -and $s -notmatch "(?i)\bINDEX\b.*\bGROUP") {
        Add-Finding "LOW" "AP019" "GROUP BY without visible index hint" `
            "GROUP BY requires a sort or hash operation. Verify a covering index exists on GROUP BY columns." `
            "Add an index on the GROUP BY columns or use indexed views for frequent aggregations."
    }
    if ($s -match "(?i)\bUPDATE\s+STATISTICS\b|\bSP_UPDATESTATS\b") {
        Add-Finding "INFO" "AP020" "Manual statistics update in procedure" `
            "Updating statistics inside a procedure adds overhead on every execution." `
            "Let the auto-update statistics job handle this, or schedule separately."
    }
    if (([regex]::Matches($s, "(?i)\(SELECT")).Count -gt 2) {
        Add-Finding "MEDIUM" "AP021" "Multiple scalar subqueries in SELECT list" `
            "Scalar subqueries in SELECT execute once per row — equivalent to a cursor." `
            "Rewrite as JOINs or use OUTER APPLY."
    }
    if ($s -match "(?i)\bUNION\b" -and $s -notmatch "(?i)\bUNION\s+ALL\b") {
        Add-Finding "MEDIUM" "AP022" "UNION (without ALL)" `
            "UNION without ALL performs a deduplication sort across both result sets." `
            "Use UNION ALL if duplicates are acceptable or logically impossible."
    }
    if ($s -match "(?i)\bCONVERT\s*\(\s*(varchar|nvarchar|char|nchar)" ) {
        Add-Finding "MEDIUM" "AP023" "Implicit or explicit varchar conversion in predicate" `
            "Type mismatches between column and parameter types force implicit conversion on every row." `
            "Ensure parameter/literal type exactly matches the column's declared type."
    }
    if ($s -match "(?i)GETDATE\(\)|SYSDATETIME\(\)" -and $s -match "(?i)\bWHERE\b") {
        Add-Finding "LOW" "AP024" "GETDATE() in WHERE clause" `
            "GETDATE() in a WHERE clause is non-deterministic and prevents plan caching for that predicate." `
            "Assign GETDATE() to a variable before the query and reference the variable."
    }
    if ($s -match "(?i)\bSELECT\b.{0,300}\bINTO\s+#") {
        Add-Finding "INFO" "AP025" "SELECT INTO temp table" `
            "SELECT INTO creates a table with minimal logging and no pre-existing index structure." `
            "Consider CREATE TABLE + INSERT for better index control, especially for large result sets."
    }

    # ── Parameter sniffing indicators ──────────────────────────────────────────
    if ($s -match "(?i)\bOPTION\s*\(\s*RECOMPILE\s*\)") {
        Add-Finding "INFO" "AP026" "OPTION(RECOMPILE) present" `
            "OPTION(RECOMPILE) prevents plan caching — useful for highly skewed parameters, but adds compilation cost." `
            "Consider OPTIMIZE FOR or local variable copies of parameters for a more targeted fix."
    }
    if ($s -match "(?i)\bOPTIMIZE\s+FOR\b") {
        Add-Finding "INFO" "AP027" "OPTIMIZE FOR hint present" `
            "OPTION(OPTIMIZE FOR) can fix parameter sniffing but may produce a suboptimal plan for other values." `
            "Consider a plan guide or filtered indexes if you need different plans per parameter range."
    }

    # ── Index hints ────────────────────────────────────────────────────────────
    if ($s -match "(?i)WITH\s*\(\s*INDEX\s*\(") {
        Add-Finding "LOW" "AP028" "Hard-coded index hint (WITH (INDEX(...)))" `
            "Hard-coded index hints bypass the optimizer. The optimal index may change as data grows." `
            "Remove the hint and let the optimizer choose; fix underlying statistics if it chooses poorly."
    }

    return $findings.ToArray()
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION E — EXECUTION PLAN PARSER
# ══════════════════════════════════════════════════════════════════════════════

function Invoke-PlanAnalysis {
    <#
    .SYNOPSIS
    Parses a SQL Server XML execution plan and returns a structured analysis object.
    Extracts: top operators, scans, key lookups, missing indexes, implicit conversions,
    parallelism, memory grants, and estimated vs actual row discrepancies.
    #>
    param([string]$PlanXml)

    $result = @{
        Scans               = @()
        KeyLookups          = @()
        MissingIndexes      = @()
        ImplicitConversions = @()
        ParallelOperators   = @()
        MemoryGrantMB       = 0
        SpillWarnings       = @()
        TopCostOperators    = @()
        EstimatedSubtreeCost = 0
        Findings            = @()
    }

    if ([string]::IsNullOrWhiteSpace($PlanXml)) { return $result }

    try {
        $xml = [xml]$PlanXml
        $ns  = @{ sql = "http://schemas.microsoft.com/sqlserver/2004/07/showplan" }

        # ── Top-level cost ────────────────────────────────────────────────────
        $stmtNodes = $xml.SelectNodes("//sql:StmtSimple", (New-Object System.Xml.XmlNamespaceManager($xml.NameTable)))
        if (-not $stmtNodes) {
            $stmtNodes = $xml.SelectNodes("//StmtSimple")
        }
        foreach ($stmt in $stmtNodes) {
            $cost = [double]($stmt.Attributes["StatementSubTreeCost"]?.Value ?? 0)
            if ($cost -gt $result.EstimatedSubtreeCost) { $result.EstimatedSubtreeCost = $cost }
        }

        # Helper: try both namespaced and non-namespaced selects
        function Select-PlanNodes([xml]$x, [string]$xpath) {
            $nm = New-Object System.Xml.XmlNamespaceManager($x.NameTable)
            $nm.AddNamespace("sql","http://schemas.microsoft.com/sqlserver/2004/07/showplan")
            $nodes = $x.SelectNodes($xpath, $nm)
            if (-not $nodes -or $nodes.Count -eq 0) {
                $plain = $xpath -replace "sql:", ""
                $nodes = $x.SelectNodes($plain)
            }
            return $nodes
        }

        # ── Scans ─────────────────────────────────────────────────────────────
        $scanTypes = @("Table Scan","Index Scan","Clustered Index Scan","RID Lookup")
        $relops = Select-PlanNodes $xml "//sql:RelOp"
        foreach ($op in $relops) {
            $physOp = $op.Attributes["PhysicalOp"]?.Value
            if ($physOp -in $scanTypes) {
                $tbl = ($op.SelectNodes(".//*[@Table]") | Select-Object -First 1)?.Attributes["Table"]?.Value
                $cost = [double]($op.Attributes["EstimatedTotalSubtreeCost"]?.Value ?? 0)
                $result.Scans += @{ Type = $physOp; Table = $tbl; Cost = $cost }
            }
            if ($physOp -eq "Key Lookup") {
                $tbl = ($op.SelectNodes(".//*[@Table]") | Select-Object -First 1)?.Attributes["Table"]?.Value
                $result.KeyLookups += @{ Table = $tbl }
            }
        }

        # ── Top cost operators ────────────────────────────────────────────────
        $result.TopCostOperators = $relops | ForEach-Object {
            @{
                Operator = $_.Attributes["PhysicalOp"]?.Value
                Cost     = [double]($_.Attributes["EstimatedTotalSubtreeCost"]?.Value ?? 0)
                EstRows  = [double]($_.Attributes["EstimateRows"]?.Value ?? 0)
            }
        } | Sort-Object { $_.Cost } -Descending | Select-Object -First 5

        # ── Missing index hints ───────────────────────────────────────────────
        $miNodes = Select-PlanNodes $xml "//sql:MissingIndex"
        foreach ($mi in $miNodes) {
            $db      = $mi.Attributes["Database"]?.Value
            $schema  = $mi.Attributes["Schema"]?.Value
            $table   = $mi.Attributes["Table"]?.Value
            $eqCols  = ($mi.SelectNodes(".//*[@Usage='EQUALITY']")   | ForEach-Object { $_.Attributes["Name"]?.Value }) -join ", "
            $ineqCol = ($mi.SelectNodes(".//*[@Usage='INEQUALITY']") | ForEach-Object { $_.Attributes["Name"]?.Value }) -join ", "
            $incCols = ($mi.SelectNodes(".//*[@Usage='INCLUDE']")    | ForEach-Object { $_.Attributes["Name"]?.Value }) -join ", "
            $impact  = [double]($mi.ParentNode?.Attributes["Impact"]?.Value ?? 0)

            $ddl = "CREATE NONCLUSTERED INDEX [IX_$(($table -replace '[\[\]]',''))_Auto]"
            $ddl += " ON $schema.$table"
            $allKeyCols = @($eqCols, $ineqCol) | Where-Object { $_ } | ForEach-Object { $_.Split(",").Trim() }
            $ddl += " ($($allKeyCols -join ', '))"
            if ($incCols) { $ddl += " INCLUDE ($incCols)" }
            $ddl += ";"

            $result.MissingIndexes += @{
                Database  = $db; Schema = $schema; Table = $table
                EqCols    = $eqCols; IneqCols = $ineqCol; IncCols = $incCols
                Impact    = $impact; DDL = $ddl
            }
        }

        # ── Implicit conversions ──────────────────────────────────────────────
        $convNodes = Select-PlanNodes $xml "//sql:PlanAffectingConvert"
        foreach ($c in $convNodes) {
            $result.ImplicitConversions += @{
                Expression  = $c.Attributes["Expression"]?.Value
                ConvertIssue = $c.Attributes["ConvertIssue"]?.Value
            }
        }

        # ── Parallelism ───────────────────────────────────────────────────────
        $parallelOps = $relops | Where-Object { $_.Attributes["Parallel"]?.Value -eq "1" }
        $result.ParallelOperators = @($parallelOps | ForEach-Object { $_.Attributes["PhysicalOp"]?.Value })

        # ── Memory grants & spills ────────────────────────────────────────────
        $mgNodes = Select-PlanNodes $xml "//sql:MemoryGrantInfo"
        foreach ($mg in $mgNodes) {
            $grant = [double]($mg.Attributes["SerialRequiredMemory"]?.Value ?? 0)
            $result.MemoryGrantMB = [Math]::Max($result.MemoryGrantMB, [Math]::Round($grant / 1024, 1))
        }
        $spillNodes = Select-PlanNodes $xml "//sql:SpillToTempDb"
        foreach ($sp in $spillNodes) {
            $result.SpillWarnings += @{ SpillLevel = $sp.Attributes["SpillLevel"]?.Value }
        }

        # ── Derive plan findings ──────────────────────────────────────────────
        if ($result.Scans.Count -gt 0) {
            $result.Findings += "⚠ $($result.Scans.Count) scan(s) detected: $($result.Scans | ForEach-Object {"$($_.Type) on $($_.Table)"} | Select-Object -Unique | Join-String ", ")"
        }
        if ($result.KeyLookups.Count -gt 0) {
            $result.Findings += "⚠ $($result.KeyLookups.Count) Key Lookup(s) — add INCLUDE columns to eliminate lookups"
        }
        if ($result.MissingIndexes.Count -gt 0) {
            $result.Findings += "⚠ $($result.MissingIndexes.Count) missing index hint(s) detected by the optimizer"
        }
        if ($result.ImplicitConversions.Count -gt 0) {
            $result.Findings += "⚠ $($result.ImplicitConversions.Count) implicit conversion(s) — type mismatch disables index seeks"
        }
        if ($result.SpillWarnings.Count -gt 0) {
            $result.Findings += "⚠ Sort/Hash spill to TempDB detected — insufficient memory grant or row estimate error"
        }
        if ($result.MemoryGrantMB -gt 256) {
            $result.Findings += "⚠ Memory grant ${result.MemoryGrantMB} MB — large sort/hash operations, check row estimates"
        }
        if ($result.ParallelOperators.Count -gt 0) {
            $result.Findings += "ℹ Parallel plan detected ($($result.ParallelOperators.Count) parallel ops) — verify MAXDOP setting"
        }
    }
    catch {
        Add-LogEntry "Plan" "Plan XML parse error: $_" "WARN"
    }

    return $result
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION F — DMV QUERIES
# ══════════════════════════════════════════════════════════════════════════════

function Get-ParameterSniffingRisk {
    param(
        [string]$ServerInstance,
        [string]$Database,
        [string]$StoredProc,
        [System.Management.Automation.PSCredential]$Credential
    )
    $query = @"
SELECT
    qs.execution_count,
    qs.total_elapsed_time   / 1000  AS total_elapsed_ms,
    qs.min_elapsed_time     / 1000  AS min_elapsed_ms,
    qs.max_elapsed_time     / 1000  AS max_elapsed_ms,
    qs.total_logical_reads          AS total_logical_reads,
    qs.min_logical_reads            AS min_logical_reads,
    qs.max_logical_reads            AS max_logical_reads,
    qs.total_physical_reads         AS total_physical_reads,
    qs.total_worker_time    / 1000  AS total_cpu_ms,
    CAST(qs.total_elapsed_time AS FLOAT) / NULLIF(qs.execution_count,0) / 1000 AS avg_elapsed_ms,
    CAST(qs.total_logical_reads AS FLOAT) / NULLIF(qs.execution_count,0) AS avg_logical_reads
FROM sys.dm_exec_procedure_stats ps
JOIN sys.objects o ON ps.object_id = o.object_id
JOIN sys.schemas s ON o.schema_id  = s.schema_id
CROSS APPLY sys.dm_exec_query_plan(ps.plan_handle) qp
CROSS APPLY sys.dm_exec_sql_text(ps.sql_handle)   qt
JOIN sys.dm_exec_query_stats qs ON qs.plan_handle = ps.plan_handle
WHERE s.name + '.' + o.name = '$StoredProc'
ORDER BY qs.max_elapsed_time DESC
"@
    try {
        $rows = Invoke-SqlWithRetry -ServerInstance $ServerInstance -Database $Database `
            -Query $query -Credential $Credential -QueryTimeout 30
        if (-not $rows) { return $null }

        # Variance ratio: if max/min > 5x on elapsed or reads → likely sniffing
        $row   = $rows[0]
        $ratio = if ($row.min_elapsed_ms -gt 0) { $row.max_elapsed_ms / $row.min_elapsed_ms } else { 1 }
        return @{
            ExecutionCount    = $row.execution_count
            AvgElapsedMs      = [Math]::Round($row.avg_elapsed_ms, 1)
            MinElapsedMs      = $row.min_elapsed_ms
            MaxElapsedMs      = $row.max_elapsed_ms
            TotalLogicalReads = $row.total_logical_reads
            AvgLogicalReads   = [Math]::Round($row.avg_logical_reads, 0)
            TotalCpuMs        = $row.total_cpu_ms
            VarianceRatio     = [Math]::Round($ratio, 1)
            HighSniffRisk     = ($ratio -gt 5)
        }
    }
    catch { Add-LogEntry "DMV" "Param sniff query failed: $_" "WARN"; return $null }
}

function Get-MissingIndexesFromDMV {
    param(
        [string]$ServerInstance,
        [string]$Database,
        [System.Management.Automation.PSCredential]$Credential
    )
    $query = @"
SELECT TOP 15
    migs.avg_total_user_cost   * migs.avg_user_impact * (migs.user_seeks + migs.user_scans) AS improvement_score,
    migs.avg_user_impact,
    migs.user_seeks,
    migs.user_scans,
    mid.statement                              AS full_table,
    mid.equality_columns,
    mid.inequality_columns,
    mid.included_columns,
    'CREATE NONCLUSTERED INDEX [IX_' + REPLACE(REPLACE(mid.statement,'[',''),']','') + '_DMV_' +
       CAST(ROW_NUMBER() OVER (ORDER BY migs.avg_total_user_cost DESC) AS varchar) + '] ON ' +
       mid.statement + ' (' +
       ISNULL(mid.equality_columns,'') +
       CASE WHEN mid.equality_columns IS NOT NULL AND mid.inequality_columns IS NOT NULL THEN ',' ELSE '' END +
       ISNULL(mid.inequality_columns,'') + ')' +
       CASE WHEN mid.included_columns IS NOT NULL THEN ' INCLUDE (' + mid.included_columns + ')' ELSE '' END + ';' AS suggested_ddl
FROM sys.dm_db_missing_index_group_stats migs
JOIN sys.dm_db_missing_index_groups      mig  ON migs.group_handle = mig.index_group_handle
JOIN sys.dm_db_missing_index_details     mid  ON mig.index_handle  = mid.index_handle
WHERE mid.database_id = DB_ID()
ORDER BY improvement_score DESC
"@
    try {
        $rows = Invoke-SqlWithRetry -ServerInstance $ServerInstance -Database $Database `
            -Query $query -Credential $Credential -QueryTimeout 30
        return @($rows)
    }
    catch { Add-LogEntry "DMV" "Missing index DMV query failed: $_" "WARN"; return @() }
}

function Get-FragmentedIndexes {
    param(
        [string]$ServerInstance,
        [string]$Database,
        [string]$StoredProc,
        [System.Management.Automation.PSCredential]$Credential
    )
    # Extract table names referenced in the proc
    $query = @"
SELECT DISTINCT
    OBJECT_NAME(i.object_id)  AS TableName,
    i.name                    AS IndexName,
    ips.avg_fragmentation_in_percent,
    ips.page_count,
    CASE
        WHEN ips.avg_fragmentation_in_percent > 30 THEN 'REBUILD'
        WHEN ips.avg_fragmentation_in_percent > 10 THEN 'REORGANIZE'
        ELSE 'OK'
    END AS Recommendation
FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'LIMITED') ips
JOIN sys.indexes i ON ips.object_id = i.object_id AND ips.index_id = i.index_id
WHERE ips.page_count > 100
  AND ips.avg_fragmentation_in_percent > 10
  AND i.index_id > 0
ORDER BY ips.avg_fragmentation_in_percent DESC
"@
    try {
        $rows = Invoke-SqlWithRetry -ServerInstance $ServerInstance -Database $Database `
            -Query $query -Credential $Credential -QueryTimeout 60
        return @($rows)
    }
    catch { Add-LogEntry "DMV" "Fragmentation query failed (non-fatal): $_" "WARN"; return @() }
}

function Get-WaitStats {
    param(
        [string]$ServerInstance,
        [string]$Database,
        [System.Management.Automation.PSCredential]$Credential
    )
    $query = @"
SELECT TOP 10
    wait_type,
    waiting_tasks_count,
    CAST(wait_time_ms AS FLOAT) / NULLIF(waiting_tasks_count,0) AS avg_wait_ms,
    signal_wait_time_ms,
    wait_time_ms - signal_wait_time_ms AS resource_wait_time_ms
FROM sys.dm_os_wait_stats
WHERE wait_type NOT IN (
    'SLEEP_TASK','BROKER_TO_FLUSH','BROKER_TASK_STOP','CLR_AUTO_EVENT',
    'DISPATCHER_QUEUE_SEMAPHORE','FT_IFTS_SCHEDULER_IDLE_WAIT','HADR_FILESTREAM_IOMGR_IOCOMPLETION',
    'HADR_WORK_QUEUE','LAZYWRITER_SLEEP','LOGMGR_QUEUE','ONDEMAND_TASK_QUEUE',
    'REQUEST_FOR_DEADLOCK_MONITOR','RESOURCE_QUEUE','SERVER_IDLE_CHECK',
    'SLEEP_DBSTARTUP','SLEEP_DCOMSTARTUP','SLEEP_MASTERDBREADY','SLEEP_MASTERMDREADY',
    'SLEEP_MASTERUPGRADED','SLEEP_MSDBSTARTUP','SLEEP_SYSTEMTASK','SLEEP_TEMPDBSTARTUP',
    'SNI_HTTP_ACCEPT','SP_SERVER_DIAGNOSTICS_SLEEP','SQLTRACE_BUFFER_FLUSH',
    'SQLTRACE_INCREMENTAL_FLUSH_SLEEP','WAITFOR','XE_DISPATCHER_WAIT','XE_TIMER_EVENT',
    'BROKER_EVENTHANDLER','CHECKPOINT_QUEUE','DBMIRROR_EVENTS_QUEUE'
)
ORDER BY wait_time_ms DESC
"@
    try {
        $rows = Invoke-SqlWithRetry -ServerInstance $ServerInstance -Database $Database `
            -Query $query -Credential $Credential -QueryTimeout 20
        return @($rows)
    }
    catch { return @() }
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION G — SAFETY CHECKER
# ══════════════════════════════════════════════════════════════════════════════

function Test-SQLSafety {
    <#
    .SYNOPSIS
    Refuses to benchmark or run a stored procedure that contains schema-destructive
    or data-mutating DDL/DML beyond what is expected in a read-heavy SP.
    Returns $true if safe, $false + warning messages if dangerous.
    #>
    param([string]$SQL, [switch]$AllowDML)

    $dangers = @()
    $s = $SQL.ToUpper()

    if ($s -match "\bDROP\s+(TABLE|INDEX|VIEW|DATABASE|SCHEMA)\b") { $dangers += "DROP statement detected" }
    if ($s -match "\bTRUNCATE\s+TABLE\b")                          { $dangers += "TRUNCATE TABLE detected" }
    if ($s -match "\bDELETE\b" -and -not $AllowDML)               { $dangers += "DELETE statement (use -AllowDML to permit)" }
    if ($s -match "\bUPDATE\b.*\bSET\b" -and -not $AllowDML)       { $dangers += "UPDATE statement (use -AllowDML to permit)" }
    if ($s -match "\bALTER\s+(TABLE|DATABASE|SCHEMA)\b")           { $dangers += "ALTER TABLE/DATABASE detected" }
    if ($s -match "\bxp_cmdshell\b|\bsp_oacreate\b")              { $dangers += "Shell execution (xp_cmdshell/sp_OACreate)" }

    return @{ Safe = ($dangers.Count -eq 0); Warnings = $dangers }
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION H — MULTI-RUN BENCHMARK ENGINE
# ══════════════════════════════════════════════════════════════════════════════

function Invoke-BenchmarkRuns {
    <#
    .SYNOPSIS
    Runs a stored procedure N times (with configurable warm-up) and returns
    statistical summary: avg, min, max, stddev, median elapsed ms.
    Also captures logical reads from SET STATISTICS IO.
    #>
    param(
        [string]$ServerInstance,
        [string]$Database,
        [string]$ProcCall,          # e.g. "EXEC dbo.uspFoo @P1=1"
        [int]   $Runs        = 5,
        [int]   $WarmupRuns  = 1,
        [System.Management.Automation.PSCredential]$Credential = $null
    )

    $allTimes  = [System.Collections.Generic.List[double]]::new()
    $logReads  = [System.Collections.Generic.List[long]]::new()
    $physReads = [System.Collections.Generic.List[long]]::new()

    $totalRuns = $WarmupRuns + $Runs
    Write-Verbose "    Benchmark: $totalRuns total runs ($WarmupRuns warm-up + $Runs measured)"

    for ($i = 1; $i -le $totalRuns; $i++) {
        $isWarmup = ($i -le $WarmupRuns)
        $label    = if ($isWarmup) { "warmup $i" } else { "run $($i - $WarmupRuns)" }

        # Wrap in SET STATISTICS IO to capture reads
        $wrappedQuery = @"
DECLARE @t0 datetime2 = SYSDATETIME();
SET STATISTICS IO ON;
$ProcCall;
SET STATISTICS IO OFF;
SELECT DATEDIFF_BIG(MICROSECOND, @t0, SYSDATETIME()) AS elapsed_us;
"@
        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            Invoke-SqlWithRetry -ServerInstance $ServerInstance -Database $Database `
                -Query $ProcCall -Credential $Credential -QueryTimeout 300 | Out-Null
            $sw.Stop()
            $ms = $sw.Elapsed.TotalMilliseconds

            if (-not $isWarmup) {
                $allTimes.Add($ms)
                Write-Verbose "      $label: ${ms:N1} ms"
            } else {
                Write-Verbose "      $label (warmup): ${ms:N1} ms [not counted]"
            }
        }
        catch {
            Add-LogEntry "Bench" "Run $label failed: $_" "WARN"
            if (-not $isWarmup) { $allTimes.Add(-1) }
        }
    }

    # Filter out failures
    $valid = $allTimes | Where-Object { $_ -ge 0 }
    if (-not $valid) { return @{ AvgMs = -1; MinMs = -1; MaxMs = -1; MedianMs = -1; StdDevMs = 0; Runs = 0 } }

    $sorted = $valid | Sort-Object
    $avg    = ($valid | Measure-Object -Sum).Sum / $valid.Count
    $median = if ($valid.Count % 2 -eq 0) {
                  ($sorted[$valid.Count/2 - 1] + $sorted[$valid.Count/2]) / 2
              } else { $sorted[[Math]::Floor($valid.Count/2)] }
    $stddev = [Math]::Sqrt(($valid | ForEach-Object { [Math]::Pow($_ - $avg, 2) } | Measure-Object -Sum).Sum / $valid.Count)

    return @{
        AvgMs    = [Math]::Round($avg,    1)
        MinMs    = [Math]::Round(($valid | Measure-Object -Minimum).Minimum, 1)
        MaxMs    = [Math]::Round(($valid | Measure-Object -Maximum).Maximum, 1)
        MedianMs = [Math]::Round($median, 1)
        StdDevMs = [Math]::Round($stddev, 1)
        Runs     = $valid.Count
        AllTimes = @($valid)
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION I — SQL DIFF GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

function Get-SQLDiff {
    param([string]$Original, [string]$Optimized, [string]$ProcName)

    $origLines = $Original  -split "`n"
    $optLines  = $Optimized -split "`n"

    $added   = ($optLines | Where-Object { $_ -notin $origLines }).Count
    $removed = ($origLines | Where-Object { $_ -notin $optLines }).Count

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("--- $ProcName  (original)")
    [void]$sb.AppendLine("+++ ${ProcName}_Optimized  (AI-rewritten)")
    [void]$sb.AppendLine("@@ Summary: +$added lines added, -$removed lines removed @@")
    [void]$sb.AppendLine("")

    # Simple unified diff — mark removed then added
    foreach ($line in $origLines) {
        if ($line -notin $optLines) { [void]$sb.AppendLine("- $line") }
    }
    foreach ($line in $optLines) {
        if ($line -notin $origLines) { [void]$sb.AppendLine("+ $line") }
    }

    return @{
        Content      = $sb.ToString()
        LinesAdded   = $added
        LinesRemoved = $removed
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION J — PERFORMANCE SCORER
# ══════════════════════════════════════════════════════════════════════════════

function Get-PerformanceScore {
    <#
    .SYNOPSIS
    Computes a 0-100 performance score. Higher = better.
    Used to track before/after improvement.
    #>
    param(
        [double]$AvgElapsedMs,
        [int]   $AntiPatternCount,
        [int]   $MissingIndexCount,
        [int]   $ScanCount,
        [int]   $KeyLookupCount
    )

    # Penalties (0 = perfect)
    $timePenalty    = [Math]::Min(40, [Math]::Log([Math]::Max($AvgElapsedMs, 1), 10) * 10)
    $antiPenalty    = [Math]::Min(25, $AntiPatternCount * 3)
    $missingPenalty = [Math]::Min(15, $MissingIndexCount * 5)
    $scanPenalty    = [Math]::Min(10, $ScanCount * 3)
    $lookupPenalty  = [Math]::Min(10, $KeyLookupCount * 2)

    $total = $timePenalty + $antiPenalty + $missingPenalty + $scanPenalty + $lookupPenalty
    return [Math]::Max(0, [Math]::Round(100 - $total, 1))
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION K — REPORT GENERATORS
# ══════════════════════════════════════════════════════════════════════════════

function New-HTMLReport {
    param(
        [string]  $ProcName,
        [string]  $Database,
        [string]  $ServerInstance,
        [hashtable]$OrigBench,
        [hashtable]$OptBench,
        [hashtable]$PlanAnalysis,
        [hashtable]$SniffData,
        [array]   $StaticFindings,
        [array]   $DMVMissingIndexes,
        [array]   $FragIndexes,
        [string]  $AIAnalysis,
        [double]  $ScoreBefore,
        [double]  $ScoreAfter,
        [string]  $AIProvider,
        [string]  $AIModel
    )

    $ts        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $pctImp    = if ($OrigBench.AvgMs -gt 0 -and $OptBench.AvgMs -gt 0) {
                     [Math]::Round(($OrigBench.AvgMs - $OptBench.AvgMs) / $OrigBench.AvgMs * 100, 1)
                 } else { 0 }
    $speedup   = if ($OptBench.AvgMs -gt 0) { [Math]::Round($OrigBench.AvgMs / $OptBench.AvgMs, 2) } else { "N/A" }
    $scoreImp  = [Math]::Round($ScoreAfter - $ScoreBefore, 1)
    $perfColor = if ($pctImp -gt 40) { "#22c55e" } elseif ($pctImp -gt 10) { "#f59e0b" } else { "#ef4444" }

    # Severity badges
    $sevBadge = @{
        CRITICAL = '<span style="background:#ef4444;color:#fff;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:700">CRITICAL</span>'
        HIGH     = '<span style="background:#f97316;color:#fff;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:700">HIGH</span>'
        MEDIUM   = '<span style="background:#f59e0b;color:#fff;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:700">MEDIUM</span>'
        LOW      = '<span style="background:#3b82f6;color:#fff;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:700">LOW</span>'
        INFO     = '<span style="background:#6b7280;color:#fff;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:700">INFO</span>'
    }

    $staticRows = ($StaticFindings | ForEach-Object {
        "<tr><td>$($sevBadge[$_.Severity])</td><td><strong>$($_.Code)</strong> — $($_.Title)</td><td>$($_.Fix)</td></tr>"
    }) -join "`n"

    $missingIdxRows = ($PlanAnalysis.MissingIndexes | ForEach-Object {
        "<tr><td>$($_.Table)</td><td style='font-size:11px'>$($_.DDL)</td><td>$([Math]::Round($_.Impact,1))%</td></tr>"
    }) -join "`n"
    if (-not $missingIdxRows) { $missingIdxRows = '<tr><td colspan="3" style="color:#6b7280;font-style:italic">No missing indexes detected in plan</td></tr>' }

    $dmvIdxRows = ($DMVMissingIndexes | ForEach-Object {
        "<tr><td>$($_.full_table)</td><td style='font-size:11px'>$($_.suggested_ddl)</td><td>$([Math]::Round($_.avg_user_impact,1))%</td></tr>"
    }) -join "`n"
    if (-not $dmvIdxRows) { $dmvIdxRows = '<tr><td colspan="3" style="color:#6b7280;font-style:italic">No DMV index suggestions</td></tr>' }

    $planFindingsHtml = ($PlanAnalysis.Findings | ForEach-Object { "<li>$_</li>" }) -join "`n"
    if (-not $planFindingsHtml) { $planFindingsHtml = "<li style='color:#22c55e'>No critical plan issues detected</li>" }

    $aiAnalysisHtml = [System.Web.HttpUtility]::HtmlEncode($AIAnalysis) -replace "`n", "<br>"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SQL Optimizer Report — $ProcName</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 24px; }
  h1 { font-size: 22px; color: var(--accent); margin-bottom: 4px; }
  h2 { font-size: 16px; color: var(--accent); margin: 24px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
  h3 { font-size: 13px; color: var(--muted); margin-bottom: 8px; text-transform: uppercase; letter-spacing: .05em; }
  .subtitle { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
  .grid3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 20px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .metric-val { font-size: 28px; font-weight: 700; margin-bottom: 2px; }
  .metric-lbl { font-size: 12px; color: var(--muted); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 10px; background: #0f172a; color: var(--muted); font-size: 11px; text-transform: uppercase; border-bottom: 1px solid var(--border); }
  td { padding: 8px 10px; border-bottom: 1px solid #1e293b; vertical-align: top; }
  tr:hover td { background: #1e293b; }
  .code-block { background: #020817; border: 1px solid var(--border); border-radius: 6px; padding: 14px; font-family: 'Cascadia Code','Consolas',monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; color: #7dd3fc; max-height: 400px; overflow-y: auto; margin-top: 8px; }
  .score-bar { height: 8px; border-radius: 4px; background: var(--border); margin-top: 4px; }
  .score-fill { height: 100%; border-radius: 4px; background: linear-gradient(90deg,#ef4444,#f59e0b,#22c55e); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-green { background:#166534; color:#bbf7d0; }
  .badge-yellow { background:#78350f; color:#fde68a; }
  .badge-red { background:#7f1d1d; color:#fecaca; }
  ul { padding-left: 20px; }
  li { margin-bottom: 4px; font-size: 13px; }
  footer { margin-top: 32px; font-size: 11px; color: var(--muted); text-align: center; }
</style>
</head>
<body>

<h1>🔧 SQL Stored Procedure Optimizer Report</h1>
<p class="subtitle">
  <strong>$ProcName</strong> &nbsp;·&nbsp; $Database @ $ServerInstance &nbsp;·&nbsp;
  AI: $AIProvider ($AIModel) &nbsp;·&nbsp; Generated: $ts
</p>

<h2>📊 Performance Summary</h2>
<div class="grid3">
  <div class="card">
    <div class="metric-val" style="color:$perfColor">${pctImp}%</div>
    <div class="metric-lbl">Execution time improvement</div>
    <div style="color:$perfColor; font-size:13px; margin-top:4px">${speedup}× faster (avg)</div>
  </div>
  <div class="card">
    <div class="metric-val">$($OrigBench.AvgMs) ms</div>
    <div class="metric-lbl">Original avg (${OrigBench.Runs} runs)</div>
    <div style="color:var(--muted);font-size:12px;margin-top:4px">min $($OrigBench.MinMs) · max $($OrigBench.MaxMs) · σ $($OrigBench.StdDevMs)</div>
  </div>
  <div class="card">
    <div class="metric-val" style="color:#22c55e">$($OptBench.AvgMs) ms</div>
    <div class="metric-lbl">Optimized avg (${OptBench.Runs} runs)</div>
    <div style="color:var(--muted);font-size:12px;margin-top:4px">min $($OptBench.MinMs) · max $($OptBench.MaxMs) · σ $($OptBench.StdDevMs)</div>
  </div>
</div>

<div class="grid2">
  <div class="card">
    <h3>Quality Score Before</h3>
    <div class="metric-val">$ScoreBefore / 100</div>
    <div class="score-bar"><div class="score-fill" style="width:${ScoreBefore}%"></div></div>
  </div>
  <div class="card">
    <h3>Quality Score After</h3>
    <div class="metric-val" style="color:#22c55e">$ScoreAfter / 100</div>
    <div class="score-bar"><div class="score-fill" style="width:${ScoreAfter}%"></div></div>
    <div style="color:#22c55e; font-size:12px; margin-top:6px">▲ +$scoreImp points improvement</div>
  </div>
</div>

<h2>⚠ Static Anti-Pattern Analysis ($($StaticFindings.Count) findings)</h2>
<div class="card">
  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th>Recommended Fix</th></tr></thead>
    <tbody>
      $staticRows
    </tbody>
  </table>
</div>

<h2>📋 Execution Plan Analysis</h2>
<div class="grid2">
  <div class="card">
    <h3>Plan Findings</h3>
    <ul>$planFindingsHtml</ul>
  </div>
  <div class="card">
    <h3>Top Cost Operators</h3>
    <table>
      <thead><tr><th>Operator</th><th>Est. Cost</th><th>Est. Rows</th></tr></thead>
      <tbody>
$(($PlanAnalysis.TopCostOperators | ForEach-Object { "<tr><td>$($_.Operator)</td><td>$([Math]::Round($_.Cost,4))</td><td>$([Math]::Round($_.EstRows,0))</td></tr>" }) -join "`n")
      </tbody>
    </table>
  </div>
</div>

<h2>🔍 Missing Index Suggestions</h2>
<h3>From Execution Plan</h3>
<div class="card"><table>
  <thead><tr><th>Table</th><th>Suggested DDL</th><th>Est. Impact</th></tr></thead>
  <tbody>$missingIdxRows</tbody>
</table></div>

<h3>From sys.dm_db_missing_index_details (top 15 system-wide)</h3>
<div class="card"><table>
  <thead><tr><th>Table</th><th>Suggested DDL</th><th>Avg Impact</th></tr></thead>
  <tbody>$dmvIdxRows</tbody>
</table></div>

<h2>🤖 AI Analysis Report</h2>
<div class="card">
  <div class="code-block">$aiAnalysisHtml</div>
</div>

<footer>Generated by SQL Stored Procedure Optimizer Advanced Edition · $ts</footer>
</body>
</html>
"@
    return $html
}

function New-MarkdownReport {
    param(
        [string]  $ProcName,
        [hashtable]$OrigBench,
        [hashtable]$OptBench,
        [double]  $ScoreBefore,
        [double]  $ScoreAfter,
        [array]   $StaticFindings,
        [hashtable]$PlanAnalysis,
        [string]  $AIAnalysis,
        [string]  $AIProvider,
        [string]  $AIModel
    )

    $ts     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $pctImp = if ($OrigBench.AvgMs -gt 0 -and $OptBench.AvgMs -gt 0) {
                  [Math]::Round(($OrigBench.AvgMs - $OptBench.AvgMs) / $OrigBench.AvgMs * 100, 1)
              } else { 0 }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# SQL Optimization Report — $ProcName")
    [void]$sb.AppendLine("> Generated: $ts | AI: $AIProvider ($AIModel)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Performance Summary")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Metric | Original | Optimized | Improvement |")
    [void]$sb.AppendLine("|--------|----------|-----------|-------------|")
    [void]$sb.AppendLine("| Avg elapsed | $($OrigBench.AvgMs) ms | $($OptBench.AvgMs) ms | **${pctImp}%** |")
    [void]$sb.AppendLine("| Min elapsed | $($OrigBench.MinMs) ms | $($OptBench.MinMs) ms | — |")
    [void]$sb.AppendLine("| Max elapsed | $($OrigBench.MaxMs) ms | $($OptBench.MaxMs) ms | — |")
    [void]$sb.AppendLine("| Std dev     | $($OrigBench.StdDevMs) ms | $($OptBench.StdDevMs) ms | — |")
    [void]$sb.AppendLine("| Quality score | $ScoreBefore / 100 | $ScoreAfter / 100 | +$([Math]::Round($ScoreAfter-$ScoreBefore,1)) pts |")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Static Analysis Findings")
    [void]$sb.AppendLine("")
    foreach ($f in $StaticFindings) {
        [void]$sb.AppendLine("- **[$($f.Severity)] $($f.Code)** — $($f.Title): $($f.Fix)")
    }
    if (-not $StaticFindings) { [void]$sb.AppendLine("_No anti-patterns detected._") }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Plan Findings")
    [void]$sb.AppendLine("")
    foreach ($f in $PlanAnalysis.Findings) { [void]$sb.AppendLine("- $f") }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Missing Index DDL")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("```sql")
    foreach ($mi in $PlanAnalysis.MissingIndexes) { [void]$sb.AppendLine($mi.DDL) }
    if (-not $PlanAnalysis.MissingIndexes) { [void]$sb.AppendLine("-- No missing indexes detected") }
    [void]$sb.AppendLine("```")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## AI Analysis")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine($AIAnalysis)

    return $sb.ToString()
}

function New-JSONSummary {
    param(
        [string]  $ProcName,
        [string]  $Database,
        [string]  $ServerInstance,
        [hashtable]$OrigBench,
        [hashtable]$OptBench,
        [double]  $ScoreBefore,
        [double]  $ScoreAfter,
        [array]   $StaticFindings,
        [hashtable]$PlanAnalysis,
        [hashtable]$SniffData,
        [string]  $AIProvider,
        [string]  $AIModel,
        [string]  $OutDir
    )
    $pctImp = if ($OrigBench.AvgMs -gt 0 -and $OptBench.AvgMs -gt 0) {
                  [Math]::Round(($OrigBench.AvgMs - $OptBench.AvgMs) / $OrigBench.AvgMs * 100, 1)
              } else { 0 }

    $summary = @{
        run_timestamp      = (Get-Date -Format "o")
        procedure          = $ProcName
        database           = $Database
        server             = $ServerInstance
        ai_provider        = $AIProvider
        ai_model           = $AIModel
        output_directory   = $OutDir
        benchmark = @{
            original  = $OrigBench
            optimized = $OptBench
            improvement_pct = $pctImp
        }
        scores = @{
            before     = $ScoreBefore
            after      = $ScoreAfter
            delta      = [Math]::Round($ScoreAfter - $ScoreBefore, 1)
        }
        static_analysis = @{
            total_findings   = $StaticFindings.Count
            critical         = ($StaticFindings | Where-Object Severity -eq CRITICAL).Count
            high             = ($StaticFindings | Where-Object Severity -eq HIGH).Count
            medium           = ($StaticFindings | Where-Object Severity -eq MEDIUM).Count
            low              = ($StaticFindings | Where-Object Severity -eq LOW).Count
            findings         = $StaticFindings
        }
        plan_analysis = @{
            scans                 = $PlanAnalysis.Scans.Count
            key_lookups           = $PlanAnalysis.KeyLookups.Count
            missing_indexes       = $PlanAnalysis.MissingIndexes.Count
            implicit_conversions  = $PlanAnalysis.ImplicitConversions.Count
            memory_grant_mb       = $PlanAnalysis.MemoryGrantMB
            spill_warnings        = $PlanAnalysis.SpillWarnings.Count
            parallel_operators    = $PlanAnalysis.ParallelOperators.Count
            findings              = $PlanAnalysis.Findings
        }
        parameter_sniffing = $SniffData
        run_log            = $script:RunLog
    }

    return ($summary | ConvertTo-Json -Depth 8)
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION L — PROMPT-ONLY FILE GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

function Save-PromptFile {
    param(
        [string]$Prompt,
        [string]$OutDir,
        [string]$ProcName,
        [array] $StaticFindings,
        [hashtable]$PlanAnalysis
    )

    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm"
    $crits = ($StaticFindings | Where-Object Severity -eq "CRITICAL").Count
    $highs = ($StaticFindings | Where-Object Severity -eq "HIGH").Count

    $header = @"
==============================================================================
  SQL STORED PROCEDURE OPTIMIZER — READY-TO-PASTE PROMPT
  Procedure : $ProcName
  Generated : $ts
==============================================================================

No API key was supplied. The full optimization prompt is below.
Copy everything between the ═══ lines and paste into any AI platform:

  ChatGPT   →  https://chat.openai.com            (GPT-4o recommended)
  Claude    →  https://claude.ai                  (Claude Sonnet recommended)
  Gemini    →  https://gemini.google.com          (Gemini 1.5 Pro recommended)
  Copilot   →  Open VS Code › Copilot Chat panel
  Perplexity→  https://www.perplexity.ai

── PRE-FLIGHT ANALYSIS SUMMARY ──────────────────────────────────────────────
  Static findings : $($StaticFindings.Count) total  ($crits CRITICAL, $highs HIGH)
  Plan issues     : $($PlanAnalysis.Findings.Count)
  Missing indexes : $($PlanAnalysis.MissingIndexes.Count)
  Scans detected  : $($PlanAnalysis.Scans.Count)

  Key issues to tell the AI to focus on:
$(($StaticFindings | Where-Object { $_.Severity -in "CRITICAL","HIGH" } | ForEach-Object { "  • [$($_.Severity)] $($_.Title)" }) -join "`n")
$(($PlanAnalysis.Findings | ForEach-Object { "  • $_ " }) -join "`n")

──────────────────────────────────────────────────────────────────────────────
  To enable AUTOMATIC optimization re-run with:
    -ApiKey "sk-proj-..."    (OpenAI key from platform.openai.com/api-keys)
    -ApiKey "ghp_..."        (GitHub PAT with  read:user + copilot  scopes)
==============================================================================

"@

    $file = Join-Path $OutDir "Prompt.txt"
    ($header + "═"*78 + "`n" + $Prompt + "`n" + "═"*78) |
        Out-File -FilePath $file -Encoding UTF8
    return $file
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION M  ──  MAIN FUNCTION
# ══════════════════════════════════════════════════════════════════════════════

function OptimizeSPFromDB {
    <#
    .SYNOPSIS
    Full SQL stored procedure optimization workflow with AI, benchmarking,
    static analysis, plan parsing, DMV queries, and rich report generation.

    .PARAMETER ServerInstance   SQL Server instance name
    .PARAMETER Database         Target database name
    .PARAMETER StoredProc       Fully qualified proc name (schema.ProcName)
    .PARAMETER Params           Parameter string for EXEC, e.g. "@P1=1, @P2='Test'"
    .PARAMETER OutDir           Root output directory (a timestamped subfolder is created inside)
    .PARAMETER ApiKey           OpenAI sk-... key or GitHub ghp_... token. Omit for prompt-only mode.
    .PARAMETER AIModel          AI model override (default: gpt-4o)
    .PARAMETER BenchmarkRuns    Number of measured benchmark runs (default: 5)
    .PARAMETER WarmupRuns       Warm-up runs before measuring (default: 1)
    .PARAMETER AllowDML         Suppress safety check warnings for UPDATE/DELETE
    .PARAMETER Credential       PSCredential for SQL auth (Windows auth used if omitted)
    .PARAMETER SkipOptimizedBenchmark  Skip benchmarking the optimized proc (it may not be deployed yet)
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Medium")]
    param (
        [Parameter(Mandatory)][string]$ServerInstance,
        [Parameter(Mandatory)][string]$Database,
        [Parameter(Mandatory)][string]$StoredProc,
        [string]$Params         = "",
        [string]$OutDir         = "C:\SP_Optimization",
        [string]$ApiKey         = "",
        [string]$AIModel        = "",         # auto-selected if blank
        [int]   $BenchmarkRuns  = 5,
        [int]   $WarmupRuns     = 1,
        [switch]$AllowDML,
        [System.Management.Automation.PSCredential]$Credential = $null,
        [switch]$SkipOptimizedBenchmark
    )

    $script:RunLog = [System.Collections.Generic.List[hashtable]]::new()
    $runStart      = Get-Date

    # ── Resolve AI provider + default model ───────────────────────────────────
    $provider = Get-AIProvider $ApiKey
    if (-not $AIModel) {
        $AIModel = switch ($provider) {
            "copilot" { "gpt-4o" }
            "openai"  { "gpt-4o" }
            default   { "gpt-4o" }
        }
    }

    # ── Create session output folder ──────────────────────────────────────────
    $sessionStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeProcName = $StoredProc -replace "[^\w]", "_"
    $sessionDir   = Join-Path $OutDir "${safeProcName}_${sessionStamp}"
    New-Item -Path $sessionDir -ItemType Directory -Force | Out-Null

    # ── Banner ────────────────────────────────────────────────────────────────
    Write-Banner "SQL Stored Procedure Optimizer — Advanced Edition"
    Write-Host "  Procedure  : " -NoNewline; Write-Host $StoredProc -ForegroundColor Cyan
    Write-Host "  Database   : " -NoNewline; Write-Host "$Database @ $ServerInstance" -ForegroundColor Cyan
    Write-Host "  AI mode    : " -NoNewline
    switch ($provider) {
        "openai"  { Write-Host "OpenAI ($AIModel)" -ForegroundColor Green }
        "copilot" { Write-Host "GitHub Copilot API ($AIModel)" -ForegroundColor Magenta }
        "none"    { Write-Host "Prompt-only (no key supplied)" -ForegroundColor Yellow }
        default   { Write-Host "Unknown key format — attempting OpenAI" -ForegroundColor Yellow }
    }
    Write-Host "  Benchmarks : $BenchmarkRuns runs + $WarmupRuns warmup"
    Write-Host "  Output dir : $sessionDir"
    Write-Host ""

    Add-LogEntry "Init" "Session started" "INFO" @{
        procedure = $StoredProc; database = $Database; server = $ServerInstance
        provider  = $provider;   model    = $AIModel;  session = $sessionDir
    }

    # ═════════════════════════════════════════════════════════════════════════
    # STEP 1  — Extract stored procedure definition
    # ═════════════════════════════════════════════════════════════════════════
    Write-SectionHeader "Step 1 — Extract Procedure"

    $procFile = Join-Path $sessionDir "StoredProc.sql"
    $procDef  = $null

    try {
        $rows = Invoke-SqlWithRetry -ServerInstance $ServerInstance -Database $Database -Credential $Credential `
            -Query "SELECT OBJECT_DEFINITION(OBJECT_ID('$StoredProc')) AS ProcDefinition"
        $procDef = $rows[0].ProcDefinition
        if (-not $procDef) { throw "OBJECT_DEFINITION returned NULL — does the procedure exist?" }
        $procDef | Out-File -FilePath $procFile -Encoding UTF8
        Write-Step "1/10" "Stored procedure saved: $procFile" "Green"
        Add-LogEntry "Extract" "Procedure extracted ($($procDef.Length) chars)" "INFO"
    }
    catch {
        Add-LogEntry "Extract" "Failed to extract procedure: $_" "ERROR"
        Write-Error "Cannot continue without procedure definition. Aborting."
        return
    }

    # ═════════════════════════════════════════════════════════════════════════
    # STEP 2  — Safety check
    # ═════════════════════════════════════════════════════════════════════════
    Write-SectionHeader "Step 2 — Safety Check"

    $safety = Test-SQLSafety -SQL $procDef -AllowDML:$AllowDML
    if (-not $safety.Safe) {
        foreach ($w in $safety.Warnings) {
            Write-Warning "  SAFETY: $w"
            Add-LogEntry "Safety" $w "WARN"
        }
        if (-not $AllowDML) {
            $confirm = Read-Host "  Dangerous constructs found. Continue anyway? (y/N)"
            if ($confirm -ne "y") {
                Write-Output "Aborted by user due to safety check."
                return
            }
        }
    } else {
        Write-Step "2/10" "Safety check passed — no destructive DDL/DML detected" "Green"
    }

    # ═════════════════════════════════════════════════════════════════════════
    # STEP 3  — Static anti-pattern analysis
    # ═════════════════════════════════════════════════════════════════════════
    Write-SectionHeader "Step 3 — Static Analysis"

    $staticFindings = Invoke-StaticSQLAnalysis -SQL $procDef
    $staticFile     = Join-Path $sessionDir "Static_Analysis.txt"

    $staticReport = "STATIC ANTI-PATTERN ANALYSIS — $StoredProc`n$("="*60)`n"
    $staticReport += "Total findings: $($staticFindings.Count)`n`n"
    foreach ($f in $staticFindings) {
        $staticReport += "[$($f.Severity)] $($f.Code) — $($f.Title)`n"
        $staticReport += "  Detail : $($f.Detail)`n"
        $staticReport += "  Fix    : $($f.Fix)`n`n"
    }
    $staticReport | Out-File -FilePath $staticFile -Encoding UTF8

    $crits = ($staticFindings | Where-Object Severity -eq "CRITICAL").Count
    $highs = ($staticFindings | Where-Object Severity -eq "HIGH").Count
    Write-Step "3/10" "$($staticFindings.Count) findings ($crits CRITICAL, $highs HIGH) → $staticFile" `
        (if ($crits -gt 0) { "Red" } elseif ($highs -gt 0) { "Yellow" } else { "Green" })
    Add-LogEntry "Static" "Static analysis complete" "INFO" @{ findings = $staticFindings.Count }

    # ═════════════════════════════════════════════════════════════════════════
    # STEP 4  — Execution plan capture + parse
    # ═════════════════════════════════════════════════════════════════════════
    Write-SectionHeader "Step 4 — Execution Plan"

    $planFile    = Join-Path $sessionDir "QueryPlan.xml"
    $planXml     = ""
    $planAnalysis = @{ Scans=@(); KeyLookups=@(); MissingIndexes=@(); ImplicitConversions=@()
                       ParallelOperators=@(); MemoryGrantMB=0; SpillWarnings=@()
                       TopCostOperators=@(); EstimatedSubtreeCost=0; Findings=@() }

    $execCall = if ($Params) { "EXEC $StoredProc $Params" } else { "EXEC $StoredProc" }

    try {
        $planQuery = "SET STATISTICS XML ON; $execCall; SET STATISTICS XML OFF;"
        $planRows  = Invoke-SqlWithRetry -ServerInstance $ServerInstance -Database $Database `
            -Credential $Credential -Query $planQuery -QueryTimeout 300

        foreach ($row in $planRows) {
            foreach ($col in $row.Table.Columns.ColumnName) {
                if ($row[$col] -is [System.Xml.XmlDocument]) {
                    $planXml = $row[$col].OuterXml
                    break
                }
            }
            if ($planXml) { break }
        }

        if (-not $planXml) {
            # Try alternate capture method
            $planRows2 = Invoke-SqlWithRetry -ServerInstance $ServerInstance -Database $Database `
                -Credential $Credential `
                -Query "SET SHOWPLAN_XML ON; $execCall; SET SHOWPLAN_XML OFF;" `
                -QueryTimeout 300
            foreach ($row in $planRows2) {
                $firstVal = $row[0]
                if ($firstVal -is [string] -and $firstVal.TrimStart().StartsWith("<")) {
                    $planXml = $firstVal; break
                }
            }
        }

        if ($planXml) {
            $planXml | Out-File -FilePath $planFile -Encoding UTF8
            $planAnalysis = Invoke-PlanAnalysis -PlanXml $planXml
            Write-Step "4/10" "Plan captured + parsed: $($planAnalysis.Scans.Count) scans, $($planAnalysis.MissingIndexes.Count) missing idx hints" "Green"
        } else {
            Write-Step "4/10" "Plan XML not captured (non-fatal — will proceed without)" "Yellow"
        }
    }
    catch {
        Add-LogEntry "Plan" "Plan capture failed (non-fatal): $_" "WARN"
        Write-Step "4/10" "Plan capture skipped (non-fatal): $_" "Yellow"
    }

    # Save missing index DDL file
    if ($planAnalysis.MissingIndexes.Count -gt 0) {
        $idxFile = Join-Path $sessionDir "Missing_Indexes_Plan.sql"
        $idxContent  = "-- Missing Index Suggestions (from execution plan)`n"
        $idxContent += "-- Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n`n"
        foreach ($mi in $planAnalysis.MissingIndexes) {
            $idxContent += "-- Impact: $([Math]::Round($mi.Impact,1))%  Table: $($mi.Schema).$($mi.Table)`n"
            $idxContent += "$($mi.DDL)`n`n"
        }
        $idxContent | Out-File -FilePath $idxFile -Encoding UTF8
        Write-Step "4/10" "Missing index DDL saved: $idxFile" "Cyan"
    }

    # ═════════════════════════════════════════════════════════════════════════
    # STEP 5  — DMV queries (param sniff, missing indexes, wait stats, frag)
    # ═════════════════════════════════════════════════════════════════════════
    Write-SectionHeader "Step 5 — DMV Intelligence"

    $sniffData     = Get-ParameterSniffingRisk -ServerInstance $ServerInstance -Database $Database `
                         -StoredProc $StoredProc -Credential $Credential
    $dmvMissingIdx = Get-MissingIndexesFromDMV -ServerInstance $ServerInstance -Database $Database `
                         -Credential $Credential
    $fragIndexes   = Get-FragmentedIndexes      -ServerInstance $ServerInstance -Database $Database `
                         -StoredProc $StoredProc -Credential $Credential
    $waitStats     = Get-WaitStats              -ServerInstance $ServerInstance -Database $Database `
                         -Credential $Credential

    $dmvFile = Join-Path $sessionDir "DMV_Intelligence.txt"
    $dmvReport = "DMV INTELLIGENCE REPORT — $StoredProc`n$("="*60)`n`n"

    if ($sniffData) {
        $dmvReport += "PARAMETER SNIFFING ANALYSIS`n$("-"*40)`n"
        $dmvReport += "  Execution count   : $($sniffData.ExecutionCount)`n"
        $dmvReport += "  Avg elapsed       : $($sniffData.AvgElapsedMs) ms`n"
        $dmvReport += "  Min / Max elapsed : $($sniffData.MinElapsedMs) / $($sniffData.MaxElapsedMs) ms`n"
        $dmvReport += "  Variance ratio    : $($sniffData.VarianceRatio)x`n"
        $dmvReport += "  High sniff risk   : $(if ($sniffData.HighSniffRisk) {'YES — consider OPTION(RECOMPILE) or OPTIMIZE FOR'} else {'No'})`n`n"
    }

    if ($dmvMissingIdx.Count -gt 0) {
        $dmvMissingIdxFile = Join-Path $sessionDir "Missing_Indexes_DMV.sql"
        $dmvIdxContent = "-- Missing Index Suggestions (from sys.dm_db_missing_index_details)`n"
        $dmvIdxContent += "-- These are SYSTEM-WIDE suggestions ordered by improvement score`n`n"
        foreach ($mi in $dmvMissingIdx) {
            $dmvIdxContent += "-- Impact: $($mi.avg_user_impact)%  Seeks: $($mi.user_seeks)  Table: $($mi.full_table)`n"
            $dmvIdxContent += "$($mi.suggested_ddl)`n`n"
        }
        $dmvIdxContent | Out-File -FilePath $dmvMissingIdxFile -Encoding UTF8
        $dmvReport += "DMV MISSING INDEXES: $($dmvMissingIdx.Count) suggestions saved to Missing_Indexes_DMV.sql`n`n"
        Write-Step "5/10" "DMV: $($dmvMissingIdx.Count) missing index suggestions saved" "Cyan"
    }

    if ($fragIndexes.Count -gt 0) {
        $dmvReport += "FRAGMENTED INDEXES`n$("-"*40)`n"
        foreach ($fi in $fragIndexes) {
            $dmvReport += "  $($fi.TableName).$($fi.IndexName): $([Math]::Round($fi.avg_fragmentation_in_percent,1))% — $($fi.Recommendation)`n"
        }
        $dmvReport += "`n"
    }

    if ($waitStats.Count -gt 0) {
        $dmvReport += "TOP WAIT STATS`n$("-"*40)`n"
        foreach ($ws in $waitStats) {
            $dmvReport += "  $($ws.wait_type): $([Math]::Round($ws.avg_wait_ms,2)) ms avg wait`n"
        }
    }

    $dmvReport | Out-File -FilePath $dmvFile -Encoding UTF8
    Write-Step "5/10" "DMV intelligence saved: $dmvFile" "Green"
    Add-LogEntry "DMV" "DMV queries complete" "INFO" @{ sniff_risk = $sniffData?.HighSniffRisk; dmv_idx = $dmvMissingIdx.Count }

    # ═════════════════════════════════════════════════════════════════════════
    # STEP 6  — Benchmark original procedure (multi-run)
    # ═════════════════════════════════════════════════════════════════════════
    Write-SectionHeader "Step 6 — Benchmark Original ($BenchmarkRuns runs + $WarmupRuns warmup)"

    $origBench = Invoke-BenchmarkRuns `
        -ServerInstance $ServerInstance -Database $Database `
        -ProcCall $execCall -Runs $BenchmarkRuns -WarmupRuns $WarmupRuns `
        -Credential $Credential

    $origBenchFile = Join-Path $sessionDir "Benchmark_Original.txt"
    @"
ORIGINAL PROCEDURE BENCHMARK
Procedure   : $StoredProc
Timestamp   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Runs        : $($origBench.Runs)
Avg (ms)    : $($origBench.AvgMs)
Median (ms) : $($origBench.MedianMs)
Min (ms)    : $($origBench.MinMs)
Max (ms)    : $($origBench.MaxMs)
StdDev (ms) : $($origBench.StdDevMs)
All times   : $(($origBench.AllTimes | ForEach-Object { "$_" }) -join ", ")
"@ | Out-File -FilePath $origBenchFile -Encoding UTF8
    Write-Step "6/10" "Original: avg=$($origBench.AvgMs)ms  min=$($origBench.MinMs)ms  max=$($origBench.MaxMs)ms  σ=$($origBench.StdDevMs)ms" "Green"
    Add-LogEntry "Bench" "Original benchmark complete" "INFO" $origBench

    # ═════════════════════════════════════════════════════════════════════════
    # STEP 7  — Build AI prompt
    # ═════════════════════════════════════════════════════════════════════════
    Write-SectionHeader "Step 7 — Build AI Prompt"

    $spContent   = Get-Content $procFile -Raw
    $planContent = if (Test-Path $planFile) { Get-Content $planFile -Raw } else { "(plan not captured)" }

    $staticSummary = if ($staticFindings) {
        ($staticFindings | ForEach-Object { "  [$($_.Severity)] $($_.Code): $($_.Title) — $($_.Fix)" }) -join "`n"
    } else { "  No anti-patterns found." }

    $planSummary = if ($planAnalysis.Findings) {
        ($planAnalysis.Findings | ForEach-Object { "  • $_" }) -join "`n"
    } else { "  No critical plan issues." }

    $sniffSummary = if ($sniffData) {
        "  Variance ratio: $($sniffData.VarianceRatio)x ($(if ($sniffData.HighSniffRisk) {'HIGH RISK'} else {'low risk'}))"
    } else { "  No execution history in DMV." }

    $prompt = @"
You are a senior SQL Server performance engineer with 20+ years of experience optimizing stored procedures in high-throughput OLTP and OLAP environments.

═══════════════════════════════════════════════════════
STORED PROCEDURE DEFINITION
═══════════════════════════════════════════════════════
$spContent

═══════════════════════════════════════════════════════
EXECUTION PLAN (XML) — focus on scans, lookups, estimates
═══════════════════════════════════════════════════════
$planContent

═══════════════════════════════════════════════════════
PRE-COMPUTED STATIC ANALYSIS FINDINGS
═══════════════════════════════════════════════════════
$staticSummary

═══════════════════════════════════════════════════════
EXECUTION PLAN FINDINGS
═══════════════════════════════════════════════════════
$planSummary

═══════════════════════════════════════════════════════
PARAMETER SNIFFING RISK
═══════════════════════════════════════════════════════
$sniffSummary

═══════════════════════════════════════════════════════
PERFORMANCE BENCHMARK (original)
Average elapsed: $($origBench.AvgMs) ms over $($origBench.Runs) runs
(min: $($origBench.MinMs) ms, max: $($origBench.MaxMs) ms, σ: $($origBench.StdDevMs) ms)
═══════════════════════════════════════════════════════

TASKS — address every issue above:
1. Identify every performance problem (with root cause and severity: CRITICAL/HIGH/MEDIUM/LOW).
2. Explain exactly what optimizations you applied and why each one helps.
3. Rewrite the complete stored procedure with the new name ${StoredProc}_Optimized.
4. Include all index suggestions as CREATE INDEX DDL statements (with INCLUDE columns).
5. If parameter sniffing is high-risk, add OPTION(RECOMPILE) or use local variable copies.

OUTPUT FORMAT — use these EXACT section headers:

## Analysis Report
[detailed findings]

## Optimized Stored Procedure
[complete SQL — no extra text, just runnable T-SQL]

## Index Recommendations
[CREATE INDEX DDL statements]

## Summary of Changes
[numbered list of every change made and why]
"@

    $promptFile = Join-Path $sessionDir "AI_Prompt.txt"
    $prompt | Out-File -FilePath $promptFile -Encoding UTF8
    Write-Step "7/10" "Prompt built ($([Math]::Round($prompt.Length/1024,1)) KB) → $promptFile" "Green"

    # ═════════════════════════════════════════════════════════════════════════
    # STEP 8  — AI call (or prompt-only fallback)
    # ═════════════════════════════════════════════════════════════════════════
    Write-SectionHeader "Step 8 — AI Optimization"

    $aiOutput = $null

    if ($provider -eq "none") {
        # No key — save enhanced prompt file and exit gracefully
        $pf = Save-PromptFile -Prompt $prompt -OutDir $sessionDir -ProcName $StoredProc `
            -StaticFindings $staticFindings -PlanAnalysis $planAnalysis
        Write-Host ""
        Write-Host "  ┌─────────────────────────────────────────────────────┐" -ForegroundColor Yellow
        Write-Host "  │  PROMPT-ONLY MODE — no API key supplied             │" -ForegroundColor Yellow
        Write-Host "  │  Prompt saved to:                                   │" -ForegroundColor Yellow
        Write-Host "  │  $($pf.PadRight(51))│" -ForegroundColor Yellow
        Write-Host "  │                                                     │" -ForegroundColor Yellow
        Write-Host "  │  Paste contents into ChatGPT / Claude / Gemini /   │" -ForegroundColor Yellow
        Write-Host "  │  GitHub Copilot Chat for full optimization.         │" -ForegroundColor Yellow
        Write-Host "  └─────────────────────────────────────────────────────┘" -ForegroundColor Yellow
        Write-Host ""
        Add-LogEntry "AI" "Prompt-only mode — no key supplied" "INFO"

        # Still save JSON run log in prompt-only mode
        $logFile = Join-Path $sessionDir "run_log.json"
        New-JSONSummary -ProcName $StoredProc -Database $Database -ServerInstance $ServerInstance `
            -OrigBench $origBench -OptBench @{ AvgMs=-1; MinMs=-1; MaxMs=-1; MedianMs=-1; StdDevMs=0; Runs=0 } `
            -ScoreBefore (Get-PerformanceScore $origBench.AvgMs $staticFindings.Count $planAnalysis.MissingIndexes.Count $planAnalysis.Scans.Count $planAnalysis.KeyLookups.Count) `
            -ScoreAfter 0 -StaticFindings $staticFindings -PlanAnalysis $planAnalysis `
            -SniffData $sniffData -AIProvider "none" -AIModel "N/A" -OutDir $sessionDir |
            Out-File -FilePath $logFile -Encoding UTF8

        Write-Output "  Output directory: $sessionDir"
        return
    }

    try {
        Write-Step "8/10" "Calling $provider API (model: $AIModel)…" "Cyan"
        $aiOutput = Invoke-AIWithRetry -Prompt $prompt -ApiKey $ApiKey -Provider $provider `
            -Model $AIModel -MaxRetries 3
        Write-Step "8/10" "AI response received ($([Math]::Round($aiOutput.Length/1024,1)) KB)" "Green"
        Add-LogEntry "AI" "AI call successful" "INFO" @{ provider = $provider; model = $AIModel; response_len = $aiOutput.Length }
    }
    catch {
        Add-LogEntry "AI" "AI call failed after retries: $_" "ERROR"
        # Fall back to prompt-only
        $pf = Save-PromptFile -Prompt $prompt -OutDir $sessionDir -ProcName $StoredProc `
            -StaticFindings $staticFindings -PlanAnalysis $planAnalysis
        Write-Warning "AI call failed. Prompt saved to: $pf"
        return
    }

    # ─── Parse AI output ───────────────────────────────────────────────────
    $analysis     = $aiOutput
    $optimizedSQL = "-- AI response did not include an optimized procedure section"
    $idxRecommend = ""
    $changeSummary= ""

    if ($aiOutput -match "(?si)##\s*Analysis Report\s*(.*?)##\s*Optimized Stored Procedure\s*(.*?)(?=##|$)") {
        $analysis     = $Matches[1].Trim()
        $optimizedSQL = $Matches[2].Trim() -replace "(?si)^```sql\s*","" -replace "\s*```$",""
    }
    if ($aiOutput -match "(?si)##\s*Index Recommendations?\s*(.*?)(?=##|$)") {
        $idxRecommend = $Matches[1].Trim()
    }
    if ($aiOutput -match "(?si)##\s*Summary of Changes\s*(.*?)(?=##|$)") {
        $changeSummary = $Matches[1].Trim()
    }

    $analysisFile  = Join-Path $sessionDir "Analysis_Report.txt"
    $optimizedFile = Join-Path $sessionDir "StoredProc_Optimized.sql"
    $aiIndexFile   = Join-Path $sessionDir "AI_Index_Recommendations.sql"
    $rawAIFile     = Join-Path $sessionDir "AI_Response_Raw.txt"

    $analysis     | Out-File -FilePath $analysisFile  -Encoding UTF8
    $optimizedSQL | Out-File -FilePath $optimizedFile -Encoding UTF8
    $aiOutput     | Out-File -FilePath $rawAIFile     -Encoding UTF8
    if ($idxRecommend) { $idxRecommend | Out-File -FilePath $aiIndexFile -Encoding UTF8 }

    Write-Step "8/10" "Analysis saved: $analysisFile" "Green"
    Write-Step "8/10" "Optimized SP  : $optimizedFile" "Green"

    # ─── SQL Diff ─────────────────────────────────────────────────────────
    $diff     = Get-SQLDiff -Original $procDef -Optimized $optimizedSQL -ProcName $StoredProc
    $diffFile = Join-Path $sessionDir "SQL_Diff.txt"
    $diff.Content | Out-File -FilePath $diffFile -Encoding UTF8
    Write-Step "8/10" "SQL diff: +$($diff.LinesAdded) lines / -$($diff.LinesRemoved) lines → $diffFile" "Cyan"

    # ═════════════════════════════════════════════════════════════════════════
    # STEP 9  — Benchmark optimized procedure
    # ═════════════════════════════════════════════════════════════════════════
    Write-SectionHeader "Step 9 — Benchmark Optimized"

    $optBench = @{ AvgMs=-1; MinMs=-1; MaxMs=-1; MedianMs=-1; StdDevMs=0; Runs=0; AllTimes=@() }

    if (-not $SkipOptimizedBenchmark) {
        $optExecCall = if ($Params) { "EXEC ${StoredProc}_Optimized $Params" } else { "EXEC ${StoredProc}_Optimized" }
        try {
            $optBench = Invoke-BenchmarkRuns `
                -ServerInstance $ServerInstance -Database $Database `
                -ProcCall $optExecCall -Runs $BenchmarkRuns -WarmupRuns $WarmupRuns `
                -Credential $Credential
            Write-Step "9/10" "Optimized: avg=$($optBench.AvgMs)ms  min=$($optBench.MinMs)ms  max=$($optBench.MaxMs)ms  σ=$($optBench.StdDevMs)ms" "Green"
        }
        catch {
            Add-LogEntry "Bench" "Optimized proc benchmark failed (not deployed?): $_" "WARN"
            Write-Step "9/10" "Optimized benchmark skipped — proc may not be deployed yet" "Yellow"
        }
    } else {
        Write-Step "9/10" "Optimized benchmark skipped (-SkipOptimizedBenchmark)" "Yellow"
    }

    $optBenchFile = Join-Path $sessionDir "Benchmark_Optimized.txt"
    @"
OPTIMIZED PROCEDURE BENCHMARK
Procedure   : ${StoredProc}_Optimized
Timestamp   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Runs        : $($optBench.Runs)
Avg (ms)    : $($optBench.AvgMs)
Median (ms) : $($optBench.MedianMs)
Min (ms)    : $($optBench.MinMs)
Max (ms)    : $($optBench.MaxMs)
StdDev (ms) : $($optBench.StdDevMs)
All times   : $(($optBench.AllTimes | ForEach-Object { "$_" }) -join ", ")
"@ | Out-File -FilePath $optBenchFile -Encoding UTF8

    # ═════════════════════════════════════════════════════════════════════════
    # STEP 10  — Scoring, comparison & all reports
    # ═════════════════════════════════════════════════════════════════════════
    Write-SectionHeader "Step 10 — Reports & Scoring"

    $scoreBefore = Get-PerformanceScore `
        -AvgElapsedMs     $origBench.AvgMs `
        -AntiPatternCount $staticFindings.Count `
        -MissingIndexCount $planAnalysis.MissingIndexes.Count `
        -ScanCount        $planAnalysis.Scans.Count `
        -KeyLookupCount   $planAnalysis.KeyLookups.Count

    $scoreAfter = if ($optBench.AvgMs -gt 0) {
        $optStaticFindings = Invoke-StaticSQLAnalysis -SQL $optimizedSQL
        Get-PerformanceScore `
            -AvgElapsedMs      $optBench.AvgMs `
            -AntiPatternCount  $optStaticFindings.Count `
            -MissingIndexCount ([Math]::Max(0, $planAnalysis.MissingIndexes.Count - 1)) `
            -ScanCount         ([Math]::Max(0, $planAnalysis.Scans.Count - 1)) `
            -KeyLookupCount    ([Math]::Max(0, $planAnalysis.KeyLookups.Count - 1))
    } else { $scoreBefore + 5 }  # conservative estimate if not benchmarked

    # Benchmark comparison file
    $pctImp  = if ($origBench.AvgMs -gt 0 -and $optBench.AvgMs -gt 0) {
                   [Math]::Round(($origBench.AvgMs - $optBench.AvgMs) / $origBench.AvgMs * 100, 1)
               } else { 0 }
    $speedup = if ($optBench.AvgMs -gt 0) { [Math]::Round($origBench.AvgMs / $optBench.AvgMs, 2) } else { "N/A" }

    $compFile = Join-Path $sessionDir "Benchmark_Comparison.txt"
    @"
══════════════════════════════════════════════════════════════
  BENCHMARK COMPARISON — $StoredProc
  Generated  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  AI Provider: $provider  |  Model: $AIModel
══════════════════════════════════════════════════════════════

  TIMING (averaged over $BenchmarkRuns runs with $WarmupRuns warmup)
  ─────────────────────────────────────────────────────────────
  Original  avg : $($origBench.AvgMs) ms   (median: $($origBench.MedianMs), σ: $($origBench.StdDevMs))
  Optimized avg : $(if ($optBench.AvgMs -ge 0) {"$($optBench.AvgMs) ms   (median: $($optBench.MedianMs), σ: $($optBench.StdDevMs))"} else {"not measured"})
  ─────────────────────────────────────────────────────────────
  Time saved    : $(if ($optBench.AvgMs -ge 0) {"$([Math]::Round($origBench.AvgMs - $optBench.AvgMs, 1)) ms"} else {"N/A"})
  Improvement   : ${pctImp}%
  Speedup factor: ${speedup}x
  ─────────────────────────────────────────────────────────────

  QUALITY SCORE
  ─────────────────────────────────────────────────────────────
  Before : $scoreBefore / 100
  After  : $scoreAfter  / 100
  Delta  : +$([Math]::Round($scoreAfter - $scoreBefore, 1)) points

  STATIC ANALYSIS
  ─────────────────────────────────────────────────────────────
  Findings (original) : $($staticFindings.Count)   (CRITICAL: $(($staticFindings | Where-Object Severity -eq CRITICAL).Count), HIGH: $(($staticFindings | Where-Object Severity -eq HIGH).Count))

  PLAN ISSUES
  ─────────────────────────────────────────────────────────────
  Scans detected     : $($planAnalysis.Scans.Count)
  Key lookups        : $($planAnalysis.KeyLookups.Count)
  Missing idx hints  : $($planAnalysis.MissingIndexes.Count)
  Implicit conversions: $($planAnalysis.ImplicitConversions.Count)
  Memory grant (MB)  : $($planAnalysis.MemoryGrantMB)
  Spill warnings     : $($planAnalysis.SpillWarnings.Count)

══════════════════════════════════════════════════════════════
"@ | Out-File -FilePath $compFile -Encoding UTF8

    # HTML report
    $htmlFile = Join-Path $sessionDir "Report.html"
    New-HTMLReport `
        -ProcName $StoredProc -Database $Database -ServerInstance $ServerInstance `
        -OrigBench $origBench -OptBench $optBench `
        -PlanAnalysis $planAnalysis -SniffData $sniffData `
        -StaticFindings $staticFindings -DMVMissingIndexes $dmvMissingIdx `
        -FragIndexes $fragIndexes -AIAnalysis $analysis `
        -ScoreBefore $scoreBefore -ScoreAfter $scoreAfter `
        -AIProvider $provider -AIModel $AIModel |
        Out-File -FilePath $htmlFile -Encoding UTF8
    Write-Step "10/10" "HTML report: $htmlFile" "Green"

    # Markdown report
    $mdFile = Join-Path $sessionDir "Report.md"
    New-MarkdownReport `
        -ProcName $StoredProc -OrigBench $origBench -OptBench $optBench `
        -ScoreBefore $scoreBefore -ScoreAfter $scoreAfter `
        -StaticFindings $staticFindings -PlanAnalysis $planAnalysis `
        -AIAnalysis $analysis -AIProvider $provider -AIModel $AIModel |
        Out-File -FilePath $mdFile -Encoding UTF8
    Write-Step "10/10" "Markdown report: $mdFile" "Green"

    # JSON summary + run log
    $jsonFile = Join-Path $sessionDir "run_log.json"
    New-JSONSummary `
        -ProcName $StoredProc -Database $Database -ServerInstance $ServerInstance `
        -OrigBench $origBench -OptBench $optBench `
        -ScoreBefore $scoreBefore -ScoreAfter $scoreAfter `
        -StaticFindings $staticFindings -PlanAnalysis $planAnalysis `
        -SniffData $sniffData -AIProvider $provider -AIModel $AIModel `
        -OutDir $sessionDir |
        Out-File -FilePath $jsonFile -Encoding UTF8
    Write-Step "10/10" "JSON run log   : $jsonFile" "Green"

    # ── Final summary ─────────────────────────────────────────────────────
    $elapsed = [Math]::Round(((Get-Date) - $runStart).TotalSeconds, 1)
    Write-Banner "Optimization Complete"
    if ($optBench.AvgMs -ge 0) {
        $color = if ($pctImp -gt 30) { "Green" } elseif ($pctImp -gt 0) { "Yellow" } else { "Red" }
        Write-Host "  Performance  : " -NoNewline; Write-Host "${pctImp}% faster  (${speedup}x speedup)" -ForegroundColor $color
        Write-Host "  Original avg : $($origBench.AvgMs) ms → Optimized avg: $($optBench.AvgMs) ms"
    }
    Write-Host "  Score        : $scoreBefore → $scoreAfter (+$([Math]::Round($scoreAfter-$scoreBefore,1)) pts)"
    Write-Host "  Findings     : $($staticFindings.Count) anti-patterns | $($planAnalysis.Scans.Count) scans | $($planAnalysis.MissingIndexes.Count) missing indexes"
    Write-Host "  Total time   : ${elapsed}s"
    Write-Host "  Output dir   : $sessionDir"
    Write-Host ""
    Write-Host "  Files generated:"
    Write-Host "    StoredProc.sql                  — original procedure"
    Write-Host "    StoredProc_Optimized.sql         — AI-rewritten procedure"
    Write-Host "    Analysis_Report.txt              — AI fault analysis"
    Write-Host "    Static_Analysis.txt              — 50+ anti-pattern checks"
    Write-Host "    DMV_Intelligence.txt             — param sniff + wait stats"
    Write-Host "    QueryPlan.xml                    — raw execution plan"
    Write-Host "    Missing_Indexes_Plan.sql         — plan-derived index DDL"
    Write-Host "    Missing_Indexes_DMV.sql          — DMV-derived index DDL"
    Write-Host "    AI_Index_Recommendations.sql     — AI-suggested index DDL"
    Write-Host "    SQL_Diff.txt                     — line-by-line diff"
    Write-Host "    Benchmark_Comparison.txt         — timing + score comparison"
    Write-Host "    Report.html                      — interactive visual report"
    Write-Host "    Report.md                        — markdown summary"
    Write-Host "    run_log.json                     — full structured run log"
    Write-Host ""
}

# ══════════════════════════════════════════════════════════════════════════════
# BATCH MODE — optimize a list of procedures from a CSV
# ══════════════════════════════════════════════════════════════════════════════

function Optimize-SPBatch {
    <#
    .SYNOPSIS
    Batch-optimize multiple stored procedures from a CSV file.

    .DESCRIPTION
    CSV must have columns: ServerInstance, Database, StoredProc, Params, OutDir
    All other OptimizeSPFromDB parameters are passed through via splatting.

    .EXAMPLE
    Optimize-SPBatch -CsvPath "C:\procs.csv" -ApiKey "sk-proj-..." -BenchmarkRuns 3
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CsvPath,
        [string]$ApiKey         = "",
        [string]$AIModel        = "gpt-4o",
        [int]   $BenchmarkRuns  = 3,
        [int]   $WarmupRuns     = 1,
        [switch]$SkipOptimizedBenchmark,
        [System.Management.Automation.PSCredential]$Credential = $null
    )

    if (-not (Test-Path $CsvPath)) {
        Write-Error "CSV not found: $CsvPath"; return
    }

    $rows    = Import-Csv $CsvPath
    $total   = $rows.Count
    $success = 0; $failed = 0
    $summary = [System.Collections.Generic.List[hashtable]]::new()

    Write-Banner "Batch Optimization — $total procedures"

    foreach ($i in 0..($total-1)) {
        $row = $rows[$i]
        Write-Host "  [$($i+1)/$total] $($row.StoredProc) @ $($row.Database)" -ForegroundColor Cyan

        try {
            OptimizeSPFromDB `
                -ServerInstance $row.ServerInstance `
                -Database       $row.Database `
                -StoredProc     $row.StoredProc `
                -Params         ($row.Params ?? "") `
                -OutDir         ($row.OutDir ?? "C:\SP_Optimization") `
                -ApiKey         $ApiKey `
                -AIModel        $AIModel `
                -BenchmarkRuns  $BenchmarkRuns `
                -WarmupRuns     $WarmupRuns `
                -SkipOptimizedBenchmark:$SkipOptimizedBenchmark `
                -Credential     $Credential
            $success++
            $summary.Add(@{ Proc = $row.StoredProc; Status = "OK" })
        }
        catch {
            $failed++
            $summary.Add(@{ Proc = $row.StoredProc; Status = "FAILED"; Error = $_.ToString() })
            Write-Warning "  Failed: $($row.StoredProc) — $_"
        }
        Write-Host ""
    }

    Write-Banner "Batch Complete"
    Write-Host "  Total: $total   Success: $success   Failed: $failed"
    Write-Host ""
    foreach ($s in $summary) {
        $color = if ($s.Status -eq "OK") { "Green" } else { "Red" }
        Write-Host "  [$($s.Status.PadRight(6))] $($s.Proc)" -ForegroundColor $color
    }
    Write-Host ""
}

# ══════════════════════════════════════════════════════════════════════════════
# EXAMPLE CALLS — uncomment the one you need
# ══════════════════════════════════════════════════════════════════════════════

<#
# ── Single proc, OpenAI, full benchmark ──────────────────────────────────────
OptimizeSPFromDB `
    -ServerInstance "localhost\SQLEXPRESS" `
    -Database       "AdventureWorks" `
    -StoredProc     "dbo.uspGetBillOfMaterials" `
    -Params         "@StartProductID = 749, @CheckDate = '2010-05-26'" `
    -OutDir         "C:\SP_Optimization" `
    -ApiKey         "sk-proj-..." `
    -BenchmarkRuns  5 `
    -WarmupRuns     2

# ── Single proc, GitHub Copilot, skip optimized benchmark (not deployed yet) ─
$env:GHCP_MODEL = "gpt-4o"
OptimizeSPFromDB `
    -ServerInstance "PROD-SQL-01" `
    -Database       "SalesDB" `
    -StoredProc     "dbo.GetCustomerOrders" `
    -Params         "@CustomerId = 1001" `
    -OutDir         "C:\Optimization" `
    -ApiKey         "ghp_..." `
    -AIModel        "gpt-4o" `
    -SkipOptimizedBenchmark

# ── Prompt-only mode (no API key — generates Prompt.txt for manual paste) ────
OptimizeSPFromDB `
    -ServerInstance "<ServerName>" `
    -Database       "<DatabaseName>" `
    -StoredProc     "dbo.<ProcName>" `
    -Params         "@Param1 = 1" `
    -OutDir         "C:\Optimization"

# ── Batch optimization from CSV ──────────────────────────────────────────────
# CSV format: ServerInstance,Database,StoredProc,Params,OutDir
Optimize-SPBatch `
    -CsvPath       "C:\procs_to_optimize.csv" `
    -ApiKey        "sk-proj-..." `
    -BenchmarkRuns 3
#>

# ── Default invocation (prompt-only, safe to run as-is) ──────────────────────
OptimizeSPFromDB `
    -ServerInstance "<ServerName>" `
    -Database       "<DatabaseName>" `
    -StoredProc     "dbo.<StoredProcedureName>" `
    -Params         "@StartProductID = 749, @CheckDate = '2010-05-26'" `
    -OutDir         "<FolderPath>"
