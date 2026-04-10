package reports

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type HTMLGenerator struct {
	OutputDir string
}

func NewHTMLGenerator(outputDir string) *HTMLGenerator {
	return &HTMLGenerator{
		OutputDir: outputDir,
	}
}

type htmlRowData struct {
	Protocol    string
	Status      string
	RuleSID     int
	RuleMsg     string
	PacketsSent int
	Error       string
	PCAPBase    string
	PCAPPath    string
}

type htmlData struct {
	CompletedAt  string
	TotalRules   int
	SuccessCount int
	FailureCount int
	SuccessRate  string
	ProtoStats   []protoStat
	ProtoOptions []string
	Rows         []htmlRowData
	TestRunID    string
	TotalRows    int
}

type protoStat struct {
	Proto        string
	SuccessPct   int
	FailedPct    int
	SuccessCount int
	Total        int
}

func (g *HTMLGenerator) Generate(result *TestRunResult) (string, error) {
	if err := os.MkdirAll(g.OutputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output dir: %w", err)
	}

	result.CompletedAt = time.Now()

	successRate := "0%"
	if result.TotalRules > 0 {
		successRate = fmt.Sprintf("%.1f%%", float64(result.SuccessCount)/float64(result.TotalRules)*100)
	}

	// Protocol breakdown
	protoStatsMap := make(map[string]map[string]int)
	protoList := []string{}
	for _, r := range result.Results {
		if _, ok := protoStatsMap[r.Protocol]; !ok {
			protoStatsMap[r.Protocol] = map[string]int{"success": 0, "failed": 0}
			protoList = append(protoList, r.Protocol)
		}
		if r.Status == "success" {
			protoStatsMap[r.Protocol]["success"]++
		} else {
			protoStatsMap[r.Protocol]["failed"]++
		}
	}

	protoStats := make([]protoStat, 0, len(protoList))
	for _, proto := range protoList {
		stats := protoStatsMap[proto]
		total := stats["success"] + stats["failed"]
		successPct := 0
		failedPct := 0
		if total > 0 {
			successPct = stats["success"] * 100 / total
			failedPct = 100 - successPct
		}
		protoStats = append(protoStats, protoStat{
			Proto:        proto,
			SuccessPct:   successPct,
			FailedPct:    failedPct,
			SuccessCount: stats["success"],
			Total:        total,
		})
	}

	// Build rows
	rows := make([]htmlRowData, 0, len(result.Results))
	for _, r := range result.Results {
		pcapBase := ""
		if r.PCAPPath != "" {
			pcapBase = filepath.Base(r.PCAPPath)
		}
		rows = append(rows, htmlRowData{
			Protocol:    r.Protocol,
			Status:      r.Status,
			RuleSID:     r.RuleSID,
			RuleMsg:     r.RuleMsg,
			PacketsSent: r.PacketsSent,
			Error:       r.Error,
			PCAPBase:    pcapBase,
			PCAPPath:    r.PCAPPath,
		})
	}

	data := htmlData{
		CompletedAt:  result.CompletedAt.Format(time.RFC3339),
		TotalRules:   result.TotalRules,
		SuccessCount: result.SuccessCount,
		FailureCount: result.FailureCount,
		SuccessRate:  successRate,
		ProtoStats:   protoStats,
		ProtoOptions: protoList,
		Rows:         rows,
		TestRunID:    result.TestRunID,
		TotalRows:    result.TotalRules,
	}

	tmpl := template.Must(template.New("report").Parse(htmlTemplate))
	fname := filepath.Join(g.OutputDir, fmt.Sprintf("report_%s.html", result.TestRunID))
	f, err := os.Create(fname)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return fname, nil
}

func basename(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return path
	}
	return path[idx+1:]
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Snort Rule Test Report</title>
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }
		.container { max-width: 1400px; margin: 0 auto; }
		h1 { color: #333; }
		h2 { color: #555; margin-top: 30px; }
		.summary { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
		.card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); flex: 1; min-width: 150px; }
		.card h3 { margin: 0 0 10px 0; color: #666; font-size: 14px; }
		.card .value { font-size: 32px; font-weight: bold; color: #333; }
		.card.success { border-left: 4px solid #4caf50; }
		.card.failed { border-left: 4px solid #f44336; }
		.card.total { border-left: 4px solid #2196f3; }
		.controls { background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; display: flex; gap: 15px; flex-wrap: wrap; align-items: center; }
		.controls label { font-weight: 500; }
		.controls input[type="text"] { padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; width: 250px; }
		.controls select { padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; }
		.controls .count { color: #666; font-size: 14px; margin-left: auto; }
		.proto-breakdown { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; }
		.proto-breakdown h3 { margin: 0 0 15px 0; color: #333; }
		.proto-row { display: flex; align-items: center; margin-bottom: 10px; }
		.proto-name { width: 60px; font-weight: 500; color: #333; }
		.proto-bar-bg { flex: 1; height: 20px; background: #f0f0f0; border-radius: 4px; overflow: hidden; display: flex; }
		.proto-bar { height: 100%; }
		.proto-success { background: #4caf50; }
		.proto-failed { background: #f44336; }
		.proto-count { width: 80px; text-align: right; color: #666; font-size: 14px; }
		table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
		th { background: #333; color: white; padding: 12px; text-align: left; cursor: pointer; user-select: none; }
		th:hover { background: #444; }
		td { padding: 12px; border-bottom: 1px solid #eee; }
		tr:last-child td { border-bottom: none; }
		tr.hidden { display: none; }
		.success { color: #4caf50; font-weight: bold; }
		.failed { color: #f44336; font-weight: bold; }
		.error-msg { color: #f44336; font-size: 12px; }
		.footer { margin-top: 20px; color: #666; font-size: 12px; text-align: center; }
	</style>
</head>
<body>
	<div class="container">
		<h1>Snort Rule Test Report</h1>
		<p>Generated: {{.CompletedAt}}</p>

		<div class="summary">
			<div class="card total">
				<h3>Total Rules</h3>
				<div class="value">{{.TotalRules}}</div>
			</div>
			<div class="card success">
				<h3>Successful</h3>
				<div class="value">{{.SuccessCount}}</div>
			</div>
			<div class="card failed">
				<h3>Failed</h3>
				<div class="value">{{.FailureCount}}</div>
			</div>
			<div class="card success">
				<h3>Success Rate</h3>
				<div class="value">{{.SuccessRate}}</div>
			</div>
		</div>

		<div class="proto-breakdown">
			<h3>Protocol Breakdown</h3>
			{{range .ProtoStats}}
			<div class="proto-row">
				<span class="proto-name">{{.Proto}}</span>
				<div class="proto-bar-bg">
					<div class="proto-bar proto-success" style="width: {{.SuccessPct}}%"></div>
					<div class="proto-bar proto-failed" style="width: {{.FailedPct}}%"></div>
				</div>
				<span class="proto-count">{{.SuccessCount}}/{{.Total}}</span>
			</div>
			{{end}}
		</div>

		<div class="controls">
			<label>Search:</label>
			<input type="text" id="searchInput" placeholder="Search by SID, message..." onkeyup="filterTable()">
			<label>Protocol:</label>
			<select id="protocolFilter" onchange="filterTable()">
				<option value="">All</option>
				{{range .ProtoOptions}}
				<option value="{{.}}">{{.}}</option>
				{{end}}
			</select>
			<label>Status:</label>
			<select id="statusFilter" onchange="filterTable()">
				<option value="">All</option>
				<option value="success">Success</option>
				<option value="failed">Failed</option>
			</select>
			<span class="count" id="resultCount">Showing {{.TotalRows}}</span>
		</div>
		</div>

		<h2>Test Results</h2>
		<table id="resultsTable">
			<thead>
				<tr>
					<th>SID</th>
					<th>Message</th>
					<th>Protocol</th>
					<th>Packets</th>
					<th>Status</th>
					<th>PCAP</th>
				</tr>
			</thead>
			<tbody>
				{{range .Rows}}
				<tr data-protocol="{{.Protocol}}" data-status="{{.Status}}">
					<td>{{.RuleSID}}</td>
					<td>{{.RuleMsg}}</td>
					<td>{{.Protocol}}</td>
					<td>{{.PacketsSent}}</td>
					<td class="{{if eq .Status "success"}}success{{else}}failed{{end}}">{{.Status}}{{if .Error}}<br><small class="error-msg" title="{{.Error}}">{{.Error}}</small>{{end}}</td>
					<td>{{if .PCAPPath}}<a href="file://{{.PCAPPath}}">{{.PCAPBase}}</a>{{else}}-{{end}}</td>
				</tr>
				{{end}}
			</tbody>
		</table>

		<div class="footer">
			Generated by snortx | Test Run ID: {{.TestRunID}}
		</div>
	</div>
	<script>
		var totalRows = {{.TotalRows}};
		function filterTable() {
			var search = document.getElementById('searchInput').value.toLowerCase();
			var protocol = document.getElementById('protocolFilter').value;
			var status = document.getElementById('statusFilter').value;
			var rows = document.querySelectorAll('#resultsTable tbody tr');
			var visible = 0;
			rows.forEach(function(row) {
				var sid = row.cells[0].textContent.toLowerCase();
				var msg = row.cells[1].textContent.toLowerCase();
				var rowProto = row.getAttribute('data-protocol');
				var rowStatus = row.getAttribute('data-status');
				var matchSearch = search === '' || sid.includes(search) || msg.includes(search);
				var matchProto = protocol === '' || rowProto === protocol;
				var matchStatus = status === '' || rowStatus === status;
				if (matchSearch && matchProto && matchStatus) {
					row.classList.remove('hidden');
					visible++;
				} else {
					row.classList.add('hidden');
				}
			});
			document.getElementById('resultCount').textContent = 'Showing ' + visible + ' of ' + totalRows;
		}
	</script>
</body>
</html>`
