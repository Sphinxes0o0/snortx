package reports

import (
	"fmt"
	"os"
	"path/filepath"
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
	protoStats := make(map[string]map[string]int)
	protoList := []string{}
	for _, r := range result.Results {
		if _, ok := protoStats[r.Protocol]; !ok {
			protoStats[r.Protocol] = map[string]int{"success": 0, "failed": 0}
			protoList = append(protoList, r.Protocol)
		}
		if r.Status == "success" {
			protoStats[r.Protocol]["success"]++
		} else {
			protoStats[r.Protocol]["failed"]++
		}
	}

	protoBars := ""
	for _, proto := range protoList {
		stats := protoStats[proto]
		total := stats["success"] + stats["failed"]
		barWidth := 0
		if total > 0 {
			barWidth = stats["success"] * 100 / total
		}
		protoBars += fmt.Sprintf(`<div class="proto-row">
			<span class="proto-name">%s</span>
			<div class="proto-bar-bg">
				<div class="proto-bar proto-success" style="width: %d%%"></div>
				<div class="proto-bar proto-failed" style="width: %d%%"></div>
			</div>
			<span class="proto-count">%d/%d</span>
		</div>`, proto, barWidth, 100-barWidth, stats["success"], total)
	}

	rows := ""
	for _, r := range result.Results {
		statusClass := r.Status
		if r.Status == "success" {
			statusClass = "success"
		} else {
			statusClass = "failed"
		}
		errorInfo := ""
		if r.Error != "" {
			errorInfo = fmt.Sprintf(`<br><small class="error-msg" title="%s">%s</small>`, r.Error, r.Error)
		}
		pcapLink := "-"
		if r.PCAPPath != "" {
			pcapLink = fmt.Sprintf(`<a href="file://%s">%s</a>`, r.PCAPPath, filepath.Base(r.PCAPPath))
		}
		rows += fmt.Sprintf(`<tr data-protocol="%s" data-status="%s">
			<td>%d</td>
			<td>%s</td>
			<td>%s</td>
			<td>%d</td>
			<td class="%s">%s%s</td>
			<td>%s</td>
		</tr>`, r.Protocol, r.Status, r.RuleSID, r.RuleMsg, r.Protocol, r.PacketsSent, statusClass, r.Status, errorInfo, pcapLink)
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
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
		.proto-bar { height: 100%%; }
		.proto-success { background: #4caf50; }
		.proto-failed { background: #f44336; }
		.proto-count { width: 80px; text-align: right; color: #666; font-size: 14px; }
		table { width: 100%%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
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
		<p>Generated: %s</p>

		<div class="summary">
			<div class="card total">
				<h3>Total Rules</h3>
				<div class="value">%d</div>
			</div>
			<div class="card success">
				<h3>Successful</h3>
				<div class="value">%d</div>
			</div>
			<div class="card failed">
				<h3>Failed</h3>
				<div class="value">%d</div>
			</div>
			<div class="card success">
				<h3>Success Rate</h3>
				<div class="value">%s</div>
			</div>
		</div>

		<div class="proto-breakdown">
			<h3>Protocol Breakdown</h3>
			%s
		</div>

		<div class="controls">
			<label>Search:</label>
			<input type="text" id="searchInput" placeholder="Search by SID, message..." onkeyup="filterTable()">
			<label>Protocol:</label>
			<select id="protocolFilter" onchange="filterTable()">
				<option value="">All</option>
				%s
			</select>
			<label>Status:</label>
			<select id="statusFilter" onchange="filterTable()">
				<option value="">All</option>
				<option value="success">Success</option>
				<option value="failed">Failed</option>
			</select>
			<span class="count" id="resultCount">Showing RESULTS_COUNT</span>
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
				%s
			</tbody>
		</table>

		<div class="footer">
			Generated by snortx | Test Run ID: %s
		</div>
	</div>
	<script>
		var totalRows = %d;
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
</html>`, result.CompletedAt.Format(time.RFC3339), result.TotalRules, result.SuccessCount, result.FailureCount, successRate, protoBars, buildProtocolOptions(protoList), rows, result.TestRunID, result.TotalRules)

	filename := filepath.Join(g.OutputDir, fmt.Sprintf("report_%s.html", result.TestRunID))
	if err := os.WriteFile(filename, []byte(html), 0644); err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	return filename, nil
}

func buildProtocolOptions(protoList []string) string {
	var opts string
	for _, p := range protoList {
		opts += fmt.Sprintf(`<option value="%s">%s</option>`, p, p)
	}
	return opts
}
