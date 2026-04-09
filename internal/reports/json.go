package reports

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type JSONGenerator struct {
	OutputDir    string
	PrettyPrint bool
}

func NewJSONGenerator(outputDir string) *JSONGenerator {
	return &JSONGenerator{
		OutputDir:    outputDir,
		PrettyPrint: true,
	}
}

func (g *JSONGenerator) Generate(result *TestRunResult) (string, error) {
	if err := os.MkdirAll(g.OutputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output dir: %w", err)
	}

	result.CompletedAt = time.Now()

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal result: %w", err)
	}

	filename := filepath.Join(g.OutputDir, fmt.Sprintf("report_%s.json", result.TestRunID))
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	return filename, nil
}
