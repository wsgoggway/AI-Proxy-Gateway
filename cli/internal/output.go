package internal

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/olekukonko/tablewriter"
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99"))
	errorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	successStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warningStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	keyStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
)

func Title(s string) string  { return titleStyle.Render(s) }
func Error(s string) string  { return errorStyle.Render(s) }
func Success(s string) string { return successStyle.Render(s) }
func Warn(s string) string   { return warningStyle.Render(s) }
func Dim(s string) string    { return dimStyle.Render(s) }
func Key(s string) string    { return keyStyle.Render(s) }

func StatusBadge(status string) string {
	switch strings.ToLower(status) {
	case "active":
		return successStyle.Render("●") + " " + status
	case "disabled", "inactive":
		return dimStyle.Render("○") + " " + status
	default:
		return status
	}
}

func RoleBadge(role string) string {
	switch strings.ToLower(role) {
	case "admin":
		return titleStyle.Render(role)
	default:
		return dimStyle.Render(role)
	}
}

func CheckMark(ok bool) string {
	if ok {
		return successStyle.Render("✓")
	}
	return errorStyle.Render("✗")
}

// PrintTable renders a Unicode-bordered table to stdout.
func PrintTable(headers []string, rows [][]string) {
	tw := tablewriter.NewWriter(os.Stdout)
	tw.SetHeader(headers)
	tw.SetAutoWrapText(false)
	tw.SetAutoFormatHeaders(true)
	tw.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	tw.SetAlignment(tablewriter.ALIGN_LEFT)
	tw.SetBorder(true)
	tw.SetRowLine(true)
	tw.SetColumnSeparator("│")
	tw.SetRowSeparator("─")
	tw.SetCenterSeparator("┼")
	tw.SetHeaderLine(true)
	for _, row := range rows {
		tw.Append(row)
	}
	tw.Render()
}

// FormatBytes converts int64 to human-readable (1.2 KB, 3.4 MB).
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	suffix := []string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.1f %s", float64(b)/float64(div), suffix[exp])
}

// FormatTokens converts int64 to K/M shorthand.
func FormatTokens(t int64) string {
	if t < 1000 {
		return fmt.Sprintf("%d", t)
	}
	if t < 1_000_000 {
		return fmt.Sprintf("%.1fK", float64(t)/1000)
	}
	return fmt.Sprintf("%.1fM", float64(t)/1_000_000)
}

// FormatOptionalInt64 renders nil as "∞", else the number.
func FormatOptionalInt64(v *int64) string {
	if v == nil {
		return "∞"
	}
	return fmt.Sprintf("%d", *v)
}

// ProgressBar renders a simple 8-char bar (█░).
func ProgressBar(pct float64) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct / 12.5)
	return strings.Repeat("█", filled) + strings.Repeat("░", 8-filled)
}
