package source

import (
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// App is a running Mac app, for choosing app:<name> as the source.
type App struct {
	Name string // the bundle's name without .app, as app:<name> matches it
	Path string // the outermost .app bundle
}

// RunningApps lists the Mac apps with a running process, by name. Only bundles that sit
// in an Applications folder count, so background agents and simulator apps are left out.
// Like Lookup it reads the kernel's process list and runs no tool.
func RunningApps() ([]App, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(procs))
	for _, p := range procs {
		if path, _ := procArgs(int(p.Proc.P_pid)); path != "" {
			paths = append(paths, path)
		}
	}
	return appsFrom(paths), nil
}

// appsFrom picks the Mac apps out of executable paths, one per name, sorted by name.
func appsFrom(paths []string) []App {
	seen := map[string]bool{}
	var apps []App
	for _, p := range paths {
		app := outermostApp(p)
		if app == "" || strings.Contains(app, "/CoreSimulator/") ||
			!strings.HasSuffix(filepath.Dir(app), "/Applications") {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(app), ".app")
		if key := strings.ToLower(name); !seen[key] {
			seen[key] = true
			apps = append(apps, App{Name: name, Path: app})
		}
	}
	slices.SortFunc(apps, func(a, b App) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return apps
}
