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
	paths, err := processPaths()
	if err != nil {
		return nil, err
	}
	return appsFrom(paths), nil
}

// SimApp is an app running inside a simulator: one installed in it, not the simulator's
// own system apps.
type SimApp struct {
	UDID string // the simulator it runs in, upper case
	Name string // the bundle's name without .app, as app:<name> matches it
}

// RunningSimApps lists the apps running inside booted simulators, per simulator, sorted.
// Like RunningApps it reads the kernel's process list and runs no tool.
func RunningSimApps() ([]SimApp, error) {
	paths, err := processPaths()
	if err != nil {
		return nil, err
	}
	return simAppsFrom(paths), nil
}

// processPaths is the executable path of every process wraith may read.
func processPaths() ([]string, error) {
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
	return paths, nil
}

// simAppsFrom picks the apps installed in simulators out of executable paths
// (.../CoreSimulator/Devices/<UDID>/data/Containers/Bundle/Application/<id>/Shop.app/Shop),
// one per simulator and name.
func simAppsFrom(paths []string) []SimApp {
	seen := map[string]bool{}
	var apps []SimApp
	for _, p := range paths {
		if !strings.Contains(p, "/data/Containers/Bundle/Application/") {
			continue
		}
		m := udidInPath.FindStringSubmatch(p)
		app := outermostApp(p)
		if m == nil || app == "" {
			continue
		}
		a := SimApp{UDID: strings.ToUpper(m[1]), Name: strings.TrimSuffix(filepath.Base(app), ".app")}
		if key := a.UDID + "/" + strings.ToLower(a.Name); !seen[key] {
			seen[key] = true
			apps = append(apps, a)
		}
	}
	slices.SortFunc(apps, func(a, b SimApp) int {
		return strings.Compare(a.UDID+"/"+strings.ToLower(a.Name), b.UDID+"/"+strings.ToLower(b.Name))
	})
	return apps
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
