package source

import (
	"reflect"
	"testing"
)

func TestAppsFromKeepsMacAppsOnce(t *testing.T) {
	got := appsFrom([]string{
		"/Applications/Slack.app/Contents/MacOS/Slack",
		"/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari",
		"/Users/me/Applications/Tool.app/Contents/MacOS/Tool",
		"/Users/me/Library/Developer/CoreSimulator/Devices/2F3A0D4E-1B2C-4D5E-8F90-A1B2C3D4E5F6/data/Containers/Bundle/Application/X/Shop.app/Shop",
		"/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock",
		"/usr/libexec/trustd",
	})
	want := []App{
		{"Google Chrome", "/Applications/Google Chrome.app"},
		{"Safari", "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app"},
		{"Slack", "/Applications/Slack.app"},
		{"Tool", "/Users/me/Applications/Tool.app"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestRunningAppsReadsTheProcessList(t *testing.T) {
	if _, err := RunningApps(); err != nil {
		t.Fatal(err)
	}
}
