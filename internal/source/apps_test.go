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

func TestSimAppsFromListsAppsInstalledInSimulators(t *testing.T) {
	const a, b = "2F3A0D4E-1B2C-4D5E-8F90-A1B2C3D4E5F6", "9c1bea91-f023-4c77-857a-a5622219dc8b"
	dev := "/Users/me/Library/Developer/CoreSimulator/Devices/"
	got := simAppsFrom([]string{
		dev + a + "/data/Containers/Bundle/Application/X1/Shop.app/Shop",
		dev + a + "/data/Containers/Bundle/Application/X1/Shop.app/PlugIns/Widget.appex/Widget",
		dev + a + "/data/Containers/Bundle/Application/X2/Bank.app/Bank",
		dev + b + "/data/Containers/Bundle/Application/X3/Shop.app/Shop",
		"/Library/Developer/CoreSimulator/Volumes/iOS_23A/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.1.simruntime/Contents/Resources/RuntimeRoot/Applications/MobileSafari.app/MobileSafari",
		"/Applications/Slack.app/Contents/MacOS/Slack",
	})
	want := []SimApp{{a, "Bank"}, {a, "Shop"}, {"9C1BEA91-F023-4C77-857A-A5622219DC8B", "Shop"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestRunningSimAppsReadsTheProcessList(t *testing.T) {
	if _, err := RunningSimApps(); err != nil {
		t.Fatal(err)
	}
}
