package classify

const (
	CatAccessibility = "accessibility"
	CatAccounts      = "accounts"
	CatAds           = "ads"
	CatAssistant     = "assistant"
	CatBrowser       = "browser"
	CatComms         = "comms"
	CatContainer     = "container"
	CatDesktop       = "desktop"
	CatDeveloper     = "developer"
	CatDocs          = "docs"
	CatFinance       = "finance"
	CatHardware      = "hardware"
	CatICloud        = "icloud"
	CatInstall       = "install"
	CatKernel        = "kernel"
	CatLocation      = "location"
	CatMedia         = "media"
	CatML            = "ml"
	CatNetworking    = "networking"
	CatProductivity  = "productivity"
	CatSearch        = "search"
	CatSecurity      = "security"
	CatSettings      = "settings"
	CatSmartHome     = "smarthome"
	CatStorage       = "storage"
	CatSync          = "sync"
	CatSystem        = "system"
	CatTelemetry     = "telemetry"
	CatTerminal      = "terminal"
)

type Cat struct {
	Name  string `json:"name"`
	About string `json:"about"`
}

var Vocabulary = []Cat{
	{CatAccessibility, "assistive technology"},
	{CatAccounts, "Apple ID, signing in, and account database behind it"},
	{CatAds, "Apple advertising platform"},
	{CatAssistant, "Siri, speech and dictation"},
	{CatBrowser, "web browsers and helper processes"},
	{CatComms, "mail, chat, calls"},
	{CatContainer, "containers and virtual machines"},
	{CatDesktop, "the window system, Dock, Finder and menu bar"},
	{CatDeveloper, "compilers, build tools, version control, package managers"},
	{CatDocs, "manuals and the tools that render them"},
	{CatFinance, "Apple Pay, Wallet and payment services"},
	{CatHardware, "bluetooth, usb, printing, power, sensors"},
	{CatICloud, "Apple iCloud services: Drive, Photos, Keychain, Mail"},
	{CatInstall, "installers and software updates"},
	{CatKernel, "kernel and system extensions, and tools to load and inspect them"},
	{CatLocation, "location services"},
	{CatMedia, "audio, video, photos"},
	{CatML, "on-device machine learning"},
	{CatNetworking, "wifi, dns, vpn, push and other packet movers"},
	{CatProductivity, "calendars, contacts, notes, documents"},
	{CatSearch, "Spotlight and metadata indexing"},
	{CatSecurity, "code signing, policy, trust, keychains"},
	{CatSettings, "System Settings, preference panes, the defaults database"},
	{CatSmartHome, "HomeKit and the accessories it talks to"},
	{CatStorage, "disks, volumes, file events, backup"},
	{CatSync, "cloud sync and its daemons"},
	{CatSystem, "core OS plumbing"},
	{CatTelemetry, "diagnostics, crash report, analytics"},
	{CatTerminal, "terminal emulators and multiplexers"},
}

func Known(cat string) bool {
	for _, c := range Vocabulary {
		if c.Name == cat {
			return true
		}
	}

	return false
}
