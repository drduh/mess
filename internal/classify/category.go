package classify

import (
	"regexp"
	"strings"
)

type prefixRule struct{ prefix, cat string }

var bySign = []prefixRule{
	{"com.apple.Safari", CatBrowser},
	{"com.apple.WebKit", CatBrowser},
	{"com.brave.", CatBrowser},
	{"com.google.Chrome", CatBrowser},
	{"com.microsoft.edgemac", CatBrowser},
	{"com.operasoftware.", CatBrowser},
	{"org.chromium.", CatBrowser},
	{"org.mozilla.thunderbird", CatComms},
	{"org.mozilla.", CatBrowser},

	{"com.apple.mail", CatComms},
	{"com.apple.MobileSMS", CatComms},
	{"com.apple.FaceTime", CatComms},
	{"com.microsoft.teams", CatComms},
	{"us.zoom.", CatComms},

	{"com.apple.audio", CatMedia},
	{"com.apple.coreaudio", CatMedia},
	{"com.apple.Music", CatMedia},
	{"com.apple.QuickTime", CatMedia},
	{"com.spotify.", CatMedia},
	{"org.videolan.", CatMedia},

	{"com.docker.", CatContainer},
	{"com.parallels.", CatContainer},
	{"com.utmapp.", CatContainer},
	{"com.vmware.", CatContainer},
	{"io.podman", CatContainer},

	{"at.obdev.littlesnitch", CatSecurity},
	{"com.apple.trustd", CatSecurity},
	{"com.apple.SecurityAgent", CatSecurity},
	{"com.apple.syspolicy", CatSecurity},
	{"com.apple.tccd", CatSecurity},
	{"com.apple.XProtect", CatSecurity},
	{"com.objective-see.", CatSecurity},

	{"com.apple.metadata", CatSearch},
	{"com.apple.spotlight", CatSearch},
	{"com.apple.Spotlight", CatSearch},

	{"com.apple.Terminal", CatTerminal},
	{"com.googlecode.iterm2", CatTerminal},

	{"com.apple.wifi.", CatNetworking},
	{"org.wireshark.", CatNetworking},

	{"com.apple.cloudpaird", CatMedia},
	{"com.apple.coremedia.", CatMedia},
	{"com.apple.MediaMLPluginApp.", CatMedia},
	{"com.apple.TV.", CatMedia},
	{"com.apple.quicklook.", CatMedia},

	{"com.apple.siri.", CatAssistant},

	{"com.apple.AddressBookSourceSync", CatSync},
	{"com.apple.biome", CatSync},
	{"com.getdropbox.", CatSync},
	{"com.google.GoogleDrive", CatSync},

	{"com.apple.bird", CatICloud},
	{"com.apple.cloudd", CatICloud},

	{"com.apple.SiriMetrics.", CatTelemetry},
}

var byPath = []prefixRule{
	{"/System/Applications/Font Book.app/", CatDesktop},
	{"/System/Applications/Utilities/ColorSync Utility.app/", CatDesktop},
	{"/System/Applications/Utilities/Digital Color Meter.app/", CatDesktop},
	{"/System/Library/CoreServices/ControlCenter.app/", CatDesktop},
	{"/System/Library/CoreServices/Dock.app/", CatDesktop},
	{"/System/Library/CoreServices/Finder.app/", CatDesktop},
	{"/System/Library/CoreServices/loginwindow.app/", CatDesktop},
	{"/System/Library/CoreServices/NotificationCenter.app/", CatDesktop},
	{"/System/Library/CoreServices/SystemUIServer.app/", CatDesktop},
	{"/System/Library/ExtensionKit/Extensions/LockScreen.appex/", CatDesktop},
	{"/System/Library/ExtensionKit/Extensions/Screen Saver.appex/", CatDesktop},
	{"/System/Library/ExtensionKit/Extensions/Wallpaper.appex/", CatDesktop},
	{"/System/Library/ExtensionKit/Extensions/WallpaperMacintoshExtension.appex/", CatDesktop},
	{"/System/Library/Frameworks/ColorSync.framework/", CatDesktop},
	{"/System/Library/PrivateFrameworks/AmbientDisplay.framework/", CatDesktop},

	{"/Library/Apple/System/Library/CoreServices/XProtect.app/", CatSecurity},
	{"/System/Applications/Utilities/Keychain Access.app/", CatSecurity},
	{"/System/Applications/Passwords.app/", CatSecurity},
	{"/System/Library/ExtensionKit/Extensions/SecurityPrivacyExtension.appex/", CatSecurity},
	{"/System/Library/ExtensionKit/Extensions/Touch ID & Password.appex/", CatSecurity},
	{"/System/Library/Frameworks/Security.framework/", CatSecurity},
	{"/System/Library/Frameworks/CryptoTokenKit.framework/", CatSecurity},

	{"/System/Library/CoreServices/Siri.app/", CatAssistant},
	{"/System/Library/ExtensionKit/Extensions/SafariAssistantWorker.appex/", CatAssistant},
	{"/System/Library/ExtensionKit/Extensions/SiriSuggestionsLightHousePlugin.appex/", CatAssistant},
	{"/System/Library/ExtensionKit/Extensions/SiriTurnRestatementExtension.appex/", CatAssistant},
	{"/System/Library/ExtensionKit/Extensions/SiriUserSegmentation.appex/", CatAssistant},
	{"/System/Library/Frameworks/Speech.framework/", CatAssistant},
	{"/System/Library/PrivateFrameworks/CoreEmbeddedSpeechRecognition.framework/", CatAssistant},
	{"/System/Library/PrivateFrameworks/HelpData.framework/", CatAssistant},

	{"/System/Applications/Books.app/", CatMedia},
	{"/System/Applications/Image Capture.app/", CatMedia},
	{"/System/Applications/Photos.app/", CatMedia},
	{"/System/Applications/Photo Booth.app/", CatMedia},
	{"/System/Applications/Podcasts.app/", CatMedia},
	{"/System/Applications/Preview.app/", CatMedia},
	{"/System/Applications/TV.app/", CatMedia},
	{"/System/Applications/Utilities/Audio MIDI Setup.app/", CatMedia},
	{"/System/Library/ExtensionKit/Extensions/MediaMLExtension.appex/", CatMedia},
	{"/System/Library/Frameworks/QuickLookUI.framework/", CatMedia},
	{"/System/Library/Frameworks/VideoToolbox.framework/", CatMedia},
	{"/System/Library/Frameworks/ImageIO.framework/", CatMedia},

	{"/System/Applications/Calculator.app/", CatProductivity},
	{"/System/Applications/Calendar.app/", CatProductivity},
	{"/System/Applications/Clock.app/", CatProductivity},
	{"/System/Applications/Contacts.app/", CatProductivity},
	{"/System/Applications/Dictionary.app/", CatProductivity},
	{"/System/Applications/Freeform.app/", CatProductivity},
	{"/System/Applications/Maps.app/", CatProductivity},
	{"/System/Applications/News.app/", CatProductivity},
	{"/System/Applications/Notes.app/", CatProductivity},
	{"/System/Applications/Reminders.app/", CatProductivity},
	{"/System/Applications/Shortcuts.app/", CatProductivity},
	{"/System/Applications/Stickies.app/", CatProductivity},
	{"/System/Applications/Stocks.app/", CatProductivity},
	{"/System/Applications/TextEdit.app/", CatProductivity},
	{"/System/Applications/Utilities/Grapher.app/", CatProductivity},
	{"/System/Applications/Weather.app/", CatProductivity},

	{"/System/Applications/Utilities/Console.app/", CatTelemetry},
	{"/System/Applications/Utilities/Feedback Assistant.app/", CatTelemetry},
	{"/System/Library/ExtensionKit/Extensions/MessagesAnalyticsWorker.appex/", CatTelemetry},
	{"/System/Library/ExtensionKit/Extensions/com.apple.mlhost.TelemetryWorker.appex/", CatTelemetry},
	{"/System/Library/ExtensionKit/Extensions/TelemetryAggregator.appex/", CatTelemetry},
	{"/System/Library/PrivateFrameworks/CloudTelemetry.framework/", CatTelemetry},

	{"/System/Applications/Utilities/AirPort Utility.app/", CatNetworking},
	{"/System/Applications/Utilities/Screen Sharing.app/", CatNetworking},
	{"/System/Library/CoreServices/WiFiAgent.app/", CatNetworking},
	{"/System/Library/ExtensionKit/Extensions/Network.appex/", CatNetworking},
	{"/System/Library/ExtensionKit/Extensions/VPN.appex/", CatNetworking},
	{"/System/Library/PrivateFrameworks/WiFiPolicy.framework/", CatNetworking},

	{"/System/Applications/Home.app/", CatHardware},
	{"/System/Applications/Utilities/Print Center.app/", CatHardware},
	{"/System/Library/ExtensionKit/Extensions/Bluetooth.appex/", CatHardware},
	{"/System/Library/ExtensionKit/Extensions/PowerPreferences.appex/", CatHardware},
	{"/System/Library/ExtensionKit/Extensions/Wi-Fi.appex/", CatHardware},

	{"/System/Applications/Utilities/Boot Camp Assistant.app/", CatInstall},
	{"/System/Applications/Utilities/Migration Assistant.app/", CatInstall},
	{"/System/Library/CoreServices/Installer.app/", CatInstall},
	{"/System/Library/CoreServices/Software Update.app/", CatInstall},

	{"/Applications/Xcode.app/", CatDeveloper},
	{"/Library/Developer/", CatDeveloper},
	{"/System/Applications/Automator.app/", CatDeveloper},
	{"/System/Applications/Utilities/Activity Monitor.app/", CatDeveloper},
	{"/System/Applications/Utilities/Script Editor.app/", CatDeveloper},

	{"/System/Applications/FaceTime.app/", CatComms},
	{"/System/Applications/Mail.app/", CatComms},
	{"/System/Applications/Messages.app/", CatComms},

	{"/System/Applications/Utilities/Disk Utility.app/", CatStorage},
	{"/System/Library/CoreServices/Applications/Archive Utility.app/", CatStorage},

	{"/System/Applications/Utilities/Directory Utility.app/", CatSystem},
	{"/System/Applications/Utilities/System Information.app/", CatSystem},

	{"/System/Applications/System Settings.app/", CatSettings},
	{"/System/Library/PreferencePanes/", CatSettings},

	{"/System/Applications/Utilities/VoiceOver Utility.app/", CatAccessibility},

	{"/System/Library/Frameworks/AddressBook.framework/", CatSync},

	{"/System/Library/CoreServices/Spotlight.app/", CatSearch},
}

var byPattern = []struct {
	re  *regexp.Regexp
	cat string
}{
	{regexp.MustCompile(
		`(?i)/ExtensionKit/Extensions/[^/]*settings[^/]*\.appex/|preferencepane|/settings\.appex/`), CatSettings},
	{regexp.MustCompile(
		`(?i)telemetry|analytics|statistic|(^|[a-z])stats([A-Z]|d?$)|diagnostic|crashreport|reportcrash|spindump|sysdiagnose|powerlog|symptom`), CatTelemetry},
	{regexp.MustCompile(
		`(?i)accessibility|voiceover|universalaccess|(^|/)AX[A-Z]`), CatAccessibility},
	{regexp.MustCompile(
		`(?i)siri|assistant|speech|dictation|voicetrigger`), CatAssistant},
	{regexp.MustCompile(
		`(?i)security|xprotect|keychain|trust|touch id|password|biometric|gatekeeper|syspolicy|filevault|fdesetup|(^|/)tcc`), CatSecurity},
	{regexp.MustCompile(
		`(?i)install|softwareupdate|appstore|storekit|commerce|mobileasset`), CatInstall},
	{regexp.MustCompile(
		`(?i)spotlight|metadata|mdworker|corespotlight`), CatSearch},
	{regexp.MustCompile(
		`(?i)wallpaper|screen ?saver|lockscreen|windowserver|controlcenter|notificationcenter|menubar|dock\.app`), CatDesktop},
	{regexp.MustCompile(
		`(?i)disk|apfs|fsevents|backup|timemachine|archive utility|(^|/)mount|volume`), CatStorage},
	{regexp.MustCompile(
		`(?i)photo|video|audio|media|music|quicklook|imageio|airplay|camera`), CatMedia},
	{regexp.MustCompile(
		`(?i)imessage|messages|facetime|telephony|callservices|identityservices|(^|/)mail`), CatComms},
	{regexp.MustCompile(
		`(?i)calendar|contacts|reminders|(^|/)notes|textedit|stickies|calculator|freeform|keynote|pages\.app|numbers\.app`), CatProductivity},
	{regexp.MustCompile(
		`(?i)network|wi-?fi|(^|/)dns|vpn|proxy|nsurlsession|apsd|sharingd|rapport|netbios|airport|bonjour`), CatNetworking},
	{regexp.MustCompile(
		`(?i)bluetooth|thunderbolt|(^|/)usb|printer|(^|/)cups|thermal|(^|/)power|battery|keyboard|trackpad|brightness|sensor|(^|/)hid`), CatHardware},
	{regexp.MustCompile(
		`(?i)icloud|cloudkit|clouddocs`), CatICloud},
	{regexp.MustCompile(
		`(?i)cloud|sync|biome|(^|/)bird`), CatSync},
	{regexp.MustCompile(
		`(?i)(^|/)kext|kernelmanager|kernel_task|systemextension|(^|/)kmutil`), CatKernel},
	{regexp.MustCompile(
		`(?i)/opt/homebrew/|/usr/local/Cellar/|/nix/store/|/opt/local/|xcode|clang|llvm|/go/bin/|\.cargo/|node_modules|toolchain`), CatDeveloper},
}

func Category(name, path, sign string) string {
	if sign != "" {
		for _, m := range bySign {
			if strings.HasPrefix(sign, m.prefix) {
				return m.cat
			}
		}
	}

	if app := Origin(path); app != "" && app != "sysapps" {
		if cat := tags.CategoryOf("", app, ""); cat != "" {
			return cat
		}
	}

	for _, m := range byPath {
		if strings.HasPrefix(path, m.prefix) {
			return m.cat
		}
	}

	if cat := tags.CategoryOf(name, "", ""); cat != "" {
		return cat
	}

	for _, m := range byPattern {
		if m.re.MatchString(path) || m.re.MatchString(name) {
			return m.cat
		}
	}

	return ""
}
