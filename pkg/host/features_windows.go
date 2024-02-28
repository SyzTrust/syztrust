package host

func init() {
	checkFeature[FeatureCoverage] = unconditionallyEnabled
	checkFeature[FeatureComparisons] = checkComparisons
	checkFeature[FeatureExtraCoverage] = checkExtraCoverage
	checkFeature[FeatureSandboxSetuid] = unconditionallyEnabled
	checkFeature[FeatureSandboxNamespace] = checkSandboxNamespace
	checkFeature[FeatureSandboxAndroid] = checkSandboxAndroid
	checkFeature[FeatureFault] = checkFault
	checkFeature[FeatureLeak] = checkLeak
	checkFeature[FeatureNetInjection] = checkNetInjection
	checkFeature[FeatureNetDevices] = checkNetDevices
	checkFeature[FeatureKCSAN] = checkKCSAN
	checkFeature[FeatureDevlinkPCI] = checkDevlinkPCI
	checkFeature[FeatureUSBEmulation] = checkUSBEmulation
	checkFeature[FeatureVhciInjection] = checkVhciInjection
	checkFeature[FeatureWifiEmulation] = checkWifiEmulation
	checkFeature[Feature802154Emulation] = check802154Emulation
}

func check802154Emulation() string {
	return "not support"

}

func checkWifiEmulation() string {
	return "not support"

}

func checkVhciInjection() string {
	return "not support"

}

func checkUSBEmulation() string {
	return "not support"

}

func checkDevlinkPCI() string {
	return "not support"

}

func checkKCSAN() string {
	return "not support"

}

func checkNetDevices() string {
	return "not support"

}

func checkLeak() string {
	return "not support"

}

func checkNetInjection() string {
	return "not support"

}

func checkFault() string {
	return "not support"

}

func checkSandboxAndroid() string {
	return "not support"

}

func checkSandboxNamespace() string {
	return "not support"

}

func checkSandboxSetuid() string {
	return "not support"

}

func checkCoverage() string {
	return "not support"
}

func checkComparisons() string {
	return "not support"
}

func checkExtraCoverage() string {
	return "not support"
}
