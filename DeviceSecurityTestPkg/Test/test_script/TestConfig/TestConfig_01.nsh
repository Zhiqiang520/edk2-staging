FS0:
mkdir test_output
load Tcg2Stub.efi
DeployCert.efi -T 01
load DeviceSecurityPolicyStub.efi
load PciIoStub.efi
load SpdmStub.efi
load SpdmDeviceSecurityDxe.efi
TestSpdm.efi
Tcg2DumpLog.efi > test_output\log\TestConfig_01.log
reset -s