package wf

import "golang.org/x/sys/windows"

var (
	guidCalloutEdgeTraversalALEListenV4              = windows.GUID{0x33486ab5, 0x6d5e, 0x4e65, [8]byte{0xa0, 0x0b, 0xa7, 0xaf, 0xed, 0x0b, 0xa9, 0xa1}}
	guidCalloutEdgeTraversalALEResourceAssignmentV4  = windows.GUID{0x079b1010, 0xf1c5, 0x4fcd, [8]byte{0xae, 0x05, 0xda, 0x41, 0x10, 0x7a, 0xbd, 0x0b}}
	guidCalloutHttpTemplateSslHandshake              = windows.GUID{0xb3423249, 0x8d09, 0x4858, [8]byte{0x92, 0x10, 0x95, 0xc7, 0xfd, 0xa8, 0xe3, 0x0f}}
	guidCalloutIPSecALEConnectV4                     = windows.GUID{0x6ac141fc, 0xf75d, 0x4203, [8]byte{0xb9, 0xc8, 0x48, 0xe6, 0x14, 0x9c, 0x27, 0x12}}
	guidCalloutIPSecALEConnectV6                     = windows.GUID{0x4c0dda05, 0xe31f, 0x4666, [8]byte{0x90, 0xb0, 0xb3, 0xdf, 0xad, 0x34, 0x12, 0x9a}}
	guidCalloutIPSecDospForwardV4                    = windows.GUID{0x2fcb56ec, 0xcd37, 0x4b4f, [8]byte{0xb1, 0x08, 0x62, 0xc2, 0xb1, 0x85, 0x0a, 0x0c}}
	guidCalloutIPSecDospForwardV6                    = windows.GUID{0x6d08a342, 0xdb9e, 0x4fbe, [8]byte{0x9e, 0xd2, 0x57, 0x37, 0x4c, 0xe8, 0x9f, 0x79}}
	guidCalloutIPSecForwardInboundTunnelV4           = windows.GUID{0x28829633, 0xc4f0, 0x4e66, [8]byte{0x87, 0x3f, 0x84, 0x4d, 0xb2, 0xa8, 0x99, 0xc7}}
	guidCalloutIPSecForwardInboundTunnelV6           = windows.GUID{0xaf50bec2, 0xc686, 0x429a, [8]byte{0x88, 0x4d, 0xb7, 0x44, 0x43, 0xe7, 0xb0, 0xb4}}
	guidCalloutIPSecForwardOutboundTunnelV4          = windows.GUID{0xfb532136, 0x15cb, 0x440b, [8]byte{0x93, 0x7c, 0x17, 0x17, 0xca, 0x32, 0x0c, 0x40}}
	guidCalloutIPSecForwardOutboundTunnelV6          = windows.GUID{0xdae640cc, 0xe021, 0x4bee, [8]byte{0x9e, 0xb6, 0xa4, 0x8b, 0x27, 0x5c, 0x8c, 0x1d}}
	guidCalloutIPSecInboundInitiateSecureV4          = windows.GUID{0x7dff309b, 0xba7d, 0x4aba, [8]byte{0x91, 0xaa, 0xae, 0x5c, 0x66, 0x40, 0xc9, 0x44}}
	guidCalloutIPSecInboundInitiateSecureV6          = windows.GUID{0xa9a0d6d9, 0xc58c, 0x474e, [8]byte{0x8a, 0xeb, 0x3c, 0xfe, 0x99, 0xd6, 0xd5, 0x3d}}
	guidCalloutIPSecInboundTransportV4               = windows.GUID{0x5132900d, 0x5e84, 0x4b5f, [8]byte{0x80, 0xe4, 0x01, 0x74, 0x1e, 0x81, 0xff, 0x10}}
	guidCalloutIPSecInboundTransportV6               = windows.GUID{0x49d3ac92, 0x2a6c, 0x4dcf, [8]byte{0x95, 0x5f, 0x1c, 0x3b, 0xe0, 0x09, 0xdd, 0x99}}
	guidCalloutIPSecInboundTunnelALEAcceptV4         = windows.GUID{0x3df6e7de, 0xfd20, 0x48f2, [8]byte{0x9f, 0x26, 0xf8, 0x54, 0x44, 0x4c, 0xba, 0x79}}
	guidCalloutIPSecInboundTunnelALEAcceptV6         = windows.GUID{0xa1e392d3, 0x72ac, 0x47bb, [8]byte{0x87, 0xa7, 0x01, 0x22, 0xc6, 0x94, 0x34, 0xab}}
	guidCalloutIPSecInboundTunnelV4                  = windows.GUID{0x191a8a46, 0x0bf8, 0x46cf, [8]byte{0xb0, 0x45, 0x4b, 0x45, 0xdf, 0xa6, 0xa3, 0x24}}
	guidCalloutIPSecInboundTunnelV6                  = windows.GUID{0x80c342e3, 0x1e53, 0x4d6f, [8]byte{0x9b, 0x44, 0x03, 0xdf, 0x5a, 0xee, 0xe1, 0x54}}
	guidCalloutIPSecOutboundTransportV4              = windows.GUID{0x4b46bf0a, 0x4523, 0x4e57, [8]byte{0xaa, 0x38, 0xa8, 0x79, 0x87, 0xc9, 0x10, 0xd9}}
	guidCalloutIPSecOutboundTransportV6              = windows.GUID{0x38d87722, 0xad83, 0x4f11, [8]byte{0xa9, 0x1f, 0xdf, 0x0f, 0xb0, 0x77, 0x22, 0x5b}}
	guidCalloutIPSecOutboundTunnelV4                 = windows.GUID{0x70a4196c, 0x835b, 0x4fb0, [8]byte{0x98, 0xe8, 0x07, 0x5f, 0x4d, 0x97, 0x7d, 0x46}}
	guidCalloutIPSecOutboundTunnelV6                 = windows.GUID{0xf1835363, 0xa6a5, 0x4e62, [8]byte{0xb1, 0x80, 0x23, 0xdb, 0x78, 0x9d, 0x8d, 0xa6}}
	guidCalloutPolicySilentModeAuthConnectLayerV4    = windows.GUID{0x5fbfc31d, 0xa51c, 0x44dc, [8]byte{0xac, 0xb6, 0x6, 0x24, 0xa0, 0x30, 0xa7, 0x00}}
	guidCalloutPolicySilentModeAuthConnectLayerV6    = windows.GUID{0x5fbfc31d, 0xa51c, 0x44dc, [8]byte{0xac, 0xb6, 0x6, 0x24, 0xa0, 0x30, 0xa7, 0x01}}
	guidCalloutPolicySilentModeAuthRecvAcceptLayerV4 = windows.GUID{0x5fbfc31d, 0xa51c, 0x44dc, [8]byte{0xac, 0xb6, 0x6, 0x24, 0xa0, 0x30, 0xa7, 0x02}}
	guidCalloutPolicySilentModeAuthRecvAcceptLayerV6 = windows.GUID{0x5fbfc31d, 0xa51c, 0x44dc, [8]byte{0xac, 0xb6, 0x6, 0x24, 0xa0, 0x30, 0xa7, 0x03}}
	guidCalloutReservedAuthConnectLayerV4            = windows.GUID{0x288b524d, 0x566, 0x4e19, [8]byte{0xb6, 0x12, 0x8f, 0x44, 0x1a, 0x2e, 0x59, 0x49}}
	guidCalloutReservedAuthConnectLayerV6            = windows.GUID{0xb84b92, 0x2b5e, 0x4b71, [8]byte{0xab, 0xe, 0xaa, 0xca, 0x43, 0xe3, 0x87, 0xe6}}
	guidCalloutSetOptionsAuthConnectLayerV4          = windows.GUID{0xbc582280, 0x1677, 0x41e9, [8]byte{0x94, 0xab, 0xc2, 0xfc, 0xb1, 0x5c, 0x2e, 0xeb}}
	guidCalloutSetOptionsAuthConnectLayerV6          = windows.GUID{0x98e5373c, 0xb884, 0x490f, [8]byte{0xb6, 0x5f, 0x2f, 0x6a, 0x4a, 0x57, 0x51, 0x95}}
	guidCalloutSetOptionsAuthRecvAcceptLayerV4       = windows.GUID{0x2d55f008, 0x0c01, 0x4f92, [8]byte{0xb2, 0x6e, 0xa0, 0x8a, 0x94, 0x56, 0x9b, 0x8d}}
	guidCalloutSetOptionsAuthRecvAcceptLayerV6       = windows.GUID{0x63018537, 0xf281, 0x4dc4, [8]byte{0x83, 0xd3, 0x8d, 0xec, 0x18, 0xb7, 0xad, 0xe2}}
	guidCalloutTCPChimneyAcceptLayerV4               = windows.GUID{0xe183ecb2, 0x3a7f, 0x4b54, [8]byte{0x8a, 0xd9, 0x76, 0x05, 0x0e, 0xd8, 0x80, 0xca}}
	guidCalloutTCPChimneyAcceptLayerV6               = windows.GUID{0x0378cf41, 0xbf98, 0x4603, [8]byte{0x81, 0xf2, 0x7f, 0x12, 0x58, 0x60, 0x79, 0xf6}}
	guidCalloutTCPChimneyConnectLayerV4              = windows.GUID{0xf3e10ab3, 0x2c25, 0x4279, [8]byte{0xac, 0x36, 0xc3, 0x0f, 0xc1, 0x81, 0xbe, 0xc4}}
	guidCalloutTCPChimneyConnectLayerV6              = windows.GUID{0x39e22085, 0xa341, 0x42fc, [8]byte{0xa2, 0x79, 0xae, 0xc9, 0x4e, 0x68, 0x9c, 0x56}}
	guidCalloutTCPTemplatesAcceptLayerV4             = windows.GUID{0x2f23f5d0, 0x40c4, 0x4c41, [8]byte{0xa2, 0x54, 0x46, 0xd8, 0xdb, 0xa8, 0x95, 0x7c}}
	guidCalloutTCPTemplatesAcceptLayerV6             = windows.GUID{0xb25152f0, 0x991c, 0x4f53, [8]byte{0xbb, 0xe7, 0xd2, 0x4b, 0x45, 0xfe, 0x63, 0x2c}}
	guidCalloutTCPTemplatesConnectLayerV4            = windows.GUID{0x215a0b39, 0x4b7e, 0x4eda, [8]byte{0x8c, 0xe4, 0x17, 0x96, 0x79, 0xdf, 0x62, 0x24}}
	guidCalloutTCPTemplatesConnectLayerV6            = windows.GUID{0x838b37a1, 0x5c12, 0x4d34, [8]byte{0x8b, 0x38, 0x07, 0x87, 0x28, 0xb2, 0xd2, 0x5c}}
	guidCalloutTeredoALEListenV6                     = windows.GUID{0x81a434e7, 0xf60c, 0x4378, [8]byte{0xba, 0xb8, 0xc6, 0x25, 0xa3, 0x0f, 0x01, 0x97}}
	guidCalloutTeredoALEResourceAssignmentV6         = windows.GUID{0x31b95392, 0x066e, 0x42a2, [8]byte{0xb7, 0xdb, 0x92, 0xf8, 0xac, 0xdd, 0x56, 0xf9}}
	guidCalloutWFPTransportLayerV4SilentDrop         = windows.GUID{0xeda08606, 0x2494, 0x4d78, [8]byte{0x89, 0xbc, 0x67, 0x83, 0x7c, 0x03, 0xb9, 0x69}}
	guidCalloutWFPTransportLayerV6SilentDrop         = windows.GUID{0x8693cc74, 0xa075, 0x4156, [8]byte{0xb4, 0x76, 0x92, 0x86, 0xee, 0xce, 0x81, 0x4e}}
)

var (
	guidConditionALEAppID                        = windows.GUID{0xd78e1e87, 0x8644, 0x4ea5, [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	guidConditionALEEffectiveName                = windows.GUID{0xb1277b9a, 0xb781, 0x40fc, [8]byte{0x96, 0x71, 0xe5, 0xf1, 0xb9, 0x89, 0xf3, 0x4e}}
	guidConditionALENAPContext                   = windows.GUID{0x46275a9d, 0xc03f, 0x4d77, [8]byte{0xb7, 0x84, 0x1c, 0x57, 0xf4, 0xd0, 0x27, 0x53}}
	guidConditionALEOriginalAppID                = windows.GUID{0x0e6cd086, 0xe1fb, 0x4212, [8]byte{0x84, 0x2f, 0x8a, 0x9f, 0x99, 0x3f, 0xb3, 0xf6}}
	guidConditionALEPackageID                    = windows.GUID{0x71bc78fa, 0xf17c, 0x4997, [8]byte{0xa6, 0x2, 0x6a, 0xbb, 0x26, 0x1f, 0x35, 0x1c}}
	guidConditionALEPromiscuousMode              = windows.GUID{0x1c974776, 0x7182, 0x46e9, [8]byte{0xaf, 0xd3, 0xb0, 0x29, 0x10, 0xe3, 0x03, 0x34}}
	guidConditionALEReauthReason                 = windows.GUID{0xb482d227, 0x1979, 0x4a98, [8]byte{0x80, 0x44, 0x18, 0xbb, 0xe6, 0x23, 0x75, 0x42}}
	guidConditionALERemoteMachineID              = windows.GUID{0x1aa47f51, 0x7f93, 0x4508, [8]byte{0xa2, 0x71, 0x81, 0xab, 0xb0, 0x0c, 0x9c, 0xab}}
	guidConditionALERemoteUserID                 = windows.GUID{0xf63073b7, 0x0189, 0x4ab0, [8]byte{0x95, 0xa4, 0x61, 0x23, 0xcb, 0xfa, 0xb8, 0x62}}
	guidConditionALESecurityAttributeFqbnValue   = windows.GUID{0x37a57699, 0x5883, 0x4963, [8]byte{0x92, 0xb8, 0x3e, 0x70, 0x46, 0x88, 0xb0, 0xad}}
	guidConditionALESioFirewallSystemPort        = windows.GUID{0xb9f4e088, 0xcb98, 0x4efb, [8]byte{0xa2, 0xc7, 0xad, 0x07, 0x33, 0x26, 0x43, 0xdb}}
	guidConditionALEUserID                       = windows.GUID{0xaf043a0a, 0xb34d, 0x4f86, [8]byte{0x97, 0x9c, 0xc9, 0x03, 0x71, 0xaf, 0x6e, 0x66}}
	guidConditionArrivalInterfaceIndex           = windows.GUID{0xcc088db3, 0x1792, 0x4a71, [8]byte{0xb0, 0xf9, 0x03, 0x7d, 0x21, 0xcd, 0x82, 0x8b}}
	guidConditionArrivalInterfaceProfileID       = windows.GUID{0xcdfe6aab, 0xc083, 0x4142, [8]byte{0x86, 0x79, 0xc0, 0x8f, 0x95, 0x32, 0x9c, 0x61}}
	guidConditionArrivalInterfaceType            = windows.GUID{0x89f990de, 0xe798, 0x4e6d, [8]byte{0xab, 0x76, 0x7c, 0x95, 0x58, 0x29, 0x2e, 0x6f}}
	guidConditionArrivalTunnelType               = windows.GUID{0x511166dc, 0x7a8c, 0x4aa7, [8]byte{0xb5, 0x33, 0x95, 0xab, 0x59, 0xfb, 0x03, 0x40}}
	guidConditionAuthenticationType              = windows.GUID{0xeb458cd5, 0xda7b, 0x4ef9, [8]byte{0x8d, 0x43, 0x7b, 0x0a, 0x84, 0x03, 0x32, 0xf2}}
	guidConditionBitmapIPLocalAddress            = windows.GUID{0x16ebc3df, 0x957a, 0x452e, [8]byte{0xa1, 0xfc, 0x3d, 0x2f, 0xf6, 0xa7, 0x30, 0xba}}
	guidConditionBitmapIPLocalPort               = windows.GUID{0x9f90a920, 0xc3b5, 0x4569, [8]byte{0xba, 0x31, 0x8b, 0xd3, 0x91, 0xd, 0xc6, 0x56}}
	guidConditionBitmapIPRemoteAddress           = windows.GUID{0x33f00e25, 0x8eec, 0x4531, [8]byte{0xa0, 0x5, 0x41, 0xb9, 0x11, 0xf6, 0x24, 0x52}}
	guidConditionBitmapIPRemotePort              = windows.GUID{0x2663d549, 0xaaf2, 0x46a2, [8]byte{0x86, 0x66, 0x1e, 0x76, 0x67, 0xf8, 0x69, 0x85}}
	guidConditionBitmapIndexKey                  = windows.GUID{0xf36514c, 0x3226, 0x4a81, [8]byte{0xa2, 0x14, 0x2d, 0x51, 0x8b, 0x4, 0xd0, 0x8a}}
	guidConditionClientCertKeyLength             = windows.GUID{0xa3ec00c7, 0x05f4, 0x4df7, [8]byte{0x91, 0xf2, 0x5f, 0x60, 0xd9, 0x1f, 0xf4, 0x43}}
	guidConditionClientCertOid                   = windows.GUID{0xc491ad5e, 0xf882, 0x4283, [8]byte{0xb9, 0x16, 0x43, 0x6b, 0x10, 0x3f, 0xf4, 0xad}}
	guidConditionClientToken                     = windows.GUID{0xc228fc1e, 0x403a, 0x4478, [8]byte{0xbe, 0x05, 0xc9, 0xba, 0xa4, 0xc0, 0x5a, 0xce}}
	guidConditionCompartmentID                   = windows.GUID{0x35a791ab, 0x4ac, 0x4ff2, [8]byte{0xa6, 0xbb, 0xda, 0x6c, 0xfa, 0xc7, 0x18, 0x6}}
	guidConditionCurrentProfileID                = windows.GUID{0xab3033c9, 0xc0e3, 0x4759, [8]byte{0x93, 0x7d, 0x57, 0x58, 0xc6, 0x5d, 0x4a, 0xe3}}
	guidConditionDCOMAppID                       = windows.GUID{0xff2e7b4d, 0x3112, 0x4770, [8]byte{0xb6, 0x36, 0x4d, 0x24, 0xae, 0x3a, 0x6a, 0xf2}}
	guidConditionDestinationInterfaceIndex       = windows.GUID{0x35cf6522, 0x4139, 0x45ee, [8]byte{0xa0, 0xd5, 0x67, 0xb8, 0x09, 0x49, 0xd8, 0x79}}
	guidConditionDestinationSubInterfaceIndex    = windows.GUID{0x2b7d4399, 0xd4c7, 0x4738, [8]byte{0xa2, 0xf5, 0xe9, 0x94, 0xb4, 0x3d, 0xa3, 0x88}}
	guidConditionDirection                       = windows.GUID{0x8784c146, 0xca97, 0x44d6, [8]byte{0x9f, 0xd1, 0x19, 0xfb, 0x18, 0x40, 0xcb, 0xf7}}
	guidConditionEmbeddedLocalAddressType        = windows.GUID{0x4672a468, 0x8a0a, 0x4202, [8]byte{0xab, 0xb4, 0x84, 0x9e, 0x92, 0xe6, 0x68, 0x09}}
	guidConditionEmbeddedLocalPort               = windows.GUID{0xbfca394d, 0xacdb, 0x484e, [8]byte{0xb8, 0xe6, 0x2a, 0xff, 0x79, 0x75, 0x73, 0x45}}
	guidConditionEmbeddedProtocol                = windows.GUID{0x07784107, 0xa29e, 0x4c7b, [8]byte{0x9e, 0xc7, 0x29, 0xc4, 0x4a, 0xfa, 0xfd, 0xbc}}
	guidConditionEmbeddedRemoteAddress           = windows.GUID{0x77ee4b39, 0x3273, 0x4671, [8]byte{0xb6, 0x3b, 0xab, 0x6f, 0xeb, 0x66, 0xee, 0xb6}}
	guidConditionEmbeddedRemotePort              = windows.GUID{0xcae4d6a1, 0x2968, 0x40ed, [8]byte{0xa4, 0xce, 0x54, 0x71, 0x60, 0xdd, 0xa8, 0x8d}}
	guidConditionEtherType                       = windows.GUID{0xfd08948d, 0xa219, 0x4d52, [8]byte{0xbb, 0x98, 0x1a, 0x55, 0x40, 0xee, 0x7b, 0x4e}}
	guidConditionFlags                           = windows.GUID{0x632ce23b, 0x5167, 0x435c, [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}}
	guidConditionIPArrivalInterface              = windows.GUID{0x618a9b6d, 0x386b, 0x4136, [8]byte{0xad, 0x6e, 0xb5, 0x15, 0x87, 0xcf, 0xb1, 0xcd}}
	guidConditionIPDestinationAddress            = windows.GUID{0x2d79133b, 0xb390, 0x45c6, [8]byte{0x86, 0x99, 0xac, 0xac, 0xea, 0xaf, 0xed, 0x33}}
	guidConditionIPDestinationAddressType        = windows.GUID{0x1ec1b7c9, 0x4eea, 0x4f5e, [8]byte{0xb9, 0xef, 0x76, 0xbe, 0xaa, 0xaf, 0x17, 0xee}}
	guidConditionIPDestinationPort               = windows.GUID{0xce6def45, 0x60fb, 0x4a7b, [8]byte{0xa3, 0x04, 0xaf, 0x30, 0xa1, 0x17, 0x00, 0x0e}}
	guidConditionIPForwardInterface              = windows.GUID{0x1076b8a5, 0x6323, 0x4c5e, [8]byte{0x98, 0x10, 0xe8, 0xd3, 0xfc, 0x9e, 0x61, 0x36}}
	guidConditionIPLocalAddress                  = windows.GUID{0xd9ee00de, 0xc1ef, 0x4617, [8]byte{0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57}}
	guidConditionIPLocalAddressType              = windows.GUID{0x6ec7f6c4, 0x376b, 0x45d7, [8]byte{0x9e, 0x9c, 0xd3, 0x37, 0xce, 0xdc, 0xd2, 0x37}}
	guidConditionIPLocalAddressV4                = windows.GUID{0x03a629cb, 0x6e52, 0x49f8, [8]byte{0x9c, 0x41, 0x57, 0x09, 0x63, 0x3c, 0x09, 0xcf}}
	guidConditionIPLocalAddressV6                = windows.GUID{0x2381be84, 0x7524, 0x45b3, [8]byte{0xa0, 0x5b, 0x1e, 0x63, 0x7d, 0x9c, 0x7a, 0x6a}}
	guidConditionIPLocalInterface                = windows.GUID{0x4cd62a49, 0x59c3, 0x4969, [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
	guidConditionIPLocalPort                     = windows.GUID{0x0c1ba1af, 0x5765, 0x453f, [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}}
	guidConditionIPNexthopAddress                = windows.GUID{0xeabe448a, 0xa711, 0x4d64, [8]byte{0x85, 0xb7, 0x3f, 0x76, 0xb6, 0x52, 0x99, 0xc7}}
	guidConditionIPNexthopInterface              = windows.GUID{0x93ae8f5b, 0x7f6f, 0x4719, [8]byte{0x98, 0xc8, 0x14, 0xe9, 0x74, 0x29, 0xef, 0x04}}
	guidConditionIPPhysicalArrivalInterface      = windows.GUID{0xda50d5c8, 0xfa0d, 0x4c89, [8]byte{0xb0, 0x32, 0x6e, 0x62, 0x13, 0x6d, 0x1e, 0x96}}
	guidConditionIPPhysicalNexthopInterface      = windows.GUID{0xf09bd5ce, 0x5150, 0x48be, [8]byte{0xb0, 0x98, 0xc2, 0x51, 0x52, 0xfb, 0x1f, 0x92}}
	guidConditionIPProtocol                      = windows.GUID{0x3971ef2b, 0x623e, 0x4f9a, [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	guidConditionIPRemoteAddress                 = windows.GUID{0xb235ae9a, 0x1d64, 0x49b8, [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	guidConditionIPRemoteAddressV4               = windows.GUID{0x1febb610, 0x3bcc, 0x45e1, [8]byte{0xbc, 0x36, 0x2e, 0x06, 0x7e, 0x2c, 0xb1, 0x86}}
	guidConditionIPRemoteAddressV6               = windows.GUID{0x246e1d8c, 0x8bee, 0x4018, [8]byte{0x9b, 0x98, 0x31, 0xd4, 0x58, 0x2f, 0x33, 0x61}}
	guidConditionIPRemotePort                    = windows.GUID{0xc35a604d, 0xd22b, 0x4e1a, [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	guidConditionIPSecPolicyKey                  = windows.GUID{0xad37dee3, 0x722f, 0x45cc, [8]byte{0xa4, 0xe3, 0x06, 0x80, 0x48, 0x12, 0x44, 0x52}}
	guidConditionIPSecSecurityRealmID            = windows.GUID{0x37a57700, 0x5884, 0x4964, [8]byte{0x92, 0xb8, 0x3e, 0x70, 0x46, 0x88, 0xb0, 0xad}}
	guidConditionIPSourceAddress                 = windows.GUID{0xae96897e, 0x2e94, 0x4bc9, [8]byte{0xb3, 0x13, 0xb2, 0x7e, 0xe8, 0x0e, 0x57, 0x4d}}
	guidConditionIPSourcePort                    = windows.GUID{0xa6afef91, 0x3df4, 0x4730, [8]byte{0xa2, 0x14, 0xf5, 0x42, 0x6a, 0xeb, 0xf8, 0x21}}
	guidConditionImageName                       = windows.GUID{0xd024de4d, 0xdeaa, 0x4317, [8]byte{0x9c, 0x85, 0xe4, 0x0e, 0xf6, 0xe1, 0x40, 0xc3}}
	guidConditionInterfaceIndex                  = windows.GUID{0x667fd755, 0xd695, 0x434a, [8]byte{0x8a, 0xf5, 0xd3, 0x83, 0x5a, 0x12, 0x59, 0xbc}}
	guidConditionInterfaceMACAddress             = windows.GUID{0xf6e63dce, 0x1f4b, 0x4c6b, [8]byte{0xb6, 0xef, 0x11, 0x65, 0xe7, 0x1f, 0x8e, 0xe7}}
	guidConditionInterfaceQuarantineEpoch        = windows.GUID{0xcce68d5e, 0x053b, 0x43a8, [8]byte{0x9a, 0x6f, 0x33, 0x38, 0x4c, 0x28, 0xe4, 0xf6}}
	guidConditionInterfaceType                   = windows.GUID{0xdaf8cd14, 0xe09e, 0x4c93, [8]byte{0xa5, 0xae, 0xc5, 0xc1, 0x3b, 0x73, 0xff, 0xca}}
	guidConditionKMAuthNAPContext                = windows.GUID{0x35d0ea0e, 0x15ca, 0x492b, [8]byte{0x90, 0x0e, 0x97, 0xfd, 0x46, 0x35, 0x2c, 0xce}}
	guidConditionKMMode                          = windows.GUID{0xfeef4582, 0xef8f, 0x4f7b, [8]byte{0x85, 0x8b, 0x90, 0x77, 0xd1, 0x22, 0xde, 0x47}}
	guidConditionKMType                          = windows.GUID{0xff0f5f49, 0x0ceb, 0x481b, [8]byte{0x86, 0x38, 0x14, 0x79, 0x79, 0x1f, 0x3f, 0x2c}}
	guidConditionL2Flags                         = windows.GUID{0x7bc43cbf, 0x37ba, 0x45f1, [8]byte{0xb7, 0x4a, 0x82, 0xff, 0x51, 0x8e, 0xeb, 0x10}}
	guidConditionLocalInterfaceProfileID         = windows.GUID{0x4ebf7562, 0x9f18, 0x4d06, [8]byte{0x99, 0x41, 0xa7, 0xa6, 0x25, 0x74, 0x4d, 0x71}}
	guidConditionMACDestinationAddress           = windows.GUID{0x04ea2a93, 0x858c, 0x4027, [8]byte{0xb6, 0x13, 0xb4, 0x31, 0x80, 0xc7, 0x85, 0x9e}}
	guidConditionMACDestinationAddressType       = windows.GUID{0xae052932, 0xef42, 0x4e99, [8]byte{0xb1, 0x29, 0xf3, 0xb3, 0x13, 0x9e, 0x34, 0xf7}}
	guidConditionMACLocalAddress                 = windows.GUID{0xd999e981, 0x7948, 0x4c83, [8]byte{0xb7, 0x42, 0xc8, 0x4e, 0x3b, 0x67, 0x8f, 0x8f}}
	guidConditionMACLocalAddressType             = windows.GUID{0xcc31355c, 0x3073, 0x4ffb, [8]byte{0xa1, 0x4f, 0x79, 0x41, 0x5c, 0xb1, 0xea, 0xd1}}
	guidConditionMACRemoteAddress                = windows.GUID{0x408f2ed4, 0x3a70, 0x4b4d, [8]byte{0x92, 0xa6, 0x41, 0x5a, 0xc2, 0x0e, 0x2f, 0x12}}
	guidConditionMACRemoteAddressType            = windows.GUID{0x027fedb4, 0xf1c1, 0x4030, [8]byte{0xb5, 0x64, 0xee, 0x77, 0x7f, 0xd8, 0x67, 0xea}}
	guidConditionMACSourceAddress                = windows.GUID{0x7b795451, 0xf1f6, 0x4d05, [8]byte{0xb7, 0xcb, 0x21, 0x77, 0x9d, 0x80, 0x23, 0x36}}
	guidConditionMACSourceAddressType            = windows.GUID{0x5c1b72e4, 0x299e, 0x4437, [8]byte{0xa2, 0x98, 0xbc, 0x3f, 0x01, 0x4b, 0x3d, 0xc2}}
	guidConditionNdisMediaType                   = windows.GUID{0xcb31cef1, 0x791d, 0x473b, [8]byte{0x89, 0xd1, 0x61, 0xc5, 0x98, 0x43, 0x04, 0xa0}}
	guidConditionNdisPhysicalMediaType           = windows.GUID{0x34c79823, 0xc229, 0x44f2, [8]byte{0xb8, 0x3c, 0x74, 0x02, 0x08, 0x82, 0xae, 0x77}}
	guidConditionNdisPort                        = windows.GUID{0xdb7bb42b, 0x2dac, 0x4cd4, [8]byte{0xa5, 0x9a, 0xe0, 0xbd, 0xce, 0x1e, 0x68, 0x34}}
	guidConditionNetEventType                    = windows.GUID{0x206e9996, 0x490e, 0x40cf, [8]byte{0xb8, 0x31, 0xb3, 0x86, 0x41, 0xeb, 0x6f, 0xcb}}
	guidConditionNexthopInterfaceIndex           = windows.GUID{0x138e6888, 0x7ab8, 0x4d65, [8]byte{0x9e, 0xe8, 0x05, 0x91, 0xbc, 0xf6, 0xa4, 0x94}}
	guidConditionNexthopInterfaceProfileID       = windows.GUID{0xd7ff9a56, 0xcdaa, 0x472b, [8]byte{0x84, 0xdb, 0xd2, 0x39, 0x63, 0xc1, 0xd1, 0xbf}}
	guidConditionNexthopInterfaceType            = windows.GUID{0x97537c6c, 0xd9a3, 0x4767, [8]byte{0xa3, 0x81, 0xe9, 0x42, 0x67, 0x5c, 0xd9, 0x20}}
	guidConditionNexthopSubInterfaceIndex        = windows.GUID{0xef8a6122, 0x0577, 0x45a7, [8]byte{0x9a, 0xaf, 0x82, 0x5f, 0xbe, 0xb4, 0xfb, 0x95}}
	guidConditionNexthopTunnelType               = windows.GUID{0x72b1a111, 0x987b, 0x4720, [8]byte{0x99, 0xdd, 0xc7, 0xc5, 0x76, 0xfa, 0x2d, 0x4c}}
	guidConditionOriginalICMPType                = windows.GUID{0x076dfdbe, 0xc56c, 0x4f72, [8]byte{0xae, 0x8a, 0x2c, 0xfe, 0x7e, 0x5c, 0x82, 0x86}}
	guidConditionOriginalProfileID               = windows.GUID{0x46ea1551, 0x2255, 0x492b, [8]byte{0x80, 0x19, 0xaa, 0xbe, 0xee, 0x34, 0x9f, 0x40}}
	guidConditionPeerName                        = windows.GUID{0x9b539082, 0xeb90, 0x4186, [8]byte{0xa6, 0xcc, 0xde, 0x5b, 0x63, 0x23, 0x50, 0x16}}
	guidConditionPipe                            = windows.GUID{0x1bd0741d, 0xe3df, 0x4e24, [8]byte{0x86, 0x34, 0x76, 0x20, 0x46, 0xee, 0xf6, 0xeb}}
	guidConditionProcessWithRPCIfUUID            = windows.GUID{0xe31180a8, 0xbbbd, 0x4d14, [8]byte{0xa6, 0x5e, 0x71, 0x57, 0xb0, 0x62, 0x33, 0xbb}}
	guidConditionQMMode                          = windows.GUID{0xf64fc6d1, 0xf9cb, 0x43d2, [8]byte{0x8a, 0x5f, 0xe1, 0x3b, 0xc8, 0x94, 0xf2, 0x65}}
	guidConditionRPCAuthLevel                    = windows.GUID{0xe5a0aed5, 0x59ac, 0x46ea, [8]byte{0xbe, 0x05, 0xa5, 0xf0, 0x5e, 0xcf, 0x44, 0x6e}}
	guidConditionRPCAuthType                     = windows.GUID{0xdaba74ab, 0x0d67, 0x43e7, [8]byte{0x98, 0x6e, 0x75, 0xb8, 0x4f, 0x82, 0xf5, 0x94}}
	guidConditionRPCEPFlags                      = windows.GUID{0x218b814a, 0x0a39, 0x49b8, [8]byte{0x8e, 0x71, 0xc2, 0x0c, 0x39, 0xc7, 0xdd, 0x2e}}
	guidConditionRPCEPValue                      = windows.GUID{0xdccea0b9, 0x0886, 0x4360, [8]byte{0x9c, 0x6a, 0xab, 0x04, 0x3a, 0x24, 0xfb, 0xa9}}
	guidConditionRPCIfFlag                       = windows.GUID{0x238a8a32, 0x3199, 0x467d, [8]byte{0x87, 0x1c, 0x27, 0x26, 0x21, 0xab, 0x38, 0x96}}
	guidConditionRPCIfUUID                       = windows.GUID{0x7c9c7d9f, 0x0075, 0x4d35, [8]byte{0xa0, 0xd1, 0x83, 0x11, 0xc4, 0xcf, 0x6a, 0xf1}}
	guidConditionRPCIfVersion                    = windows.GUID{0xeabfd9b7, 0x1262, 0x4a2e, [8]byte{0xad, 0xaa, 0x5f, 0x96, 0xf6, 0xfe, 0x32, 0x6d}}
	guidConditionRPCProtocol                     = windows.GUID{0x2717bc74, 0x3a35, 0x4ce7, [8]byte{0xb7, 0xef, 0xc8, 0x38, 0xfa, 0xbd, 0xec, 0x45}}
	guidConditionRPCProxyAuthType                = windows.GUID{0x40953fe2, 0x8565, 0x4759, [8]byte{0x84, 0x88, 0x17, 0x71, 0xb4, 0xb4, 0xb5, 0xdb}}
	guidConditionRPCServerName                   = windows.GUID{0xb605a225, 0xc3b3, 0x48c7, [8]byte{0x98, 0x33, 0x7a, 0xef, 0xa9, 0x52, 0x75, 0x46}}
	guidConditionRPCServerPort                   = windows.GUID{0x8090f645, 0x9ad5, 0x4e3b, [8]byte{0x9f, 0x9f, 0x80, 0x23, 0xca, 0x09, 0x79, 0x09}}
	guidConditionReauthorizeReason               = windows.GUID{0x11205e8c, 0x11ae, 0x457a, [8]byte{0x8a, 0x44, 0x47, 0x70, 0x26, 0xdd, 0x76, 0x4a}}
	guidConditionRemoteID                        = windows.GUID{0xf68166fd, 0x0682, 0x4c89, [8]byte{0xb8, 0xf5, 0x86, 0x43, 0x6c, 0x7e, 0xf9, 0xb7}}
	guidConditionRemoteUserToken                 = windows.GUID{0x9bf0ee66, 0x06c9, 0x41b9, [8]byte{0x84, 0xda, 0x28, 0x8c, 0xb4, 0x3a, 0xf5, 0x1f}}
	guidConditionReserved0                       = windows.GUID{0x678f4deb, 0x45af, 0x4882, [8]byte{0x93, 0xfe, 0x19, 0xd4, 0x72, 0x9d, 0x98, 0x34}}
	guidConditionReserved1                       = windows.GUID{0xd818f827, 0x5c69, 0x48eb, [8]byte{0xbf, 0x80, 0xd8, 0x6b, 0x17, 0x75, 0x5f, 0x97}}
	guidConditionReserved10                      = windows.GUID{0xb979e282, 0xd621, 0x4c8c, [8]byte{0xb1, 0x84, 0xb1, 0x05, 0xa6, 0x1c, 0x36, 0xce}}
	guidConditionReserved11                      = windows.GUID{0x2d62ee4d, 0x023d, 0x411f, [8]byte{0x95, 0x82, 0x43, 0xac, 0xbb, 0x79, 0x59, 0x75}}
	guidConditionReserved12                      = windows.GUID{0xa3677c32, 0x7e35, 0x4ddc, [8]byte{0x93, 0xda, 0xe8, 0xc3, 0x3f, 0xc9, 0x23, 0xc7}}
	guidConditionReserved13                      = windows.GUID{0x335a3e90, 0x84aa, 0x42f5, [8]byte{0x9e, 0x6f, 0x59, 0x30, 0x95, 0x36, 0xa4, 0x4c}}
	guidConditionReserved14                      = windows.GUID{0x30e44da2, 0x2f1a, 0x4116, [8]byte{0xa5, 0x59, 0xf9, 0x07, 0xde, 0x83, 0x60, 0x4a}}
	guidConditionReserved15                      = windows.GUID{0xbab8340f, 0xafe0, 0x43d1, [8]byte{0x80, 0xd8, 0x5c, 0xa4, 0x56, 0x96, 0x2d, 0xe3}}
	guidConditionReserved2                       = windows.GUID{0x53d4123d, 0xe15b, 0x4e84, [8]byte{0xb7, 0xa8, 0xdc, 0xe1, 0x6f, 0x7b, 0x62, 0xd9}}
	guidConditionReserved3                       = windows.GUID{0x7f6e8ca3, 0x6606, 0x4932, [8]byte{0x97, 0xc7, 0xe1, 0xf2, 0x07, 0x10, 0xaf, 0x3b}}
	guidConditionReserved4                       = windows.GUID{0x5f58e642, 0xb937, 0x495e, [8]byte{0xa9, 0x4b, 0xf6, 0xb0, 0x51, 0xa4, 0x92, 0x50}}
	guidConditionReserved5                       = windows.GUID{0x9ba8f6cd, 0xf77c, 0x43e6, [8]byte{0x88, 0x47, 0x11, 0x93, 0x9d, 0xc5, 0xdb, 0x5a}}
	guidConditionReserved6                       = windows.GUID{0xf13d84bd, 0x59d5, 0x44c4, [8]byte{0x88, 0x17, 0x5e, 0xcd, 0xae, 0x18, 0x05, 0xbd}}
	guidConditionReserved7                       = windows.GUID{0x65a0f930, 0x45dd, 0x4983, [8]byte{0xaa, 0x33, 0xef, 0xc7, 0xb6, 0x11, 0xaf, 0x08}}
	guidConditionReserved8                       = windows.GUID{0x4f424974, 0x0c12, 0x4816, [8]byte{0x9b, 0x47, 0x9a, 0x54, 0x7d, 0xb3, 0x9a, 0x32}}
	guidConditionReserved9                       = windows.GUID{0xce78e10f, 0x13ff, 0x4c70, [8]byte{0x86, 0x43, 0x36, 0xad, 0x18, 0x79, 0xaf, 0xa3}}
	guidConditionSecEncryptAlgorithm             = windows.GUID{0x0d306ef0, 0xe974, 0x4f74, [8]byte{0xb5, 0xc7, 0x59, 0x1b, 0x0d, 0xa7, 0xd5, 0x62}}
	guidConditionSecKeySize                      = windows.GUID{0x4772183b, 0xccf8, 0x4aeb, [8]byte{0xbc, 0xe1, 0xc6, 0xc6, 0x16, 0x1c, 0x8f, 0xe4}}
	guidConditionSourceInterfaceIndex            = windows.GUID{0x2311334d, 0xc92d, 0x45bf, [8]byte{0x94, 0x96, 0xed, 0xf4, 0x47, 0x82, 0x0e, 0x2d}}
	guidConditionSourceSubInterfaceIndex         = windows.GUID{0x055edd9d, 0xacd2, 0x4361, [8]byte{0x8d, 0xab, 0xf9, 0x52, 0x5d, 0x97, 0x66, 0x2f}}
	guidConditionSubInterfaceIndex               = windows.GUID{0x0cd42473, 0xd621, 0x4be3, [8]byte{0xae, 0x8c, 0x72, 0xa3, 0x48, 0xd2, 0x83, 0xe1}}
	guidConditionTunnelType                      = windows.GUID{0x77a40437, 0x8779, 0x4868, [8]byte{0xa2, 0x61, 0xf5, 0xa9, 0x02, 0xf1, 0xc0, 0xcd}}
	guidConditionVLANID                          = windows.GUID{0x938eab21, 0x3618, 0x4e64, [8]byte{0x9c, 0xa5, 0x21, 0x41, 0xeb, 0xda, 0x1c, 0xa2}}
	guidConditionVSwitchDestinationInterfaceID   = windows.GUID{0x8ed48be4, 0xc926, 0x49f6, [8]byte{0xa4, 0xf6, 0xef, 0x30, 0x30, 0xe3, 0xfc, 0x16}}
	guidConditionVSwitchDestinationInterfaceType = windows.GUID{0xfa9b3f06, 0x2f1a, 0x4c57, [8]byte{0x9e, 0x68, 0xa7, 0x09, 0x8b, 0x28, 0xdb, 0xfe}}
	guidConditionVSwitchDestinationVmID          = windows.GUID{0x6106aace, 0x4de1, 0x4c84, [8]byte{0x96, 0x71, 0x36, 0x37, 0xf8, 0xbc, 0xf7, 0x31}}
	guidConditionVSwitchID                       = windows.GUID{0xc4a414ba, 0x437b, 0x4de6, [8]byte{0x99, 0x46, 0xd9, 0x9c, 0x1b, 0x95, 0xb3, 0x12}}
	guidConditionVSwitchNetworkType              = windows.GUID{0x11d48b4b, 0xe77a, 0x40b4, [8]byte{0x91, 0x55, 0x39, 0x2c, 0x90, 0x6c, 0x26, 0x08}}
	guidConditionVSwitchSourceInterfaceID        = windows.GUID{0x7f4ef24b, 0xb2c1, 0x4938, [8]byte{0xba, 0x33, 0xa1, 0xec, 0xbe, 0xd5, 0x12, 0xba}}
	guidConditionVSwitchSourceInterfaceType      = windows.GUID{0xe6b040a2, 0xedaf, 0x4c36, [8]byte{0x90, 0x8b, 0xf2, 0xf5, 0x8a, 0xe4, 0x38, 0x07}}
	guidConditionVSwitchSourceVmID               = windows.GUID{0x9c2a9ec2, 0x9fc6, 0x42bc, [8]byte{0xbd, 0xd8, 0x40, 0x6d, 0x4d, 0xa0, 0xbe, 0x64}}
	guidConditionVSwitchTenantNetworkID          = windows.GUID{0xdc04843c, 0x79e6, 0x4e44, [8]byte{0xa0, 0x25, 0x65, 0xb9, 0xbb, 0x0f, 0x9f, 0x94}}
)

var (
	guidKeyingModuleAuthIP = windows.GUID{0x11e3dae0, 0xdd26, 0x4590, [8]byte{0x85, 0x7d, 0xab, 0x4b, 0x28, 0xd1, 0xa0, 0x95}}
	guidKeyingModuleIKE    = windows.GUID{0xa9bbf787, 0x82a8, 0x45bb, [8]byte{0xa4, 0x00, 0x5d, 0x7e, 0x59, 0x52, 0xc7, 0xa9}}
	guidKeyingModuleIKEv2  = windows.GUID{0x041792cc, 0x8f07, 0x419d, [8]byte{0xa3, 0x94, 0x71, 0x69, 0x68, 0xcb, 0x16, 0x47}}
)

var (
	LayerALEAuthConnectV4               = LayerID{0xc38d57d1, 0x05a7, 0x4c33, [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	LayerALEAuthConnectV4Discard        = LayerID{0xd632a801, 0xf5ba, 0x4ad6, [8]byte{0x96, 0xe3, 0x60, 0x70, 0x17, 0xd9, 0x83, 0x6a}}
	LayerALEAuthConnectV6               = LayerID{0x4a72393b, 0x319f, 0x44bc, [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	LayerALEAuthConnectV6Discard        = LayerID{0xc97bc3b8, 0xc9a3, 0x4e33, [8]byte{0x86, 0x95, 0x8e, 0x17, 0xaa, 0xd4, 0xde, 0x09}}
	LayerALEAuthListenV4                = LayerID{0x88bb5dad, 0x76d7, 0x4227, [8]byte{0x9c, 0x71, 0xdf, 0x0a, 0x3e, 0xd7, 0xbe, 0x7e}}
	LayerALEAuthListenV4Discard         = LayerID{0x371dfada, 0x9f26, 0x45fd, [8]byte{0xb4, 0xeb, 0xc2, 0x9e, 0xb2, 0x12, 0x89, 0x3f}}
	LayerALEAuthListenV6                = LayerID{0x7ac9de24, 0x17dd, 0x4814, [8]byte{0xb4, 0xbd, 0xa9, 0xfb, 0xc9, 0x5a, 0x32, 0x1b}}
	LayerALEAuthListenV6Discard         = LayerID{0x60703b07, 0x63c8, 0x48e9, [8]byte{0xad, 0xa3, 0x12, 0xb1, 0xaf, 0x40, 0xa6, 0x17}}
	LayerALEAuthRecvAcceptV4            = LayerID{0xe1cd9fe7, 0xf4b5, 0x4273, [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
	LayerALEAuthRecvAcceptV4Discard     = LayerID{0x9eeaa99b, 0xbd22, 0x4227, [8]byte{0x91, 0x9f, 0x00, 0x73, 0xc6, 0x33, 0x57, 0xb1}}
	LayerALEAuthRecvAcceptV6            = LayerID{0xa3b42c97, 0x9f04, 0x4672, [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}
	LayerALEAuthRecvAcceptV6Discard     = LayerID{0x89455b97, 0xdbe1, 0x453f, [8]byte{0xa2, 0x24, 0x13, 0xda, 0x89, 0x5a, 0xf3, 0x96}}
	LayerALEBindRedirectV4              = LayerID{0x66978cad, 0xc704, 0x42ac, [8]byte{0x86, 0xac, 0x7c, 0x1a, 0x23, 0x1b, 0xd2, 0x53}}
	LayerALEBindRedirectV6              = LayerID{0xbef02c9c, 0x606b, 0x4536, [8]byte{0x8c, 0x26, 0x1c, 0x2f, 0xc7, 0xb6, 0x31, 0xd4}}
	LayerALEConnectRedirectV4           = LayerID{0xc6e63c8c, 0xb784, 0x4562, [8]byte{0xaa, 0x7d, 0x0a, 0x67, 0xcf, 0xca, 0xf9, 0xa3}}
	LayerALEConnectRedirectV6           = LayerID{0x587e54a7, 0x8046, 0x42ba, [8]byte{0xa0, 0xaa, 0xb7, 0x16, 0x25, 0x0f, 0xc7, 0xfd}}
	LayerALEEndpointClosureV4           = LayerID{0xb4766427, 0xe2a2, 0x467a, [8]byte{0xbd, 0x7e, 0xdb, 0xcd, 0x1b, 0xd8, 0x5a, 0x09}}
	LayerALEEndpointClosureV6           = LayerID{0xbb536ccd, 0x4755, 0x4ba9, [8]byte{0x9f, 0xf7, 0xf9, 0xed, 0xf8, 0x69, 0x9c, 0x7b}}
	LayerALEFlowEstablishedV4           = LayerID{0xaf80470a, 0x5596, 0x4c13, [8]byte{0x99, 0x92, 0x53, 0x9e, 0x6f, 0xe5, 0x79, 0x67}}
	LayerALEFlowEstablishedV4Discard    = LayerID{0x146ae4a9, 0xa1d2, 0x4d43, [8]byte{0xa3, 0x1a, 0x4c, 0x42, 0x68, 0x2b, 0x8e, 0x4f}}
	LayerALEFlowEstablishedV6           = LayerID{0x7021d2b3, 0xdfa4, 0x406e, [8]byte{0xaf, 0xeb, 0x6a, 0xfa, 0xf7, 0xe7, 0x0e, 0xfd}}
	LayerALEFlowEstablishedV6Discard    = LayerID{0x46928636, 0xbbca, 0x4b76, [8]byte{0x94, 0x1d, 0x0f, 0xa7, 0xf5, 0xd7, 0xd3, 0x72}}
	LayerALEResourceAssignmentV4        = LayerID{0x1247d66d, 0x0b60, 0x4a15, [8]byte{0x8d, 0x44, 0x71, 0x55, 0xd0, 0xf5, 0x3a, 0x0c}}
	LayerALEResourceAssignmentV4Discard = LayerID{0x0b5812a2, 0xc3ff, 0x4eca, [8]byte{0xb8, 0x8d, 0xc7, 0x9e, 0x20, 0xac, 0x63, 0x22}}
	LayerALEResourceAssignmentV6        = LayerID{0x55a650e1, 0x5f0a, 0x4eca, [8]byte{0xa6, 0x53, 0x88, 0xf5, 0x3b, 0x26, 0xaa, 0x8c}}
	LayerALEResourceAssignmentV6Discard = LayerID{0xcbc998bb, 0xc51f, 0x4c1a, [8]byte{0xbb, 0x4f, 0x97, 0x75, 0xfc, 0xac, 0xab, 0x2f}}
	LayerALEResourceReleaseV4           = LayerID{0x74365cce, 0xccb0, 0x401a, [8]byte{0xbf, 0xc1, 0xb8, 0x99, 0x34, 0xad, 0x7e, 0x15}}
	LayerALEResourceReleaseV6           = LayerID{0xf4e5ce80, 0xedcc, 0x4e13, [8]byte{0x8a, 0x2f, 0xb9, 0x14, 0x54, 0xbb, 0x05, 0x7b}}
	LayerDatagramDataV4                 = LayerID{0x3d08bf4e, 0x45f6, 0x4930, [8]byte{0xa9, 0x22, 0x41, 0x70, 0x98, 0xe2, 0x00, 0x27}}
	LayerDatagramDataV4Discard          = LayerID{0x18e330c6, 0x7248, 0x4e52, [8]byte{0xaa, 0xab, 0x47, 0x2e, 0xd6, 0x77, 0x04, 0xfd}}
	LayerDatagramDataV6                 = LayerID{0xfa45fe2f, 0x3cba, 0x4427, [8]byte{0x87, 0xfc, 0x57, 0xb9, 0xa4, 0xb1, 0x0d, 0x00}}
	LayerDatagramDataV6Discard          = LayerID{0x09d1dfe1, 0x9b86, 0x4a42, [8]byte{0xbe, 0x9d, 0x8c, 0x31, 0x5b, 0x92, 0xa5, 0xd0}}
	LayerEgressVSwitchEthernet          = LayerID{0x86c872b0, 0x76fa, 0x4b79, [8]byte{0x93, 0xa4, 0x07, 0x50, 0x53, 0x0a, 0xe2, 0x92}}
	LayerEgressVSwitchTransportV4       = LayerID{0xb92350b6, 0x91f0, 0x46b6, [8]byte{0xbd, 0xc4, 0x87, 0x1d, 0xfd, 0x4a, 0x7c, 0x98}}
	LayerEgressVSwitchTransportV6       = LayerID{0x1b2def23, 0x1881, 0x40bd, [8]byte{0x82, 0xf4, 0x42, 0x54, 0xe6, 0x31, 0x41, 0xcb}}
	LayerIKEExtV4                       = LayerID{0xb14b7bdb, 0xdbbd, 0x473e, [8]byte{0xbe, 0xd4, 0x8b, 0x47, 0x08, 0xd4, 0xf2, 0x70}}
	LayerIKEExtV6                       = LayerID{0xb64786b3, 0xf687, 0x4eb9, [8]byte{0x89, 0xd2, 0x8e, 0xf3, 0x2a, 0xcd, 0xab, 0xe2}}
	LayerIPForwardV4                    = LayerID{0xa82acc24, 0x4ee1, 0x4ee1, [8]byte{0xb4, 0x65, 0xfd, 0x1d, 0x25, 0xcb, 0x10, 0xa4}}
	LayerIPForwardV4Discard             = LayerID{0x9e9ea773, 0x2fae, 0x4210, [8]byte{0x8f, 0x17, 0x34, 0x12, 0x9e, 0xf3, 0x69, 0xeb}}
	LayerIPForwardV6                    = LayerID{0x7b964818, 0x19c7, 0x493a, [8]byte{0xb7, 0x1f, 0x83, 0x2c, 0x36, 0x84, 0xd2, 0x8c}}
	LayerIPForwardV6Discard             = LayerID{0x31524a5d, 0x1dfe, 0x472f, [8]byte{0xbb, 0x93, 0x51, 0x8e, 0xe9, 0x45, 0xd8, 0xa2}}
	LayerIPSecKMDemuxV4                 = LayerID{0xf02b1526, 0xa459, 0x4a51, [8]byte{0xb9, 0xe3, 0x75, 0x9d, 0xe5, 0x2b, 0x9d, 0x2c}}
	LayerIPSecKMDemuxV6                 = LayerID{0x2f755cf6, 0x2fd4, 0x4e88, [8]byte{0xb3, 0xe4, 0xa9, 0x1b, 0xca, 0x49, 0x52, 0x35}}
	LayerIPSecV4                        = LayerID{0xeda65c74, 0x610d, 0x4bc5, [8]byte{0x94, 0x8f, 0x3c, 0x4f, 0x89, 0x55, 0x68, 0x67}}
	LayerIPSecV6                        = LayerID{0x13c48442, 0x8d87, 0x4261, [8]byte{0x9a, 0x29, 0x59, 0xd2, 0xab, 0xc3, 0x48, 0xb4}}
	LayerInboundICMPErrorV4             = LayerID{0x61499990, 0x3cb6, 0x4e84, [8]byte{0xb9, 0x50, 0x53, 0xb9, 0x4b, 0x69, 0x64, 0xf3}}
	LayerInboundICMPErrorV4Discard      = LayerID{0xa6b17075, 0xebaf, 0x4053, [8]byte{0xa4, 0xe7, 0x21, 0x3c, 0x81, 0x21, 0xed, 0xe5}}
	LayerInboundICMPErrorV6             = LayerID{0x65f9bdff, 0x3b2d, 0x4e5d, [8]byte{0xb8, 0xc6, 0xc7, 0x20, 0x65, 0x1f, 0xe8, 0x98}}
	LayerInboundICMPErrorV6Discard      = LayerID{0xa6e7ccc0, 0x08fb, 0x468d, [8]byte{0xa4, 0x72, 0x97, 0x71, 0xd5, 0x59, 0x5e, 0x09}}
	LayerInboundIPPacketV4              = LayerID{0xc86fd1bf, 0x21cd, 0x497e, [8]byte{0xa0, 0xbb, 0x17, 0x42, 0x5c, 0x88, 0x5c, 0x58}}
	LayerInboundIPPacketV4Discard       = LayerID{0xb5a230d0, 0xa8c0, 0x44f2, [8]byte{0x91, 0x6e, 0x99, 0x1b, 0x53, 0xde, 0xd1, 0xf7}}
	LayerInboundIPPacketV6              = LayerID{0xf52032cb, 0x991c, 0x46e7, [8]byte{0x97, 0x1d, 0x26, 0x01, 0x45, 0x9a, 0x91, 0xca}}
	LayerInboundIPPacketV6Discard       = LayerID{0xbb24c279, 0x93b4, 0x47a2, [8]byte{0x83, 0xad, 0xae, 0x16, 0x98, 0xb5, 0x08, 0x85}}
	LayerInboundMACFrameEthernet        = LayerID{0xeffb7edb, 0x0055, 0x4f9a, [8]byte{0xa2, 0x31, 0x4f, 0xf8, 0x13, 0x1a, 0xd1, 0x91}}
	LayerInboundMACFrameNative          = LayerID{0xd4220bd3, 0x62ce, 0x4f08, [8]byte{0xae, 0x88, 0xb5, 0x6e, 0x85, 0x26, 0xdf, 0x50}}
	LayerInboundMACFrameNativeFast      = LayerID{0x853aaa8e, 0x2b78, 0x4d24, [8]byte{0xa8, 0x04, 0x36, 0xdb, 0x08, 0xb2, 0x97, 0x11}}
	LayerInboundReserved2               = LayerID{0xf4fb8d55, 0xc076, 0x46d8, [8]byte{0xa2, 0xc7, 0x6a, 0x4c, 0x72, 0x2c, 0xa4, 0xed}}
	LayerInboundTransportFast           = LayerID{0xe41d2719, 0x05c7, 0x40f0, [8]byte{0x89, 0x83, 0xea, 0x8d, 0x17, 0xbb, 0xc2, 0xf6}}
	LayerInboundTransportV4             = LayerID{0x5926dfc8, 0xe3cf, 0x4426, [8]byte{0xa2, 0x83, 0xdc, 0x39, 0x3f, 0x5d, 0x0f, 0x9d}}
	LayerInboundTransportV4Discard      = LayerID{0xac4a9833, 0xf69d, 0x4648, [8]byte{0xb2, 0x61, 0x6d, 0xc8, 0x48, 0x35, 0xef, 0x39}}
	LayerInboundTransportV6             = LayerID{0x634a869f, 0xfc23, 0x4b90, [8]byte{0xb0, 0xc1, 0xbf, 0x62, 0x0a, 0x36, 0xae, 0x6f}}
	LayerInboundTransportV6Discard      = LayerID{0x2a6ff955, 0x3b2b, 0x49d2, [8]byte{0x98, 0x48, 0xad, 0x9d, 0x72, 0xdc, 0xaa, 0xb7}}
	LayerIngressVSwitchEthernet         = LayerID{0x7d98577a, 0x9a87, 0x41ec, [8]byte{0x97, 0x18, 0x7c, 0xf5, 0x89, 0xc9, 0xf3, 0x2d}}
	LayerIngressVSwitchTransportV4      = LayerID{0xb2696ff6, 0x774f, 0x4554, [8]byte{0x9f, 0x7d, 0x3d, 0xa3, 0x94, 0x5f, 0x8e, 0x85}}
	LayerIngressVSwitchTransportV6      = LayerID{0x5ee314fc, 0x7d8a, 0x47f4, [8]byte{0xb7, 0xe3, 0x29, 0x1a, 0x36, 0xda, 0x4e, 0x12}}
	LayerKMAuthorization                = LayerID{0x4aa226e9, 0x9020, 0x45fb, [8]byte{0x95, 0x6a, 0xc0, 0x24, 0x9d, 0x84, 0x11, 0x95}}
	LayerNameResolutionCacheV4          = LayerID{0x0c2aa681, 0x905b, 0x4ccd, [8]byte{0xa4, 0x67, 0x4d, 0xd8, 0x11, 0xd0, 0x7b, 0x7b}}
	LayerNameResolutionCacheV6          = LayerID{0x92d592fa, 0x6b01, 0x434a, [8]byte{0x9d, 0xea, 0xd1, 0xe9, 0x6e, 0xa9, 0x7d, 0xa9}}
	LayerOutboundICMPErrorV4            = LayerID{0x41390100, 0x564c, 0x4b32, [8]byte{0xbc, 0x1d, 0x71, 0x80, 0x48, 0x35, 0x4d, 0x7c}}
	LayerOutboundICMPErrorV4Discard     = LayerID{0xb3598d36, 0x0561, 0x4588, [8]byte{0xa6, 0xbf, 0xe9, 0x55, 0xe3, 0xf6, 0x26, 0x4b}}
	LayerOutboundICMPErrorV6            = LayerID{0x7fb03b60, 0x7b8d, 0x4dfa, [8]byte{0xba, 0xdd, 0x98, 0x01, 0x76, 0xfc, 0x4e, 0x12}}
	LayerOutboundICMPErrorV6Discard     = LayerID{0x65f2e647, 0x8d0c, 0x4f47, [8]byte{0xb1, 0x9b, 0x33, 0xa4, 0xd3, 0xf1, 0x35, 0x7c}}
	LayerOutboundIPPacketV4             = LayerID{0x1e5c9fae, 0x8a84, 0x4135, [8]byte{0xa3, 0x31, 0x95, 0x0b, 0x54, 0x22, 0x9e, 0xcd}}
	LayerOutboundIPPacketV4Discard      = LayerID{0x08e4bcb5, 0xb647, 0x48f3, [8]byte{0x95, 0x3c, 0xe5, 0xdd, 0xbd, 0x03, 0x93, 0x7e}}
	LayerOutboundIPPacketV6             = LayerID{0xa3b3ab6b, 0x3564, 0x488c, [8]byte{0x91, 0x17, 0xf3, 0x4e, 0x82, 0x14, 0x27, 0x63}}
	LayerOutboundIPPacketV6Discard      = LayerID{0x9513d7c4, 0xa934, 0x49dc, [8]byte{0x91, 0xa7, 0x6c, 0xcb, 0x80, 0xcc, 0x02, 0xe3}}
	LayerOutboundMACFrameEthernet       = LayerID{0x694673bc, 0xd6db, 0x4870, [8]byte{0xad, 0xee, 0x0a, 0xcd, 0xbd, 0xb7, 0xf4, 0xb2}}
	LayerOutboundMACFrameNative         = LayerID{0x94c44912, 0x9d6f, 0x4ebf, [8]byte{0xb9, 0x95, 0x05, 0xab, 0x8a, 0x08, 0x8d, 0x1b}}
	LayerOutboundMACFrameNativeFast     = LayerID{0x470df946, 0xc962, 0x486f, [8]byte{0x94, 0x46, 0x82, 0x93, 0xcb, 0xc7, 0x5e, 0xb8}}
	LayerOutboundTransportFast          = LayerID{0x13ed4388, 0xa070, 0x4815, [8]byte{0x99, 0x35, 0x7a, 0x9b, 0xe6, 0x40, 0x8b, 0x78}}
	LayerOutboundTransportV4            = LayerID{0x09e61aea, 0xd214, 0x46e2, [8]byte{0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8}}
	LayerOutboundTransportV4Discard     = LayerID{0xc5f10551, 0xbdb0, 0x43d7, [8]byte{0xa3, 0x13, 0x50, 0xe2, 0x11, 0xf4, 0xd6, 0x8a}}
	LayerOutboundTransportV6            = LayerID{0xe1735bde, 0x013f, 0x4655, [8]byte{0xb3, 0x51, 0xa4, 0x9e, 0x15, 0x76, 0x2d, 0xf0}}
	LayerOutboundTransportV6Discard     = LayerID{0xf433df69, 0xccbd, 0x482e, [8]byte{0xb9, 0xb2, 0x57, 0x16, 0x56, 0x58, 0xc3, 0xb3}}
	LayerRPCEPAdd                       = LayerID{0x618dffc7, 0xc450, 0x4943, [8]byte{0x95, 0xdb, 0x99, 0xb4, 0xc1, 0x6a, 0x55, 0xd4}}
	LayerRPCEPMap                       = LayerID{0x9247bc61, 0xeb07, 0x47ee, [8]byte{0x87, 0x2c, 0xbf, 0xd7, 0x8b, 0xfd, 0x16, 0x16}}
	LayerRPCProxyConn                   = LayerID{0x94a4b50b, 0xba5c, 0x4f27, [8]byte{0x90, 0x7a, 0x22, 0x9f, 0xac, 0x0c, 0x2a, 0x7a}}
	LayerRPCProxyIf                     = LayerID{0xf8a38615, 0xe12c, 0x41ac, [8]byte{0x98, 0xdf, 0x12, 0x1a, 0xd9, 0x81, 0xaa, 0xde}}
	LayerRPCUM                          = LayerID{0x75a89dda, 0x95e4, 0x40f3, [8]byte{0xad, 0xc7, 0x76, 0x88, 0xa9, 0xc8, 0x47, 0xe1}}
	LayerStreamPacketV4                 = LayerID{0xaf52d8ec, 0xcb2d, 0x44e5, [8]byte{0xad, 0x92, 0xf8, 0xdc, 0x38, 0xd2, 0xeb, 0x29}}
	LayerStreamPacketV6                 = LayerID{0x779a8ca3, 0xf099, 0x468f, [8]byte{0xb5, 0xd4, 0x83, 0x53, 0x5c, 0x46, 0x1c, 0x02}}
	LayerStreamV4                       = LayerID{0x3b89653c, 0xc170, 0x49e4, [8]byte{0xb1, 0xcd, 0xe0, 0xee, 0xee, 0xe1, 0x9a, 0x3e}}
	LayerStreamV4Discard                = LayerID{0x25c4c2c2, 0x25ff, 0x4352, [8]byte{0x82, 0xf9, 0xc5, 0x4a, 0x4a, 0x47, 0x26, 0xdc}}
	LayerStreamV6                       = LayerID{0x47c9137a, 0x7ec4, 0x46b3, [8]byte{0xb6, 0xe4, 0x48, 0xe9, 0x26, 0xb1, 0xed, 0xa4}}
	LayerStreamV6Discard                = LayerID{0x10a59fc7, 0xb628, 0x4c41, [8]byte{0x9e, 0xb8, 0xcf, 0x37, 0xd5, 0x51, 0x03, 0xcf}}
)

var (
	guidProviderContextSecureSocketAuthIP = windows.GUID{0xb25ea800, 0x0d02, 0x46ed, [8]byte{0x92, 0xbd, 0x7f, 0xa8, 0x4b, 0xb7, 0x3e, 0x9d}}
	guidProviderContextSecureSocketIPSec  = windows.GUID{0x8c2d4144, 0xf8e0, 0x42c0, [8]byte{0x94, 0xce, 0x7c, 0xcf, 0xc6, 0x3b, 0x2f, 0x9b}}
	guidProviderIKEExt                    = windows.GUID{0x10ad9216, 0xccde, 0x456c, [8]byte{0x8b, 0x16, 0xe9, 0xf0, 0x4e, 0x60, 0xa9, 0x0b}}
	guidProviderIPSecDospConfig           = windows.GUID{0x3c6c05a9, 0xc05c, 0x4bb9, [8]byte{0x83, 0x38, 0x23, 0x27, 0x81, 0x4c, 0xe8, 0xbf}}
	guidProviderTCPChimneyOffload         = windows.GUID{0x896aa19e, 0x9a34, 0x4bcb, [8]byte{0xae, 0x79, 0xbe, 0xb9, 0x12, 0x7c, 0x84, 0xb9}}
	guidProviderTCPTemplates              = windows.GUID{0x76cfcd30, 0x3394, 0x432d, [8]byte{0xbe, 0xd3, 0x44, 0x1a, 0xe5, 0x0e, 0x63, 0xc3}}
)

var (
	guidSublayerIPSecDosp                  = windows.GUID{0xe076d572, 0x5d3d, 0x48ef, [8]byte{0x80, 0x2b, 0x90, 0x9e, 0xdd, 0xb0, 0x98, 0xbd}}
	guidSublayerIPSecForwardOutboundTunnel = windows.GUID{0xa5082e73, 0x8f71, 0x4559, [8]byte{0x8a, 0x9a, 0x10, 0x1c, 0xea, 0x04, 0xef, 0x87}}
	guidSublayerIPSecSecurityRealm         = windows.GUID{0x37a57701, 0x5884, 0x4964, [8]byte{0x92, 0xb8, 0x3e, 0x70, 0x46, 0x88, 0xb0, 0xad}}
	guidSublayerIPSecTunnel                = windows.GUID{0x83f299ed, 0x9ff4, 0x4967, [8]byte{0xaf, 0xf4, 0xc3, 0x09, 0xf4, 0xda, 0xb8, 0x27}}
	guidSublayerInspection                 = windows.GUID{0x877519e1, 0xe6a9, 0x41a5, [8]byte{0x81, 0xb4, 0x8c, 0x4f, 0x11, 0x8e, 0x4a, 0x60}}
	guidSublayerLIPS                       = windows.GUID{0x1b75c0ce, 0xff60, 0x4711, [8]byte{0xa7, 0x0f, 0xb4, 0x95, 0x8c, 0xc3, 0xb2, 0xd0}}
	guidSublayerRPCAudit                   = windows.GUID{0x758c84f4, 0xfb48, 0x4de9, [8]byte{0x9a, 0xeb, 0x3e, 0xd9, 0x55, 0x1a, 0xb1, 0xfd}}
	guidSublayerSecureSocket               = windows.GUID{0x15a66e17, 0x3f3c, 0x4f7b, [8]byte{0xaa, 0x6c, 0x81, 0x2a, 0xa6, 0x13, 0xdd, 0x82}}
	guidSublayerTCPChimneyOffload          = windows.GUID{0x337608b9, 0xb7d5, 0x4d5f, [8]byte{0x82, 0xf9, 0x36, 0x18, 0x61, 0x8b, 0xc0, 0x58}}
	guidSublayerTCPTemplates               = windows.GUID{0x24421dcf, 0x0ac5, 0x4caa, [8]byte{0x9e, 0x14, 0x50, 0xf6, 0xe3, 0x63, 0x6a, 0xf0}}
	guidSublayerTeredo                     = windows.GUID{0xba69dc66, 0x5176, 0x4979, [8]byte{0x9c, 0x89, 0x26, 0xa7, 0xb4, 0x6a, 0x83, 0x27}}
	guidSublayerUniversal                  = windows.GUID{0xeebecc03, 0xced4, 0x4380, [8]byte{0x81, 0x9a, 0x27, 0x34, 0x39, 0x7b, 0x2b, 0x74}}
)

var guidNames = map[windows.GUID]string{
	guidCalloutEdgeTraversalALEListenV4:               "CALLOUT_EDGE_TRAVERSAL_ALE_LISTEN_V4",
	guidCalloutEdgeTraversalALEResourceAssignmentV4:   "CALLOUT_EDGE_TRAVERSAL_ALE_RESOURCE_ASSIGNMENT_V4",
	guidCalloutHttpTemplateSslHandshake:               "CALLOUT_HTTP_TEMPLATE_SSL_HANDSHAKE",
	guidCalloutIPSecALEConnectV4:                      "CALLOUT_IPSEC_ALE_CONNECT_V4",
	guidCalloutIPSecALEConnectV6:                      "CALLOUT_IPSEC_ALE_CONNECT_V6",
	guidCalloutIPSecDospForwardV4:                     "CALLOUT_IPSEC_DOSP_FORWARD_V4",
	guidCalloutIPSecDospForwardV6:                     "CALLOUT_IPSEC_DOSP_FORWARD_V6",
	guidCalloutIPSecForwardInboundTunnelV4:            "CALLOUT_IPSEC_FORWARD_INBOUND_TUNNEL_V4",
	guidCalloutIPSecForwardInboundTunnelV6:            "CALLOUT_IPSEC_FORWARD_INBOUND_TUNNEL_V6",
	guidCalloutIPSecForwardOutboundTunnelV4:           "CALLOUT_IPSEC_FORWARD_OUTBOUND_TUNNEL_V4",
	guidCalloutIPSecForwardOutboundTunnelV6:           "CALLOUT_IPSEC_FORWARD_OUTBOUND_TUNNEL_V6",
	guidCalloutIPSecInboundInitiateSecureV4:           "CALLOUT_IPSEC_INBOUND_INITIATE_SECURE_V4",
	guidCalloutIPSecInboundInitiateSecureV6:           "CALLOUT_IPSEC_INBOUND_INITIATE_SECURE_V6",
	guidCalloutIPSecInboundTransportV4:                "CALLOUT_IPSEC_INBOUND_TRANSPORT_V4",
	guidCalloutIPSecInboundTransportV6:                "CALLOUT_IPSEC_INBOUND_TRANSPORT_V6",
	guidCalloutIPSecInboundTunnelALEAcceptV4:          "CALLOUT_IPSEC_INBOUND_TUNNEL_ALE_ACCEPT_V4",
	guidCalloutIPSecInboundTunnelALEAcceptV6:          "CALLOUT_IPSEC_INBOUND_TUNNEL_ALE_ACCEPT_V6",
	guidCalloutIPSecInboundTunnelV4:                   "CALLOUT_IPSEC_INBOUND_TUNNEL_V4",
	guidCalloutIPSecInboundTunnelV6:                   "CALLOUT_IPSEC_INBOUND_TUNNEL_V6",
	guidCalloutIPSecOutboundTransportV4:               "CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V4",
	guidCalloutIPSecOutboundTransportV6:               "CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V6",
	guidCalloutIPSecOutboundTunnelV4:                  "CALLOUT_IPSEC_OUTBOUND_TUNNEL_V4",
	guidCalloutIPSecOutboundTunnelV6:                  "CALLOUT_IPSEC_OUTBOUND_TUNNEL_V6",
	guidCalloutPolicySilentModeAuthConnectLayerV4:     "CALLOUT_POLICY_SILENT_MODE_AUTH_CONNECT_LAYER_V4",
	guidCalloutPolicySilentModeAuthConnectLayerV6:     "CALLOUT_POLICY_SILENT_MODE_AUTH_CONNECT_LAYER_V6",
	guidCalloutPolicySilentModeAuthRecvAcceptLayerV4:  "CALLOUT_POLICY_SILENT_MODE_AUTH_RECV_ACCEPT_LAYER_V4",
	guidCalloutPolicySilentModeAuthRecvAcceptLayerV6:  "CALLOUT_POLICY_SILENT_MODE_AUTH_RECV_ACCEPT_LAYER_V6",
	guidCalloutReservedAuthConnectLayerV4:             "CALLOUT_RESERVED_AUTH_CONNECT_LAYER_V4",
	guidCalloutReservedAuthConnectLayerV6:             "CALLOUT_RESERVED_AUTH_CONNECT_LAYER_V6",
	guidCalloutSetOptionsAuthConnectLayerV4:           "CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V4",
	guidCalloutSetOptionsAuthConnectLayerV6:           "CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V6",
	guidCalloutSetOptionsAuthRecvAcceptLayerV4:        "CALLOUT_SET_OPTIONS_AUTH_RECV_ACCEPT_LAYER_V4",
	guidCalloutSetOptionsAuthRecvAcceptLayerV6:        "CALLOUT_SET_OPTIONS_AUTH_RECV_ACCEPT_LAYER_V6",
	guidCalloutTCPChimneyAcceptLayerV4:                "CALLOUT_TCP_CHIMNEY_ACCEPT_LAYER_V4",
	guidCalloutTCPChimneyAcceptLayerV6:                "CALLOUT_TCP_CHIMNEY_ACCEPT_LAYER_V6",
	guidCalloutTCPChimneyConnectLayerV4:               "CALLOUT_TCP_CHIMNEY_CONNECT_LAYER_V4",
	guidCalloutTCPChimneyConnectLayerV6:               "CALLOUT_TCP_CHIMNEY_CONNECT_LAYER_V6",
	guidCalloutTCPTemplatesAcceptLayerV4:              "CALLOUT_TCP_TEMPLATES_ACCEPT_LAYER_V4",
	guidCalloutTCPTemplatesAcceptLayerV6:              "CALLOUT_TCP_TEMPLATES_ACCEPT_LAYER_V6",
	guidCalloutTCPTemplatesConnectLayerV4:             "CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V4",
	guidCalloutTCPTemplatesConnectLayerV6:             "CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V6",
	guidCalloutTeredoALEListenV6:                      "CALLOUT_TEREDO_ALE_LISTEN_V6",
	guidCalloutTeredoALEResourceAssignmentV6:          "CALLOUT_TEREDO_ALE_RESOURCE_ASSIGNMENT_V6",
	guidCalloutWFPTransportLayerV4SilentDrop:          "CALLOUT_WFP_TRANSPORT_LAYER_V4_SILENT_DROP",
	guidCalloutWFPTransportLayerV6SilentDrop:          "CALLOUT_WFP_TRANSPORT_LAYER_V6_SILENT_DROP",
	guidConditionALEAppID:                             "CONDITION_ALE_APP_ID",
	guidConditionALEEffectiveName:                     "CONDITION_ALE_EFFECTIVE_NAME",
	guidConditionALENAPContext:                        "CONDITION_ALE_NAP_CONTEXT",
	guidConditionALEOriginalAppID:                     "CONDITION_ALE_ORIGINAL_APP_ID",
	guidConditionALEPackageID:                         "CONDITION_ALE_PACKAGE_ID",
	guidConditionALEPromiscuousMode:                   "CONDITION_ALE_PROMISCUOUS_MODE",
	guidConditionALEReauthReason:                      "CONDITION_ALE_REAUTH_REASON",
	guidConditionALERemoteMachineID:                   "CONDITION_ALE_REMOTE_MACHINE_ID",
	guidConditionALERemoteUserID:                      "CONDITION_ALE_REMOTE_USER_ID",
	guidConditionALESecurityAttributeFqbnValue:        "CONDITION_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE",
	guidConditionALESioFirewallSystemPort:             "CONDITION_ALE_SIO_FIREWALL_SYSTEM_PORT",
	guidConditionALEUserID:                            "CONDITION_ALE_USER_ID",
	guidConditionArrivalInterfaceIndex:                "CONDITION_ARRIVAL_INTERFACE_INDEX",
	guidConditionArrivalInterfaceProfileID:            "CONDITION_ARRIVAL_INTERFACE_PROFILE_ID",
	guidConditionArrivalInterfaceType:                 "CONDITION_ARRIVAL_INTERFACE_TYPE",
	guidConditionArrivalTunnelType:                    "CONDITION_ARRIVAL_TUNNEL_TYPE",
	guidConditionAuthenticationType:                   "CONDITION_AUTHENTICATION_TYPE",
	guidConditionBitmapIndexKey:                       "CONDITION_BITMAP_INDEX_KEY",
	guidConditionBitmapIPLocalAddress:                 "CONDITION_BITMAP_IP_LOCAL_ADDRESS",
	guidConditionBitmapIPLocalPort:                    "CONDITION_BITMAP_IP_LOCAL_PORT",
	guidConditionBitmapIPRemoteAddress:                "CONDITION_BITMAP_IP_REMOTE_ADDRESS",
	guidConditionBitmapIPRemotePort:                   "CONDITION_BITMAP_IP_REMOTE_PORT",
	guidConditionClientCertKeyLength:                  "CONDITION_CLIENT_CERT_KEY_LENGTH",
	guidConditionClientCertOid:                        "CONDITION_CLIENT_CERT_OID",
	guidConditionClientToken:                          "CONDITION_CLIENT_TOKEN",
	guidConditionCompartmentID:                        "CONDITION_COMPARTMENT_ID",
	guidConditionCurrentProfileID:                     "CONDITION_CURRENT_PROFILE_ID",
	guidConditionDCOMAppID:                            "CONDITION_DCOM_APP_ID",
	guidConditionDestinationInterfaceIndex:            "CONDITION_DESTINATION_INTERFACE_INDEX",
	guidConditionDestinationSubInterfaceIndex:         "CONDITION_DESTINATION_SUB_INTERFACE_INDEX",
	guidConditionDirection:                            "CONDITION_DIRECTION",
	guidConditionEmbeddedLocalAddressType:             "CONDITION_EMBEDDED_LOCAL_ADDRESS_TYPE",
	guidConditionEmbeddedLocalPort:                    "CONDITION_EMBEDDED_LOCAL_PORT",
	guidConditionEmbeddedProtocol:                     "CONDITION_EMBEDDED_PROTOCOL",
	guidConditionEmbeddedRemoteAddress:                "CONDITION_EMBEDDED_REMOTE_ADDRESS",
	guidConditionEmbeddedRemotePort:                   "CONDITION_EMBEDDED_REMOTE_PORT",
	guidConditionEtherType:                            "CONDITION_ETHER_TYPE",
	guidConditionFlags:                                "CONDITION_FLAGS",
	guidConditionImageName:                            "CONDITION_IMAGE_NAME",
	guidConditionInterfaceIndex:                       "CONDITION_INTERFACE_INDEX",
	guidConditionInterfaceMACAddress:                  "CONDITION_INTERFACE_MAC_ADDRESS",
	guidConditionInterfaceQuarantineEpoch:             "CONDITION_INTERFACE_QUARANTINE_EPOCH",
	guidConditionInterfaceType:                        "CONDITION_INTERFACE_TYPE",
	guidConditionIPSecPolicyKey:                       "CONDITION_IPSEC_POLICY_KEY",
	guidConditionIPSecSecurityRealmID:                 "CONDITION_IPSEC_SECURITY_REALM_ID",
	guidConditionIPArrivalInterface:                   "CONDITION_IP_ARRIVAL_INTERFACE",
	guidConditionIPDestinationAddress:                 "CONDITION_IP_DESTINATION_ADDRESS",
	guidConditionIPDestinationAddressType:             "CONDITION_IP_DESTINATION_ADDRESS_TYPE",
	guidConditionIPDestinationPort:                    "CONDITION_IP_DESTINATION_PORT",
	guidConditionIPForwardInterface:                   "CONDITION_IP_FORWARD_INTERFACE",
	guidConditionIPLocalAddress:                       "CONDITION_IP_LOCAL_ADDRESS",
	guidConditionIPLocalAddressType:                   "CONDITION_IP_LOCAL_ADDRESS_TYPE",
	guidConditionIPLocalAddressV4:                     "CONDITION_IP_LOCAL_ADDRESS_V4",
	guidConditionIPLocalAddressV6:                     "CONDITION_IP_LOCAL_ADDRESS_V6",
	guidConditionIPLocalInterface:                     "CONDITION_IP_LOCAL_INTERFACE",
	guidConditionIPLocalPort:                          "CONDITION_IP_LOCAL_PORT",
	guidConditionIPNexthopAddress:                     "CONDITION_IP_NEXTHOP_ADDRESS",
	guidConditionIPNexthopInterface:                   "CONDITION_IP_NEXTHOP_INTERFACE",
	guidConditionIPPhysicalArrivalInterface:           "CONDITION_IP_PHYSICAL_ARRIVAL_INTERFACE",
	guidConditionIPPhysicalNexthopInterface:           "CONDITION_IP_PHYSICAL_NEXTHOP_INTERFACE",
	guidConditionIPProtocol:                           "CONDITION_IP_PROTOCOL",
	guidConditionIPRemoteAddress:                      "CONDITION_IP_REMOTE_ADDRESS",
	guidConditionIPRemoteAddressV4:                    "CONDITION_IP_REMOTE_ADDRESS_V4",
	guidConditionIPRemoteAddressV6:                    "CONDITION_IP_REMOTE_ADDRESS_V6",
	guidConditionIPRemotePort:                         "CONDITION_IP_REMOTE_PORT",
	guidConditionIPSourceAddress:                      "CONDITION_IP_SOURCE_ADDRESS",
	guidConditionIPSourcePort:                         "CONDITION_IP_SOURCE_PORT",
	guidConditionKMAuthNAPContext:                     "CONDITION_KM_AUTH_NAP_CONTEXT",
	guidConditionKMMode:                               "CONDITION_KM_MODE",
	guidConditionKMType:                               "CONDITION_KM_TYPE",
	guidConditionL2Flags:                              "CONDITION_L2_FLAGS",
	guidConditionLocalInterfaceProfileID:              "CONDITION_LOCAL_INTERFACE_PROFILE_ID",
	guidConditionMACDestinationAddress:                "CONDITION_MAC_DESTINATION_ADDRESS",
	guidConditionMACDestinationAddressType:            "CONDITION_MAC_DESTINATION_ADDRESS_TYPE",
	guidConditionMACLocalAddress:                      "CONDITION_MAC_LOCAL_ADDRESS",
	guidConditionMACLocalAddressType:                  "CONDITION_MAC_LOCAL_ADDRESS_TYPE",
	guidConditionMACRemoteAddress:                     "CONDITION_MAC_REMOTE_ADDRESS",
	guidConditionMACRemoteAddressType:                 "CONDITION_MAC_REMOTE_ADDRESS_TYPE",
	guidConditionMACSourceAddress:                     "CONDITION_MAC_SOURCE_ADDRESS",
	guidConditionMACSourceAddressType:                 "CONDITION_MAC_SOURCE_ADDRESS_TYPE",
	guidConditionNdisMediaType:                        "CONDITION_NDIS_MEDIA_TYPE",
	guidConditionNdisPhysicalMediaType:                "CONDITION_NDIS_PHYSICAL_MEDIA_TYPE",
	guidConditionNdisPort:                             "CONDITION_NDIS_PORT",
	guidConditionNetEventType:                         "CONDITION_NET_EVENT_TYPE",
	guidConditionNexthopInterfaceIndex:                "CONDITION_NEXTHOP_INTERFACE_INDEX",
	guidConditionNexthopInterfaceProfileID:            "CONDITION_NEXTHOP_INTERFACE_PROFILE_ID",
	guidConditionNexthopInterfaceType:                 "CONDITION_NEXTHOP_INTERFACE_TYPE",
	guidConditionNexthopSubInterfaceIndex:             "CONDITION_NEXTHOP_SUB_INTERFACE_INDEX",
	guidConditionNexthopTunnelType:                    "CONDITION_NEXTHOP_TUNNEL_TYPE",
	guidConditionOriginalICMPType:                     "CONDITION_ORIGINAL_ICMP_TYPE",
	guidConditionOriginalProfileID:                    "CONDITION_ORIGINAL_PROFILE_ID",
	guidConditionPeerName:                             "CONDITION_PEER_NAME",
	guidConditionPipe:                                 "CONDITION_PIPE",
	guidConditionProcessWithRPCIfUUID:                 "CONDITION_PROCESS_WITH_RPC_IF_UUID",
	guidConditionQMMode:                               "CONDITION_QM_MODE",
	guidConditionReauthorizeReason:                    "CONDITION_REAUTHORIZE_REASON",
	guidConditionRemoteID:                             "CONDITION_REMOTE_ID",
	guidConditionRemoteUserToken:                      "CONDITION_REMOTE_USER_TOKEN",
	guidConditionReserved0:                            "CONDITION_RESERVED0",
	guidConditionReserved1:                            "CONDITION_RESERVED1",
	guidConditionReserved10:                           "CONDITION_RESERVED10",
	guidConditionReserved11:                           "CONDITION_RESERVED11",
	guidConditionReserved12:                           "CONDITION_RESERVED12",
	guidConditionReserved13:                           "CONDITION_RESERVED13",
	guidConditionReserved14:                           "CONDITION_RESERVED14",
	guidConditionReserved15:                           "CONDITION_RESERVED15",
	guidConditionReserved2:                            "CONDITION_RESERVED2",
	guidConditionReserved3:                            "CONDITION_RESERVED3",
	guidConditionReserved4:                            "CONDITION_RESERVED4",
	guidConditionReserved5:                            "CONDITION_RESERVED5",
	guidConditionReserved6:                            "CONDITION_RESERVED6",
	guidConditionReserved7:                            "CONDITION_RESERVED7",
	guidConditionReserved8:                            "CONDITION_RESERVED8",
	guidConditionReserved9:                            "CONDITION_RESERVED9",
	guidConditionRPCAuthLevel:                         "CONDITION_RPC_AUTH_LEVEL",
	guidConditionRPCAuthType:                          "CONDITION_RPC_AUTH_TYPE",
	guidConditionRPCEPFlags:                           "CONDITION_RPC_EP_FLAGS",
	guidConditionRPCEPValue:                           "CONDITION_RPC_EP_VALUE",
	guidConditionRPCIfFlag:                            "CONDITION_RPC_IF_FLAG",
	guidConditionRPCIfUUID:                            "CONDITION_RPC_IF_UUID",
	guidConditionRPCIfVersion:                         "CONDITION_RPC_IF_VERSION",
	guidConditionRPCProtocol:                          "CONDITION_RPC_PROTOCOL",
	guidConditionRPCProxyAuthType:                     "CONDITION_RPC_PROXY_AUTH_TYPE",
	guidConditionRPCServerName:                        "CONDITION_RPC_SERVER_NAME",
	guidConditionRPCServerPort:                        "CONDITION_RPC_SERVER_PORT",
	guidConditionSecEncryptAlgorithm:                  "CONDITION_SEC_ENCRYPT_ALGORITHM",
	guidConditionSecKeySize:                           "CONDITION_SEC_KEY_SIZE",
	guidConditionSourceInterfaceIndex:                 "CONDITION_SOURCE_INTERFACE_INDEX",
	guidConditionSourceSubInterfaceIndex:              "CONDITION_SOURCE_SUB_INTERFACE_INDEX",
	guidConditionSubInterfaceIndex:                    "CONDITION_SUB_INTERFACE_INDEX",
	guidConditionTunnelType:                           "CONDITION_TUNNEL_TYPE",
	guidConditionVLANID:                               "CONDITION_VLAN_ID",
	guidConditionVSwitchDestinationInterfaceID:        "CONDITION_VSWITCH_DESTINATION_INTERFACE_ID",
	guidConditionVSwitchDestinationInterfaceType:      "CONDITION_VSWITCH_DESTINATION_INTERFACE_TYPE",
	guidConditionVSwitchDestinationVmID:               "CONDITION_VSWITCH_DESTINATION_VM_ID",
	guidConditionVSwitchID:                            "CONDITION_VSWITCH_ID",
	guidConditionVSwitchNetworkType:                   "CONDITION_VSWITCH_NETWORK_TYPE",
	guidConditionVSwitchSourceInterfaceID:             "CONDITION_VSWITCH_SOURCE_INTERFACE_ID",
	guidConditionVSwitchSourceInterfaceType:           "CONDITION_VSWITCH_SOURCE_INTERFACE_TYPE",
	guidConditionVSwitchSourceVmID:                    "CONDITION_VSWITCH_SOURCE_VM_ID",
	guidConditionVSwitchTenantNetworkID:               "CONDITION_VSWITCH_TENANT_NETWORK_ID",
	guidKeyingModuleAuthIP:                            "KEYING_MODULE_AUTHIP",
	guidKeyingModuleIKE:                               "KEYING_MODULE_IKE",
	guidKeyingModuleIKEv2:                             "KEYING_MODULE_IKEV2",
	windows.GUID(LayerALEAuthConnectV4):               "ALE_AUTH_CONNECT_V4",
	windows.GUID(LayerALEAuthConnectV4Discard):        "ALE_AUTH_CONNECT_V4_DISCARD",
	windows.GUID(LayerALEAuthConnectV6):               "ALE_AUTH_CONNECT_V6",
	windows.GUID(LayerALEAuthConnectV6Discard):        "ALE_AUTH_CONNECT_V6_DISCARD",
	windows.GUID(LayerALEAuthListenV4):                "ALE_AUTH_LISTEN_V4",
	windows.GUID(LayerALEAuthListenV4Discard):         "ALE_AUTH_LISTEN_V4_DISCARD",
	windows.GUID(LayerALEAuthListenV6):                "ALE_AUTH_LISTEN_V6",
	windows.GUID(LayerALEAuthListenV6Discard):         "ALE_AUTH_LISTEN_V6_DISCARD",
	windows.GUID(LayerALEAuthRecvAcceptV4):            "ALE_AUTH_RECV_ACCEPT_V4",
	windows.GUID(LayerALEAuthRecvAcceptV4Discard):     "ALE_AUTH_RECV_ACCEPT_V4_DISCARD",
	windows.GUID(LayerALEAuthRecvAcceptV6):            "ALE_AUTH_RECV_ACCEPT_V6",
	windows.GUID(LayerALEAuthRecvAcceptV6Discard):     "ALE_AUTH_RECV_ACCEPT_V6_DISCARD",
	windows.GUID(LayerALEBindRedirectV4):              "ALE_BIND_REDIRECT_V4",
	windows.GUID(LayerALEBindRedirectV6):              "ALE_BIND_REDIRECT_V6",
	windows.GUID(LayerALEConnectRedirectV4):           "ALE_CONNECT_REDIRECT_V4",
	windows.GUID(LayerALEConnectRedirectV6):           "ALE_CONNECT_REDIRECT_V6",
	windows.GUID(LayerALEEndpointClosureV4):           "ALE_ENDPOINT_CLOSURE_V4",
	windows.GUID(LayerALEEndpointClosureV6):           "ALE_ENDPOINT_CLOSURE_V6",
	windows.GUID(LayerALEFlowEstablishedV4):           "ALE_FLOW_ESTABLISHED_V4",
	windows.GUID(LayerALEFlowEstablishedV4Discard):    "ALE_FLOW_ESTABLISHED_V4_DISCARD",
	windows.GUID(LayerALEFlowEstablishedV6):           "ALE_FLOW_ESTABLISHED_V6",
	windows.GUID(LayerALEFlowEstablishedV6Discard):    "ALE_FLOW_ESTABLISHED_V6_DISCARD",
	windows.GUID(LayerALEResourceAssignmentV4):        "ALE_RESOURCE_ASSIGNMENT_V4",
	windows.GUID(LayerALEResourceAssignmentV4Discard): "ALE_RESOURCE_ASSIGNMENT_V4_DISCARD",
	windows.GUID(LayerALEResourceAssignmentV6):        "ALE_RESOURCE_ASSIGNMENT_V6",
	windows.GUID(LayerALEResourceAssignmentV6Discard): "ALE_RESOURCE_ASSIGNMENT_V6_DISCARD",
	windows.GUID(LayerALEResourceReleaseV4):           "ALE_RESOURCE_RELEASE_V4",
	windows.GUID(LayerALEResourceReleaseV6):           "ALE_RESOURCE_RELEASE_V6",
	windows.GUID(LayerDatagramDataV4):                 "DATAGRAM_DATA_V4",
	windows.GUID(LayerDatagramDataV4Discard):          "DATAGRAM_DATA_V4_DISCARD",
	windows.GUID(LayerDatagramDataV6):                 "DATAGRAM_DATA_V6",
	windows.GUID(LayerDatagramDataV6Discard):          "DATAGRAM_DATA_V6_DISCARD",
	windows.GUID(LayerEgressVSwitchEthernet):          "EGRESS_VSWITCH_ETHERNET",
	windows.GUID(LayerEgressVSwitchTransportV4):       "EGRESS_VSWITCH_TRANSPORT_V4",
	windows.GUID(LayerEgressVSwitchTransportV6):       "EGRESS_VSWITCH_TRANSPORT_V6",
	windows.GUID(LayerIKEExtV4):                       "IKEEXT_V4",
	windows.GUID(LayerIKEExtV6):                       "IKEEXT_V6",
	windows.GUID(LayerInboundICMPErrorV4):             "INBOUND_ICMP_ERROR_V4",
	windows.GUID(LayerInboundICMPErrorV4Discard):      "INBOUND_ICMP_ERROR_V4_DISCARD",
	windows.GUID(LayerInboundICMPErrorV6):             "INBOUND_ICMP_ERROR_V6",
	windows.GUID(LayerInboundICMPErrorV6Discard):      "INBOUND_ICMP_ERROR_V6_DISCARD",
	windows.GUID(LayerInboundIPPacketV4):              "INBOUND_IPPACKET_V4",
	windows.GUID(LayerInboundIPPacketV4Discard):       "INBOUND_IPPACKET_V4_DISCARD",
	windows.GUID(LayerInboundIPPacketV6):              "INBOUND_IPPACKET_V6",
	windows.GUID(LayerInboundIPPacketV6Discard):       "INBOUND_IPPACKET_V6_DISCARD",
	windows.GUID(LayerInboundMACFrameEthernet):        "INBOUND_MAC_FRAME_ETHERNET",
	windows.GUID(LayerInboundMACFrameNative):          "INBOUND_MAC_FRAME_NATIVE",
	windows.GUID(LayerInboundMACFrameNativeFast):      "INBOUND_MAC_FRAME_NATIVE_FAST",
	windows.GUID(LayerInboundReserved2):               "INBOUND_RESERVED2",
	windows.GUID(LayerInboundTransportFast):           "INBOUND_TRANSPORT_FAST",
	windows.GUID(LayerInboundTransportV4):             "INBOUND_TRANSPORT_V4",
	windows.GUID(LayerInboundTransportV4Discard):      "INBOUND_TRANSPORT_V4_DISCARD",
	windows.GUID(LayerInboundTransportV6):             "INBOUND_TRANSPORT_V6",
	windows.GUID(LayerInboundTransportV6Discard):      "INBOUND_TRANSPORT_V6_DISCARD",
	windows.GUID(LayerIngressVSwitchEthernet):         "INGRESS_VSWITCH_ETHERNET",
	windows.GUID(LayerIngressVSwitchTransportV4):      "INGRESS_VSWITCH_TRANSPORT_V4",
	windows.GUID(LayerIngressVSwitchTransportV6):      "INGRESS_VSWITCH_TRANSPORT_V6",
	windows.GUID(LayerIPForwardV4):                    "IPFORWARD_V4",
	windows.GUID(LayerIPForwardV4Discard):             "IPFORWARD_V4_DISCARD",
	windows.GUID(LayerIPForwardV6):                    "IPFORWARD_V6",
	windows.GUID(LayerIPForwardV6Discard):             "IPFORWARD_V6_DISCARD",
	windows.GUID(LayerIPSecKMDemuxV4):                 "IPSEC_KM_DEMUX_V4",
	windows.GUID(LayerIPSecKMDemuxV6):                 "IPSEC_KM_DEMUX_V6",
	windows.GUID(LayerIPSecV4):                        "IPSEC_V4",
	windows.GUID(LayerIPSecV6):                        "IPSEC_V6",
	windows.GUID(LayerKMAuthorization):                "KM_AUTHORIZATION",
	windows.GUID(LayerNameResolutionCacheV4):          "NAME_RESOLUTION_CACHE_V4",
	windows.GUID(LayerNameResolutionCacheV6):          "NAME_RESOLUTION_CACHE_V6",
	windows.GUID(LayerOutboundICMPErrorV4):            "OUTBOUND_ICMP_ERROR_V4",
	windows.GUID(LayerOutboundICMPErrorV4Discard):     "OUTBOUND_ICMP_ERROR_V4_DISCARD",
	windows.GUID(LayerOutboundICMPErrorV6):            "OUTBOUND_ICMP_ERROR_V6",
	windows.GUID(LayerOutboundICMPErrorV6Discard):     "OUTBOUND_ICMP_ERROR_V6_DISCARD",
	windows.GUID(LayerOutboundIPPacketV4):             "OUTBOUND_IPPACKET_V4",
	windows.GUID(LayerOutboundIPPacketV4Discard):      "OUTBOUND_IPPACKET_V4_DISCARD",
	windows.GUID(LayerOutboundIPPacketV6):             "OUTBOUND_IPPACKET_V6",
	windows.GUID(LayerOutboundIPPacketV6Discard):      "OUTBOUND_IPPACKET_V6_DISCARD",
	windows.GUID(LayerOutboundMACFrameEthernet):       "OUTBOUND_MAC_FRAME_ETHERNET",
	windows.GUID(LayerOutboundMACFrameNative):         "OUTBOUND_MAC_FRAME_NATIVE",
	windows.GUID(LayerOutboundMACFrameNativeFast):     "OUTBOUND_MAC_FRAME_NATIVE_FAST",
	windows.GUID(LayerOutboundTransportFast):          "OUTBOUND_TRANSPORT_FAST",
	windows.GUID(LayerOutboundTransportV4):            "OUTBOUND_TRANSPORT_V4",
	windows.GUID(LayerOutboundTransportV4Discard):     "OUTBOUND_TRANSPORT_V4_DISCARD",
	windows.GUID(LayerOutboundTransportV6):            "OUTBOUND_TRANSPORT_V6",
	windows.GUID(LayerOutboundTransportV6Discard):     "OUTBOUND_TRANSPORT_V6_DISCARD",
	windows.GUID(LayerRPCEPMap):                       "RPC_EPMAP",
	windows.GUID(LayerRPCEPAdd):                       "RPC_EP_ADD",
	windows.GUID(LayerRPCProxyConn):                   "RPC_PROXY_CONN",
	windows.GUID(LayerRPCProxyIf):                     "RPC_PROXY_IF",
	windows.GUID(LayerRPCUM):                          "RPC_UM",
	windows.GUID(LayerStreamPacketV4):                 "STREAM_PACKET_V4",
	windows.GUID(LayerStreamPacketV6):                 "STREAM_PACKET_V6",
	windows.GUID(LayerStreamV4):                       "STREAM_V4",
	windows.GUID(LayerStreamV4Discard):                "STREAM_V4_DISCARD",
	windows.GUID(LayerStreamV6):                       "STREAM_V6",
	windows.GUID(LayerStreamV6Discard):                "STREAM_V6_DISCARD",
	guidProviderContextSecureSocketAuthIP:             "PROVIDER_CONTEXT_SECURE_SOCKET_AUTHIP",
	guidProviderContextSecureSocketIPSec:              "PROVIDER_CONTEXT_SECURE_SOCKET_IPSEC",
	guidProviderIKEExt:                                "PROVIDER_IKEEXT",
	guidProviderIPSecDospConfig:                       "PROVIDER_IPSEC_DOSP_CONFIG",
	guidProviderTCPChimneyOffload:                     "PROVIDER_TCP_CHIMNEY_OFFLOAD",
	guidProviderTCPTemplates:                          "PROVIDER_TCP_TEMPLATES",
	guidSublayerInspection:                            "SUBLAYER_INSPECTION",
	guidSublayerIPSecDosp:                             "SUBLAYER_IPSEC_DOSP",
	guidSublayerIPSecForwardOutboundTunnel:            "SUBLAYER_IPSEC_FORWARD_OUTBOUND_TUNNEL",
	guidSublayerIPSecSecurityRealm:                    "SUBLAYER_IPSEC_SECURITY_REALM",
	guidSublayerIPSecTunnel:                           "SUBLAYER_IPSEC_TUNNEL",
	guidSublayerLIPS:                                  "SUBLAYER_LIPS",
	guidSublayerRPCAudit:                              "SUBLAYER_RPC_AUDIT",
	guidSublayerSecureSocket:                          "SUBLAYER_SECURE_SOCKET",
	guidSublayerTCPChimneyOffload:                     "SUBLAYER_TCP_CHIMNEY_OFFLOAD",
	guidSublayerTCPTemplates:                          "SUBLAYER_TCP_TEMPLATES",
	guidSublayerTeredo:                                "SUBLAYER_TEREDO",
	guidSublayerUniversal:                             "SUBLAYER_UNIVERSAL",
}
