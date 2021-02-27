package winfirewall

import "golang.org/x/sys/windows"

var guidLayerInboundIPPacketV4 = windows.GUID{
Data1: 0xc86fd1bf,
Data2: 0x21cd,
Data3: 0x497e,
Data4: [8]byte{0xa0, 0xbb, 0x17, 0x42, 0x5c, 0x88, 0x5c, 0x58},
}

var guidLayerInboundIPPacketV4Discard = windows.GUID{
Data1: 0xb5a230d0,
Data2: 0xa8c0,
Data3: 0x44f2,
Data4: [8]byte{0x91, 0x6e, 0x99, 0x1b, 0x53, 0xde, 0xd1, 0xf7},
}

var guidLayerInboundIPPacketV6 = windows.GUID{
Data1: 0xf52032cb,
Data2: 0x991c,
Data3: 0x46e7,
Data4: [8]byte{0x97, 0x1d, 0x26, 0x01, 0x45, 0x9a, 0x91, 0xca},
}

var guidLayerInboundIPPacketV6Discard = windows.GUID{
Data1: 0xbb24c279,
Data2: 0x93b4,
Data3: 0x47a2,
Data4: [8]byte{0x83, 0xad, 0xae, 0x16, 0x98, 0xb5, 0x08, 0x85},
}

var guidLayerOutboundIPPacketV4 = windows.GUID{
Data1: 0x1e5c9fae,
Data2: 0x8a84,
Data3: 0x4135,
Data4: [8]byte{0xa3, 0x31, 0x95, 0x0b, 0x54, 0x22, 0x9e, 0xcd},
}

var guidLayerOutboundIPPacketV4Discard = windows.GUID{
Data1: 0x08e4bcb5,
Data2: 0xb647,
Data3: 0x48f3,
Data4: [8]byte{0x95, 0x3c, 0xe5, 0xdd, 0xbd, 0x03, 0x93, 0x7e},
}

var guidLayerOutboundIPPacketV6 = windows.GUID{
Data1: 0xa3b3ab6b,
Data2: 0x3564,
Data3: 0x488c,
Data4: [8]byte{0x91, 0x17, 0xf3, 0x4e, 0x82, 0x14, 0x27, 0x63},
}

var guidLayerOutboundIPPacketV6Discard = windows.GUID{
Data1: 0x9513d7c4,
Data2: 0xa934,
Data3: 0x49dc,
Data4: [8]byte{0x91, 0xa7, 0x6c, 0xcb, 0x80, 0xcc, 0x02, 0xe3},
}

var guidLayerIPForwardV4 = windows.GUID{
Data1: 0xa82acc24,
Data2: 0x4ee1,
Data3: 0x4ee1,
Data4: [8]byte{0xb4, 0x65, 0xfd, 0x1d, 0x25, 0xcb, 0x10, 0xa4},
}

var guidLayerIPForwardV4Discard = windows.GUID{
Data1: 0x9e9ea773,
Data2: 0x2fae,
Data3: 0x4210,
Data4: [8]byte{0x8f, 0x17, 0x34, 0x12, 0x9e, 0xf3, 0x69, 0xeb},
}

var guidLayerIPForwardV6 = windows.GUID{
Data1: 0x7b964818,
Data2: 0x19c7,
Data3: 0x493a,
Data4: [8]byte{0xb7, 0x1f, 0x83, 0x2c, 0x36, 0x84, 0xd2, 0x8c},
}

var guidLayerIPForwardV6Discard = windows.GUID{
Data1: 0x31524a5d,
Data2: 0x1dfe,
Data3: 0x472f,
Data4: [8]byte{0xbb, 0x93, 0x51, 0x8e, 0xe9, 0x45, 0xd8, 0xa2},
}

var guidLayerInboundTransportV4 = windows.GUID{
Data1: 0x5926dfc8,
Data2: 0xe3cf,
Data3: 0x4426,
Data4: [8]byte{0xa2, 0x83, 0xdc, 0x39, 0x3f, 0x5d, 0x0f, 0x9d},
}

var guidLayerInboundTransportV4Discard = windows.GUID{
Data1: 0xac4a9833,
Data2: 0xf69d,
Data3: 0x4648,
Data4: [8]byte{0xb2, 0x61, 0x6d, 0xc8, 0x48, 0x35, 0xef, 0x39},
}

var guidLayerInboundTransportV6 = windows.GUID{
Data1: 0x634a869f,
Data2: 0xfc23,
Data3: 0x4b90,
Data4: [8]byte{0xb0, 0xc1, 0xbf, 0x62, 0x0a, 0x36, 0xae, 0x6f},
}

var guidLayerInboundTransportV6Discard = windows.GUID{
Data1: 0x2a6ff955,
Data2: 0x3b2b,
Data3: 0x49d2,
Data4: [8]byte{0x98, 0x48, 0xad, 0x9d, 0x72, 0xdc, 0xaa, 0xb7},
}

var guidLayerOutboundTransportV4 = windows.GUID{
Data1: 0x09e61aea,
Data2: 0xd214,
Data3: 0x46e2,
Data4: [8]byte{0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8},
}

var guidLayerOutboundTransportV4Discard = windows.GUID{
Data1: 0xc5f10551,
Data2: 0xbdb0,
Data3: 0x43d7,
Data4: [8]byte{0xa3, 0x13, 0x50, 0xe2, 0x11, 0xf4, 0xd6, 0x8a},
}

var guidLayerOutboundTransportV6 = windows.GUID{
Data1: 0xe1735bde,
Data2: 0x013f,
Data3: 0x4655,
Data4: [8]byte{0xb3, 0x51, 0xa4, 0x9e, 0x15, 0x76, 0x2d, 0xf0},
}

var guidLayerOutboundTransportV6Discard = windows.GUID{
Data1: 0xf433df69,
Data2: 0xccbd,
Data3: 0x482e,
Data4: [8]byte{0xb9, 0xb2, 0x57, 0x16, 0x56, 0x58, 0xc3, 0xb3},
}

var guidLayerStreamV4 = windows.GUID{
Data1: 0x3b89653c,
Data2: 0xc170,
Data3: 0x49e4,
Data4: [8]byte{0xb1, 0xcd, 0xe0, 0xee, 0xee, 0xe1, 0x9a, 0x3e},
}

var guidLayerStreamV4Discard = windows.GUID{
Data1: 0x25c4c2c2,
Data2: 0x25ff,
Data3: 0x4352,
Data4: [8]byte{0x82, 0xf9, 0xc5, 0x4a, 0x4a, 0x47, 0x26, 0xdc},
}

var guidLayerStreamV6 = windows.GUID{
Data1: 0x47c9137a,
Data2: 0x7ec4,
Data3: 0x46b3,
Data4: [8]byte{0xb6, 0xe4, 0x48, 0xe9, 0x26, 0xb1, 0xed, 0xa4},
}

var guidLayerStreamV6Discard = windows.GUID{
Data1: 0x10a59fc7,
Data2: 0xb628,
Data3: 0x4c41,
Data4: [8]byte{0x9e, 0xb8, 0xcf, 0x37, 0xd5, 0x51, 0x03, 0xcf},
}

var guidLayerDatagramDataV4 = windows.GUID{
Data1: 0x3d08bf4e,
Data2: 0x45f6,
Data3: 0x4930,
Data4: [8]byte{0xa9, 0x22, 0x41, 0x70, 0x98, 0xe2, 0x00, 0x27},
}

var guidLayerDatagramDataV4Discard = windows.GUID{
Data1: 0x18e330c6,
Data2: 0x7248,
Data3: 0x4e52,
Data4: [8]byte{0xaa, 0xab, 0x47, 0x2e, 0xd6, 0x77, 0x04, 0xfd},
}

var guidLayerDatagramDataV6 = windows.GUID{
Data1: 0xfa45fe2f,
Data2: 0x3cba,
Data3: 0x4427,
Data4: [8]byte{0x87, 0xfc, 0x57, 0xb9, 0xa4, 0xb1, 0x0d, 0x00},
}

var guidLayerDatagramDataV6Discard = windows.GUID{
Data1: 0x09d1dfe1,
Data2: 0x9b86,
Data3: 0x4a42,
Data4: [8]byte{0xbe, 0x9d, 0x8c, 0x31, 0x5b, 0x92, 0xa5, 0xd0},
}

var guidLayerInboundICMPErrorV4 = windows.GUID{
Data1: 0x61499990,
Data2: 0x3cb6,
Data3: 0x4e84,
Data4: [8]byte{0xb9, 0x50, 0x53, 0xb9, 0x4b, 0x69, 0x64, 0xf3},
}

var guidLayerInboundICMPErrorV4Discard = windows.GUID{
Data1: 0xa6b17075,
Data2: 0xebaf,
Data3: 0x4053,
Data4: [8]byte{0xa4, 0xe7, 0x21, 0x3c, 0x81, 0x21, 0xed, 0xe5},
}

var guidLayerInboundICMPErrorV6 = windows.GUID{
Data1: 0x65f9bdff,
Data2: 0x3b2d,
Data3: 0x4e5d,
Data4: [8]byte{0xb8, 0xc6, 0xc7, 0x20, 0x65, 0x1f, 0xe8, 0x98},
}

var guidLayerInboundICMPErrorV6Discard = windows.GUID{
Data1: 0xa6e7ccc0,
Data2: 0x08fb,
Data3: 0x468d,
Data4: [8]byte{0xa4, 0x72, 0x97, 0x71, 0xd5, 0x59, 0x5e, 0x09},
}

var guidLayerOutboundICMPErrorV4 = windows.GUID{
Data1: 0x41390100,
Data2: 0x564c,
Data3: 0x4b32,
Data4: [8]byte{0xbc, 0x1d, 0x71, 0x80, 0x48, 0x35, 0x4d, 0x7c},
}

var guidLayerOutboundICMPErrorV4Discard = windows.GUID{
Data1: 0xb3598d36,
Data2: 0x0561,
Data3: 0x4588,
Data4: [8]byte{0xa6, 0xbf, 0xe9, 0x55, 0xe3, 0xf6, 0x26, 0x4b},
}

var guidLayerOutboundICMPErrorV6 = windows.GUID{
Data1: 0x7fb03b60,
Data2: 0x7b8d,
Data3: 0x4dfa,
Data4: [8]byte{0xba, 0xdd, 0x98, 0x01, 0x76, 0xfc, 0x4e, 0x12},
}

var guidLayerOutboundICMPErrorV6Discard = windows.GUID{
Data1: 0x65f2e647,
Data2: 0x8d0c,
Data3: 0x4f47,
Data4: [8]byte{0xb1, 0x9b, 0x33, 0xa4, 0xd3, 0xf1, 0x35, 0x7c},
}

var guidLayerALEResourceAssignmentV4 = windows.GUID{
Data1: 0x1247d66d,
Data2: 0x0b60,
Data3: 0x4a15,
Data4: [8]byte{0x8d, 0x44, 0x71, 0x55, 0xd0, 0xf5, 0x3a, 0x0c},
}

var guidLayerALEResourceAssignmentV4Discard = windows.GUID{
Data1: 0x0b5812a2,
Data2: 0xc3ff,
Data3: 0x4eca,
Data4: [8]byte{0xb8, 0x8d, 0xc7, 0x9e, 0x20, 0xac, 0x63, 0x22},
}

var guidLayerALEResourceAssignmentV6 = windows.GUID{
Data1: 0x55a650e1,
Data2: 0x5f0a,
Data3: 0x4eca,
Data4: [8]byte{0xa6, 0x53, 0x88, 0xf5, 0x3b, 0x26, 0xaa, 0x8c},
}

var guidLayerALEResourceAssignmentV6Discard = windows.GUID{
Data1: 0xcbc998bb,
Data2: 0xc51f,
Data3: 0x4c1a,
Data4: [8]byte{0xbb, 0x4f, 0x97, 0x75, 0xfc, 0xac, 0xab, 0x2f},
}

var guidLayerALEAuthListenV4 = windows.GUID{
Data1: 0x88bb5dad,
Data2: 0x76d7,
Data3: 0x4227,
Data4: [8]byte{0x9c, 0x71, 0xdf, 0x0a, 0x3e, 0xd7, 0xbe, 0x7e},
}

var guidLayerALEAuthListenV4Discard = windows.GUID{
Data1: 0x371dfada,
Data2: 0x9f26,
Data3: 0x45fd,
Data4: [8]byte{0xb4, 0xeb, 0xc2, 0x9e, 0xb2, 0x12, 0x89, 0x3f},
}

var guidLayerALEAuthListenV6 = windows.GUID{
Data1: 0x7ac9de24,
Data2: 0x17dd,
Data3: 0x4814,
Data4: [8]byte{0xb4, 0xbd, 0xa9, 0xfb, 0xc9, 0x5a, 0x32, 0x1b},
}

var guidLayerALEAuthListenV6Discard = windows.GUID{
Data1: 0x60703b07,
Data2: 0x63c8,
Data3: 0x48e9,
Data4: [8]byte{0xad, 0xa3, 0x12, 0xb1, 0xaf, 0x40, 0xa6, 0x17},
}

var guidLayerALEAuthRecvAcceptV4 = windows.GUID{
Data1: 0xe1cd9fe7,
Data2: 0xf4b5,
Data3: 0x4273,
Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50},
}

var guidLayerALEAuthRecvAcceptV4Discard = windows.GUID{
Data1: 0x9eeaa99b,
Data2: 0xbd22,
Data3: 0x4227,
Data4: [8]byte{0x91, 0x9f, 0x00, 0x73, 0xc6, 0x33, 0x57, 0xb1},
}

var guidLayerALEAuthRecvAcceptV6 = windows.GUID{
Data1: 0xa3b42c97,
Data2: 0x9f04,
Data3: 0x4672,
Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f},
}

var guidLayerALEAuthRecvAcceptV6Discard = windows.GUID{
Data1: 0x89455b97,
Data2: 0xdbe1,
Data3: 0x453f,
Data4: [8]byte{0xa2, 0x24, 0x13, 0xda, 0x89, 0x5a, 0xf3, 0x96},
}

var guidLayerALEAuthConnectV4 = windows.GUID{
Data1: 0xc38d57d1,
Data2: 0x05a7,
Data3: 0x4c33,
Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
}

var guidLayerALEAuthConnectV4Discard = windows.GUID{
Data1: 0xd632a801,
Data2: 0xf5ba,
Data3: 0x4ad6,
Data4: [8]byte{0x96, 0xe3, 0x60, 0x70, 0x17, 0xd9, 0x83, 0x6a},
}

var guidLayerALEAuthConnectV6 = windows.GUID{
Data1: 0x4a72393b,
Data2: 0x319f,
Data3: 0x44bc,
Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4},
}

var guidLayerALEAuthConnectV6Discard = windows.GUID{
Data1: 0xc97bc3b8,
Data2: 0xc9a3,
Data3: 0x4e33,
Data4: [8]byte{0x86, 0x95, 0x8e, 0x17, 0xaa, 0xd4, 0xde, 0x09},
}

var guidLayerALEFlowEstablishedV4 = windows.GUID{
Data1: 0xaf80470a,
Data2: 0x5596,
Data3: 0x4c13,
Data4: [8]byte{0x99, 0x92, 0x53, 0x9e, 0x6f, 0xe5, 0x79, 0x67},
}

var guidLayerALEFlowEstablishedV4Discard = windows.GUID{
Data1: 0x146ae4a9,
Data2: 0xa1d2,
Data3: 0x4d43,
Data4: [8]byte{0xa3, 0x1a, 0x4c, 0x42, 0x68, 0x2b, 0x8e, 0x4f},
}

var guidLayerALEFlowEstablishedV6 = windows.GUID{
Data1: 0x7021d2b3,
Data2: 0xdfa4,
Data3: 0x406e,
Data4: [8]byte{0xaf, 0xeb, 0x6a, 0xfa, 0xf7, 0xe7, 0x0e, 0xfd},
}

var guidLayerALEFlowEstablishedV6Discard = windows.GUID{
Data1: 0x46928636,
Data2: 0xbbca,
Data3: 0x4b76,
Data4: [8]byte{0x94, 0x1d, 0x0f, 0xa7, 0xf5, 0xd7, 0xd3, 0x72},
}

var guidLayerInboundMACFrameEthernet = windows.GUID{
Data1: 0xeffb7edb,
Data2: 0x0055,
Data3: 0x4f9a,
Data4: [8]byte{0xa2, 0x31, 0x4f, 0xf8, 0x13, 0x1a, 0xd1, 0x91},
}

var guidLayerOutboundMACFrameEthernet = windows.GUID{
Data1: 0x694673bc,
Data2: 0xd6db,
Data3: 0x4870,
Data4: [8]byte{0xad, 0xee, 0x0a, 0xcd, 0xbd, 0xb7, 0xf4, 0xb2},
}

var guidLayerInboundMACFrameNative = windows.GUID{
Data1: 0xd4220bd3,
Data2: 0x62ce,
Data3: 0x4f08,
Data4: [8]byte{0xae, 0x88, 0xb5, 0x6e, 0x85, 0x26, 0xdf, 0x50},
}

var guidLayerOutboundMACFrameNative = windows.GUID{
Data1: 0x94c44912,
Data2: 0x9d6f,
Data3: 0x4ebf,
Data4: [8]byte{0xb9, 0x95, 0x05, 0xab, 0x8a, 0x08, 0x8d, 0x1b},
}

var guidLayerIngressVswitchEthernet = windows.GUID{
Data1: 0x7d98577a,
Data2: 0x9a87,
Data3: 0x41ec,
Data4: [8]byte{0x97, 0x18, 0x7c, 0xf5, 0x89, 0xc9, 0xf3, 0x2d},
}

var guidLayerEgressVswitchEthernet = windows.GUID{
Data1: 0x86c872b0,
Data2: 0x76fa,
Data3: 0x4b79,
Data4: [8]byte{0x93, 0xa4, 0x07, 0x50, 0x53, 0x0a, 0xe2, 0x92},
}

var guidLayerIngressVswitchTransportV4 = windows.GUID{
Data1: 0xb2696ff6,
Data2: 0x774f,
Data3: 0x4554,
Data4: [8]byte{0x9f, 0x7d, 0x3d, 0xa3, 0x94, 0x5f, 0x8e, 0x85},
}

var guidLayerIngressVswitchTransportV6 = windows.GUID{
Data1: 0x5ee314fc,
Data2: 0x7d8a,
Data3: 0x47f4,
Data4: [8]byte{0xb7, 0xe3, 0x29, 0x1a, 0x36, 0xda, 0x4e, 0x12},
}

var guidLayerEgressVswitchTransportV4 = windows.GUID{
Data1: 0xb92350b6,
Data2: 0x91f0,
Data3: 0x46b6,
Data4: [8]byte{0xbd, 0xc4, 0x87, 0x1d, 0xfd, 0x4a, 0x7c, 0x98},
}

var guidLayerEgressVswitchTransportV6 = windows.GUID{
Data1: 0x1b2def23,
Data2: 0x1881,
Data3: 0x40bd,
Data4: [8]byte{0x82, 0xf4, 0x42, 0x54, 0xe6, 0x31, 0x41, 0xcb},
}

var guidLayerInboundTransportFast = windows.GUID{
Data1: 0xe41d2719,
Data2: 0x05c7,
Data3: 0x40f0,
Data4: [8]byte{0x89, 0x83, 0xea, 0x8d, 0x17, 0xbb, 0xc2, 0xf6},
}

var guidLayerOutboundTransportFast = windows.GUID{
Data1: 0x13ed4388,
Data2: 0xa070,
Data3: 0x4815,
Data4: [8]byte{0x99,0x35,0x7a,0x9b,0xe6,0x40,0x8b,0x78},
}

var guidLayerInboundMACFrameNativeFast = windows.GUID{
Data1: 0x853aaa8e,
Data2: 0x2b78,
Data3: 0x4d24,
Data4: [8]byte{0xa8,0x04,0x36,0xdb,0x08,0xb2,0x97,0x11},
}

var guidLayerOutboundMACFrameNativeFast = windows.GUID{
Data1: 0x470df946,
Data2: 0xc962,
Data3: 0x486f,
Data4: [8]byte{0x94,0x46,0x82,0x93,0xcb,0xc7,0x5e,0xb8},
}

var guidLayerIPSecKMDemuxV4 = windows.GUID{
Data1: 0xf02b1526,
Data2: 0xa459,
Data3: 0x4a51,
Data4: [8]byte{0xb9, 0xe3, 0x75, 0x9d, 0xe5, 0x2b, 0x9d, 0x2c},
}

var guidLayerIPSecKMDemuxV6 = windows.GUID{
Data1: 0x2f755cf6,
Data2: 0x2fd4,
Data3: 0x4e88,
Data4: [8]byte{0xb3, 0xe4, 0xa9, 0x1b, 0xca, 0x49, 0x52, 0x35},
}

var guidLayerIPSecV4 = windows.GUID{
Data1: 0xeda65c74,
Data2: 0x610d,
Data3: 0x4bc5,
Data4: [8]byte{0x94, 0x8f, 0x3c, 0x4f, 0x89, 0x55, 0x68, 0x67},
}

var guidLayerIPSecV6 = windows.GUID{
Data1: 0x13c48442,
Data2: 0x8d87,
Data3: 0x4261,
Data4: [8]byte{0x9a, 0x29, 0x59, 0xd2, 0xab, 0xc3, 0x48, 0xb4},
}

var guidLayerIKEExtV4 = windows.GUID{
Data1: 0xb14b7bdb,
Data2: 0xdbbd,
Data3: 0x473e,
Data4: [8]byte{0xbe, 0xd4, 0x8b, 0x47, 0x08, 0xd4, 0xf2, 0x70},
}

var guidLayerIKEExtV6 = windows.GUID{
Data1: 0xb64786b3,
Data2: 0xf687,
Data3: 0x4eb9,
Data4: [8]byte{0x89, 0xd2, 0x8e, 0xf3, 0x2a, 0xcd, 0xab, 0xe2},
}

var guidLayerRPCUM = windows.GUID{
Data1: 0x75a89dda,
Data2: 0x95e4,
Data3: 0x40f3,
Data4: [8]byte{0xad, 0xc7, 0x76, 0x88, 0xa9, 0xc8, 0x47, 0xe1},
}

var guidLayerRPCEPMap = windows.GUID{
Data1: 0x9247bc61,
Data2: 0xeb07,
Data3: 0x47ee,
Data4: [8]byte{0x87, 0x2c, 0xbf, 0xd7, 0x8b, 0xfd, 0x16, 0x16},
}

var guidLayerRPCEPAdd = windows.GUID{
Data1: 0x618dffc7,
Data2: 0xc450,
Data3: 0x4943,
Data4: [8]byte{0x95, 0xdb, 0x99, 0xb4, 0xc1, 0x6a, 0x55, 0xd4},
}

var guidLayerRPCProxyConn = windows.GUID{
Data1: 0x94a4b50b,
Data2: 0xba5c,
Data3: 0x4f27,
Data4: [8]byte{0x90, 0x7a, 0x22, 0x9f, 0xac, 0x0c, 0x2a, 0x7a},
}

var guidLayerRPCProxyIf = windows.GUID{
Data1: 0xf8a38615,
Data2: 0xe12c,
Data3: 0x41ac,
Data4: [8]byte{0x98, 0xdf, 0x12, 0x1a, 0xd9, 0x81, 0xaa, 0xde},
}

var guidLayerKMAuthorization = windows.GUID{
Data1: 0x4aa226e9,
Data2: 0x9020,
Data3: 0x45fb,
Data4: [8]byte{0x95,0x6a, 0xc0, 0x24, 0x9d, 0x84, 0x11, 0x95},
}

var guidLayerNameResolutionCacheV4 = windows.GUID{
Data1: 0x0c2aa681,
Data2: 0x905b,
Data3: 0x4ccd,
Data4: [8]byte{0xa4, 0x67, 0x4d, 0xd8, 0x11, 0xd0, 0x7b, 0x7b},
}

var guidLayerNameResolutionCacheV6 = windows.GUID{
Data1: 0x92d592fa,
Data2: 0x6b01,
Data3: 0x434a,
Data4: [8]byte{0x9d, 0xea, 0xd1, 0xe9, 0x6e, 0xa9, 0x7d, 0xa9},
}

var guidLayerALEResourceReleaseV4 = windows.GUID{
Data1: 0x74365cce,
Data2: 0xccb0,
Data3: 0x401a,
Data4: [8]byte{0xbf, 0xc1, 0xb8, 0x99, 0x34, 0xad, 0x7e, 0x15},
}

var guidLayerALEResourceReleaseV6 = windows.GUID{
Data1: 0xf4e5ce80,
Data2: 0xedcc,
Data3: 0x4e13,
Data4: [8]byte{0x8a, 0x2f, 0xb9, 0x14, 0x54, 0xbb, 0x05, 0x7b},
}

var guidLayerALEEndpointClosureV4 = windows.GUID{
Data1: 0xb4766427,
Data2: 0xe2a2,
Data3: 0x467a,
Data4: [8]byte{0xbd, 0x7e, 0xdb, 0xcd, 0x1b, 0xd8, 0x5a, 0x09},
}

var guidLayerALEEndpointClosureV6 = windows.GUID{
Data1: 0xbb536ccd,
Data2: 0x4755,
Data3: 0x4ba9,
Data4: [8]byte{0x9f, 0xf7, 0xf9, 0xed, 0xf8, 0x69, 0x9c, 0x7b},
}

var guidLayerALEConnectRedirectV4 = windows.GUID{
Data1: 0xc6e63c8c,
Data2: 0xb784,
Data3: 0x4562,
Data4: [8]byte{0xaa, 0x7d, 0x0a, 0x67, 0xcf, 0xca, 0xf9, 0xa3},
}

var guidLayerALEConnectRedirectV6 = windows.GUID{
Data1: 0x587e54a7,
Data2: 0x8046,
Data3: 0x42ba,
Data4: [8]byte{0xa0, 0xaa, 0xb7, 0x16, 0x25, 0x0f, 0xc7, 0xfd},
}

var guidLayerALEBindRedirectV4 = windows.GUID{
Data1: 0x66978cad,
Data2: 0xc704,
Data3: 0x42ac,
Data4: [8]byte{0x86, 0xac, 0x7c, 0x1a, 0x23, 0x1b, 0xd2, 0x53},
}

var guidLayerALEBindRedirectV6 = windows.GUID{
Data1: 0xbef02c9c,
Data2: 0x606b,
Data3: 0x4536,
Data4: [8]byte{0x8c, 0x26, 0x1c, 0x2f, 0xc7, 0xb6, 0x31, 0xd4},
}

var guidLayerStreamPacketV4 = windows.GUID{
Data1: 0xaf52d8ec,
Data2: 0xcb2d,
Data3: 0x44e5,
Data4: [8]byte{0xad, 0x92, 0xf8, 0xdc, 0x38, 0xd2, 0xeb, 0x29},
}

var guidLayerStreamPacketV6 = windows.GUID{
Data1: 0x779a8ca3,
Data2: 0xf099,
Data3: 0x468f,
Data4: [8]byte{0xb5, 0xd4, 0x83, 0x53, 0x5c, 0x46, 0x1c, 0x02},
}

var guidLayerInboundReserved2 = windows.GUID{
Data1: 0xf4fb8d55,
Data2: 0xc076,
Data3: 0x46d8,
Data4: [8]byte{0xa2, 0xc7, 0x6a, 0x4c, 0x72, 0x2c, 0xa4, 0xed},
}

var guidSublayerRPCAudit = windows.GUID{
Data1: 0x758c84f4,
Data2: 0xfb48,
Data3: 0x4de9,
Data4: [8]byte{0x9a, 0xeb, 0x3e, 0xd9, 0x55, 0x1a, 0xb1, 0xfd},
}

var guidSublayerIPSecTunnel = windows.GUID{
Data1: 0x83f299ed,
Data2: 0x9ff4,
Data3: 0x4967,
Data4: [8]byte{0xaf, 0xf4, 0xc3, 0x09, 0xf4, 0xda, 0xb8, 0x27},
}

var guidSublayerUniversal = windows.GUID{
Data1: 0xeebecc03,
Data2: 0xced4,
Data3: 0x4380,
Data4: [8]byte{0x81, 0x9a, 0x27, 0x34, 0x39, 0x7b, 0x2b, 0x74},
}

var guidSublayerLIPS = windows.GUID{
Data1: 0x1b75c0ce,
Data2: 0xff60,
Data3: 0x4711,
Data4: [8]byte{0xa7, 0x0f, 0xb4, 0x95, 0x8c, 0xc3, 0xb2, 0xd0},
}

var guidSublayerSecureSocket = windows.GUID{
Data1: 0x15a66e17,
Data2: 0x3f3c,
Data3: 0x4f7b,
Data4: [8]byte{0xaa, 0x6c, 0x81, 0x2a, 0xa6, 0x13, 0xdd, 0x82},
}

var guidSublayerTCPChimneyOffload = windows.GUID{
Data1: 0x337608b9,
Data2: 0xb7d5,
Data3: 0x4d5f,
Data4: [8]byte{0x82, 0xf9, 0x36, 0x18, 0x61, 0x8b, 0xc0, 0x58},
}

var guidSublayerInspection = windows.GUID{
Data1: 0x877519e1,
Data2: 0xe6a9,
Data3: 0x41a5,
Data4: [8]byte{0x81, 0xb4, 0x8c, 0x4f, 0x11, 0x8e, 0x4a, 0x60},
}

var guidSublayerTeredo = windows.GUID{
Data1: 0xba69dc66,
Data2: 0x5176,
Data3: 0x4979,
Data4: [8]byte{0x9c, 0x89, 0x26, 0xa7, 0xb4, 0x6a, 0x83, 0x27},
}

var guidSublayerIPSecForwardOutboundTunnel = windows.GUID{
Data1: 0xa5082e73,
Data2: 0x8f71,
Data3: 0x4559,
Data4: [8]byte{0x8a, 0x9a, 0x10, 0x1c, 0xea, 0x04, 0xef, 0x87},
}

var guidSublayerIPSecDosp = windows.GUID{
Data1: 0xe076d572,
Data2: 0x5d3d,
Data3: 0x48ef,
Data4: [8]byte{0x80, 0x2b, 0x90, 0x9e, 0xdd, 0xb0, 0x98, 0xbd},
}

var guidSublayerTCPTemplates = windows.GUID{
Data1: 0x24421dcf,
Data2: 0x0ac5,
Data3: 0x4caa,
Data4: [8]byte{0x9e, 0x14, 0x50, 0xf6, 0xe3, 0x63, 0x6a, 0xf0},
}

var guidSublayerIPSecSecurityRealm = windows.GUID{
Data1: 0x37a57701,
Data2: 0x5884,
Data3: 0x4964,
Data4: [8]byte{0x92, 0xb8, 0x3e, 0x70, 0x46, 0x88, 0xb0, 0xad},
}

var guidConditionInterfaceMACAddress = windows.GUID{
Data1: 0xf6e63dce,
Data2: 0x1f4b,
Data3: 0x4c6b,
Data4: [8]byte{0xb6, 0xef, 0x11, 0x65, 0xe7, 0x1f, 0x8e, 0xe7},
}

var guidConditionMACLocalAddress = windows.GUID{
Data1: 0xd999e981,
Data2: 0x7948,
Data3: 0x4c83,
Data4: [8]byte{0xb7, 0x42, 0xc8, 0x4e, 0x3b, 0x67, 0x8f, 0x8f},
}

var guidConditionMACRemoteAddress = windows.GUID{
Data1: 0x408f2ed4,
Data2: 0x3a70,
Data3: 0x4b4d,
Data4: [8]byte{0x92, 0xa6, 0x41, 0x5a, 0xc2, 0x0e, 0x2f, 0x12},
}

var guidConditionEtherType = windows.GUID{
Data1: 0xfd08948d,
Data2: 0xa219,
Data3: 0x4d52,
Data4: [8]byte{0xbb, 0x98, 0x1a, 0x55, 0x40, 0xee, 0x7b, 0x4e},
}

var guidConditionVLANID = windows.GUID{
Data1: 0x938eab21,
Data2: 0x3618,
Data3: 0x4e64,
Data4: [8]byte{0x9c, 0xa5, 0x21, 0x41, 0xeb, 0xda, 0x1c, 0xa2},
}

var guidConditionVswitchTenantNetworkID = windows.GUID{
Data1: 0xdc04843c,
Data2: 0x79e6,
Data3: 0x4e44,
Data4: [8]byte{0xa0, 0x25, 0x65, 0xb9, 0xbb, 0x0f, 0x9f, 0x94},
}

var guidConditionNdisPort = windows.GUID{
Data1: 0xdb7bb42b,
Data2: 0x2dac,
Data3: 0x4cd4,
Data4: [8]byte{0xa5, 0x9a, 0xe0, 0xbd, 0xce, 0x1e, 0x68, 0x34},
}

var guidConditionNdisMediaType = windows.GUID{
Data1: 0xcb31cef1,
Data2: 0x791d,
Data3: 0x473b,
Data4: [8]byte{0x89, 0xd1, 0x61, 0xc5, 0x98, 0x43, 0x04, 0xa0},
}

var guidConditionNdisPhysicalMediaType = windows.GUID{
Data1: 0x34c79823,
Data2: 0xc229,
Data3: 0x44f2,
Data4: [8]byte{0xb8, 0x3c, 0x74, 0x02, 0x08, 0x82, 0xae, 0x77},
}

var guidConditionL2Flags = windows.GUID{
Data1: 0x7bc43cbf,
Data2: 0x37ba,
Data3: 0x45f1,
Data4: [8]byte{0xb7, 0x4a, 0x82, 0xff, 0x51, 0x8e, 0xeb, 0x10},
}

var guidConditionMACLocalAddressType = windows.GUID{
Data1: 0xcc31355c,
Data2: 0x3073,
Data3: 0x4ffb,
Data4: [8]byte{0xa1, 0x4f, 0x79, 0x41, 0x5c, 0xb1, 0xea, 0xd1},
}

var guidConditionMACRemoteAddressType = windows.GUID{
Data1: 0x027fedb4,
Data2: 0xf1c1,
Data3: 0x4030,
Data4: [8]byte{0xb5, 0x64, 0xee, 0x77, 0x7f, 0xd8, 0x67, 0xea},
}

var guidConditionALEPackageID = windows.GUID{
Data1: 0x71bc78fa,
Data2: 0xf17c,
Data3: 0x4997,
Data4: [8]byte{0xa6, 0x2, 0x6a, 0xbb, 0x26, 0x1f, 0x35, 0x1c},
}

var guidConditionMACSourceAddress = windows.GUID{
Data1: 0x7b795451,
Data2: 0xf1f6,
Data3: 0x4d05,
Data4: [8]byte{0xb7, 0xcb, 0x21, 0x77, 0x9d, 0x80, 0x23, 0x36},
}

var guidConditionMACDestinationAddress = windows.GUID{
Data1: 0x04ea2a93,
Data2: 0x858c,
Data3: 0x4027,
Data4: [8]byte{0xb6, 0x13, 0xb4, 0x31, 0x80, 0xc7, 0x85, 0x9e},
}

var guidConditionMACSourceAddressType = windows.GUID{
Data1: 0x5c1b72e4,
Data2: 0x299e,
Data3: 0x4437,
Data4: [8]byte{0xa2, 0x98, 0xbc, 0x3f, 0x01, 0x4b, 0x3d, 0xc2},
}

var guidConditionMACDestinationAddressType = windows.GUID{
Data1: 0xae052932,
Data2: 0xef42,
Data3: 0x4e99,
Data4: [8]byte{0xb1, 0x29, 0xf3, 0xb3, 0x13, 0x9e, 0x34, 0xf7},
}

var guidConditionIPSourcePort = windows.GUID{
Data1: 0xa6afef91,
Data2: 0x3df4,
Data3: 0x4730,
Data4: [8]byte{0xa2, 0x14, 0xf5, 0x42, 0x6a, 0xeb, 0xf8, 0x21},
}

var guidConditionIPDestinationPort = windows.GUID{
Data1: 0xce6def45,
Data2: 0x60fb,
Data3: 0x4a7b,
Data4: [8]byte{0xa3, 0x04, 0xaf, 0x30, 0xa1, 0x17, 0x00, 0x0e},
}

var guidConditionVswitchID = windows.GUID{
Data1: 0xc4a414ba,
Data2: 0x437b,
Data3: 0x4de6,
Data4: [8]byte{0x99, 0x46, 0xd9, 0x9c, 0x1b, 0x95, 0xb3, 0x12},
}

var guidConditionVswitchNetworkType = windows.GUID{
Data1: 0x11d48b4b,
Data2: 0xe77a,
Data3: 0x40b4,
Data4: [8]byte{0x91, 0x55, 0x39, 0x2c, 0x90, 0x6c, 0x26, 0x08},
}

var guidConditionVswitchSourceInterfaceID = windows.GUID{
Data1: 0x7f4ef24b,
Data2: 0xb2c1,
Data3: 0x4938,
Data4: [8]byte{0xba, 0x33, 0xa1, 0xec, 0xbe, 0xd5, 0x12, 0xba},
}

var guidConditionVswitchDestinationInterfaceID = windows.GUID{
Data1: 0x8ed48be4,
Data2: 0xc926,
Data3: 0x49f6,
Data4: [8]byte{0xa4, 0xf6, 0xef, 0x30, 0x30, 0xe3, 0xfc, 0x16},
}

var guidConditionVswitchSourceVmID = windows.GUID{
Data1: 0x9c2a9ec2,
Data2: 0x9fc6,
Data3: 0x42bc,
Data4: [8]byte{0xbd, 0xd8, 0x40, 0x6d, 0x4d, 0xa0, 0xbe, 0x64},
}

var guidConditionVswitchDestinationVmID = windows.GUID{
Data1: 0x6106aace,
Data2: 0x4de1,
Data3: 0x4c84,
Data4: [8]byte{0x96, 0x71, 0x36, 0x37, 0xf8, 0xbc, 0xf7, 0x31},
}

var guidConditionVswitchSourceInterfaceType = windows.GUID{
Data1: 0xe6b040a2,
Data2: 0xedaf,
Data3: 0x4c36,
Data4: [8]byte{0x90, 0x8b, 0xf2, 0xf5, 0x8a, 0xe4, 0x38, 0x07},
}

var guidConditionVswitchDestinationInterfaceType = windows.GUID{
Data1: 0xfa9b3f06,
Data2: 0x2f1a,
Data3: 0x4c57,
Data4: [8]byte{0x9e, 0x68, 0xa7, 0x09, 0x8b, 0x28, 0xdb, 0xfe},
}

var guidConditionALESecurityAttributeFqbnValue = windows.GUID{
Data1: 0x37a57699,
Data2: 0x5883,
Data3: 0x4963,
Data4: [8]byte{0x92, 0xb8, 0x3e, 0x70, 0x46, 0x88, 0xb0, 0xad},
}

var guidConditionIPSecSecurityRealmID = windows.GUID{
Data1: 0x37a57700,
Data2: 0x5884,
Data3: 0x4964,
Data4: [8]byte{0x92, 0xb8, 0x3e, 0x70, 0x46, 0x88, 0xb0, 0xad},
}

var guidConditionALEEffectiveName = windows.GUID{
Data1: 0xb1277b9a,
Data2: 0xb781,
Data3: 0x40fc,
Data4: [8]byte{0x96, 0x71, 0xe5, 0xf1, 0xb9, 0x89, 0xf3, 0x4e},
}

var guidConditionIPLocalAddress = windows.GUID{
Data1: 0xd9ee00de,
Data2: 0xc1ef,
Data3: 0x4617,
Data4: [8]byte{0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57},
}

var guidConditionIPRemoteAddress = windows.GUID{
Data1: 0xb235ae9a,
Data2: 0x1d64,
Data3: 0x49b8,
Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45},
}

var guidConditionIPSourceAddress = windows.GUID{
Data1: 0xae96897e,
Data2: 0x2e94,
Data3: 0x4bc9,
Data4: [8]byte{0xb3, 0x13, 0xb2, 0x7e, 0xe8, 0x0e, 0x57, 0x4d},
}

var guidConditionIPDestinationAddress = windows.GUID{
Data1: 0x2d79133b,
Data2: 0xb390,
Data3: 0x45c6,
Data4: [8]byte{0x86, 0x99, 0xac, 0xac, 0xea, 0xaf, 0xed, 0x33},
}

var guidConditionIPLocalAddressType = windows.GUID{
Data1: 0x6ec7f6c4,
Data2: 0x376b,
Data3: 0x45d7,
Data4: [8]byte{0x9e, 0x9c, 0xd3, 0x37, 0xce, 0xdc, 0xd2, 0x37},
}

var guidConditionIPDestinationAddressType = windows.GUID{
Data1: 0x1ec1b7c9,
Data2: 0x4eea,
Data3: 0x4f5e,
Data4: [8]byte{0xb9, 0xef, 0x76, 0xbe, 0xaa, 0xaf, 0x17, 0xee},
}

var guidConditionBitmapIPLocalAddress = windows.GUID{
Data1: 0x16ebc3df,
Data2: 0x957a,
Data3: 0x452e,
Data4: [8]byte{0xa1, 0xfc, 0x3d, 0x2f, 0xf6, 0xa7, 0x30, 0xba},
}

var guidConditionBitmapIPLocalPort = windows.GUID{
Data1: 0x9f90a920,
Data2: 0xc3b5,
Data3: 0x4569,
Data4: [8]byte{0xba, 0x31, 0x8b, 0xd3, 0x91, 0xd, 0xc6, 0x56},
}

var guidConditionBitmapIPRemoteAddress = windows.GUID{
Data1: 0x33f00e25,
Data2: 0x8eec,
Data3: 0x4531,
Data4: [8]byte{0xa0, 0x5, 0x41, 0xb9, 0x11, 0xf6, 0x24, 0x52},
}

var guidConditionBitmapIPRemotePort = windows.GUID{
Data1: 0x2663d549,
Data2: 0xaaf2,
Data3: 0x46a2,
Data4: [8]byte{0x86, 0x66, 0x1e, 0x76, 0x67, 0xf8, 0x69, 0x85},
}

var guidConditionIPNexthopAddress = windows.GUID{
Data1: 0xeabe448a,
Data2: 0xa711,
Data3: 0x4d64,
Data4: [8]byte{0x85, 0xb7, 0x3f, 0x76, 0xb6, 0x52, 0x99, 0xc7},
}

var guidConditionBitmapIndexKey = windows.GUID{
Data1: 0xf36514c,
Data2: 0x3226,
Data3: 0x4a81,
Data4: [8]byte{0xa2, 0x14, 0x2d, 0x51, 0x8b, 0x4, 0xd0, 0x8a},
}

var guidConditionIPLocalInterface = windows.GUID{
Data1: 0x4cd62a49,
Data2: 0x59c3,
Data3: 0x4969,
Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4},
}

var guidConditionIPArrivalInterface = windows.GUID{
Data1: 0x618a9b6d,
Data2: 0x386b,
Data3: 0x4136,
Data4: [8]byte{0xad, 0x6e, 0xb5, 0x15, 0x87, 0xcf, 0xb1, 0xcd},
}

var guidConditionArrivalInterfaceType = windows.GUID{
Data1: 0x89f990de,
Data2: 0xe798,
Data3: 0x4e6d,
Data4: [8]byte{0xab, 0x76, 0x7c, 0x95, 0x58, 0x29, 0x2e, 0x6f},
}

var guidConditionArrivalTunnelType = windows.GUID{
Data1: 0x511166dc,
Data2: 0x7a8c,
Data3: 0x4aa7,
Data4: [8]byte{0xb5, 0x33, 0x95, 0xab, 0x59, 0xfb, 0x03, 0x40},
}

var guidConditionArrivalInterfaceIndex = windows.GUID{
Data1: 0xcc088db3,
Data2: 0x1792,
Data3: 0x4a71,
Data4: [8]byte{0xb0, 0xf9, 0x03, 0x7d, 0x21, 0xcd, 0x82, 0x8b},
}

var guidConditionNexthopSubInterfaceIndex = windows.GUID{
Data1: 0xef8a6122,
Data2: 0x0577,
Data3: 0x45a7,
Data4: [8]byte{0x9a, 0xaf, 0x82, 0x5f, 0xbe, 0xb4, 0xfb, 0x95},
}

var guidConditionIPNexthopInterface = windows.GUID{
Data1: 0x93ae8f5b,
Data2: 0x7f6f,
Data3: 0x4719,
Data4: [8]byte{0x98, 0xc8, 0x14, 0xe9, 0x74, 0x29, 0xef, 0x04},
}

var guidConditionNexthopInterfaceType = windows.GUID{
Data1: 0x97537c6c,
Data2: 0xd9a3,
Data3: 0x4767,
Data4: [8]byte{0xa3, 0x81, 0xe9, 0x42, 0x67, 0x5c, 0xd9, 0x20},
}

var guidConditionNexthopTunnelType = windows.GUID{
Data1: 0x72b1a111,
Data2: 0x987b,
Data3: 0x4720,
Data4: [8]byte{0x99, 0xdd, 0xc7, 0xc5, 0x76, 0xfa, 0x2d, 0x4c},
}

var guidConditionNexthopInterfaceIndex = windows.GUID{
Data1: 0x138e6888,
Data2: 0x7ab8,
Data3: 0x4d65,
Data4: [8]byte{0x9e, 0xe8, 0x05, 0x91, 0xbc, 0xf6, 0xa4, 0x94},
}

var guidConditionOriginalProfileID = windows.GUID{
Data1: 0x46ea1551,
Data2: 0x2255,
Data3: 0x492b,
Data4: [8]byte{0x80, 0x19, 0xaa, 0xbe, 0xee, 0x34, 0x9f, 0x40},
}

var guidConditionCurrentProfileID = windows.GUID{
Data1: 0xab3033c9,
Data2: 0xc0e3,
Data3: 0x4759,
Data4: [8]byte{0x93, 0x7d, 0x57, 0x58, 0xc6, 0x5d, 0x4a, 0xe3},
}

var guidConditionLocalInterfaceProfileID = windows.GUID{
Data1: 0x4ebf7562,
Data2: 0x9f18,
Data3: 0x4d06,
Data4: [8]byte{0x99, 0x41, 0xa7, 0xa6, 0x25, 0x74, 0x4d, 0x71},
}

var guidConditionArrivalInterfaceProfileID = windows.GUID{
Data1: 0xcdfe6aab,
Data2: 0xc083,
Data3: 0x4142,
Data4: [8]byte{0x86, 0x79, 0xc0, 0x8f, 0x95, 0x32, 0x9c, 0x61},
}

var guidConditionNexthopInterfaceProfileID = windows.GUID{
Data1: 0xd7ff9a56,
Data2: 0xcdaa,
Data3: 0x472b,
Data4: [8]byte{0x84, 0xdb, 0xd2, 0x39, 0x63, 0xc1, 0xd1, 0xbf},
}

var guidConditionReauthorizeReason = windows.GUID{
Data1: 0x11205e8c,
Data2: 0x11ae,
Data3: 0x457a,
Data4: [8]byte{0x8a, 0x44, 0x47, 0x70, 0x26, 0xdd, 0x76, 0x4a},
}

var guidConditionOriginalICMPType = windows.GUID{
Data1: 0x076dfdbe,
Data2: 0xc56c,
Data3: 0x4f72,
Data4: [8]byte{0xae, 0x8a, 0x2c, 0xfe, 0x7e, 0x5c, 0x82, 0x86},
}

var guidConditionIPPhysicalArrivalInterface = windows.GUID{
Data1: 0xda50d5c8,
Data2: 0xfa0d,
Data3: 0x4c89,
Data4: [8]byte{0xb0, 0x32, 0x6e, 0x62, 0x13, 0x6d, 0x1e, 0x96},
}

var guidConditionIPPhysicalNexthopInterface = windows.GUID{
Data1: 0xf09bd5ce,
Data2: 0x5150,
Data3: 0x48be,
Data4: [8]byte{0xb0, 0x98, 0xc2, 0x51, 0x52, 0xfb, 0x1f, 0x92},
}

var guidConditionInterfaceQuarantineEpoch = windows.GUID{
Data1: 0xcce68d5e,
Data2: 0x053b,
Data3: 0x43a8,
Data4: [8]byte{0x9a, 0x6f, 0x33, 0x38, 0x4c, 0x28, 0xe4, 0xf6},
}

var guidConditionInterfaceType = windows.GUID{
Data1: 0xdaf8cd14,
Data2: 0xe09e,
Data3: 0x4c93,
Data4: [8]byte{0xa5, 0xae, 0xc5, 0xc1, 0x3b, 0x73, 0xff, 0xca},
}

var guidConditionTunnelType = windows.GUID{
Data1: 0x77a40437,
Data2: 0x8779,
Data3: 0x4868,
Data4: [8]byte{0xa2, 0x61, 0xf5, 0xa9, 0x02, 0xf1, 0xc0, 0xcd},
}

var guidConditionIPForwardInterface = windows.GUID{
Data1: 0x1076b8a5,
Data2: 0x6323,
Data3: 0x4c5e,
Data4: [8]byte{0x98, 0x10, 0xe8, 0xd3, 0xfc, 0x9e, 0x61, 0x36},
}

var guidConditionIPProtocol = windows.GUID{
Data1: 0x3971ef2b,
Data2: 0x623e,
Data3: 0x4f9a,
Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7},
}

var guidConditionIPLocalPort = windows.GUID{
Data1: 0x0c1ba1af,
Data2: 0x5765,
Data3: 0x453f,
Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b},
}

var guidConditionIPRemotePort = windows.GUID{
Data1: 0xc35a604d,
Data2: 0xd22b,
Data3: 0x4e1a,
Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b},
}

var guidConditionEmbeddedLocalAddressType = windows.GUID{
Data1: 0x4672a468,
Data2: 0x8a0a,
Data3: 0x4202,
Data4: [8]byte{0xab, 0xb4, 0x84, 0x9e, 0x92, 0xe6, 0x68, 0x09},
}

var guidConditionEmbeddedRemoteAddress = windows.GUID{
Data1: 0x77ee4b39,
Data2: 0x3273,
Data3: 0x4671,
Data4: [8]byte{0xb6, 0x3b, 0xab, 0x6f, 0xeb, 0x66, 0xee, 0xb6},
}

var guidConditionEmbeddedProtocol = windows.GUID{
Data1: 0x07784107,
Data2: 0xa29e,
Data3: 0x4c7b,
Data4: [8]byte{0x9e, 0xc7, 0x29, 0xc4, 0x4a, 0xfa, 0xfd, 0xbc},
}

var guidConditionEmbeddedLocalPort = windows.GUID{
Data1: 0xbfca394d,
Data2: 0xacdb,
Data3: 0x484e,
Data4: [8]byte{0xb8, 0xe6, 0x2a, 0xff, 0x79, 0x75, 0x73, 0x45},
}

var guidConditionEmbeddedRemotePort = windows.GUID{
Data1: 0xcae4d6a1,
Data2: 0x2968,
Data3: 0x40ed,
Data4: [8]byte{0xa4, 0xce, 0x54, 0x71, 0x60, 0xdd, 0xa8, 0x8d},
}

var guidConditionFlags = windows.GUID{
Data1: 0x632ce23b,
Data2: 0x5167,
Data3: 0x435c,
Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c},
}

var guidConditionDirection = windows.GUID{
Data1: 0x8784c146,
Data2: 0xca97,
Data3: 0x44d6,
Data4: [8]byte{0x9f, 0xd1, 0x19, 0xfb, 0x18, 0x40, 0xcb, 0xf7},
}

var guidConditionInterfaceIndex = windows.GUID{
Data1: 0x667fd755,
Data2: 0xd695,
Data3: 0x434a,
Data4: [8]byte{0x8a, 0xf5, 0xd3, 0x83, 0x5a, 0x12, 0x59, 0xbc},
}

var guidConditionSubInterfaceIndex = windows.GUID{
Data1: 0x0cd42473,
Data2: 0xd621,
Data3: 0x4be3,
Data4: [8]byte{0xae, 0x8c, 0x72, 0xa3, 0x48, 0xd2, 0x83, 0xe1},
}

var guidConditionSourceInterfaceIndex = windows.GUID{
Data1: 0x2311334d,
Data2: 0xc92d,
Data3: 0x45bf,
Data4: [8]byte{0x94, 0x96, 0xed, 0xf4, 0x47, 0x82, 0x0e, 0x2d},
}

var guidConditionSourceSubInterfaceIndex = windows.GUID{
Data1: 0x055edd9d,
Data2: 0xacd2,
Data3: 0x4361,
Data4: [8]byte{0x8d, 0xab, 0xf9, 0x52, 0x5d, 0x97, 0x66, 0x2f},
}

var guidConditionDestinationInterfaceIndex = windows.GUID{
Data1: 0x35cf6522,
Data2: 0x4139,
Data3: 0x45ee,
Data4: [8]byte{0xa0, 0xd5, 0x67, 0xb8, 0x09, 0x49, 0xd8, 0x79},
}

var guidConditionDestinationSubInterfaceIndex = windows.GUID{
Data1: 0x2b7d4399,
Data2: 0xd4c7,
Data3: 0x4738,
Data4: [8]byte{0xa2, 0xf5, 0xe9, 0x94, 0xb4, 0x3d, 0xa3, 0x88},
}

var guidConditionALEAppID = windows.GUID{
Data1: 0xd78e1e87,
Data2: 0x8644,
Data3: 0x4ea5,
Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71},
}

var guidConditionALEOriginalAppID = windows.GUID{
Data1: 0x0e6cd086,
Data2: 0xe1fb,
Data3: 0x4212,
Data4: [8]byte{0x84, 0x2f, 0x8a, 0x9f, 0x99, 0x3f, 0xb3, 0xf6},
}

var guidConditionALEUserID = windows.GUID{
Data1: 0xaf043a0a,
Data2: 0xb34d,
Data3: 0x4f86,
Data4: [8]byte{0x97, 0x9c, 0xc9, 0x03, 0x71, 0xaf, 0x6e, 0x66},
}

var guidConditionALERemoteUserID = windows.GUID{
Data1: 0xf63073b7,
Data2: 0x0189,
Data3: 0x4ab0,
Data4: [8]byte{0x95, 0xa4, 0x61, 0x23, 0xcb, 0xfa, 0xb8, 0x62},
}

var guidConditionALERemoteMachineID = windows.GUID{
Data1: 0x1aa47f51,
Data2: 0x7f93,
Data3: 0x4508,
Data4: [8]byte{0xa2, 0x71, 0x81, 0xab, 0xb0, 0x0c, 0x9c, 0xab},
}

var guidConditionALEPromiscuousMode = windows.GUID{
Data1: 0x1c974776,
Data2: 0x7182,
Data3: 0x46e9,
Data4: [8]byte{0xaf, 0xd3, 0xb0, 0x29, 0x10, 0xe3, 0x03, 0x34},
}

var guidConditionALESioFirewallSystemPort = windows.GUID{
Data1: 0xb9f4e088,
Data2: 0xcb98,
Data3: 0x4efb,
Data4: [8]byte{0xa2, 0xc7, 0xad, 0x07, 0x33, 0x26, 0x43, 0xdb},
}

var guidConditionALEReauthReason = windows.GUID{
Data1: 0xb482d227,
Data2: 0x1979,
Data3: 0x4a98,
Data4: [8]byte{0x80, 0x44, 0x18, 0xbb, 0xe6, 0x23, 0x75, 0x42},
}

var guidConditionALENapContext = windows.GUID{
Data1: 0x46275a9d,
Data2: 0xc03f,
Data3: 0x4d77,
Data4: [8]byte{0xb7, 0x84, 0x1c, 0x57, 0xf4, 0xd0, 0x27, 0x53},
}

var guidConditionKMAuthNapContext = windows.GUID{
Data1: 0x35d0ea0e,
Data2: 0x15ca,
Data3: 0x492b,
Data4: [8]byte{0x90, 0x0e, 0x97, 0xfd, 0x46, 0x35, 0x2c, 0xce},
}

var guidConditionRemoteUserToken = windows.GUID{
Data1: 0x9bf0ee66,
Data2: 0x06c9,
Data3: 0x41b9,
Data4: [8]byte{0x84, 0xda, 0x28, 0x8c, 0xb4, 0x3a, 0xf5, 0x1f},
}

var guidConditionRPCIfUUID = windows.GUID{
Data1: 0x7c9c7d9f,
Data2: 0x0075,
Data3: 0x4d35,
Data4: [8]byte{0xa0, 0xd1, 0x83, 0x11, 0xc4, 0xcf, 0x6a, 0xf1},
}

var guidConditionRPCIfVersion = windows.GUID{
Data1: 0xeabfd9b7,
Data2: 0x1262,
Data3: 0x4a2e,
Data4: [8]byte{0xad, 0xaa, 0x5f, 0x96, 0xf6, 0xfe, 0x32, 0x6d},
}

var guidConditionRPCIfFlag = windows.GUID{
Data1: 0x238a8a32,
Data2: 0x3199,
Data3: 0x467d,
Data4: [8]byte{0x87, 0x1c, 0x27, 0x26, 0x21, 0xab, 0x38, 0x96},
}

var guidConditionDCOMAppID = windows.GUID{
Data1: 0xff2e7b4d,
Data2: 0x3112,
Data3: 0x4770,
Data4: [8]byte{0xb6, 0x36, 0x4d, 0x24, 0xae, 0x3a, 0x6a, 0xf2},
}

var guidConditionImageName = windows.GUID{
Data1: 0xd024de4d,
Data2: 0xdeaa,
Data3: 0x4317,
Data4: [8]byte{0x9c, 0x85, 0xe4, 0x0e, 0xf6, 0xe1, 0x40, 0xc3},
}

var guidConditionRPCProtocol = windows.GUID{
Data1: 0x2717bc74,
Data2: 0x3a35,
Data3: 0x4ce7,
Data4: [8]byte{0xb7, 0xef, 0xc8, 0x38, 0xfa, 0xbd, 0xec, 0x45},
}

var guidConditionRPCAuthType = windows.GUID{
Data1: 0xdaba74ab,
Data2: 0x0d67,
Data3: 0x43e7,
Data4: [8]byte{0x98, 0x6e, 0x75, 0xb8, 0x4f, 0x82, 0xf5, 0x94},
}

var guidConditionRPCAuthLevel = windows.GUID{
Data1: 0xe5a0aed5,
Data2: 0x59ac,
Data3: 0x46ea,
Data4: [8]byte{0xbe, 0x05, 0xa5, 0xf0, 0x5e, 0xcf, 0x44, 0x6e},
}

var guidConditionSecEncryptAlgorithm = windows.GUID{
Data1: 0x0d306ef0,
Data2: 0xe974,
Data3: 0x4f74,
Data4: [8]byte{0xb5, 0xc7, 0x59, 0x1b, 0x0d, 0xa7, 0xd5, 0x62},
}

var guidConditionSecKeySize = windows.GUID{
Data1: 0x4772183b,
Data2: 0xccf8,
Data3: 0x4aeb,
Data4: [8]byte{0xbc, 0xe1, 0xc6, 0xc6, 0x16, 0x1c, 0x8f, 0xe4},
}

var guidConditionIPLocalAddressV4 = windows.GUID{
Data1: 0x03a629cb,
Data2: 0x6e52,
Data3: 0x49f8,
Data4: [8]byte{0x9c, 0x41, 0x57, 0x09, 0x63, 0x3c, 0x09, 0xcf},
}

var guidConditionIPLocalAddressV6 = windows.GUID{
Data1: 0x2381be84,
Data2: 0x7524,
Data3: 0x45b3,
Data4: [8]byte{0xa0, 0x5b, 0x1e, 0x63, 0x7d, 0x9c, 0x7a, 0x6a},
}

var guidConditionPipe = windows.GUID{
Data1: 0x1bd0741d,
Data2: 0xe3df,
Data3: 0x4e24,
Data4: [8]byte{0x86, 0x34, 0x76, 0x20, 0x46, 0xee, 0xf6, 0xeb},
}

var guidConditionIPRemoteAddressV4 = windows.GUID{
Data1: 0x1febb610,
Data2: 0x3bcc,
Data3: 0x45e1,
Data4: [8]byte{0xbc, 0x36, 0x2e, 0x06, 0x7e, 0x2c, 0xb1, 0x86},
}

var guidConditionIPRemoteAddressV6 = windows.GUID{
Data1: 0x246e1d8c,
Data2: 0x8bee,
Data3: 0x4018,
Data4: [8]byte{0x9b, 0x98, 0x31, 0xd4, 0x58, 0x2f, 0x33, 0x61},
}

var guidConditionProcessWithRPCIfUUID = windows.GUID{
Data1: 0xe31180a8,
Data2: 0xbbbd,
Data3: 0x4d14,
Data4: [8]byte{0xa6, 0x5e, 0x71, 0x57, 0xb0, 0x62, 0x33, 0xbb},
}

var guidConditionRPCEPValue = windows.GUID{
Data1: 0xdccea0b9,
Data2: 0x0886,
Data3: 0x4360,
Data4: [8]byte{0x9c, 0x6a, 0xab, 0x04, 0x3a, 0x24, 0xfb, 0xa9},
}

var guidConditionRPCEPFlags = windows.GUID{
Data1: 0x218b814a,
Data2: 0x0a39,
Data3: 0x49b8,
Data4: [8]byte{0x8e, 0x71, 0xc2, 0x0c, 0x39, 0xc7, 0xdd, 0x2e},
}

var guidConditionClientToken = windows.GUID{
Data1: 0xc228fc1e,
Data2: 0x403a,
Data3: 0x4478,
Data4: [8]byte{0xbe, 0x05, 0xc9, 0xba, 0xa4, 0xc0, 0x5a, 0xce},
}

var guidConditionRPCServerName = windows.GUID{
Data1: 0xb605a225,
Data2: 0xc3b3,
Data3: 0x48c7,
Data4: [8]byte{0x98, 0x33, 0x7a, 0xef, 0xa9, 0x52, 0x75, 0x46},
}

var guidConditionRPCServerPort = windows.GUID{
Data1: 0x8090f645,
Data2: 0x9ad5,
Data3: 0x4e3b,
Data4: [8]byte{0x9f, 0x9f, 0x80, 0x23, 0xca, 0x09, 0x79, 0x09},
}

var guidConditionRPCProxyAuthType = windows.GUID{
Data1: 0x40953fe2,
Data2: 0x8565,
Data3: 0x4759,
Data4: [8]byte{0x84, 0x88, 0x17, 0x71, 0xb4, 0xb4, 0xb5, 0xdb},
}

var guidConditionClientCertKeyLength = windows.GUID{
Data1: 0xa3ec00c7,
Data2: 0x05f4,
Data3: 0x4df7,
Data4: [8]byte{0x91, 0xf2, 0x5f, 0x60, 0xd9, 0x1f, 0xf4, 0x43},
}

var guidConditionClientCertOid = windows.GUID{
Data1: 0xc491ad5e,
Data2: 0xf882,
Data3: 0x4283,
Data4: [8]byte{0xb9, 0x16, 0x43, 0x6b, 0x10, 0x3f, 0xf4, 0xad},
}

var guidConditionNetEventType = windows.GUID{
Data1: 0x206e9996,
Data2: 0x490e,
Data3: 0x40cf,
Data4: [8]byte{0xb8, 0x31, 0xb3, 0x86, 0x41, 0xeb, 0x6f, 0xcb},
}

var guidConditionPeerName = windows.GUID{
Data1: 0x9b539082,
Data2: 0xeb90,
Data3: 0x4186,
Data4: [8]byte{0xa6, 0xcc, 0xde, 0x5b, 0x63, 0x23, 0x50, 0x16},
}

var guidConditionRemoteID = windows.GUID{
Data1: 0xf68166fd,
Data2: 0x0682,
Data3: 0x4c89,
Data4: [8]byte{0xb8, 0xf5, 0x86, 0x43, 0x6c, 0x7e, 0xf9, 0xb7},
}

var guidConditionAuthenticationType = windows.GUID{
Data1: 0xeb458cd5,
Data2: 0xda7b,
Data3: 0x4ef9,
Data4: [8]byte{0x8d, 0x43, 0x7b, 0x0a, 0x84, 0x03, 0x32, 0xf2},
}

var guidConditionKMType = windows.GUID{
Data1: 0xff0f5f49,
Data2: 0x0ceb,
Data3: 0x481b,
Data4: [8]byte{0x86, 0x38, 0x14, 0x79, 0x79, 0x1f, 0x3f, 0x2c},
}

var guidConditionKMMode = windows.GUID{
Data1: 0xfeef4582,
Data2: 0xef8f,
Data3: 0x4f7b,
Data4: [8]byte{0x85, 0x8b, 0x90, 0x77, 0xd1, 0x22, 0xde, 0x47},
}

var guidConditionIPSecPolicyKey = windows.GUID{
Data1: 0xad37dee3,
Data2: 0x722f,
Data3: 0x45cc,
Data4: [8]byte{0xa4, 0xe3, 0x06, 0x80, 0x48, 0x12, 0x44, 0x52},
}

var guidConditionQmMode = windows.GUID{
Data1: 0xf64fc6d1,
Data2: 0xf9cb,
Data3: 0x43d2,
Data4: [8]byte{0x8a, 0x5f, 0xe1, 0x3b, 0xc8, 0x94, 0xf2, 0x65},
}

var guidConditionCompartmentID = windows.GUID{
Data1: 0x35a791ab,
Data2: 0x4ac,
Data3: 0x4ff2,
Data4: [8]byte{0xa6, 0xbb, 0xda, 0x6c, 0xfa, 0xc7, 0x18, 0x6},
}

var guidConditionReserved0 = windows.GUID{
Data1: 0x678f4deb,
Data2: 0x45af,
Data3: 0x4882,
Data4: [8]byte{0x93, 0xfe, 0x19, 0xd4, 0x72, 0x9d, 0x98, 0x34},
}

var guidConditionReserved1 = windows.GUID{
Data1: 0xd818f827,
Data2: 0x5c69,
Data3: 0x48eb,
Data4: [8]byte{0xbf, 0x80, 0xd8, 0x6b, 0x17, 0x75, 0x5f, 0x97},
}

var guidConditionReserved2 = windows.GUID{
Data1: 0x53d4123d,
Data2: 0xe15b,
Data3: 0x4e84,
Data4: [8]byte{0xb7, 0xa8,0xdc, 0xe1, 0x6f, 0x7b, 0x62, 0xd9},
}

var guidConditionReserved3 = windows.GUID{
Data1: 0x7f6e8ca3,
Data2: 0x6606,
Data3: 0x4932,
Data4: [8]byte{0x97, 0xc7, 0xe1, 0xf2, 0x07, 0x10, 0xaf, 0x3b},
}

var guidConditionReserved4 = windows.GUID{
Data1: 0x5f58e642,
Data2: 0xb937,
Data3: 0x495e,
Data4: [8]byte{0xa9, 0x4b, 0xf6, 0xb0, 0x51, 0xa4, 0x92, 0x50},
}

var guidConditionReserved5 = windows.GUID{
Data1: 0x9ba8f6cd,
Data2: 0xf77c,
Data3: 0x43e6,
Data4: [8]byte{0x88, 0x47, 0x11, 0x93, 0x9d, 0xc5, 0xdb, 0x5a},
}

var guidConditionReserved6 = windows.GUID{
Data1: 0xf13d84bd,
Data2: 0x59d5,
Data3: 0x44c4,
Data4: [8]byte{0x88, 0x17, 0x5e, 0xcd, 0xae, 0x18, 0x05, 0xbd},
}

var guidConditionReserved7 = windows.GUID{
Data1: 0x65a0f930,
Data2: 0x45dd,
Data3: 0x4983,
Data4: [8]byte{0xaa, 0x33, 0xef, 0xc7, 0xb6, 0x11, 0xaf, 0x08},
}

var guidConditionReserved8 = windows.GUID{
Data1: 0x4f424974,
Data2: 0x0c12,
Data3: 0x4816,
Data4: [8]byte{0x9b, 0x47, 0x9a, 0x54, 0x7d, 0xb3, 0x9a, 0x32},
}

var guidConditionReserved9 = windows.GUID{
Data1: 0xce78e10f,
Data2: 0x13ff,
Data3: 0x4c70,
Data4: [8]byte{0x86, 0x43, 0x36, 0xad, 0x18, 0x79, 0xaf, 0xa3},
}

var guidConditionReserved10 = windows.GUID{
Data1: 0xb979e282,
Data2: 0xd621,
Data3: 0x4c8c,
Data4: [8]byte{0xb1, 0x84, 0xb1, 0x05, 0xa6, 0x1c, 0x36, 0xce},
}

var guidConditionReserved11 = windows.GUID{
Data1: 0x2d62ee4d,
Data2: 0x023d,
Data3: 0x411f,
Data4: [8]byte{0x95, 0x82, 0x43, 0xac, 0xbb, 0x79, 0x59, 0x75},
}

var guidConditionReserved12 = windows.GUID{
Data1: 0xa3677c32,
Data2: 0x7e35,
Data3: 0x4ddc,
Data4: [8]byte{0x93, 0xda, 0xe8, 0xc3, 0x3f, 0xc9, 0x23, 0xc7},
}

var guidConditionReserved13 = windows.GUID{
Data1: 0x335a3e90,
Data2: 0x84aa,
Data3: 0x42f5,
Data4: [8]byte{0x9e, 0x6f, 0x59, 0x30, 0x95, 0x36, 0xa4, 0x4c},
}

var guidConditionReserved14 = windows.GUID{
Data1: 0x30e44da2,
Data2: 0x2f1a,
Data3: 0x4116,
Data4: [8]byte{0xa5, 0x59, 0xf9, 0x07, 0xde, 0x83, 0x60, 0x4a},
}

var guidConditionReserved15 = windows.GUID{
Data1: 0xbab8340f,
Data2: 0xafe0,
Data3: 0x43d1,
Data4: [8]byte{0x80, 0xd8, 0x5c, 0xa4, 0x56, 0x96, 0x2d, 0xe3},
}

var guidProviderIKEExt = windows.GUID{
Data1: 0x10ad9216,
Data2: 0xccde,
Data3: 0x456c,
Data4: [8]byte{0x8b, 0x16, 0xe9, 0xf0, 0x4e, 0x60, 0xa9, 0x0b},
}

var guidProviderIPSecDospConfig = windows.GUID{
Data1: 0x3c6c05a9,
Data2: 0xc05c,
Data3: 0x4bb9,
Data4: [8]byte{0x83, 0x38, 0x23, 0x27, 0x81, 0x4c, 0xe8, 0xbf},
}

var guidProviderTCPChimneyOffload = windows.GUID{
Data1: 0x896aa19e,
Data2: 0x9a34,
Data3: 0x4bcb,
Data4: [8]byte{0xae, 0x79, 0xbe, 0xb9, 0x12, 0x7c, 0x84, 0xb9},
}

var guidProviderTCPTemplates = windows.GUID{
Data1: 0x76cfcd30,
Data2: 0x3394,
Data3: 0x432d,
Data4: [8]byte{0xbe, 0xd3, 0x44, 0x1a, 0xe5, 0x0e, 0x63, 0xc3},
}

var guidCalloutIPSecInboundTransportV4 = windows.GUID{
Data1: 0x5132900d,
Data2: 0x5e84,
Data3: 0x4b5f,
Data4: [8]byte{0x80, 0xe4, 0x01, 0x74, 0x1e, 0x81, 0xff, 0x10},
}

var guidCalloutIPSecInboundTransportV6 = windows.GUID{
Data1: 0x49d3ac92,
Data2: 0x2a6c,
Data3: 0x4dcf,
Data4: [8]byte{0x95, 0x5f, 0x1c, 0x3b, 0xe0, 0x09, 0xdd, 0x99},
}

var guidCalloutIPSecOutboundTransportV4 = windows.GUID{
Data1: 0x4b46bf0a,
Data2: 0x4523,
Data3: 0x4e57,
Data4: [8]byte{0xaa, 0x38, 0xa8, 0x79, 0x87, 0xc9, 0x10, 0xd9},
}

var guidCalloutIPSecOutboundTransportV6 = windows.GUID{
Data1: 0x38d87722,
Data2: 0xad83,
Data3: 0x4f11,
Data4: [8]byte{0xa9, 0x1f, 0xdf, 0x0f, 0xb0, 0x77, 0x22, 0x5b},
}

var guidCalloutIPSecInboundTunnelV4 = windows.GUID{
Data1: 0x191a8a46,
Data2: 0x0bf8,
Data3: 0x46cf,
Data4: [8]byte{0xb0, 0x45, 0x4b, 0x45, 0xdf, 0xa6, 0xa3, 0x24},
}

var guidCalloutIPSecInboundTunnelV6 = windows.GUID{
Data1: 0x80c342e3,
Data2: 0x1e53,
Data3: 0x4d6f,
Data4: [8]byte{0x9b, 0x44, 0x03, 0xdf, 0x5a, 0xee, 0xe1, 0x54},
}

var guidCalloutIPSecOutboundTunnelV4 = windows.GUID{
Data1: 0x70a4196c,
Data2: 0x835b,
Data3: 0x4fb0,
Data4: [8]byte{0x98, 0xe8, 0x07, 0x5f, 0x4d, 0x97, 0x7d, 0x46},
}

var guidCalloutIPSecOutboundTunnelV6 = windows.GUID{
Data1: 0xf1835363,
Data2: 0xa6a5,
Data3: 0x4e62,
Data4: [8]byte{0xb1, 0x80, 0x23, 0xdb, 0x78, 0x9d, 0x8d, 0xa6},
}

var guidCalloutIPSecForwardInboundTunnelV4 = windows.GUID{
Data1: 0x28829633,
Data2: 0xc4f0,
Data3: 0x4e66,
Data4: [8]byte{0x87, 0x3f, 0x84, 0x4d, 0xb2, 0xa8, 0x99, 0xc7},
}

var guidCalloutIPSecForwardInboundTunnelV6 = windows.GUID{
Data1: 0xaf50bec2,
Data2: 0xc686,
Data3: 0x429a,
Data4: [8]byte{0x88, 0x4d, 0xb7, 0x44, 0x43, 0xe7, 0xb0, 0xb4},
}

var guidCalloutIPSecForwardOutboundTunnelV4 = windows.GUID{
Data1: 0xfb532136,
Data2: 0x15cb,
Data3: 0x440b,
Data4: [8]byte{0x93, 0x7c, 0x17, 0x17, 0xca, 0x32, 0x0c, 0x40},
}

var guidCalloutIPSecForwardOutboundTunnelV6 = windows.GUID{
Data1: 0xdae640cc,
Data2: 0xe021,
Data3: 0x4bee,
Data4: [8]byte{0x9e, 0xb6, 0xa4, 0x8b, 0x27, 0x5c, 0x8c, 0x1d},
}

var guidCalloutIPSecInboundInitiateSecureV4 = windows.GUID{
Data1: 0x7dff309b,
Data2: 0xba7d,
Data3: 0x4aba,
Data4: [8]byte{0x91, 0xaa, 0xae, 0x5c, 0x66, 0x40, 0xc9, 0x44},
}

var guidCalloutIPSecInboundInitiateSecureV6 = windows.GUID{
Data1: 0xa9a0d6d9,
Data2: 0xc58c,
Data3: 0x474e,
Data4: [8]byte{0x8a, 0xeb, 0x3c, 0xfe, 0x99, 0xd6, 0xd5, 0x3d},
}

var guidCalloutIPSecInboundTunnelALEAcceptV4 = windows.GUID{
Data1: 0x3df6e7de,
Data2: 0xfd20,
Data3: 0x48f2,
Data4: [8]byte{0x9f, 0x26, 0xf8, 0x54, 0x44, 0x4c, 0xba, 0x79},
}

var guidCalloutIPSecInboundTunnelALEAcceptV6 = windows.GUID{
Data1: 0xa1e392d3,
Data2: 0x72ac,
Data3: 0x47bb,
Data4: [8]byte{0x87, 0xa7, 0x01, 0x22, 0xc6, 0x94, 0x34, 0xab},
}

var guidCalloutIPSecALEConnectV4 = windows.GUID{
Data1: 0x6ac141fc,
Data2: 0xf75d,
Data3: 0x4203,
Data4: [8]byte{0xb9,0xc8,0x48, 0xe6, 0x14, 0x9c, 0x27, 0x12},
}

var guidCalloutIPSecALEConnectV6 = windows.GUID{
Data1: 0x4c0dda05,
Data2: 0xe31f,
Data3: 0x4666,
Data4: [8]byte{0x90, 0xb0, 0xb3, 0xdf, 0xad, 0x34, 0x12, 0x9a},
}

var guidCalloutIPSecDospForwardV6 = windows.GUID{
Data1: 0x6d08a342,
Data2: 0xdb9e,
Data3: 0x4fbe,
Data4: [8]byte{0x9e, 0xd2, 0x57, 0x37, 0x4c, 0xe8, 0x9f, 0x79},
}

var guidCalloutIPSecDospForwardV4 = windows.GUID{
Data1: 0x2fcb56ec,
Data2: 0xcd37,
Data3: 0x4b4f,
Data4: [8]byte{0xb1, 0x08, 0x62, 0xc2, 0xb1, 0x85, 0x0a, 0x0c},
}

var guidCalloutWFPTransportLayerV4SilentDrop = windows.GUID{
Data1: 0xeda08606,
Data2: 0x2494,
Data3: 0x4d78,
Data4: [8]byte{0x89, 0xbc, 0x67, 0x83, 0x7c, 0x03, 0xb9, 0x69},
}

var guidCalloutWFPTransportLayerV6SilentDrop = windows.GUID{
Data1: 0x8693cc74,
Data2: 0xa075,
Data3: 0x4156,
Data4: [8]byte{0xb4, 0x76, 0x92, 0x86, 0xee, 0xce, 0x81, 0x4e},
}

var guidCalloutTCPChimneyConnectLayerV4 = windows.GUID{
Data1: 0xf3e10ab3,
Data2: 0x2c25,
Data3: 0x4279,
Data4: [8]byte{0xac, 0x36, 0xc3, 0x0f, 0xc1, 0x81, 0xbe, 0xc4},
}

var guidCalloutTCPChimneyConnectLayerV6 = windows.GUID{
Data1: 0x39e22085,
Data2: 0xa341,
Data3: 0x42fc,
Data4: [8]byte{0xa2, 0x79, 0xae, 0xc9, 0x4e, 0x68, 0x9c, 0x56},
}

var guidCalloutTCPChimneyAcceptLayerV4 = windows.GUID{
Data1: 0xe183ecb2,
Data2: 0x3a7f,
Data3: 0x4b54,
Data4: [8]byte{0x8a, 0xd9, 0x76, 0x05, 0x0e, 0xd8, 0x80, 0xca},
}

var guidCalloutTCPChimneyAcceptLayerV6 = windows.GUID{
Data1: 0x0378cf41,
Data2: 0xbf98,
Data3: 0x4603,
Data4: [8]byte{0x81, 0xf2, 0x7f, 0x12, 0x58, 0x60, 0x79, 0xf6},
}

var guidCalloutSetOptionsAuthConnectLayerV4 = windows.GUID{
Data1: 0xbc582280,
Data2: 0x1677,
Data3: 0x41e9,
Data4: [8]byte{0x94, 0xab, 0xc2, 0xfc, 0xb1, 0x5c, 0x2e, 0xeb},
}

var guidCalloutSetOptionsAuthConnectLayerV6 = windows.GUID{
Data1: 0x98e5373c,
Data2: 0xb884,
Data3: 0x490f,
Data4: [8]byte{0xb6, 0x5f, 0x2f, 0x6a, 0x4a, 0x57, 0x51, 0x95},
}

var guidCalloutSetOptionsAuthRecvAcceptLayerV4 = windows.GUID{
Data1: 0x2d55f008,
Data2: 0x0c01,
Data3: 0x4f92,
Data4: [8]byte{0xb2, 0x6e, 0xa0, 0x8a, 0x94, 0x56, 0x9b, 0x8d},
}

var guidCalloutSetOptionsAuthRecvAcceptLayerV6 = windows.GUID{
Data1: 0x63018537,
Data2: 0xf281,
Data3: 0x4dc4,
Data4: [8]byte{0x83, 0xd3, 0x8d, 0xec, 0x18, 0xb7, 0xad, 0xe2},
}

var guidCalloutReservedAuthConnectLayerV4 = windows.GUID{
Data1: 0x288b524d,
Data2: 0x566,
Data3: 0x4e19,
Data4: [8]byte{0xb6, 0x12, 0x8f, 0x44, 0x1a, 0x2e, 0x59, 0x49},
}

var guidCalloutReservedAuthConnectLayerV6 = windows.GUID{
Data1: 0xb84b92,
Data2: 0x2b5e,
Data3: 0x4b71,
Data4: [8]byte{0xab, 0xe, 0xaa, 0xca, 0x43, 0xe3, 0x87, 0xe6},
}

var guidCalloutTeredoALEResourceAssignmentV6 = windows.GUID{
Data1: 0x31b95392,
Data2: 0x066e,
Data3: 0x42a2,
Data4: [8]byte{0xb7, 0xdb, 0x92, 0xf8, 0xac, 0xdd, 0x56, 0xf9},
}

var guidCalloutEdgeTraversalALEResourceAssignmentV4 = windows.GUID{
Data1: 0x079b1010,
Data2: 0xf1c5,
Data3: 0x4fcd,
Data4: [8]byte{0xae, 0x05, 0xda, 0x41, 0x10, 0x7a, 0xbd, 0x0b},
}

var guidCalloutTeredoALEListenV6 = windows.GUID{
Data1: 0x81a434e7,
Data2: 0xf60c,
Data3: 0x4378,
Data4: [8]byte{0xba, 0xb8, 0xc6, 0x25, 0xa3, 0x0f, 0x01, 0x97},
}

var guidCalloutEdgeTraversalALEListenV4 = windows.GUID{
Data1: 0x33486ab5,
Data2: 0x6d5e,
Data3: 0x4e65,
Data4: [8]byte{0xa0, 0x0b, 0xa7, 0xaf, 0xed, 0x0b, 0xa9, 0xa1},
}

var guidCalloutTCPTemplatesConnectLayerV4 = windows.GUID{
Data1: 0x215a0b39,
Data2: 0x4b7e,
Data3: 0x4eda,
Data4: [8]byte{0x8c, 0xe4, 0x17, 0x96, 0x79, 0xdf, 0x62, 0x24},
}

var guidCalloutTCPTemplatesConnectLayerV6 = windows.GUID{
Data1: 0x838b37a1,
Data2: 0x5c12,
Data3: 0x4d34,
Data4: [8]byte{0x8b, 0x38, 0x07, 0x87, 0x28, 0xb2, 0xd2, 0x5c},
}

var guidCalloutTCPTemplatesAcceptLayerV4 = windows.GUID{
Data1: 0x2f23f5d0,
Data2: 0x40c4,
Data3: 0x4c41,
Data4: [8]byte{0xa2, 0x54, 0x46, 0xd8, 0xdb, 0xa8, 0x95, 0x7c},
}

var guidCalloutTCPTemplatesAcceptLayerV6 = windows.GUID{
Data1: 0xb25152f0,
Data2: 0x991c,
Data3: 0x4f53,
Data4: [8]byte{0xbb, 0xe7, 0xd2, 0x4b, 0x45, 0xfe, 0x63, 0x2c},
}

var guidCalloutPolicySilentModeAuthConnectLayerV4 = windows.GUID{
Data1: 0x5fbfc31d,
Data2: 0xa51c,
Data3: 0x44dc,
Data4: [8]byte{0xac, 0xb6, 0x6, 0x24, 0xa0, 0x30, 0xa7, 0x00},
}

var guidCalloutPolicySilentModeAuthConnectLayerV6 = windows.GUID{
Data1: 0x5fbfc31d,
Data2: 0xa51c,
Data3: 0x44dc,
Data4: [8]byte{0xac, 0xb6, 0x6, 0x24, 0xa0, 0x30, 0xa7, 0x01},
}

var guidCalloutPolicySilentModeAuthRecvAcceptLayerV4 = windows.GUID{
Data1: 0x5fbfc31d,
Data2: 0xa51c,
Data3: 0x44dc,
Data4: [8]byte{0xac, 0xb6, 0x6, 0x24, 0xa0, 0x30, 0xa7, 0x02},
}

var guidCalloutPolicySilentModeAuthRecvAcceptLayerV6 = windows.GUID{
Data1: 0x5fbfc31d,
Data2: 0xa51c,
Data3: 0x44dc,
Data4: [8]byte{0xac, 0xb6, 0x6, 0x24, 0xa0, 0x30, 0xa7, 0x03},
}

var guidCalloutHttpTemplateSslHandshake = windows.GUID{
Data1: 0xb3423249,
Data2: 0x8d09,
Data3: 0x4858,
Data4: [8]byte{0x92, 0x10, 0x95, 0xc7, 0xfd, 0xa8, 0xe3, 0x0f},
}

var guidProviderContextSecureSocketAuthIP = windows.GUID{
Data1: 0xb25ea800,
Data2: 0x0d02,
Data3: 0x46ed,
Data4: [8]byte{0x92, 0xbd, 0x7f, 0xa8, 0x4b, 0xb7, 0x3e, 0x9d},
}

var guidProviderContextSecureSocketIPSec = windows.GUID{
Data1: 0x8c2d4144,
Data2: 0xf8e0,
Data3: 0x42c0,
Data4: [8]byte{0x94, 0xce, 0x7c, 0xcf, 0xc6, 0x3b, 0x2f, 0x9b},
}

var guidKeyingModuleIKE = windows.GUID{
Data1: 0xa9bbf787,
Data2: 0x82a8,
Data3: 0x45bb,
Data4: [8]byte{0xa4, 0x00, 0x5d, 0x7e, 0x59, 0x52, 0xc7, 0xa9},
}

var guidKeyingModuleAuthIP = windows.GUID{
Data1: 0x11e3dae0,
Data2: 0xdd26,
Data3: 0x4590,
Data4: [8]byte{0x85, 0x7d, 0xab, 0x4b, 0x28, 0xd1, 0xa0, 0x95},
}

var guidKeyingModuleIKEv2 = windows.GUID{
Data1: 0x041792cc,
Data2: 0x8f07,
Data3: 0x419d,
Data4: [8]byte{0xa3, 0x94, 0x71, 0x69, 0x68, 0xcb, 0x16, 0x47},
}

var guidNames = map[windows.GUID]string{
guidLayerInboundIPPacketV4: "FWPM_LAYER_INBOUND_IPPACKET_V4",
guidLayerInboundIPPacketV4Discard: "FWPM_LAYER_INBOUND_IPPACKET_V4_DISCARD",
guidLayerInboundIPPacketV6: "FWPM_LAYER_INBOUND_IPPACKET_V6",
guidLayerInboundIPPacketV6Discard: "FWPM_LAYER_INBOUND_IPPACKET_V6_DISCARD",
guidLayerOutboundIPPacketV4: "FWPM_LAYER_OUTBOUND_IPPACKET_V4",
guidLayerOutboundIPPacketV4Discard: "FWPM_LAYER_OUTBOUND_IPPACKET_V4_DISCARD",
guidLayerOutboundIPPacketV6: "FWPM_LAYER_OUTBOUND_IPPACKET_V6",
guidLayerOutboundIPPacketV6Discard: "FWPM_LAYER_OUTBOUND_IPPACKET_V6_DISCARD",
guidLayerIPForwardV4: "FWPM_LAYER_IPFORWARD_V4",
guidLayerIPForwardV4Discard: "FWPM_LAYER_IPFORWARD_V4_DISCARD",
guidLayerIPForwardV6: "FWPM_LAYER_IPFORWARD_V6",
guidLayerIPForwardV6Discard: "FWPM_LAYER_IPFORWARD_V6_DISCARD",
guidLayerInboundTransportV4: "FWPM_LAYER_INBOUND_TRANSPORT_V4",
guidLayerInboundTransportV4Discard: "FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD",
guidLayerInboundTransportV6: "FWPM_LAYER_INBOUND_TRANSPORT_V6",
guidLayerInboundTransportV6Discard: "FWPM_LAYER_INBOUND_TRANSPORT_V6_DISCARD",
guidLayerOutboundTransportV4: "FWPM_LAYER_OUTBOUND_TRANSPORT_V4",
guidLayerOutboundTransportV4Discard: "FWPM_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD",
guidLayerOutboundTransportV6: "FWPM_LAYER_OUTBOUND_TRANSPORT_V6",
guidLayerOutboundTransportV6Discard: "FWPM_LAYER_OUTBOUND_TRANSPORT_V6_DISCARD",
guidLayerStreamV4: "FWPM_LAYER_STREAM_V4",
guidLayerStreamV4Discard: "FWPM_LAYER_STREAM_V4_DISCARD",
guidLayerStreamV6: "FWPM_LAYER_STREAM_V6",
guidLayerStreamV6Discard: "FWPM_LAYER_STREAM_V6_DISCARD",
guidLayerDatagramDataV4: "FWPM_LAYER_DATAGRAM_DATA_V4",
guidLayerDatagramDataV4Discard: "FWPM_LAYER_DATAGRAM_DATA_V4_DISCARD",
guidLayerDatagramDataV6: "FWPM_LAYER_DATAGRAM_DATA_V6",
guidLayerDatagramDataV6Discard: "FWPM_LAYER_DATAGRAM_DATA_V6_DISCARD",
guidLayerInboundICMPErrorV4: "FWPM_LAYER_INBOUND_ICMP_ERROR_V4",
guidLayerInboundICMPErrorV4Discard: "FWPM_LAYER_INBOUND_ICMP_ERROR_V4_DISCARD",
guidLayerInboundICMPErrorV6: "FWPM_LAYER_INBOUND_ICMP_ERROR_V6",
guidLayerInboundICMPErrorV6Discard: "FWPM_LAYER_INBOUND_ICMP_ERROR_V6_DISCARD",
guidLayerOutboundICMPErrorV4: "FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4",
guidLayerOutboundICMPErrorV4Discard: "FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4_DISCARD",
guidLayerOutboundICMPErrorV6: "FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6",
guidLayerOutboundICMPErrorV6Discard: "FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6_DISCARD",
guidLayerALEResourceAssignmentV4: "FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4",
guidLayerALEResourceAssignmentV4Discard: "FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4_DISCARD",
guidLayerALEResourceAssignmentV6: "FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6",
guidLayerALEResourceAssignmentV6Discard: "FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6_DISCARD",
guidLayerALEAuthListenV4: "FWPM_LAYER_ALE_AUTH_LISTEN_V4",
guidLayerALEAuthListenV4Discard: "FWPM_LAYER_ALE_AUTH_LISTEN_V4_DISCARD",
guidLayerALEAuthListenV6: "FWPM_LAYER_ALE_AUTH_LISTEN_V6",
guidLayerALEAuthListenV6Discard: "FWPM_LAYER_ALE_AUTH_LISTEN_V6_DISCARD",
guidLayerALEAuthRecvAcceptV4: "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
guidLayerALEAuthRecvAcceptV4Discard: "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD",
guidLayerALEAuthRecvAcceptV6: "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6",
guidLayerALEAuthRecvAcceptV6Discard: "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6_DISCARD",
guidLayerALEAuthConnectV4: "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
guidLayerALEAuthConnectV4Discard: "FWPM_LAYER_ALE_AUTH_CONNECT_V4_DISCARD",
guidLayerALEAuthConnectV6: "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
guidLayerALEAuthConnectV6Discard: "FWPM_LAYER_ALE_AUTH_CONNECT_V6_DISCARD",
guidLayerALEFlowEstablishedV4: "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4",
guidLayerALEFlowEstablishedV4Discard: "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD",
guidLayerALEFlowEstablishedV6: "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6",
guidLayerALEFlowEstablishedV6Discard: "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6_DISCARD",
guidLayerInboundMACFrameEthernet: "FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET",
guidLayerOutboundMACFrameEthernet: "FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET",
guidLayerInboundMACFrameNative: "FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE",
guidLayerOutboundMACFrameNative: "FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE",
guidLayerIngressVswitchEthernet: "FWPM_LAYER_INGRESS_VSWITCH_ETHERNET",
guidLayerEgressVswitchEthernet: "FWPM_LAYER_EGRESS_VSWITCH_ETHERNET",
guidLayerIngressVswitchTransportV4: "FWPM_LAYER_INGRESS_VSWITCH_TRANSPORT_V4",
guidLayerIngressVswitchTransportV6: "FWPM_LAYER_INGRESS_VSWITCH_TRANSPORT_V6",
guidLayerEgressVswitchTransportV4: "FWPM_LAYER_EGRESS_VSWITCH_TRANSPORT_V4",
guidLayerEgressVswitchTransportV6: "FWPM_LAYER_EGRESS_VSWITCH_TRANSPORT_V6",
guidLayerInboundTransportFast: "FWPM_LAYER_INBOUND_TRANSPORT_FAST",
guidLayerOutboundTransportFast: "FWPM_LAYER_OUTBOUND_TRANSPORT_FAST",
guidLayerInboundMACFrameNativeFast: "FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE_FAST",
guidLayerOutboundMACFrameNativeFast: "FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE_FAST",
guidLayerIPSecKMDemuxV4: "FWPM_LAYER_IPSEC_KM_DEMUX_V4",
guidLayerIPSecKMDemuxV6: "FWPM_LAYER_IPSEC_KM_DEMUX_V6",
guidLayerIPSecV4: "FWPM_LAYER_IPSEC_V4",
guidLayerIPSecV6: "FWPM_LAYER_IPSEC_V6",
guidLayerIKEExtV4: "FWPM_LAYER_IKEEXT_V4",
guidLayerIKEExtV6: "FWPM_LAYER_IKEEXT_V6",
guidLayerRPCUM: "FWPM_LAYER_RPC_UM",
guidLayerRPCEPMap: "FWPM_LAYER_RPC_EPMAP",
guidLayerRPCEPAdd: "FWPM_LAYER_RPC_EP_ADD",
guidLayerRPCProxyConn: "FWPM_LAYER_RPC_PROXY_CONN",
guidLayerRPCProxyIf: "FWPM_LAYER_RPC_PROXY_IF",
guidLayerKMAuthorization: "FWPM_LAYER_KM_AUTHORIZATION",
guidLayerNameResolutionCacheV4: "FWPM_LAYER_NAME_RESOLUTION_CACHE_V4",
guidLayerNameResolutionCacheV6: "FWPM_LAYER_NAME_RESOLUTION_CACHE_V6",
guidLayerALEResourceReleaseV4: "FWPM_LAYER_ALE_RESOURCE_RELEASE_V4",
guidLayerALEResourceReleaseV6: "FWPM_LAYER_ALE_RESOURCE_RELEASE_V6",
guidLayerALEEndpointClosureV4: "FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4",
guidLayerALEEndpointClosureV6: "FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6",
guidLayerALEConnectRedirectV4: "FWPM_LAYER_ALE_CONNECT_REDIRECT_V4",
guidLayerALEConnectRedirectV6: "FWPM_LAYER_ALE_CONNECT_REDIRECT_V6",
guidLayerALEBindRedirectV4: "FWPM_LAYER_ALE_BIND_REDIRECT_V4",
guidLayerALEBindRedirectV6: "FWPM_LAYER_ALE_BIND_REDIRECT_V6",
guidLayerStreamPacketV4: "FWPM_LAYER_STREAM_PACKET_V4",
guidLayerStreamPacketV6: "FWPM_LAYER_STREAM_PACKET_V6",
guidLayerInboundReserved2: "FWPM_LAYER_INBOUND_RESERVED2",
guidSublayerRPCAudit: "FWPM_SUBLAYER_RPC_AUDIT",
guidSublayerIPSecTunnel: "FWPM_SUBLAYER_IPSEC_TUNNEL",
guidSublayerUniversal: "FWPM_SUBLAYER_UNIVERSAL",
guidSublayerLIPS: "FWPM_SUBLAYER_LIPS",
guidSublayerSecureSocket: "FWPM_SUBLAYER_SECURE_SOCKET",
guidSublayerTCPChimneyOffload: "FWPM_SUBLAYER_TCP_CHIMNEY_OFFLOAD",
guidSublayerInspection: "FWPM_SUBLAYER_INSPECTION",
guidSublayerTeredo: "FWPM_SUBLAYER_TEREDO",
guidSublayerIPSecForwardOutboundTunnel: "FWPM_SUBLAYER_IPSEC_FORWARD_OUTBOUND_TUNNEL",
guidSublayerIPSecDosp: "FWPM_SUBLAYER_IPSEC_DOSP",
guidSublayerTCPTemplates: "FWPM_SUBLAYER_TCP_TEMPLATES",
guidSublayerIPSecSecurityRealm: "FWPM_SUBLAYER_IPSEC_SECURITY_REALM",
guidConditionInterfaceMACAddress: "FWPM_CONDITION_INTERFACE_MAC_ADDRESS",
guidConditionMACLocalAddress: "FWPM_CONDITION_MAC_LOCAL_ADDRESS",
guidConditionMACRemoteAddress: "FWPM_CONDITION_MAC_REMOTE_ADDRESS",
guidConditionEtherType: "FWPM_CONDITION_ETHER_TYPE",
guidConditionVLANID: "FWPM_CONDITION_VLAN_ID",
guidConditionVswitchTenantNetworkID: "FWPM_CONDITION_VSWITCH_TENANT_NETWORK_ID",
guidConditionNdisPort: "FWPM_CONDITION_NDIS_PORT",
guidConditionNdisMediaType: "FWPM_CONDITION_NDIS_MEDIA_TYPE",
guidConditionNdisPhysicalMediaType: "FWPM_CONDITION_NDIS_PHYSICAL_MEDIA_TYPE",
guidConditionL2Flags: "FWPM_CONDITION_L2_FLAGS",
guidConditionMACLocalAddressType: "FWPM_CONDITION_MAC_LOCAL_ADDRESS_TYPE",
guidConditionMACRemoteAddressType: "FWPM_CONDITION_MAC_REMOTE_ADDRESS_TYPE",
guidConditionALEPackageID: "FWPM_CONDITION_ALE_PACKAGE_ID",
guidConditionMACSourceAddress: "FWPM_CONDITION_MAC_SOURCE_ADDRESS",
guidConditionMACDestinationAddress: "FWPM_CONDITION_MAC_DESTINATION_ADDRESS",
guidConditionMACSourceAddressType: "FWPM_CONDITION_MAC_SOURCE_ADDRESS_TYPE",
guidConditionMACDestinationAddressType: "FWPM_CONDITION_MAC_DESTINATION_ADDRESS_TYPE",
guidConditionIPSourcePort: "FWPM_CONDITION_IP_SOURCE_PORT",
guidConditionIPDestinationPort: "FWPM_CONDITION_IP_DESTINATION_PORT",
guidConditionVswitchID: "FWPM_CONDITION_VSWITCH_ID",
guidConditionVswitchNetworkType: "FWPM_CONDITION_VSWITCH_NETWORK_TYPE",
guidConditionVswitchSourceInterfaceID: "FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_ID",
guidConditionVswitchDestinationInterfaceID: "FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_ID",
guidConditionVswitchSourceVmID: "FWPM_CONDITION_VSWITCH_SOURCE_VM_ID",
guidConditionVswitchDestinationVmID: "FWPM_CONDITION_VSWITCH_DESTINATION_VM_ID",
guidConditionVswitchSourceInterfaceType: "FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_TYPE",
guidConditionVswitchDestinationInterfaceType: "FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_TYPE",
guidConditionALESecurityAttributeFqbnValue: "FWPM_CONDITION_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE",
guidConditionIPSecSecurityRealmID: "FWPM_CONDITION_IPSEC_SECURITY_REALM_ID",
guidConditionALEEffectiveName: "FWPM_CONDITION_ALE_EFFECTIVE_NAME",
guidConditionIPLocalAddress: "FWPM_CONDITION_IP_LOCAL_ADDRESS",
guidConditionIPRemoteAddress: "FWPM_CONDITION_IP_REMOTE_ADDRESS",
guidConditionIPSourceAddress: "FWPM_CONDITION_IP_SOURCE_ADDRESS",
guidConditionIPDestinationAddress: "FWPM_CONDITION_IP_DESTINATION_ADDRESS",
guidConditionIPLocalAddressType: "FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE",
guidConditionIPDestinationAddressType: "FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE",
guidConditionBitmapIPLocalAddress: "FWPM_CONDITION_BITMAP_IP_LOCAL_ADDRESS",
guidConditionBitmapIPLocalPort: "FWPM_CONDITION_BITMAP_IP_LOCAL_PORT",
guidConditionBitmapIPRemoteAddress: "FWPM_CONDITION_BITMAP_IP_REMOTE_ADDRESS",
guidConditionBitmapIPRemotePort: "FWPM_CONDITION_BITMAP_IP_REMOTE_PORT",
guidConditionIPNexthopAddress: "FWPM_CONDITION_IP_NEXTHOP_ADDRESS",
guidConditionBitmapIndexKey: "FWPM_CONDITION_BITMAP_INDEX_KEY",
guidConditionIPLocalInterface: "FWPM_CONDITION_IP_LOCAL_INTERFACE",
guidConditionIPArrivalInterface: "FWPM_CONDITION_IP_ARRIVAL_INTERFACE",
guidConditionArrivalInterfaceType: "FWPM_CONDITION_ARRIVAL_INTERFACE_TYPE",
guidConditionArrivalTunnelType: "FWPM_CONDITION_ARRIVAL_TUNNEL_TYPE",
guidConditionArrivalInterfaceIndex: "FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX",
guidConditionNexthopSubInterfaceIndex: "FWPM_CONDITION_NEXTHOP_SUB_INTERFACE_INDEX",
guidConditionIPNexthopInterface: "FWPM_CONDITION_IP_NEXTHOP_INTERFACE",
guidConditionNexthopInterfaceType: "FWPM_CONDITION_NEXTHOP_INTERFACE_TYPE",
guidConditionNexthopTunnelType: "FWPM_CONDITION_NEXTHOP_TUNNEL_TYPE",
guidConditionNexthopInterfaceIndex: "FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX",
guidConditionOriginalProfileID: "FWPM_CONDITION_ORIGINAL_PROFILE_ID",
guidConditionCurrentProfileID: "FWPM_CONDITION_CURRENT_PROFILE_ID",
guidConditionLocalInterfaceProfileID: "FWPM_CONDITION_LOCAL_INTERFACE_PROFILE_ID",
guidConditionArrivalInterfaceProfileID: "FWPM_CONDITION_ARRIVAL_INTERFACE_PROFILE_ID",
guidConditionNexthopInterfaceProfileID: "FWPM_CONDITION_NEXTHOP_INTERFACE_PROFILE_ID",
guidConditionReauthorizeReason: "FWPM_CONDITION_REAUTHORIZE_REASON",
guidConditionOriginalICMPType: "FWPM_CONDITION_ORIGINAL_ICMP_TYPE",
guidConditionIPPhysicalArrivalInterface: "FWPM_CONDITION_IP_PHYSICAL_ARRIVAL_INTERFACE",
guidConditionIPPhysicalNexthopInterface: "FWPM_CONDITION_IP_PHYSICAL_NEXTHOP_INTERFACE",
guidConditionInterfaceQuarantineEpoch: "FWPM_CONDITION_INTERFACE_QUARANTINE_EPOCH",
guidConditionInterfaceType: "FWPM_CONDITION_INTERFACE_TYPE",
guidConditionTunnelType: "FWPM_CONDITION_TUNNEL_TYPE",
guidConditionIPForwardInterface: "FWPM_CONDITION_IP_FORWARD_INTERFACE",
guidConditionIPProtocol: "FWPM_CONDITION_IP_PROTOCOL",
guidConditionIPLocalPort: "FWPM_CONDITION_IP_LOCAL_PORT",
guidConditionIPRemotePort: "FWPM_CONDITION_IP_REMOTE_PORT",
guidConditionEmbeddedLocalAddressType: "FWPM_CONDITION_EMBEDDED_LOCAL_ADDRESS_TYPE",
guidConditionEmbeddedRemoteAddress: "FWPM_CONDITION_EMBEDDED_REMOTE_ADDRESS",
guidConditionEmbeddedProtocol: "FWPM_CONDITION_EMBEDDED_PROTOCOL",
guidConditionEmbeddedLocalPort: "FWPM_CONDITION_EMBEDDED_LOCAL_PORT",
guidConditionEmbeddedRemotePort: "FWPM_CONDITION_EMBEDDED_REMOTE_PORT",
guidConditionFlags: "FWPM_CONDITION_FLAGS",
guidConditionDirection: "FWPM_CONDITION_DIRECTION",
guidConditionInterfaceIndex: "FWPM_CONDITION_INTERFACE_INDEX",
guidConditionSubInterfaceIndex: "FWPM_CONDITION_SUB_INTERFACE_INDEX",
guidConditionSourceInterfaceIndex: "FWPM_CONDITION_SOURCE_INTERFACE_INDEX",
guidConditionSourceSubInterfaceIndex: "FWPM_CONDITION_SOURCE_SUB_INTERFACE_INDEX",
guidConditionDestinationInterfaceIndex: "FWPM_CONDITION_DESTINATION_INTERFACE_INDEX",
guidConditionDestinationSubInterfaceIndex: "FWPM_CONDITION_DESTINATION_SUB_INTERFACE_INDEX",
guidConditionALEAppID: "FWPM_CONDITION_ALE_APP_ID",
guidConditionALEOriginalAppID: "FWPM_CONDITION_ALE_ORIGINAL_APP_ID",
guidConditionALEUserID: "FWPM_CONDITION_ALE_USER_ID",
guidConditionALERemoteUserID: "FWPM_CONDITION_ALE_REMOTE_USER_ID",
guidConditionALERemoteMachineID: "FWPM_CONDITION_ALE_REMOTE_MACHINE_ID",
guidConditionALEPromiscuousMode: "FWPM_CONDITION_ALE_PROMISCUOUS_MODE",
guidConditionALESioFirewallSystemPort: "FWPM_CONDITION_ALE_SIO_FIREWALL_SYSTEM_PORT",
guidConditionALEReauthReason: "FWPM_CONDITION_ALE_REAUTH_REASON",
guidConditionALENapContext: "FWPM_CONDITION_ALE_NAP_CONTEXT",
guidConditionKMAuthNapContext: "FWPM_CONDITION_KM_AUTH_NAP_CONTEXT",
guidConditionRemoteUserToken: "FWPM_CONDITION_REMOTE_USER_TOKEN",
guidConditionRPCIfUUID: "FWPM_CONDITION_RPC_IF_UUID",
guidConditionRPCIfVersion: "FWPM_CONDITION_RPC_IF_VERSION",
guidConditionRPCIfFlag: "FWPM_CONDITION_RPC_IF_FLAG",
guidConditionDCOMAppID: "FWPM_CONDITION_DCOM_APP_ID",
guidConditionImageName: "FWPM_CONDITION_IMAGE_NAME",
guidConditionRPCProtocol: "FWPM_CONDITION_RPC_PROTOCOL",
guidConditionRPCAuthType: "FWPM_CONDITION_RPC_AUTH_TYPE",
guidConditionRPCAuthLevel: "FWPM_CONDITION_RPC_AUTH_LEVEL",
guidConditionSecEncryptAlgorithm: "FWPM_CONDITION_SEC_ENCRYPT_ALGORITHM",
guidConditionSecKeySize: "FWPM_CONDITION_SEC_KEY_SIZE",
guidConditionIPLocalAddressV4: "FWPM_CONDITION_IP_LOCAL_ADDRESS_V4",
guidConditionIPLocalAddressV6: "FWPM_CONDITION_IP_LOCAL_ADDRESS_V6",
guidConditionPipe: "FWPM_CONDITION_PIPE",
guidConditionIPRemoteAddressV4: "FWPM_CONDITION_IP_REMOTE_ADDRESS_V4",
guidConditionIPRemoteAddressV6: "FWPM_CONDITION_IP_REMOTE_ADDRESS_V6",
guidConditionProcessWithRPCIfUUID: "FWPM_CONDITION_PROCESS_WITH_RPC_IF_UUID",
guidConditionRPCEPValue: "FWPM_CONDITION_RPC_EP_VALUE",
guidConditionRPCEPFlags: "FWPM_CONDITION_RPC_EP_FLAGS",
guidConditionClientToken: "FWPM_CONDITION_CLIENT_TOKEN",
guidConditionRPCServerName: "FWPM_CONDITION_RPC_SERVER_NAME",
guidConditionRPCServerPort: "FWPM_CONDITION_RPC_SERVER_PORT",
guidConditionRPCProxyAuthType: "FWPM_CONDITION_RPC_PROXY_AUTH_TYPE",
guidConditionClientCertKeyLength: "FWPM_CONDITION_CLIENT_CERT_KEY_LENGTH",
guidConditionClientCertOid: "FWPM_CONDITION_CLIENT_CERT_OID",
guidConditionNetEventType: "FWPM_CONDITION_NET_EVENT_TYPE",
guidConditionPeerName: "FWPM_CONDITION_PEER_NAME",
guidConditionRemoteID: "FWPM_CONDITION_REMOTE_ID",
guidConditionAuthenticationType: "FWPM_CONDITION_AUTHENTICATION_TYPE",
guidConditionKMType: "FWPM_CONDITION_KM_TYPE",
guidConditionKMMode: "FWPM_CONDITION_KM_MODE",
guidConditionIPSecPolicyKey: "FWPM_CONDITION_IPSEC_POLICY_KEY",
guidConditionQmMode: "FWPM_CONDITION_QM_MODE",
guidConditionCompartmentID: "FWPM_CONDITION_COMPARTMENT_ID",
guidConditionReserved0: "FWPM_CONDITION_RESERVED0",
guidConditionReserved1: "FWPM_CONDITION_RESERVED1",
guidConditionReserved2: "FWPM_CONDITION_RESERVED2",
guidConditionReserved3: "FWPM_CONDITION_RESERVED3",
guidConditionReserved4: "FWPM_CONDITION_RESERVED4",
guidConditionReserved5: "FWPM_CONDITION_RESERVED5",
guidConditionReserved6: "FWPM_CONDITION_RESERVED6",
guidConditionReserved7: "FWPM_CONDITION_RESERVED7",
guidConditionReserved8: "FWPM_CONDITION_RESERVED8",
guidConditionReserved9: "FWPM_CONDITION_RESERVED9",
guidConditionReserved10: "FWPM_CONDITION_RESERVED10",
guidConditionReserved11: "FWPM_CONDITION_RESERVED11",
guidConditionReserved12: "FWPM_CONDITION_RESERVED12",
guidConditionReserved13: "FWPM_CONDITION_RESERVED13",
guidConditionReserved14: "FWPM_CONDITION_RESERVED14",
guidConditionReserved15: "FWPM_CONDITION_RESERVED15",
guidProviderIKEExt: "FWPM_PROVIDER_IKEEXT",
guidProviderIPSecDospConfig: "FWPM_PROVIDER_IPSEC_DOSP_CONFIG",
guidProviderTCPChimneyOffload: "FWPM_PROVIDER_TCP_CHIMNEY_OFFLOAD",
guidProviderTCPTemplates: "FWPM_PROVIDER_TCP_TEMPLATES",
guidCalloutIPSecInboundTransportV4: "FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V4",
guidCalloutIPSecInboundTransportV6: "FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V6",
guidCalloutIPSecOutboundTransportV4: "FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V4",
guidCalloutIPSecOutboundTransportV6: "FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V6",
guidCalloutIPSecInboundTunnelV4: "FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_V4",
guidCalloutIPSecInboundTunnelV6: "FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_V6",
guidCalloutIPSecOutboundTunnelV4: "FWPM_CALLOUT_IPSEC_OUTBOUND_TUNNEL_V4",
guidCalloutIPSecOutboundTunnelV6: "FWPM_CALLOUT_IPSEC_OUTBOUND_TUNNEL_V6",
guidCalloutIPSecForwardInboundTunnelV4: "FWPM_CALLOUT_IPSEC_FORWARD_INBOUND_TUNNEL_V4",
guidCalloutIPSecForwardInboundTunnelV6: "FWPM_CALLOUT_IPSEC_FORWARD_INBOUND_TUNNEL_V6",
guidCalloutIPSecForwardOutboundTunnelV4: "FWPM_CALLOUT_IPSEC_FORWARD_OUTBOUND_TUNNEL_V4",
guidCalloutIPSecForwardOutboundTunnelV6: "FWPM_CALLOUT_IPSEC_FORWARD_OUTBOUND_TUNNEL_V6",
guidCalloutIPSecInboundInitiateSecureV4: "FWPM_CALLOUT_IPSEC_INBOUND_INITIATE_SECURE_V4",
guidCalloutIPSecInboundInitiateSecureV6: "FWPM_CALLOUT_IPSEC_INBOUND_INITIATE_SECURE_V6",
guidCalloutIPSecInboundTunnelALEAcceptV4: "FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_ALE_ACCEPT_V4",
guidCalloutIPSecInboundTunnelALEAcceptV6: "FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_ALE_ACCEPT_V6",
guidCalloutIPSecALEConnectV4: "FWPM_CALLOUT_IPSEC_ALE_CONNECT_V4",
guidCalloutIPSecALEConnectV6: "FWPM_CALLOUT_IPSEC_ALE_CONNECT_V6",
guidCalloutIPSecDospForwardV6: "FWPM_CALLOUT_IPSEC_DOSP_FORWARD_V6",
guidCalloutIPSecDospForwardV4: "FWPM_CALLOUT_IPSEC_DOSP_FORWARD_V4",
guidCalloutWFPTransportLayerV4SilentDrop: "FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V4_SILENT_DROP",
guidCalloutWFPTransportLayerV6SilentDrop: "FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V6_SILENT_DROP",
guidCalloutTCPChimneyConnectLayerV4: "FWPM_CALLOUT_TCP_CHIMNEY_CONNECT_LAYER_V4",
guidCalloutTCPChimneyConnectLayerV6: "FWPM_CALLOUT_TCP_CHIMNEY_CONNECT_LAYER_V6",
guidCalloutTCPChimneyAcceptLayerV4: "FWPM_CALLOUT_TCP_CHIMNEY_ACCEPT_LAYER_V4",
guidCalloutTCPChimneyAcceptLayerV6: "FWPM_CALLOUT_TCP_CHIMNEY_ACCEPT_LAYER_V6",
guidCalloutSetOptionsAuthConnectLayerV4: "FWPM_CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V4",
guidCalloutSetOptionsAuthConnectLayerV6: "FWPM_CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V6",
guidCalloutSetOptionsAuthRecvAcceptLayerV4: "FWPM_CALLOUT_SET_OPTIONS_AUTH_RECV_ACCEPT_LAYER_V4",
guidCalloutSetOptionsAuthRecvAcceptLayerV6: "FWPM_CALLOUT_SET_OPTIONS_AUTH_RECV_ACCEPT_LAYER_V6",
guidCalloutReservedAuthConnectLayerV4: "FWPM_CALLOUT_RESERVED_AUTH_CONNECT_LAYER_V4",
guidCalloutReservedAuthConnectLayerV6: "FWPM_CALLOUT_RESERVED_AUTH_CONNECT_LAYER_V6",
guidCalloutTeredoALEResourceAssignmentV6: "FWPM_CALLOUT_TEREDO_ALE_RESOURCE_ASSIGNMENT_V6",
guidCalloutEdgeTraversalALEResourceAssignmentV4: "FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_RESOURCE_ASSIGNMENT_V4",
guidCalloutTeredoALEListenV6: "FWPM_CALLOUT_TEREDO_ALE_LISTEN_V6",
guidCalloutEdgeTraversalALEListenV4: "FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_LISTEN_V4",
guidCalloutTCPTemplatesConnectLayerV4: "FWPM_CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V4",
guidCalloutTCPTemplatesConnectLayerV6: "FWPM_CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V6",
guidCalloutTCPTemplatesAcceptLayerV4: "FWPM_CALLOUT_TCP_TEMPLATES_ACCEPT_LAYER_V4",
guidCalloutTCPTemplatesAcceptLayerV6: "FWPM_CALLOUT_TCP_TEMPLATES_ACCEPT_LAYER_V6",
guidCalloutPolicySilentModeAuthConnectLayerV4: "FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_CONNECT_LAYER_V4",
guidCalloutPolicySilentModeAuthConnectLayerV6: "FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_CONNECT_LAYER_V6",
guidCalloutPolicySilentModeAuthRecvAcceptLayerV4: "FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_RECV_ACCEPT_LAYER_V4",
guidCalloutPolicySilentModeAuthRecvAcceptLayerV6: "FWPM_CALLOUT_POLICY_SILENT_MODE_AUTH_RECV_ACCEPT_LAYER_V6",
guidCalloutHttpTemplateSslHandshake: "FWPM_CALLOUT_HTTP_TEMPLATE_SSL_HANDSHAKE",
guidProviderContextSecureSocketAuthIP: "FWPM_PROVIDER_CONTEXT_SECURE_SOCKET_AUTHIP",
guidProviderContextSecureSocketIPSec: "FWPM_PROVIDER_CONTEXT_SECURE_SOCKET_IPSEC",
guidKeyingModuleIKE: "FWPM_KEYING_MODULE_IKE",
guidKeyingModuleAuthIP: "FWPM_KEYING_MODULE_AUTHIP",
guidKeyingModuleIKEv2: "FWPM_KEYING_MODULE_IKEV2",
}
