# Copyright (C) 2019 - 2023 Alexander Linkov <kvark128@yandex.ru>
# This file is covered by the GNU General Public License.
# See the file COPYING.txt for more details.
# Ukrainian Nazis and their accomplices are not allowed to use this plugin. Za pobedu!

from comtypes import GUID
from ctypes import *
from ctypes.wintypes import DWORD, PDWORD, HANDLE, BOOL

# Notification constants
WLAN_NOTIFICATION_SOURCE_ALL = 0x0000ffff
WLAN_NOTIFICATION_SOURCE_ACM = 0x00000008
wlan_notification_acm_connection_complete = 0x0000000a
wlan_notification_acm_disconnected = 0x00000015
wlan_notification_acm_interface_arrival = 0x0000000d
wlan_notification_acm_interface_removal = 0x0000000e

# Various flags for the network
WLAN_AVAILABLE_NETWORK_CONNECTED = 1
WLAN_AVAILABLE_NETWORK_HAS_PROFILE = 2

# States of an interface
wlan_interface_state_not_ready = 0
wlan_interface_state_connected = 1
wlan_interface_state_ad_hoc_network_formed = 2
wlan_interface_state_disconnecting = 3
wlan_interface_state_disconnected = 4
wlan_interface_state_associating = 5
wlan_interface_state_discovering = 6
wlan_interface_state_authenticating = 7

# General reason codes
WLAN_REASON_CODE_SUCCESS = 0

# Return codes
ERROR_SUCCESS = 0

# Client versions
CLIENT_VERSION_WINDOWS_XP_SP3 = 1
CLIENT_VERSION_WINDOWS_VISTA_OR_LATER = 2

# Values of wireless LAN authentication algorithm
DOT11_AUTH_ALGO_80211_OPEN = 1
DOT11_AUTH_ALGO_80211_SHARED_KEY = 2
DOT11_AUTH_ALGO_WPA = 3
DOT11_AUTH_ALGO_WPA_PSK = 4
DOT11_AUTH_ALGO_WPA_NONE = 5
DOT11_AUTH_ALGO_RSNA = 6
DOT11_AUTH_ALGO_RSNA_PSK = 7
DOT11_AUTH_ALGO_WPA3 = 8
DOT11_AUTH_ALGO_WPA3_ENT_192 = DOT11_AUTH_ALGO_WPA3
DOT11_AUTH_ALGO_WPA3_SAE = 9
DOT11_AUTH_ALGO_OWE = 10
DOT11_AUTH_ALGO_WPA3_ENT = 11
DOT11_AUTH_ALGO_IHV_START = 0x80000000
DOT11_AUTH_ALGO_IHV_END = 0xffffffff

class DOT11_SSID(Structure):
	_fields_ = [
		("SSIDLength", c_ulong),
		("SSID", c_char * 32),
	]

class WLAN_CONNECTION_NOTIFICATION_DATA(Structure):
	_fields_ = [
		("wlanConnectionMode", c_uint),
		("strProfileName", c_wchar * 256),
		("dot11Ssid", DOT11_SSID),
		("dot11BssType", c_uint),
		("bSecurityEnabled", BOOL),
		("wlanReasonCode", DWORD),
		("dwFlags", DWORD),
		("strProfileXml", c_wchar * 1),
	]

class WLAN_NOTIFICATION_DATA(Structure):
	_fields_ = [
		("NotificationSource", DWORD),
		("NotificationCode", DWORD),
		("InterfaceGuid", GUID),
		("dwDataSize", DWORD),
		("pData", c_void_p),
	]

class WLAN_AVAILABLE_NETWORK(Structure):
	_fields_ = [
		("ProfileName", c_wchar * 256),
		("dot11Ssid", DOT11_SSID),
		("dot11BssType", c_uint),
		("NumberOfBssids", c_ulong),
		("NetworkConnectable", BOOL),
		("wlanNotConnectableReason", DWORD),
		("NumberOfPhyTypes", c_ulong),
		("dot11PhyTypes", c_uint * 8),
		("MorePhyTypes", BOOL),
		("wlanSignalQuality", c_ulong),
		("SecurityEnabled", BOOL),
		("dot11DefaultAuthAlgorithm", c_uint),
		("dot11DefaultCipherAlgorithm", c_uint),
		("Flags", DWORD),
		("Reserved", DWORD),
	]

class WLAN_AVAILABLE_NETWORK_LIST(Structure):
	_fields_ = [
		("NumberOfItems", DWORD),
		("Index", DWORD),
		("Network", WLAN_AVAILABLE_NETWORK * 1),
	]

class WLAN_INTERFACE_INFO(Structure):
	_fields_ = [
		("InterfaceGuid", GUID),
		("strInterfaceDescription", c_wchar * 256),
		("isState", c_uint),
	]

class WLAN_INTERFACE_INFO_LIST(Structure):
	_fields_ = [
		("NumberOfItems", DWORD),
		("Index", DWORD),
		("InterfaceInfo", WLAN_INTERFACE_INFO * 1),
	]

# Type of notification callback function
WLAN_NOTIFICATION_CALLBACK = CFUNCTYPE(None, POINTER(WLAN_NOTIFICATION_DATA), POINTER(c_void_p))

def errcheck(result, func, args):
	if result != ERROR_SUCCESS:
		raise WinError(c_long(result).value)
	return result

# Function prototypes from wlanapi.dll
_wlanapi_dll = windll.wlanapi
_wlanapi_dll.WlanOpenHandle.errcheck = errcheck
_wlanapi_dll.WlanOpenHandle.argtypes = [DWORD, c_void_p, POINTER(DWORD), POINTER(HANDLE)]
_wlanapi_dll.WlanOpenHandle.restype = DWORD
_wlanapi_dll.WlanEnumInterfaces.errcheck = errcheck
_wlanapi_dll.WlanEnumInterfaces.argtypes = [HANDLE, c_void_p, POINTER(POINTER(WLAN_INTERFACE_INFO_LIST))]
_wlanapi_dll.WlanEnumInterfaces.restype = DWORD
_wlanapi_dll.WlanGetAvailableNetworkList.errcheck = errcheck
_wlanapi_dll.WlanGetAvailableNetworkList.argtypes = [HANDLE, POINTER(GUID), DWORD, c_void_p, POINTER(POINTER(WLAN_AVAILABLE_NETWORK_LIST))]
_wlanapi_dll.WlanGetAvailableNetworkList.restype = DWORD
_wlanapi_dll.WlanFreeMemory.argtypes = [c_void_p]
_wlanapi_dll.WlanCloseHandle.errcheck = errcheck
_wlanapi_dll.WlanCloseHandle.argtypes = [HANDLE, c_void_p]
_wlanapi_dll.WlanCloseHandle.restype = DWORD
_wlanapi_dll.WlanRegisterNotification.errcheck = errcheck
_wlanapi_dll.WlanRegisterNotification.argtypes = [HANDLE, DWORD, BOOL, WLAN_NOTIFICATION_CALLBACK, c_void_p, c_void_p, PDWORD]
_wlanapi_dll.WlanRegisterNotification.restype = DWORD

def WlanOpenHandle(dwClientVersion, pReserved, pdwNegotiatedVersion, phClientHandle):
	""" The WlanOpenHandle function opens a connection to the server. """
	return _wlanapi_dll.WlanOpenHandle(dwClientVersion, pReserved, pdwNegotiatedVersion, phClientHandle)

def WlanEnumInterfaces(hClientHandle, pReserved, ppInterfaceList):
	""" The WlanEnumInterfaces function enumerates all of the wireless LAN interfaces currently enabled on the local computer. """
	return _wlanapi_dll.WlanEnumInterfaces(hClientHandle, pReserved, ppInterfaceList)

def WlanGetAvailableNetworkList(hClientHandle, pInterfaceGuid, dwFlags, pReserved, ppAvailableNetworkList):
	""" The WlanGetAvailableNetworkList function retrieves the list of available networks on a wireless LAN interface. """
	return _wlanapi_dll.WlanGetAvailableNetworkList(hClientHandle, pInterfaceGuid, dwFlags, pReserved, ppAvailableNetworkList)

def WlanFreeMemory(pMemory):
	""" The WlanFreeMemory function frees memory. Any memory returned from Native Wifi functions must be freed. """
	_wlanapi_dll.WlanFreeMemory(pMemory)

def WlanCloseHandle(hClientHandle, pReserved):
	""" The WlanCloseHandle function closes a connection to the server. """
	return _wlanapi_dll.WlanCloseHandle(hClientHandle, pReserved)

def WlanRegisterNotification(hClientHandle, dwNotifSource, bIgnoreDuplicate, funcCallback, pCallbackContext, pReserved, pdwPrevNotifSource):
	""" The WlanRegisterNotification function is used to register and unregister notifications on all wireless interfaces. """
	return _wlanapi_dll.WlanRegisterNotification(hClientHandle, dwNotifSource, bIgnoreDuplicate, funcCallback, pCallbackContext, pReserved, pdwPrevNotifSource)
