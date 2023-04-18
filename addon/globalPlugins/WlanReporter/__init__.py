# Copyright (C) 2019 - 2023 Alexander Linkov <kvark128@yandex.ru>
# This file is covered by the GNU General Public License.
# See the file COPYING.txt for more details.
# Ukrainian Nazis and their accomplices are not allowed to use this plugin. Za pobedu!

import os.path
import winsound
from ctypes import addressof, byref, POINTER, wintypes

import globalPluginHandler
import addonHandler
import queueHandler
import ui
import globalCommands
from scriptHandler import script
from . import wlanapi

MODULE_DIR = os.path.dirname(__file__)
addonHandler.initTranslation()

def message(text, fileName):
	ui.message(text)
	path = os.path.join(MODULE_DIR, fileName)
	if os.path.isfile(path):
		winsound.PlaySound(path, winsound.SND_ASYNC)

@wlanapi.WLAN_NOTIFICATION_CALLBACK
def notifyHandler(pData, pCtx):
	if pData.contents.NotificationSource != wlanapi.WLAN_NOTIFICATION_SOURCE_ACM:
		return
	if pData.contents.NotificationCode == wlanapi.wlan_notification_acm_connection_complete:
		notificationData = wlanapi.WLAN_CONNECTION_NOTIFICATION_DATA.from_address(pData.contents.pData)
		if notificationData.wlanReasonCode == wlanapi.WLAN_REASON_CODE_SUCCESS:
			text = _("Connected to {ssid}").format(ssid=notificationData.dot11Ssid.SSID.decode("utf-8"))
			queueHandler.queueFunction(queueHandler.eventQueue, message, text, "connect.wav")
	elif pData.contents.NotificationCode == wlanapi.wlan_notification_acm_disconnected:
		notificationData = wlanapi.WLAN_CONNECTION_NOTIFICATION_DATA.from_address(pData.contents.pData)
		text = _("Disconnected from {ssid}").format(ssid=notificationData.dot11Ssid.SSID.decode("utf-8"))
		queueHandler.queueFunction(queueHandler.eventQueue, message, text, "disconnect.wav")
	elif pData.contents.NotificationCode == wlanapi.wlan_notification_acm_interface_arrival:
		queueHandler.queueFunction(queueHandler.eventQueue, message, _("A wireless device has been enabled"), "connect.wav")
	elif pData.contents.NotificationCode == wlanapi.wlan_notification_acm_interface_removal:
		queueHandler.queueFunction(queueHandler.eventQueue, message, _("A wireless device has been disabled"), "disconnect.wav")

def customResize(array, newSize):
	return (array._type_ * newSize).from_address(addressof(array))

class GlobalPlugin(globalPluginHandler.GlobalPlugin):
	scriptCategory = globalCommands.SCRCAT_SYSTEM

	def __init__(self):
		super().__init__()
		self._negotiated_version = wintypes.DWORD()
		self._client_handle = wintypes.HANDLE()
		wlanapi.WlanOpenHandle(wlanapi.CLIENT_VERSION_WINDOWS_VISTA_OR_LATER, None, byref(self._negotiated_version), byref(self._client_handle))
		wlanapi.WlanRegisterNotification(self._client_handle, wlanapi.WLAN_NOTIFICATION_SOURCE_ACM, True, notifyHandler, None, None, None)

	@script(description=_("Reports the status of the wireless connection"))
	def script_wlanStatusReport(self, gesture):
		wlan_ifaces = POINTER(wlanapi.WLAN_INTERFACE_INFO_LIST)()
		wlanapi.WlanEnumInterfaces(self._client_handle, None, byref(wlan_ifaces))

		if wlan_ifaces.contents.NumberOfItems == 0:
			ui.message(_("No wireless devices"))
			wlanapi.WlanFreeMemory(wlan_ifaces)
			return

		for i in customResize(wlan_ifaces.contents.InterfaceInfo, wlan_ifaces.contents.NumberOfItems):
			if i.isState != wlanapi.wlan_interface_state_connected:
				ui.message(_("No wireless connections"))
				continue

			wlan_available_network_list = POINTER(wlanapi.WLAN_AVAILABLE_NETWORK_LIST)()
			wlanapi.WlanGetAvailableNetworkList(self._client_handle, byref(i.InterfaceGuid), 0, None, byref(wlan_available_network_list))
			for n in customResize(wlan_available_network_list.contents.Network, wlan_available_network_list.contents.NumberOfItems):
				if n.Flags & wlanapi.WLAN_AVAILABLE_NETWORK_CONNECTED:
					ui.message(_("Connected to {ssid}, signal {signal}%").format(ssid=n.dot11Ssid.SSID.decode(), signal=n.wlanSignalQuality))
					break
			wlanapi.WlanFreeMemory(wlan_available_network_list)
		wlanapi.WlanFreeMemory(wlan_ifaces)

	def terminate(self):
		# Unregistering the callback function for notifications is optional. It's enough just to close the client handle
		wlanapi.WlanCloseHandle(self._client_handle, None)
