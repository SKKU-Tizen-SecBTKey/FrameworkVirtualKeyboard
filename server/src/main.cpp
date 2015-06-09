#include <stdio.h>
#include <unistd.h>
#include <iostream>

#include "common.h"
#include <stdlib.h>
#include <dlog.h>
#include <glib.h>
#include <bluetooth.h>

#include "keyExchange.h"

#undef LOG_TAG
#define LOG_TAG "Secured_Data_FW"

static GMainLoop* gMainLoop = NULL;
static bt_adapter_visibility_mode_e gVisibilityMode = BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE;
static int gSocketFd = -1;
static int g_connected_socket_fd = -1;
static bt_adapter_state_e gBtState = BT_ADAPTER_DISABLED;
static const char uuid[] = "00001101-0000-1000-8000-00805F9B34FB";

static char p[512];
static char eBob[512];
static int g;
static char cipherText[512];

// Lifecycle of this framework
int secured_fw_initialize_bluetooth(void);
int secured_fw_finalize_bluetooth_socket(void);
int secured_fw_finalize_bluetooth(void);
int secured_fw_listen_connection(void);

// Callbacks
void secured_fw_received_data_cb(bt_socket_received_data_s *, void *);
void secured_fw_socket_connection_state_changed_cb(int, bt_socket_connection_state_e, bt_socket_connection_s *, void *);
void secured_fw_state_changed_cb(int, bt_adapter_state_e, void *);
gboolean timeout_func_cb(gpointer);

int secured_fw_initialize_bluetooth(const char *device_name) {
	// Initialize bluetooth and get adapter state
	int ret;
	ret = bt_initialize();
	if(ret != BT_ERROR_NONE) {
		ALOGD("Unknown exception is occured in bt_initialize(): %x", ret);
		return -1;
	}

	ret = bt_adapter_get_state(&gBtState);
	if(ret != BT_ERROR_NONE) {
		ALOGD("Unknown exception is occured in bt_adapter_get_state(): %x", ret);
		return -2;
	}

	// Enable bluetooth device manually
	if(gBtState == BT_ADAPTER_DISABLED)
	{
		ALOGE("[%s] bluetooth is not enabled.", __FUNCTION__);
		return -3;
	}
	else
	{
		ALOGI("[%s] BT was already enabled.", __FUNCTION__);
	}

	// Set adapter's name
	if(gBtState == BT_ADAPTER_ENABLED) {
		char *name = NULL;
		ret = bt_adapter_get_name(&name);
		if(name == NULL) {
			ALOGD("NULL name exception is occured in bt_adapter_get_name(): %x", ret);
			return -5;
		}

		if(strncmp(name, device_name, strlen(name)) != 0) {
			if(bt_adapter_set_name(device_name) != BT_ERROR_NONE)
			{   
				if (NULL != name)
					free(name);
				ALOGD("Unknown exception is occured in bt_adapter_set_name : %x", ret);
				return -6;
			}   
		}
		free(name);
	} else {
		ALOGD("Bluetooth is not enabled");
		return -7;
	}

	//  Set visibility as BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE
	if(bt_adapter_get_visibility(&gVisibilityMode, NULL) != BT_ERROR_NONE)
	{
		LOGE("[%s] bt_adapter_get_visibility() failed.", __FUNCTION__);
		return -11; 
	}

	if(gVisibilityMode != BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE)
	{
		if(bt_adapter_set_visibility(BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE, 0) != BT_ERROR_NONE)
		{   
			LOGE("[%s] bt_adapter_set_visibility() failed.", __FUNCTION__);
			return -12; 
		}   
		gVisibilityMode = BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE;
	}
	else
	{
		LOGI("[%s] Visibility mode was already set as BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE.", __FUNCTION__);
	}

	// Connecting socket as a server
	ret = bt_socket_create_rfcomm(uuid, &gSocketFd);
	if(ret != BT_ERROR_NONE) {
		ALOGD("Unknown exception is occured in bt_socket_create_rfcomm(): %x", ret);
		return -8;
	}

	ret = bt_socket_set_connection_state_changed_cb(secured_fw_socket_connection_state_changed_cb, NULL);
	if(ret != BT_ERROR_NONE) {
		ALOGD("Unknown exception is occured in bt_socket_set_connection_state_changed_cb(): %x", ret);
		return -9;
	}

	ret = bt_socket_set_data_received_cb(secured_fw_received_data_cb, NULL);
	if(ret != BT_ERROR_NONE) {
		ALOGD("Unknown exception is occured in bt_socket_set_data_received_cb(): %x", ret);
		return -10;
	}

	return 0;
}

int secured_fw_finalize_bluetooth_socket(void) {
	int ret;
	sleep(5); // Wait for completing delivery
	ret = bt_socket_destroy_rfcomm(gSocketFd);
	if(ret != BT_ERROR_NONE)
	{
		ALOGD("Unknown exception is occured in bt_socket_destory_rfcomm(): %x", ret);
		return -1;
	}

	bt_deinitialize();
	return 0;
}

int secured_fw_finalize_bluetooth(void) {
	bt_deinitialize();
	return 0;
}

int secured_fw_listen_connection(void) {
	// Success to get a socket
	int ret = bt_socket_listen_and_accept_rfcomm(gSocketFd, 5);
	switch(ret) {
		case BT_ERROR_NONE:
			{
				// Success to listen and accept a connection from client
				ALOGD("listen successful");
				return 0;
			}
			break;
		case BT_ERROR_INVALID_PARAMETER:
			{
				// Invalid parameter exception
				ALOGD("Invalid parameter exception is occured in bt_socket_listen_and_accept_rfcomm()");
				return -1;
			}
			break;
		default:
			{
				// Unknown exception
				ALOGD("Unknown exception is occured in bt_socket_listen_and_accept_rfcomm(): %x", ret);
				return -2;
			}
	}
}

int gReceiveCount = 0;

// bt_socket_data_received_cb
void secured_fw_received_data_cb(bt_socket_received_data_s *data, void *user_data)
{
	static char buffer[1024];
	int ret;
  static int flag = 0;

	strncpy(buffer, data->data, 1024);
	buffer[data->data_size] = '\0';

  // p
  if (flag ==0) {
    memset(&p[0], 0x00, sizeof(p));
    strncpy(p, buffer, data->data_size);
    ALOGD("Received p:");
    ALOGD("%s", p);
  }

  // g
  else if (flag == 1) {
    g = buffer[0] - '0';
    ALOGD("Received g: %d", g);
  }

  // eBob
  else if (flag == 2) {
    const char* eAlice;
    memset(&eBob[0], 0x00, sizeof(eBob));
    strncpy(eBob, buffer, data->data_size);
    ALOGD("Received eBob:");
    ALOGD("%s", eBob);
    
    secure_key_exchange(p, g);
    eAlice = secure_find_key(eBob);
    ALOGD("Sent eAlice:");
    ALOGD("%s", eAlice);
    ret = bt_socket_send_data(g_connected_socket_fd, eAlice, strlen(eAlice));
  	if (ret != BT_ERROR_NONE) {
         ALOGD("[bt_socket_send_data] %d", ret);
    }
    secure_aes_cbc_init();
  }

  // CipherText
  else if (flag == 3) {
    const char* plainText;
    memset(&cipherText[0], 0x00, sizeof(cipherText));
    strncpy(cipherText, buffer, data->data_size);
    ALOGD("Received cipherText:");
    ALOGD("%s", cipherText);
    plainText = secure_aes_cbc_decrypt(cipherText);
    ALOGD("Decrypted PlainText:");
    ALOGD("%s", plainText);

  	if(plainText[0] == '1') {
  		system("/bin/echo 1 > /sys/bus/platform/devices/homekey/coordinates");
  	} else if(plainText[0] == '2') {
  		system("/bin/echo 11 > /sys/bus/platform/devices/homekey/coordinates");
  	} else if(plainText[0] == '3') {
  		system("/bin/echo 111 > /sys/bus/platform/devices/homekey/coordinates");
  	}
    secure_aes_cbc_dispose();
  }

  if (flag != 3) flag++;
  else flag = 0;
}

// bt_socket_connection_state_changed_cb
void secured_fw_socket_connection_state_changed_cb(int result, bt_socket_connection_state_e connection_state_event, bt_socket_connection_s *connection, void *user_data) {
	if(result == BT_ERROR_NONE) {
		ALOGD("RemoteKeyFW: connection state changed (BT_ERROR_NONE)");
	} else {
		ALOGD("RemoteKeyFW: connection state changed (not BT_ERROR_NONE)");
	}

	if(connection_state_event == BT_SOCKET_CONNECTED) {
		ALOGD("RemoteKeyFW: connected");
		if (connection != NULL) {
			g_connected_socket_fd = connection->socket_fd;
		}
	} else if(connection_state_event == BT_SOCKET_DISCONNECTED) {
		ALOGD("RemoteKeyFW: disconnected");
		g_main_loop_quit(gMainLoop);
	}
}

void secured_fw_state_changed_cb(int result, bt_adapter_state_e adapter_state, void *user_data) {
	if(adapter_state == BT_ADAPTER_ENABLED) {
		if(result == BT_ERROR_NONE) {
			ALOGD("RemoteKeyFW: bluetooth was enabled successfully.");
			gBtState = BT_ADAPTER_ENABLED;
		} else {
			ALOGD("RemoteKeyFW: failed to enable BT.: %x", result);
			gBtState = BT_ADAPTER_DISABLED;
		}
	}
	if(gMainLoop) {
		ALOGD("It will terminate gMainLoop.", result);
		g_main_loop_quit(gMainLoop);
	}
}

gboolean timeout_func_cb(gpointer data)
{
	ALOGE("timeout_func_cb");
	if(gMainLoop)
	{
		g_main_loop_quit((GMainLoop*)data);
	}
	return FALSE;
}

int main(int argc, char *argv[])
{
	int error, ret = 0;
	const char default_device_name[] = "Tizen-RK";
	const char *device_name = NULL;
	gMainLoop = g_main_loop_new(NULL, FALSE);
	ALOGD("Sever started\n");

	if(argc < 2) {
		char errMsg[] = "No bluetooth device name, so its name is set as default.";
		printf("%s\n", errMsg);
		ALOGW("%s\n", errMsg);
		device_name = default_device_name;
	} else {
		device_name = argv[1];
	}

	// Initialize bluetooth
	error = secured_fw_initialize_bluetooth(device_name);
	if(error != 0) {
		ret = -2;
		goto error_end_without_socket;
	}
	ALOGD("succeed in rkf_initialize_bluetooth()\n");

	// Listen connection
	error = secured_fw_listen_connection();
	if(error != 0) {
		ret = -3;
		goto error_end_with_socket;
	}

	// If succeed to accept a connection, start a main loop.
	g_main_loop_run(gMainLoop);

	ALOGI("Server is terminated successfully\n");

error_end_with_socket:
	// Finalized bluetooth
	secured_fw_finalize_bluetooth_socket();

error_end_without_socket:
	secured_fw_finalize_bluetooth();
	return ret;
}

//! End of a file
