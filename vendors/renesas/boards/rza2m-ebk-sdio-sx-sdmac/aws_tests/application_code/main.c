/*
FreeRTOS
Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 http://aws.amazon.com/freertos
 http://www.FreeRTOS.org
*/

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"

/* Version includes. */
#include "aws_application_version.h"

/* System init includes. */
#include "iot_system_init.h"

/* Logging includes. */
#include "iot_logging_task.h"

/* Key provisioning includes. */
#include "aws_dev_mode_key_provisioning.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_IP.h"

/* Demo includes */
//210618 modified. refered from RX65N-RSK Amazon FreeRTOS Version202012.00 -->>
//#include "iot_demo_runner.h"
//210618 modified. <<--
#include "aws_clientcredential.h"

//210618 modified. refered from RX65N-RSK Amazon FreeRTOS Version202012.00 -->>
/* Test application include. */
#include "aws_test_runner.h"
//210618 modified. <<--

/*from app.c*/
#include "queue.h"
#include <stdio.h>
#include <string.h>

#include "r_devlink_wrapper.h"
#include "r_ether_rza2_if.h"
#include "FreeRTOS_IP_Private.h"

/* Aws Library Includes includes. */
#include "iot_system_init.h"
#include "iot_logging_task.h"
#include "aws_application_version.h"
#include "aws_dev_mode_key_provisioning.h"
#include "iot_wifi.h"   //210618 modified. refered from EBK Version202007.00

/*from main.c*/
#include <fcntl.h>
#include <unistd.h>
#include "r_typedefs.h"
#include "iodefine.h"
#include "r_cpg_drv_api.h"
#include "r_ostm_drv_api.h"
#include "r_scifa_drv_api.h"
#include "r_gpio_drv_api.h"
#include "r_startup_config.h"
#include "compiler_settings.h"
#include "main.h"
#include "r_os_abstraction_api.h"
#include "r_task_priority.h"
#include "version.h"

#define mainLOGGING_TASK_STACK_SIZE         ( configMINIMAL_STACK_SIZE * 6 )
#define mainLOGGING_MESSAGE_QUEUE_LENGTH    ( 15 )
#define mainTEST_RUNNER_TASK_STACK_SIZE    ( configMINIMAL_STACK_SIZE * 8 )

/* Declare the firmware version structure for all to see. */
/* The MAC address array is not declared const as the MAC address will
normally be read from an EEPROM and not hard coded (in real deployed
applications).*/
static uint8_t ucMACAddress[ 6 ] =
{
    configMAC_ADDR0,
    configMAC_ADDR1,
    configMAC_ADDR2,
    configMAC_ADDR3,
    configMAC_ADDR4,
    configMAC_ADDR5
}; //XXX

/* Define the network addressing.  These parameters will be used if either
ipconfigUDE_DHCP is 0 or if ipconfigUSE_DHCP is 1 but DHCP auto configuration
failed. */
static const uint8_t ucIPAddress[ 4 ] =
{
    configIP_ADDR0,
    configIP_ADDR1,
    configIP_ADDR2,
    configIP_ADDR3
};
static const uint8_t ucNetMask[ 4 ] =
{
    configNET_MASK0,
    configNET_MASK1,
    configNET_MASK2,
    configNET_MASK3
};
static const uint8_t ucGatewayAddress[ 4 ] =
{
    configGATEWAY_ADDR0,
    configGATEWAY_ADDR1,
    configGATEWAY_ADDR2,
    configGATEWAY_ADDR3
};

/* The following is the address of an OpenDNS server. */
static const uint8_t ucDNSServerAddress[ 4 ] =
{
    configDNS_SERVER_ADDR0,
    configDNS_SERVER_ADDR1,
    configDNS_SERVER_ADDR2,
    configDNS_SERVER_ADDR3
};

/**
 * @brief Application task startup hook.
 */
void vApplicationDaemonTaskStartupHook( void );

/**
 * @brief Initializes the board.
 */
static void prvMiscInitialization( void );

void os_main_task_t( void );
/*-----------------------------------------------------------*/

int_t main(void)
{
    int_t cpg_handle;

    /* configure any drivers that are required before the Kernel initialises */

    /* Initialize the devlink layer */
    R_DEVLINK_Init();

    /* Initialize CPG */
    cpg_handle = direct_open("cpg", 0);
    if ( cpg_handle < 0 )
    {
        /* stop execute */
        while(1);
    }

    /* Can close handle if no need to change clock after here */
    direct_close(cpg_handle);

    /* Start FreeRTOS */
    /* R_OS_InitKernel should never return */
    R_OS_KernelInit();
}


/**
 * @brief The application entry point from a power on reset is PowerON_Reset_PC()
 * in resetprg.c.
 */
//void main( void )
void os_main_task_t( void )
{
    TaskHandle_t xHandle = NULL;
#if defined(__IDT_MODE__)
    uint32_t boot_count=(*((uint32_t*)0x23FFC000)) + 1;
#endif
    WIFINetworkParams_t xNetworkParams;
    memset( &xNetworkParams, 0x00, sizeof( WIFIIPConfiguration_t ) );
    vTaskDelay(3000);

    /* Setup parameters. */
    xNetworkParams.ucSSIDLength = strlen( clientcredentialWIFI_SSID );
    memcpy(xNetworkParams.ucSSID, clientcredentialWIFI_SSID, xNetworkParams.ucSSIDLength);
    xNetworkParams.xPassword.xWPA.ucLength = strlen( clientcredentialWIFI_PASSWORD );
    memcpy(xNetworkParams.xPassword.xWPA.cPassphrase, clientcredentialWIFI_PASSWORD, xNetworkParams.xPassword.xWPA.ucLength);
    xNetworkParams.xSecurity = clientcredentialWIFI_SECURITY;

#if defined(__IDT_MODE__)
    printf("boot_count=%d\r\n",boot_count);
#endif
    R_OS_TaskSleep(1000);
    /* Initialise the RTOS's TCP/IP stack.  The tasks that use the network
    are created in the vApplicationIPNetworkEventHook() hook function
    below.  The hook function is called when the network connects. */
    WIFI_On();
    if( WIFI_ConnectAP(&xNetworkParams) == eWiFiFailure)
    {
        printf("WIFI_ConnectAP failed\n");
    }

    /* Provision the device with AWS certificate and private key. */
    vDevModeKeyProvisioning();

    /* Run all demos. */
    vTaskDelay(3000);	// todo: this is renesas issue.

    /* Create the task to run tests. */
    xTaskCreate( TEST_RUNNER_RunTests_task,
                 "RunTests_task",
                 mainTEST_RUNNER_TASK_STACK_SIZE,
                 NULL,
                 tskIDLE_PRIORITY,
                 &xHandle );
    while(1)
    {
    	TaskStatus_t xTaskDetails;
        vTaskDelay(1000);
#if defined(__IDT_MODE__)
        vTaskGetInfo(xHandle, &xTaskDetails, pdTRUE, eInvalid);
        if( xTaskDetails.eCurrentState == eDeleted )
        {
            vTaskDelay( 500 );
            printf("WIFI_Off\n");
            WIFI_Off();
            while(1)
            {
                vTaskDelay(1000);
            }
        }
#endif

}
/*-----------------------------------------------------------*/

static void prvMiscInitialization( void )
{
    /* Start logging task. */
    xLoggingTaskInitialize( mainLOGGING_TASK_STACK_SIZE,
                            25,
                            mainLOGGING_MESSAGE_QUEUE_LENGTH );
}
/*-----------------------------------------------------------*/

void vApplicationDaemonTaskStartupHook( void )
{
    prvMiscInitialization();

    if( SYSTEM_Init() == pdPASS )
    {
//210618 modified. refered from EBK Version202007.00 -->>
        ;
//210618 modified. <<--
    }
}

/*-----------------------------------------------------------*/

__attribute__((weak))
const char * pcApplicationHostnameHook( void )
{
    /* Assign the name "FreeRTOS" to this network node.  This function will
     * be called during the DHCP: the machine will be registered with an IP
     * address plus this name. */
    return clientcredentialIOT_THING_NAME;
}

/* configUSE_STATIC_ALLOCATION is set to 1, so the application must provide an
 * implementation of vApplicationGetIdleTaskMemory() to provide the memory that is
 * used by the Idle task. */
__attribute__((weak))
void vApplicationGetIdleTaskMemory( StaticTask_t ** ppxIdleTaskTCBBuffer,
                                    StackType_t ** ppxIdleTaskStackBuffer,
                                    uint32_t * pulIdleTaskStackSize )
{
/* If the buffers to be provided to the Idle task are declared inside this
 * function then they must be declared static - otherwise they will be allocated on
 * the stack and so not exists after this function exits. */
    static StaticTask_t xIdleTaskTCB;
    static StackType_t uxIdleTaskStack[ configMINIMAL_STACK_SIZE ];

    /* Pass out a pointer to the StaticTask_t structure in which the Idle
     * task's state will be stored. */
    *ppxIdleTaskTCBBuffer = &xIdleTaskTCB;

    /* Pass out the array that will be used as the Idle task's stack. */
    *ppxIdleTaskStackBuffer = uxIdleTaskStack;

    /* Pass out the size of the array pointed to by *ppxIdleTaskStackBuffer.
     * Note that, as the array is necessarily of type StackType_t,
     * configMINIMAL_STACK_SIZE is specified in words, not bytes. */
    *pulIdleTaskStackSize = configMINIMAL_STACK_SIZE;
}
/*-----------------------------------------------------------*/

/* configUSE_STATIC_ALLOCATION is set to 1, so the application must provide an
 * implementation of vApplicationGetTimerTaskMemory() to provide the memory that is
 * used by the RTOS daemon/time task. */
__attribute__((weak))
void vApplicationGetTimerTaskMemory( StaticTask_t ** ppxTimerTaskTCBBuffer,
                                     StackType_t ** ppxTimerTaskStackBuffer,
                                     uint32_t * pulTimerTaskStackSize )
{
/* If the buffers to be provided to the Timer task are declared inside this
 * function then they must be declared static - otherwise they will be allocated on
 * the stack and so not exists after this function exits. */
    static StaticTask_t xTimerTaskTCB;
    static StackType_t uxTimerTaskStack[ configMINIMAL_STACK_SIZE ];

    /* Pass out a pointer to the StaticTask_t structure in which the Idle
     * task's state will be stored. */
    *ppxTimerTaskTCBBuffer = &xTimerTaskTCB;

    /* Pass out the array that will be used as the Timer task's stack. */
    *ppxTimerTaskStackBuffer = uxTimerTaskStack;

    /* Pass out the size of the array pointed to by *ppxTimerTaskStackBuffer.
     * Note that, as the array is necessarily of type StackType_t,
     * configMINIMAL_STACK_SIZE is specified in words, not bytes. */
    *pulTimerTaskStackSize = configMINIMAL_STACK_SIZE;
}
/*-----------------------------------------------------------*/
