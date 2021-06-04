/***********************************************************************
*
*  FILE        : main.c
*  DATE        : 2020-03-19
*  DESCRIPTION : Main Program
*
*  NOTE:THIS IS A TYPICAL EXAMPLE.
*
***********************************************************************/
#include <stdio.h>
#include "r_typedefs.h"
#include "r_os_abstraction_api.h"
#include "r_cpg_drv_api.h"
#include "r_ostm_drv_api.h"
#include "r_gpio_drv_api.h"
#include "r_devlink_wrapper.h"
#include "resetprg.h"
#include "command.h"
#include "r_os_abstraction_api.h"
#include "r_compiler_abstraction_api.h"
#include "version.h"
#include "flash_api.h"
#include "r_scifa_drv_api.h"

#include "base64_decode.h"
#include "code_signer_public_key.h"

/* tinycrypto */
#include "sha256.h"

#include "r_cache_lld_rza2m.h"
#include "r_cache_l1_rza2m_asm.h"
#include "ecc_dsa.h"
#include "r_mmu_lld_rza2m.h"

#define     __DSB()  asm volatile ("DSB")

/*------------------------------------------ firmware update configuration (start) --------------------------------------------*/

static uint8_t hyper[0x400000] __attribute((section("HYPER_RAM")));

#define BOOT_LOADER_IMAGE_SIZE_BOT_ADR 0x218
#define BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH 0x200
#define BOOT_LOADER_USER_FIRMWARE_DESCRIPTOR_LENGTH 0x100
#define INITIAL_FIRMWARE_FILE_NAME "userprog.rsu"
#define SF_SECTOR_SIZE	0x1000

static uint32_t downloaded_image_size = BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH + BOOT_LOADER_USER_FIRMWARE_DESCRIPTOR_LENGTH;
static uint32_t image_size = BOOT_LOADER_USER_FIRMWARE_DESCRIPTOR_LENGTH;

#define BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS 	(0x50600000)	// top address of temporary area.
#define BOOT_LOADER_UPDATE_EXECUTE_AREA_LOW_ADDRESS		(0x50200000)	// top address of exec area.
#define USER_RESET_VECTOR_ADDRESS (0x50200300)	// The header of .rsu file uses 0x000 to 0x300.

#define BOOT_LOADER_USER_FIRMWARE_MAXSIZE (0x400000 - BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH)

#define BOOT_LOADER_SUCCESS         (0)
#define BOOT_LOADER_FAIL            (-1)
#define BOOT_LOADER_GOTO_INSTALL    (-2)
#define BOOT_LOADER_IN_PROGRESS     (-3)

#define BOOT_LOADER_STATE_INITIALIZING								1
#define BOOT_LOADER_STATE_BANK1_CHECK								2
#define BOOT_LOADER_STATE_BANK1_UPDATE_LIFECYCLE_ERASE_COMPLETE		4
#define BOOT_LOADER_STATE_BANK1_UPDATE_LIFECYCLE_WRITE_COMPLETE		6
#define BOOT_LOADER_STATE_BANK0_CHECK								7
#define BOOT_LOADER_STATE_BANK0_INSTALL_CODE_FLASH_ERASE_COMPLETE	17
#define BOOT_LOADER_STATE_BANK0_INSTALL_CODE_FLASH_READ_WAIT		18
#define BOOT_LOADER_STATE_BANK0_INSTALL_CODE_FLASH_WRITE_COMPLETE	21
#define BOOT_LOADER_STATE_BANK0_UPDATE_CHECK						26
#define BOOT_LOADER_STATE_BANK1_UPDATE_CODE_FLASH_ERASE_COMPLETE	28
#define BOOT_LOADER_STATE_FINALIZE									29
#define BOOT_LOADER_STATE_FATAL_ERROR								200

#define BOOT_LOADER_SCIFA_CONTROL_BLOCK_A (0)
#define BOOT_LOADER_SCIFA_CONTROL_BLOCK_B (1)
#define BOOT_LOADER_SCIFA_CONTROL_BLOCK_TOTAL_NUM (2)

#define BOOT_LOADER_SCIFA_RECEIVE_BUFFER_EMPTY (0)
#define BOOT_LOADER_SCIFA_RECEIVE_BUFFER_FULL  (1)

#define LIFECYCLE_STATE_BLANK		(0xff)
#define LIFECYCLE_STATE_TESTING		(0xfe)
#define LIFECYCLE_STATE_VALID		(0xfc)
#define LIFECYCLE_STATE_INVALID		(0xf8)

#define INTEGRITY_CHECK_SCHEME_HASH_SHA256_STANDALONE "hash-sha256"
#define INTEGRITY_CHECK_SCHEME_SIG_SHA256_ECDSA_STANDALONE "sig-sha256-ecdsa"

#define TC_SHA256_DIGEST_SIZE (32)

typedef struct _load_firmware_control_block {
    uint32_t flash_buffer[SF_SECTOR_SIZE / 4];
    uint32_t offset;
    uint32_t progress;
}LOAD_FIRMWARE_CONTROL_BLOCK;

typedef struct _sci_buffer_control {
   uint8_t buffer[SF_SECTOR_SIZE];
   uint32_t buffer_occupied_byte_size;
   uint32_t buffer_full_flag;
}SCI_BUFFER_CONTROL;

typedef struct _sci_receive_control_block {
   SCI_BUFFER_CONTROL * p_sci_buffer_control;
   uint32_t total_byte_size;
   uint32_t current_state;
}SCI_RECEIVE_CONTROL_BLOCK;

typedef struct _firmware_update_control_block
{
	uint8_t magic_code[7];
    uint8_t image_flag;
    uint8_t signature_type[32];
    uint32_t signature_size;
    uint8_t signature[256];
    uint32_t dataflash_flag;
    uint32_t dataflash_start_address;
    uint32_t dataflash_end_address;
    uint8_t reserved1[200];
    uint32_t sequence_number;
    uint32_t start_address;
    uint32_t end_address;
    uint32_t execution_address;
    uint32_t hardware_id;
    uint32_t image_size;
    uint8_t reserved2[232];
}FIRMWARE_UPDATE_CONTROL_BLOCK;

static int32_t secure_boot(void);
static void bank_swap_with_software_reset(void);
static void software_reset(void);
static const uint8_t *get_status_string(uint8_t status);

static FIRMWARE_UPDATE_CONTROL_BLOCK *firmware_update_control_block_bank0 = (FIRMWARE_UPDATE_CONTROL_BLOCK*)BOOT_LOADER_UPDATE_EXECUTE_AREA_LOW_ADDRESS;
static FIRMWARE_UPDATE_CONTROL_BLOCK *firmware_update_control_block_bank1 = (FIRMWARE_UPDATE_CONTROL_BLOCK*)BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS;
static LOAD_FIRMWARE_CONTROL_BLOCK load_firmware_control_block;
static uint32_t secure_boot_state = BOOT_LOADER_STATE_INITIALIZING;

static int32_t firmware_verification_sha256_ecdsa(const uint8_t * pucData, uint32_t ulSize, const uint8_t * pucSignature, uint32_t ulSignatureSize);
const uint8_t code_signer_public_key[] = CODE_SIGNER_PUBLIC_KEY_PEM;
const uint32_t code_signer_public_key_length = sizeof(code_signer_public_key);


#define MAIN_PRV_LED_ON     (1)
#define MAIN_PRV_LED_OFF    (0)
static uint32_t gs_main_led_flg;      /* LED lighting/turning off */
static int_t gs_my_gpio_handle;
static st_r_drv_gpio_pin_rw_t gs_p60_hi =
{
    GPIO_PORT_6_PIN_0,
    GPIO_LEVEL_HIGH,
    GPIO_SUCCESS
};
static st_r_drv_gpio_pin_rw_t gs_p60_lo =
{
    GPIO_PORT_6_PIN_0,
    GPIO_LEVEL_LOW,
    GPIO_SUCCESS
};
static const r_gpio_port_pin_t gs_led_pin_list[] =
{
    GPIO_PORT_6_PIN_0,
};


int_t main( void )
{
    int32_t result_secure_boot;

    int_t err;
    st_r_drv_gpio_pin_list_t pin_led;

    if (!R_OS_AbstractionLayerInit())
    {
        /* stop execution */
            while (true)
        {
            /* Spin here forever.. */
            R_COMPILER_Nop();
        }
    }

    while(1)
    {
    	result_secure_boot = secure_boot();
		if (BOOT_LOADER_SUCCESS == result_secure_boot)
		{
		    R_OS_TaskSleep(150);
			/* stop all interrupt completely */
            /* ==== System Lock ==== */
            R_OS_SysLock();

            /* ==== Cleaning and invalidation of the L1 data cache ==== */
            R_CACHE_L1DataCleanInvalidAll();
            __DSB();

            /* ==== Cleaning and invalidation of the L2 cache ==== */
            R_CACHE_L2CleanInvalidAll();

            /* ==== Invalidate all TLB entries ==== */
            r_mmu_tlbiall();

            /* ==== Invalidate the L1 instruction cache ==== */
            r_cache_l1_i_inv_all();
            
            memset(hyper,0,sizeof(hyper));
			/* address jump */	// RZ/A2M OTA 2020.03.19 //
			((void(*)(void))USER_RESET_VECTOR_ADDRESS)();

			while(1); /* infinite loop */
		}
		else if (BOOT_LOADER_FAIL == result_secure_boot)
		{
			while(1)
			{
				/* infinity loop */
			}
		}
		else if (BOOT_LOADER_IN_PROGRESS == result_secure_boot)
		{
			continue;
		}
		else
		{
			while(1)
			{
				/* infinite loop */
			}
		}
    }

    return 0;
}


static int32_t secure_boot(void)
{
	int_t scifa_handle;
	scifa_config_t my_scifa_config;
	int32_t secure_boot_error_code = BOOT_LOADER_IN_PROGRESS;
	int32_t flash_api_error_code = 0;
	int32_t fl_ret;
	FIRMWARE_UPDATE_CONTROL_BLOCK *firmware_update_control_block_tmp = (FIRMWARE_UPDATE_CONTROL_BLOCK*)load_firmware_control_block.flash_buffer;
	int32_t verification_result = -1;

	uint32_t i;

    uint32_t k, cnt, cntcnt;

 	 /* Initialize Image Flags of exec area and temporary area. This is used when the new application to execute will be written. */
/*
  	flash_erase_sector(NULL, BOOT_LOADER_UPDATE_EXECUTE_AREA_LOW_ADDRESS);
  	printf("exec area erase complete.\r\n");
  	flash_erase_sector(NULL, BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS);
    printf("temporary area erase complete.\r\n");
*/
	switch(secure_boot_state)
	{
		case BOOT_LOADER_STATE_INITIALIZING:
			/* SCIFA4 is used for downloading applicaitons via UART */
			scifa_handle = direct_open("scifa4", 0);
			direct_control(scifa_handle, CTL_SCIFA_GET_CONFIGURATION, &my_scifa_config);

			my_scifa_config.baud_rate = 115200;

			direct_control(scifa_handle, CTL_SCIFA_SET_CONFIGURATION, &my_scifa_config);

			/* startup system */
			printf("-------------------------------------------------\r\n");
			printf("RZ/A2M secure boot program\r\n");
			printf("-------------------------------------------------\r\n");

    	    printf("Checking flash ROM status.\r\n");

    	    printf("bank 0 status = 0x%x [%s]\r\n", firmware_update_control_block_bank0->image_flag, get_status_string(firmware_update_control_block_bank0->image_flag));
			printf("bank 1 status = 0x%x [%s]\r\n", firmware_update_control_block_bank1->image_flag, get_status_string(firmware_update_control_block_bank1->image_flag));

			secure_boot_state = BOOT_LOADER_STATE_BANK1_CHECK;
			break;

		/* temporary area check */
		case BOOT_LOADER_STATE_BANK1_CHECK:
			if(firmware_update_control_block_bank1->image_flag == LIFECYCLE_STATE_TESTING)
			{
				image_size = firmware_update_control_block_bank1->image_size;
				if(image_size > BOOT_LOADER_USER_FIRMWARE_MAXSIZE)
				{
					image_size = BOOT_LOADER_USER_FIRMWARE_MAXSIZE;
				}
				memcpy(load_firmware_control_block.flash_buffer, (void*)BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS, SF_SECTOR_SIZE);
    	    	printf("integrity check scheme = %-.32s\r\n", firmware_update_control_block_bank1->signature_type);
				printf("bank1(temporary area) on code flash integrity check...");

				/* Firmware verification for the signature type. */
				if (!strcmp((const char *)firmware_update_control_block_bank1->signature_type, INTEGRITY_CHECK_SCHEME_HASH_SHA256_STANDALONE))
				{
					uint8_t hash_sha256[TC_SHA256_DIGEST_SIZE];
				    /* Hash message */
				    struct tc_sha256_state_struct xCtx;
				    tc_sha256_init(&xCtx);
				    tc_sha256_update(&xCtx,
				    		(uint8_t*)BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS + BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH,
							image_size);
				    tc_sha256_final(hash_sha256, &xCtx);
	    	        verification_result = memcmp(firmware_update_control_block_bank1->signature, hash_sha256, sizeof(hash_sha256));
	    	    }
	    	    else if (!strcmp((const char *)firmware_update_control_block_bank1->signature_type, INTEGRITY_CHECK_SCHEME_SIG_SHA256_ECDSA_STANDALONE))
	    	    {
					verification_result = firmware_verification_sha256_ecdsa(
														(const uint8_t *)BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS + BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH,
														image_size,
														firmware_update_control_block_bank1->signature,
														firmware_update_control_block_bank1->signature_size);
				}
				else
				{
					verification_result = -1;
				}

    	        if(0 == verification_result)
    	        {
    	            printf("OK\r\n");
    	        	firmware_update_control_block_tmp->image_flag = LIFECYCLE_STATE_VALID;
    	        }
    	        else
    	        {
    	            printf("NG\r\n");
    	        	firmware_update_control_block_tmp->image_flag = LIFECYCLE_STATE_INVALID;
    	        }
    	    	printf("update LIFECYCLE_STATE from [%s] to [%s]\r\n", get_status_string(firmware_update_control_block_bank1->image_flag), get_status_string(firmware_update_control_block_tmp->image_flag));
    	    	printf("bank1(temporary area) block0 erase (to update LIFECYCLE_STATE)...");

    	        /* 1 sector erase */
    	        fl_ret = flash_erase_sector(NULL, BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS);
    	        if(fl_ret == -1)
    	        {
    	            printf("flash_erase_sector() returns error.\r\n");
    	            printf("system error.\r\n");
					secure_boot_state = BOOT_LOADER_STATE_FATAL_ERROR;
					secure_boot_error_code = BOOT_LOADER_FAIL;
    	            break;
    	        }
    	        else
    	        {
    	        	secure_boot_state = BOOT_LOADER_STATE_BANK1_UPDATE_LIFECYCLE_ERASE_COMPLETE;
    	        }
    		}
    		else
    		{
				if (firmware_update_control_block_bank0->image_flag == LIFECYCLE_STATE_VALID)
				{
					secure_boot_state = BOOT_LOADER_STATE_BANK0_UPDATE_CHECK;
	    		}
	    		else
	    		{
	    			secure_boot_state = BOOT_LOADER_STATE_BANK0_CHECK;
				}
			}
			break;

		case BOOT_LOADER_STATE_BANK1_UPDATE_LIFECYCLE_ERASE_COMPLETE:
	        printf("bank1(temporary area) block0 write (to update LIFECYCLE_STATE)...");
			fl_ret = flash_program_page(NULL,BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS,firmware_update_control_block_tmp,SF_SECTOR_SIZE);
			if(fl_ret == -1)
			{
				printf("flash_program_page() returns error.\r\n");
				printf("system error.\r\n");
				secure_boot_state = BOOT_LOADER_STATE_FATAL_ERROR;
				secure_boot_error_code = BOOT_LOADER_FAIL;
				break;
			}
			secure_boot_state = BOOT_LOADER_STATE_BANK1_UPDATE_LIFECYCLE_WRITE_COMPLETE;
			break;

		case BOOT_LOADER_STATE_BANK1_UPDATE_LIFECYCLE_WRITE_COMPLETE:
			/*  The flags in the temporaly area will be invalid except
			*   in the case application written in temporaly area is correct.
			*   Then, if the flags in the temporaly area is invalid,
			*   RZ/A2M will erase the flags to 0xFF,
			*   and run the application written in the execution area.
			*/
			if((firmware_update_control_block_bank1->image_flag) == LIFECYCLE_STATE_VALID)
			{
		        printf("swap bank...\r\n");
				R_SoftwareDelay(7500000);	//3s wait
				/* bank swap */
				bank_swap_with_software_reset();
			}
			else
			{
    	        printf("illegal status\r\n");
    	        printf("not swap bank...");
   	            flash_erase_sector(NULL, BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS);

				R_SoftwareDelay(7500000);	//3s wait
				software_reset();
			}
			while(1);
			break;


		/* exec area check */
		case BOOT_LOADER_STATE_BANK0_CHECK:
		case BOOT_LOADER_STATE_BANK0_INSTALL_CODE_FLASH_ERASE_COMPLETE:
		case BOOT_LOADER_STATE_BANK0_INSTALL_CODE_FLASH_READ_WAIT:
		case BOOT_LOADER_STATE_BANK0_INSTALL_CODE_FLASH_WRITE_COMPLETE:
		case BOOT_LOADER_STATE_BANK0_UPDATE_CHECK:
		case BOOT_LOADER_STATE_FINALIZE:
			switch(firmware_update_control_block_bank0->image_flag)
			{
				case LIFECYCLE_STATE_BLANK:
    	        	switch(secure_boot_state)
					{
    	        		case BOOT_LOADER_STATE_BANK0_CHECK:
							printf("start installing user program.\r\n");
							printf("========== install user program phase ==========\r\n");

			    	        secure_boot_state = BOOT_LOADER_STATE_BANK0_INSTALL_CODE_FLASH_ERASE_COMPLETE;
			    	        break;
    	        		case BOOT_LOADER_STATE_BANK0_INSTALL_CODE_FLASH_ERASE_COMPLETE:
    	        	        printf("send \"%s\" via UART.\r\n", INITIAL_FIRMWARE_FILE_NAME);
							secure_boot_state = BOOT_LOADER_STATE_BANK0_INSTALL_CODE_FLASH_READ_WAIT;
    	        	        break;

    	        		case BOOT_LOADER_STATE_BANK0_INSTALL_CODE_FLASH_READ_WAIT:
							/* install code flash area */
	                        cnt = 0;
    	                    cntcnt = 0;
        	                for (k=0; k < downloaded_image_size; k++)
	                        {
	                            direct_read(scifa_handle, &hyper[k], 1);
	                            cntcnt ++;
	                            if (cntcnt >= 0x1000)
	                            {
	                                printf("downloaded:0x%08x\n\r", k);
	                                cntcnt = 0;
	                            }
		                        if( k == BOOT_LOADER_IMAGE_SIZE_BOT_ADR )
		                        {
		                        	FIRMWARE_UPDATE_CONTROL_BLOCK* p_header = (FIRMWARE_UPDATE_CONTROL_BLOCK*)&hyper;
		                        	if( p_header->image_size > BOOT_LOADER_USER_FIRMWARE_DESCRIPTOR_LENGTH
		                        	 && p_header->image_size <= BOOT_LOADER_USER_FIRMWARE_MAXSIZE )
	                                {
										image_size = p_header->image_size;
	                                	downloaded_image_size = image_size + BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH;
	                                	printf("DownLoad Image Size:0x%08x\n\r", downloaded_image_size);
	                                }
	                            }
	                        }

							if(downloaded_image_size == (BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH + BOOT_LOADER_USER_FIRMWARE_DESCRIPTOR_LENGTH))
							{
				    	        printf("Image Size error.\r\n");
								secure_boot_state = BOOT_LOADER_STATE_FATAL_ERROR;
								secure_boot_error_code = BOOT_LOADER_FAIL;
				    	        break;
							}

							direct_close(scifa_handle);
						
							uint8_t* pflash = (uint8_t*)BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS;

							/* temporary area clear */
							for (i = 0; i < downloaded_image_size; i+=SF_SECTOR_SIZE)
							{
								flash_erase_sector(NULL, BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS + i);
							}

							/* Hyper RAM -> temporary area write*/
							fl_ret = flash_program_page(NULL,BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS,hyper,downloaded_image_size);

							if(fl_ret == -1)
							{
								printf("flash_program_page() returns error.\r\n");
								printf("system error.\r\n");
								secure_boot_error_code = BOOT_LOADER_FAIL;
								break;
							}
							secure_boot_state = BOOT_LOADER_STATE_BANK0_INSTALL_CODE_FLASH_WRITE_COMPLETE;
							break;

    	        		case BOOT_LOADER_STATE_BANK0_INSTALL_CODE_FLASH_WRITE_COMPLETE:
							printf("\n");
							printf("completed installing firmware.\r\n");
			    	    	printf("integrity check scheme = %-.32s\r\n", firmware_update_control_block_bank1->signature_type);
							printf("bank1(temporary area) on code flash integrity check...");

							/* Firmware verification for the signature type. */
							if (!strcmp((const char *)firmware_update_control_block_bank1->signature_type, INTEGRITY_CHECK_SCHEME_HASH_SHA256_STANDALONE))
							{
								uint8_t hash_sha256[TC_SHA256_DIGEST_SIZE];
							    /* Hash message */
							    struct tc_sha256_state_struct xCtx;
							    tc_sha256_init(&xCtx);
							    tc_sha256_update(&xCtx,
							    		(uint8_t*)BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS + BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH,
										image_size);
							    tc_sha256_final(hash_sha256, &xCtx);
					   	        verification_result = memcmp(firmware_update_control_block_bank1->signature, hash_sha256, sizeof(hash_sha256));
					   	    }
					   	    else if (!strcmp((const char *)firmware_update_control_block_bank1->signature_type, INTEGRITY_CHECK_SCHEME_SIG_SHA256_ECDSA_STANDALONE))
					   	    {
								verification_result = firmware_verification_sha256_ecdsa(
																	(const uint8_t *)BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS + BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH,
																	image_size,
																	firmware_update_control_block_bank1->signature,
																	firmware_update_control_block_bank1->signature_size);
							}
							else
							{
								verification_result = -1;
							}

							if(0 == verification_result)
							{
								printf("OK\r\n");
								printf("completed installing const data.\r\n");
								printf("software reset...\r\n");
								R_SoftwareDelay(7500000);	//3s wait
								software_reset();
							}
							else
							{
								printf("NG\r\n");
								printf("fatal error occurred.\r\n");
	    	        			secure_boot_state = BOOT_LOADER_STATE_FATAL_ERROR;
	    	        			secure_boot_error_code = BOOT_LOADER_FAIL;
							}
							break;
						}
    				break;
				case LIFECYCLE_STATE_TESTING:
    	            printf("illegal status\r\n");
    	            printf("not swap bank...");
    	            /* In the case the flags in the execution area is TESTING,
    	            *  it is concerned that the written application in the execution area is invalid.
    	            *  In this case RZ/A2M will erase the application in the execution area,
    	            *  and go to the state to download the new application via UART.
    	            */
    	            flash_erase_sector(NULL, BOOT_LOADER_UPDATE_EXECUTE_AREA_LOW_ADDRESS);
                    R_SoftwareDelay(7500000);	//3s wait
					software_reset();
    	            while(1);
    	            break;
				case LIFECYCLE_STATE_VALID:
					switch(secure_boot_state)
					{
						case BOOT_LOADER_STATE_BANK0_UPDATE_CHECK:
			    	    	printf("integrity check scheme = %-.32s\r\n", firmware_update_control_block_bank0->signature_type);
		    	            printf("bank0(execute area) on code flash integrity check...");
		    	            image_size = firmware_update_control_block_bank0->image_size;
							if(image_size > BOOT_LOADER_USER_FIRMWARE_MAXSIZE)
							{
								image_size = BOOT_LOADER_USER_FIRMWARE_MAXSIZE;
							}
							/* Firmware verification for the signature type. */
							if (!strcmp((const char *)firmware_update_control_block_bank0->signature_type, INTEGRITY_CHECK_SCHEME_HASH_SHA256_STANDALONE))
							{
							    /* Hash message */
								uint8_t hash_sha256[TC_SHA256_DIGEST_SIZE];
							    struct tc_sha256_state_struct xCtx;
							    tc_sha256_init(&xCtx);
							    tc_sha256_update(&xCtx,
							    		(uint8_t*)BOOT_LOADER_UPDATE_EXECUTE_AREA_LOW_ADDRESS + BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH,
										image_size);
							    tc_sha256_final(hash_sha256, &xCtx);
				    	        verification_result = memcmp(firmware_update_control_block_bank0->signature, hash_sha256, sizeof(hash_sha256));
				    	    }
				    	    else if (!strcmp((const char *)firmware_update_control_block_bank0->signature_type, INTEGRITY_CHECK_SCHEME_SIG_SHA256_ECDSA_STANDALONE))
				    	    {
								verification_result = firmware_verification_sha256_ecdsa(
																	(const uint8_t *)BOOT_LOADER_UPDATE_EXECUTE_AREA_LOW_ADDRESS + BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH,
																	image_size,
																	firmware_update_control_block_bank0->signature,
																	firmware_update_control_block_bank0->signature_size);
							}
							else
							{
								verification_result = -1;
							}

							if(0 == verification_result)
		    	            {
		    	                printf("OK\r\n");
		    	                secure_boot_state = BOOT_LOADER_STATE_FINALIZE;
		    	            }
		    	            else
		    	            {
		    					printf("NG.\r\n");
		    					printf("Code flash is completely broken.\r\n");
		    					printf("Please erase all code flash.\r\n");
		    					printf("And, write secure boot using debugger.\r\n");
								secure_boot_state = BOOT_LOADER_STATE_FATAL_ERROR;
		    					secure_boot_error_code = BOOT_LOADER_FAIL;
		    	            }
		    	            break;

		    	        case BOOT_LOADER_STATE_FINALIZE:
	    	                printf("jump to user program\r\n");
							R_SoftwareDelay(2500000);	//1s wait
	
	    	                secure_boot_error_code = BOOT_LOADER_SUCCESS;
		    	        	break;
		    	    }
   	            	break;

				default:
    	            printf("illegal flash rom status code 0x%x.\r\n", firmware_update_control_block_bank0->image_flag);
        	    	printf("integrity check scheme = %-.32s\r\n", firmware_update_control_block_bank1->signature_type);
    	            printf("bank1(temporary area) on code flash integrity check...");

    	            secure_boot_state = BOOT_LOADER_STATE_FATAL_ERROR;
		    		secure_boot_error_code = BOOT_LOADER_FAIL;
					break;
			}
	}
    return secure_boot_error_code;
}

static void software_reset(void)
{
	volatile uint16_t data;
	WDT.WTCNT.WORD = 0x5A00;
	data = WDT.WRCSR.WORD;
	WDT.WTCNT.WORD = 0x5A00;
	WDT.WRCSR.WORD = 0xA500;
	WDT.WTCSR.WORD = 0xA578;
	WDT.WRCSR.WORD = 0x5A40;
	while(1){}
}


/* Bank swap */
static void bank_swap_with_software_reset(void)
{
	uint32_t i;
	uint8_t* pflash = (uint8_t*)BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS;
	int32_t  fl_ret;

    /* Hyper RAM clear */
    memset(hyper, 0x00, sizeof(hyper));

    /* exec area clear */
    for (i = 0; i < (image_size + BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH); i+=SF_SECTOR_SIZE)
    {
    	flash_erase_sector(NULL, BOOT_LOADER_UPDATE_EXECUTE_AREA_LOW_ADDRESS + i);
    }

    /* temporary area -> HyperRAM */
    for (i = 0; i < (image_size + BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH); i++)
    {
    	hyper[i] = *(pflash + i);
    }

    /* Hyper RAM -> exec area */
    fl_ret = flash_program_page(NULL, BOOT_LOADER_UPDATE_EXECUTE_AREA_LOW_ADDRESS, hyper, (image_size + BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH));

	if(fl_ret == -1)
	{
		printf("R_FLASH_Write() returns error.\r\n");
		printf("system error.\r\n");
		secure_boot_state = BOOT_LOADER_STATE_FATAL_ERROR;
	}
	else
	{
	    /* temporary area clear */
	    for (i = 0; i < (image_size + BOOT_LOADER_USER_FIRMWARE_HEADER_LENGTH); i+=SF_SECTOR_SIZE)
	    {
	    	flash_erase_sector(NULL, BOOT_LOADER_UPDATE_TEMPORARY_AREA_LOW_ADDRESS + i);
	    }
	}
    software_reset();
}



static const uint8_t *get_status_string(uint8_t status)
{
	static const uint8_t status_string[][32] = {{"LIFECYCLE_STATE_BLANK"},
	                                            {"LIFECYCLE_STATE_TESTING"},
	                                            {"LIFECYCLE_STATE_VALID"},
	                                            {"LIFECYCLE_STATE_INVALID"},
	                                            {"LIFECYCLE_STATE_UNKNOWN"}};
	const uint8_t *tmp;

	if(status == LIFECYCLE_STATE_BLANK)
	{
		tmp = status_string[0];
	}
	else if(status == LIFECYCLE_STATE_TESTING)
	{
		tmp = status_string[1];
	}
	else if(status == LIFECYCLE_STATE_VALID)
	{
		tmp = status_string[2];
	}
	else if(status == LIFECYCLE_STATE_INVALID)
	{
		tmp = status_string[3];
	}
	else
	{
		tmp = status_string[4];
	}
	return tmp;
}

static int32_t firmware_verification_sha256_ecdsa(const uint8_t * pucData, uint32_t ulSize, const uint8_t * pucSignature, uint32_t ulSignatureSize)
{
    int32_t xResult = -1;
    uint8_t pucHash[TC_SHA256_DIGEST_SIZE];
    uint8_t data_length;
    uint8_t public_key[64];
    uint8_t binary[256];
    uint8_t *head_pointer, *current_pointer, *tail_pointer;;

    /* Hash message */
    struct tc_sha256_state_struct xCtx;
    tc_sha256_init(&xCtx);
    tc_sha256_update(&xCtx, pucData, ulSize);
    tc_sha256_final(pucHash, &xCtx);

    /* extract public key from code_signer_public_key (pem format) */
    head_pointer = (uint8_t*)strstr((char *)code_signer_public_key, "-----BEGIN PUBLIC KEY-----");
    if(head_pointer)
    {
    	head_pointer += strlen("-----BEGIN PUBLIC KEY-----");
        tail_pointer = (uint8_t*)strstr((char *)code_signer_public_key, "-----END PUBLIC KEY-----");
    	base64_decode(head_pointer, binary, tail_pointer - head_pointer);
    	current_pointer = binary;
		data_length = *(current_pointer + 1);
    	while(1)
    	{
    		switch(*current_pointer)
    		{
    			case 0x30: /* found "SEQUENCE" */
    				current_pointer += 2;
    				break;
    			case 0x03: /* found BIT STRING (maybe public key) */
        			if(*(current_pointer + 1) == 0x42)
        			{
        				memcpy(public_key, current_pointer + 4, 64);
						/* Verify signature */
						if(uECC_verify(public_key, pucHash, TC_SHA256_DIGEST_SIZE, pucSignature, uECC_secp256r1()))
						{
							xResult = 0;
						}
        			}
    				current_pointer += *(current_pointer + 1) + 2;
					break;
    			default:
    				current_pointer += *(current_pointer + 1) + 2;
    				break;
    		}
			if((current_pointer - binary) > data_length)
			{
				/* parsing error */
				break;
			}
    	}
    }
    return xResult;
}

/**********************************************************************************************************************
 * Function Name: Sample_LED_Blink
 * Description  : This function is executed when the OSTM0 interrupt is received.
 *              : In this sample code, the processing to blink the LEDs on the CPU board every 500ms is executed.
 * Arguments    : uint32_t int_sense : Interrupt detection
 *              :                    :   INTC_LEVEL_SENSITIVE : Level sense
 *              :                    :   INTC_EDGE_TRIGGER    : Edge trigger
 * Return Value : none
 *********************************************************************************************************************/
void Sample_LED_Blink(uint32_t int_sense)
{
    /* int_sense not used */
    UNUSED_PARAM(int_sense);

    /* ==== LED blink ==== */
    gs_main_led_flg ^= 1;

    if (MAIN_PRV_LED_ON == gs_main_led_flg)
    {
        direct_control(gs_my_gpio_handle, CTL_GPIO_PIN_WRITE, &gs_p60_hi);
    }
    else
    {
        direct_control(gs_my_gpio_handle, CTL_GPIO_PIN_WRITE, &gs_p60_lo);
    }
}
/**********************************************************************************************************************
 * End of function Sample_LED_Blink
 *********************************************************************************************************************/

/* End of File */


