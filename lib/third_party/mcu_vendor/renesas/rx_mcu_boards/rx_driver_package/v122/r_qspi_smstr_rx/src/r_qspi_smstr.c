/*******************************************************************************
* DISCLAIMER
* This software is supplied by Renesas Electronics Corporation and is only
* intended for use with Renesas products. No other uses are authorized. This
* software is owned by Renesas Electronics Corporation and is protected under
* all applicable laws, including copyright laws.
* THIS SOFTWARE IS PROVIDED "AS IS" AND RENESAS MAKES NO WARRANTIES REGARDING
* THIS SOFTWARE, WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING BUT NOT
* LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
* AND NON-INFRINGEMENT. ALL SUCH WARRANTIES ARE EXPRESSLY DISCLAIMED.
* TO THE MAXIMUM EXTENT PERMITTED NOT PROHIBITED BY LAW, NEITHER RENESAS
* ELECTRONICS CORPORATION NOR ANY OF ITS AFFILIATED COMPANIES SHALL BE LIABLE
* FOR ANY DIRECT, INDIRECT, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES FOR
* ANY REASON RELATED TO THIS SOFTWARE, EVEN IF RENESAS OR ITS AFFILIATES HAVE
* BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
* Renesas reserves the right, without notice, to make changes to this software
* and to discontinue the availability of this software. By using this software,
* you agree to the additional terms and conditions found by accessing the
* following link:
* http://www.renesas.com/disclaimer
*
* Copyright (C) 2014(2015-2019) Renesas Electronics Corporation. All rights reserved.
*******************************************************************************/
/*******************************************************************************
* System Name  : QSPI single master driver
* File Name    : r_qspi_smstr.c
* Version      : 1.13
* Device       : RX
* Abstract     : Main processing source file for QSPI single master driver
* Tool-Chain   : Renesas RXC Toolchain v3.01.00
* OS           : not use
* H/W Platform : not use
* Description  : Functions for QSPI single master driver
* Limitation   : none
*******************************************************************************/
/*******************************************************************************
* History      : DD.MM.YYYY Version  Description
*              : 24.06.2014 1.05     First Release
*              : 29.08.2014 1.06     Added the pointer check for transmission data buffer
*              :                     and reception data buffer.
*              :                     Added demo source for DTC in this driver.
*              : 28.11.2014 1.07     Changed r_qspi_smstr_single_writeread_dmacdtc(), 
*              :                     r_qspi_smstr_dualquad_write_dmacdtc() and
*              :                     r_qspi_smstr_dualquad_read_dmacdtc().
*              : 30.01.2015 1.08     Added RX71M.
*              : 31.07.2017 2.08     Supported RX65N-2MB.
*              :                     Fixed to correspond to Renesas coding rule.
*              : 20.05.2019 1.12     Added support for GNUC and ICCRX.
*              :                     Fixed coding style. 
*              : 30.07.2019 1.13     Added WAIT LOOP.
*******************************************************************************/

/*******************************************************************************
Includes <System Includes> , "Project Includes"
*******************************************************************************/
/* Public interface header file for this package */
#include "r_qspi_smstr_rx_if.h"
/* Configuration for this package. */
#include "r_qspi_smstr_rx_config.h"
/* Private header file for this package. */
#include "./src/r_qspi_smstr_private.h"

#ifdef QSPI_SMSTR_CFG_LONGQ_ENABLE
/* Uses LONGQ driver header file */
#include "r_longq_if.h"
#endif /* QSPI_SMSTR_CFG_LONGQ_ENABLE */


/*******************************************************************************
Macro definitions
*******************************************************************************/


/*******************************************************************************
Typedef definitions
*******************************************************************************/


/*******************************************************************************
Private variables and functions
*******************************************************************************/
#ifdef QSPI_SMSTR_CFG_LONGQ_ENABLE
static longq_hdl_t       p_qspi_smstr_long_que;       /* LONGQ handler */
#endif  /* QSPI_SMSTR_CFG_LONGQ_ENABLE */


/*******************************************************************************
* Function Name: R_QSPI_SMstr_Open
* Description  : Initializes setting of ports.
*                Initializes the QSPI registers for QSPI control.
* Arguments    : channel -
*                    Which channel to use
*                spbr_data -
*                    Setting of QSPI Bit Rate Register (SPBR)
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*                QSPI_SMSTR_ERR_PARAM -
*                    Parameter error
*                QSPI_SMSTR_ERR_OTHER -
*                    QSPI resource has been acquired by other task already.
*******************************************************************************/
qspi_smstr_status_t R_QSPI_SMstr_Open(uint8_t channel, uint8_t spbr_data)
{
    qspi_smstr_status_t ret = QSPI_SMSTR_SUCCESS;
#ifdef QSPI_SMSTR_CFG_USE_FIT
    bool              retbool = false;
#endif  /* QSPI_SMSTR_CFG_USE_FIT */
    
    /* ---- Check argument. ---- */
    ret = r_qspi_smstr_ch_check(channel);
    if (QSPI_SMSTR_SUCCESS != ret)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }
    
    /* ---- QSPI hardware lock ---- */
#ifdef QSPI_SMSTR_CFG_USE_FIT
    retbool = R_BSP_HardwareLock((mcu_lock_t)(BSP_LOCK_QSPI + channel));
    if (false == retbool)
    {
        /* Lock has already been acquired by other task. Needs to try again later. */
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_OTHER;
    }
#endif  /* QSPI_SMSTR_CFG_USE_FIT */
    
    /* Initialize the ports. */
    r_qspi_smstr_io_init(channel);
    
    /* Initialize the QSPI registers for QSPI control. */
    r_qspi_smstr_enable(channel, spbr_data);
    
    return QSPI_SMSTR_SUCCESS;
}


/*******************************************************************************
* Function Name: R_QSPI_SMstr_Close
* Description  : Stops QSPI and puts it in module stop to conserve power.
*                Resets setting of ports..
* Arguments    : channel -
*                    Which channel to use
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*                QSPI_SMSTR_ERR_PARAM -
*                    Parameter error
*******************************************************************************/
qspi_smstr_status_t R_QSPI_SMstr_Close(uint8_t channel)
{
    qspi_smstr_status_t ret = QSPI_SMSTR_SUCCESS;
    
    /* ---- Check argument. ---- */
    ret = r_qspi_smstr_ch_check(channel);
    if (QSPI_SMSTR_SUCCESS != ret)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }
    
    /* Set module stop of QSPI. */
    r_qspi_smstr_disable(channel);
    
    /* Reset setting of ports. */
    r_qspi_smstr_io_reset(channel);
    
    /* QSPI hardware unlock */
#ifdef QSPI_SMSTR_CFG_USE_FIT
    R_BSP_HardwareUnlock((mcu_lock_t)(BSP_LOCK_QSPI + channel));
#endif  /* QSPI_SMSTR_CFG_USE_FIT */
    
    return QSPI_SMSTR_SUCCESS;
}


/*******************************************************************************
* Function Name: R_QSPI_SMstr_Control
* Description  : Changes setting of SPI clock mode and bit rate of QSPI.
* Arguments    : channel -
*                    Which channel to use
*                clk_mode -
*                    Number of SPI clock mode
*                        0: CPOL=0, CPHA=0
*                        1: CPOL=0, CPHA=1
*                        2: CPOL=1, CPHA=0
*                        3: CPOL=1, CPHA=1
*                spbr_data -
*                    Setting of QSPI Bit Rate Register (SPBR)
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*                QSPI_SMSTR_ERR_PARAM -
*                    Parameter error
*******************************************************************************/
qspi_smstr_status_t R_QSPI_SMstr_Control(uint8_t channel, uint8_t clk_mode, uint8_t spbr_data)
{
    qspi_smstr_status_t ret = QSPI_SMSTR_SUCCESS;
    
    /* ---- Check argument. ---- */
    ret = r_qspi_smstr_ch_check(channel);
    if (QSPI_SMSTR_SUCCESS != ret)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }
    
    if (3 < clk_mode)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }
    
    /* Change SPI clock mode and bit rate of QSPI. */
    r_qspi_smstr_change(channel, clk_mode, spbr_data);
    
    return QSPI_SMSTR_SUCCESS;
}


/*******************************************************************************
* Function Name: R_QSPI_SMstr_Write
* Description  : Executes transmission operation.
*                When using DMAC or DTC, supports that the number of data is a multiple of 16.
* Arguments    : channel -
*                    Which channel to use
*                * p_qspi_smstr_info -
*                    QSPI information
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*                QSPI_SMSTR_ERR_PARAM -
*                    Parameter error
*                QSPI_SMSTR_ERR_HARD -
*                    Hardware error
*------------------------------------------------------------------------------
* Note         : Set the "p_qspi_smstr_info->data_cnt" to a multiple of 16 using DMAC or DTC.
*******************************************************************************/
qspi_smstr_status_t R_QSPI_SMstr_Write(uint8_t channel, qspi_smstr_info_t * p_qspi_smstr_info)
{
    qspi_smstr_status_t   ret = QSPI_SMSTR_SUCCESS;
    
    /* ---- Check argument. ---- */
    ret = r_qspi_smstr_ch_check(channel);
    if (QSPI_SMSTR_SUCCESS != ret)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }

    if (0 == p_qspi_smstr_info)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }

    if (0 == p_qspi_smstr_info->data_cnt)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }

    if (0 == p_qspi_smstr_info->p_tx_data)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }

    if ((QSPI_SMSTR_SINGLE_SPI_READ      == p_qspi_smstr_info->op_mode) ||
        (QSPI_SMSTR_SINGLE_SPI_WRITEREAD == p_qspi_smstr_info->op_mode))
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }

    if ((QSPI_SMSTR_DMAC == p_qspi_smstr_info->tran_mode) ||
        (QSPI_SMSTR_DTC  == p_qspi_smstr_info->tran_mode))
    {
        /* ---- Check the buffer boundary (4-byte unit). ---- */
        /* Cast the variable to a uint32_t type because the address of this pointer may not be 4-byte unit. */
        if (0 != ((uint32_t)p_qspi_smstr_info->p_tx_data & 0x00000003u))
        {
            R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
            return QSPI_SMSTR_ERR_PARAM;
        }

        /* ---- Check the counter (16-byte unit). ---- */
        /* NOTE: Do not support the number of data other than a multiple of 16 using DMAC or DTC. */
        if (0 != (p_qspi_smstr_info->data_cnt & 0x0000000fu))
        {
            R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
            return QSPI_SMSTR_ERR_PARAM;
        }
    }

    switch (p_qspi_smstr_info->tran_mode)
    {
        case QSPI_SMSTR_SW:
            switch (p_qspi_smstr_info->op_mode)
            {
                case QSPI_SMSTR_SINGLE_SPI_WRITE:
                    ret = r_qspi_smstr_single_writeread_software(channel, p_qspi_smstr_info);
                break;
                case QSPI_SMSTR_DUAL_SPI:
                case QSPI_SMSTR_QUAD_SPI:
                    ret = r_qspi_smstr_dualquad_write_software(channel, p_qspi_smstr_info);
                break;
                default:
                    ret = QSPI_SMSTR_ERR_PARAM;
                    R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
                break;
            }
        break;
        case QSPI_SMSTR_DMAC:
        case QSPI_SMSTR_DTC:
            switch (p_qspi_smstr_info->op_mode)
            {
                case QSPI_SMSTR_SINGLE_SPI_WRITE:
                    ret = r_qspi_smstr_single_writeread_dmacdtc(channel, p_qspi_smstr_info);
                break;
                case QSPI_SMSTR_DUAL_SPI:
                case QSPI_SMSTR_QUAD_SPI:
                    ret = r_qspi_smstr_dualquad_write_dmacdtc(channel, p_qspi_smstr_info);
                break;
                default:
                    ret = QSPI_SMSTR_ERR_PARAM;
                    R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
                break;
            }
        break;
        default:
            ret = QSPI_SMSTR_ERR_PARAM;
            R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        break;
    }

    return ret;
}


/*******************************************************************************
* Function Name: R_QSPI_SMstr_Read
* Description  : Executes reception operation.
*                When using DMAC or DTC, supports that the number of data is a multiple of 16.
* Arguments    : channel -
*                    Which channel to use
*                * p_qspi_smstr_info -
*                    QSPI information
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*                QSPI_SMSTR_ERR_PARAM -
*                    Parameter error
*                QSPI_SMSTR_ERR_HARD -
*                    Hardware error
*------------------------------------------------------------------------------
* Note         : Set the "p_qspi_smstr_info->data_cnt" to a multiple of 16 using DMAC or DTC.
*******************************************************************************/
qspi_smstr_status_t R_QSPI_SMstr_Read(uint8_t channel, qspi_smstr_info_t * p_qspi_smstr_info)
{
    qspi_smstr_status_t   ret = QSPI_SMSTR_SUCCESS;
    
    /* ---- Check argument. ---- */
    ret = r_qspi_smstr_ch_check(channel);
    if (QSPI_SMSTR_SUCCESS != ret)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }

    if (0 == p_qspi_smstr_info)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }

    if (0 == p_qspi_smstr_info->data_cnt)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }

    if (0 == p_qspi_smstr_info->p_rx_data)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }

    if ((QSPI_SMSTR_SINGLE_SPI_WRITE     == p_qspi_smstr_info->op_mode) ||
        (QSPI_SMSTR_SINGLE_SPI_WRITEREAD == p_qspi_smstr_info->op_mode))
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }

    if ((QSPI_SMSTR_DMAC == p_qspi_smstr_info->tran_mode) ||
        (QSPI_SMSTR_DTC  == p_qspi_smstr_info->tran_mode))
    {
        /* ---- Check the buffer boundary (4-byte unit). ---- */
        /* Cast the variable to a uint32_t type because the address of this pointer may not be 4 bytes unit. */
        if (0 != ((uint32_t)p_qspi_smstr_info->p_rx_data & 0x00000003u))
        {
            R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
            return QSPI_SMSTR_ERR_PARAM;
        }

        /* ---- Check the counter (16-byte unit). ---- */
        /* NOTE: Do not support the number of data other than a multiple of 16 using DMAC or DTC. */
        if (0 != (p_qspi_smstr_info->data_cnt & 0x0000000fu))
        {
            R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
            return QSPI_SMSTR_ERR_PARAM;
        }
    }

    switch (p_qspi_smstr_info->tran_mode)
    {
        case QSPI_SMSTR_SW:
            switch (p_qspi_smstr_info->op_mode)
            {
                case QSPI_SMSTR_SINGLE_SPI_READ:
                    ret = r_qspi_smstr_single_writeread_software(channel, p_qspi_smstr_info);
                break;
                case QSPI_SMSTR_DUAL_SPI:
                case QSPI_SMSTR_QUAD_SPI:
                    ret = r_qspi_smstr_dualquad_read_software(channel, p_qspi_smstr_info);
                break;
                default:
                    ret = QSPI_SMSTR_ERR_PARAM;
                    R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
                break;
            }
        break;
        case QSPI_SMSTR_DMAC:
        case QSPI_SMSTR_DTC:
            switch (p_qspi_smstr_info->op_mode)
            {
                case QSPI_SMSTR_SINGLE_SPI_READ:
                    ret = r_qspi_smstr_single_writeread_dmacdtc(channel, p_qspi_smstr_info);
                break;
                case QSPI_SMSTR_DUAL_SPI:
                case QSPI_SMSTR_QUAD_SPI:
                    ret = r_qspi_smstr_dualquad_read_dmacdtc(channel, p_qspi_smstr_info);
                break;
                default:
                    ret = QSPI_SMSTR_ERR_PARAM;
                    R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
                break;
            }
        break;
        default:
            ret = QSPI_SMSTR_ERR_PARAM;
            R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        break;
    }

    return ret;
}


/*******************************************************************************
* Function Name: r_qspi_smstr_single_writeread_software
* Description  : Transmits data, receives data and stores to the specified buffer in single mode using software.
* Arguments    : channel -
*                    Which channel to use
*                * p_qspi_smstr_info -
*                    QSPI information
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*                QSPI_SMSTR_ERR_HARD -
*                    Hardware error
*******************************************************************************/
qspi_smstr_status_t r_qspi_smstr_single_writeread_software(uint8_t channel, qspi_smstr_info_t * p_qspi_smstr_info)
{
    qspi_smstr_status_t   ret = QSPI_SMSTR_SUCCESS;
    uint32_t            trx_wait;
    uint32_t            trx_cnt;
    uint32_t            cnt;
    uint32_t            tx_data[4];
    uint32_t            rx_data[4];
    uint8_t           * p_tx_data;
    uint8_t           * p_rx_data;
    volatile uint8_t R_BSP_EVENACCESS_SFR * spsr_addr;
    volatile uint8_t    uc_tmp;

    /* Get address of status register for QSPI. */
    spsr_addr   = r_qspi_smstr_spsr_addr(channel);
    
    /* ---- Get QSPI information. ---- */
    trx_cnt     = p_qspi_smstr_info->data_cnt;

    /* Get address of transmit data. */
    if ((QSPI_SMSTR_SINGLE_SPI_WRITE == p_qspi_smstr_info->op_mode) ||
        (QSPI_SMSTR_SINGLE_SPI_WRITEREAD == p_qspi_smstr_info->op_mode))
    {
        p_tx_data   = p_qspi_smstr_info->p_tx_data;
    }
    
    /* Get address of receive data. */
    if ((QSPI_SMSTR_SINGLE_SPI_READ == p_qspi_smstr_info->op_mode) ||
        (QSPI_SMSTR_SINGLE_SPI_WRITEREAD == p_qspi_smstr_info->op_mode))
    {
        p_rx_data   = p_qspi_smstr_info->p_rx_data;
    }

    /* Clear flags of transmit buffer empty, receive buffer full and QSSL negation. */
    /* Enable QSPI transmission and reception in Single-SPI. */
    r_qspi_smstr_trx_enable_single(channel, trx_cnt);
    
    /* ==== Start QSPI transmission and reception. ==== */
    /* Transmit of the data more than half of the transmit buffer size. */
    if (QSPI_FIFO_HALF_SIZE <= trx_cnt)
    {
        /* ---- Transfer data or dummy data from RAM to QSPI Data Register. ---- */
        switch (p_qspi_smstr_info->op_mode)
        {
            case QSPI_SMSTR_SINGLE_SPI_WRITE:
            case QSPI_SMSTR_SINGLE_SPI_WRITEREAD:
                /* Exchange data by endian. */
                r_qspi_smstr_tx_exchg(channel, p_tx_data, &tx_data[0]);

                /* ---- Write transmit data in long. ---- */
                r_qspi_smstr_tx_software_trans(channel, &tx_data[0]);

                /* ---- Update address of transmit data. ---- */
                p_tx_data   += (uint8_t)QSPI_FIFO_HALF_SIZE;
            break;
            case QSPI_SMSTR_SINGLE_SPI_READ:
                r_qspi_smstr_tx_software_trans_dummy(channel);
            break;
            default:
                /* Do nothing. */
            break;
        }

        /* ---- Update count of transmit data. ---- */
        trx_cnt     -= QSPI_FIFO_HALF_SIZE;

        /* Clear flag of transmit buffer empty. */
        r_qspi_smstr_sptef_clear(channel);

        if (QSPI_FIFO_HALF_SIZE <= trx_cnt)
        {
            do
            {
                /* ---- Check transmit buffer empty. ---- */
                trx_wait = QSPI_SMSTR_TX_WAIT;
                ret     = r_qspi_smstr_wait(spsr_addr, trx_wait, QSPI_SMSTR_MASK_SPTEF);
                if (QSPI_SMSTR_ERR_HARD == ret)
                {
                    /* ---- Disable QSPI transmission and reception. ---- */
                    r_qspi_smstr_trx_disable(channel);
                    R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
                    return ret;
                }

                /* ---- Transfer data or dummy data from RAM to QSPI Data Register. ---- */
                switch (p_qspi_smstr_info->op_mode)
                {
                    case QSPI_SMSTR_SINGLE_SPI_WRITE:
                    case QSPI_SMSTR_SINGLE_SPI_WRITEREAD:
                        /* Exchange data by endian. */
                        r_qspi_smstr_tx_exchg(channel, p_tx_data, &tx_data[0]);

                        /* ---- Write transmit data in long. ---- */
                        r_qspi_smstr_tx_software_trans(channel, &tx_data[0]);

                        /* ---- Update address of transmit data. ---- */
                        p_tx_data   += (uint8_t)QSPI_FIFO_HALF_SIZE;
                    break;
                    case QSPI_SMSTR_SINGLE_SPI_READ:
                        r_qspi_smstr_tx_software_trans_dummy(channel);
                    break;
                    default:
                        /* Do nothing. */
                    break;
                }

                /* ---- Update count of transmit data. ---- */
                trx_cnt     -= QSPI_FIFO_HALF_SIZE;

                /* Clear flag of transmit buffer empty. */
                r_qspi_smstr_sptef_clear(channel);
                
                /* ---- Check receive buffer full. ---- */
                trx_wait = QSPI_SMSTR_RX_WAIT;
                ret     = r_qspi_smstr_wait(spsr_addr, trx_wait, QSPI_SMSTR_MASK_SPRFF);
                if (QSPI_SMSTR_ERR_HARD == ret)
                {
                    /* ---- Disable QSPI transmission and reception. ---- */
                    r_qspi_smstr_trx_disable(channel);
                    R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
                    return ret;
                }

                /* ---- Transfer data or dummy data from QSPI Data Register to RAM. ---- */
                switch (p_qspi_smstr_info->op_mode)
                {
                    case QSPI_SMSTR_SINGLE_SPI_READ:
                    case QSPI_SMSTR_SINGLE_SPI_WRITEREAD:
                        /* ---- Read receive data in long. ---- */
                        r_qspi_smstr_rx_software_trans(channel, &rx_data[0]);

                        /* Exchange data by endian. */
                        r_qspi_smstr_rx_exchg(channel, p_rx_data, &rx_data[0]);

                        /* ---- Update address of receive data. ---- */
                        p_rx_data   += (uint8_t)QSPI_FIFO_HALF_SIZE;
                    break;
                    case QSPI_SMSTR_SINGLE_SPI_WRITE:
                        r_qspi_smstr_rx_software_trans_dummy(channel);
                    break;
                    default:
                        /* Do nothing. */
                    break;
                }

                /* Clear flag of receive buffer full. */
                r_qspi_smstr_sprff_clear(channel);
            }
            while (QSPI_FIFO_HALF_SIZE <= trx_cnt); /* WAIT_LOOP */
        }
        
        /* ---- Check receive buffer full. ---- */
        trx_wait = QSPI_SMSTR_RX_WAIT;
        ret     = r_qspi_smstr_wait(spsr_addr, trx_wait, QSPI_SMSTR_MASK_SPRFF);
        if (QSPI_SMSTR_ERR_HARD == ret)
        {
            /* ---- Disable QSPI transmission and reception. ---- */
            r_qspi_smstr_trx_disable(channel);
            R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
            return ret;
        }

        /* ---- Transfer dummy data from QSPI Data Register to RAM. ---- */
        switch (p_qspi_smstr_info->op_mode)
        {
            case QSPI_SMSTR_SINGLE_SPI_READ:
            case QSPI_SMSTR_SINGLE_SPI_WRITEREAD:
                /* ---- Read receive data in long. ---- */
                r_qspi_smstr_rx_software_trans(channel, &rx_data[0]);

                /* Exchange data by endian. */
                r_qspi_smstr_rx_exchg(channel, p_rx_data, &rx_data[0]);

                /* ---- Update address of receive data. ---- */
                p_rx_data   += (uint8_t)QSPI_FIFO_HALF_SIZE;
            break;
            case QSPI_SMSTR_SINGLE_SPI_WRITE:
                r_qspi_smstr_rx_software_trans_dummy(channel);
            break;
            default:
                /* Do nothing. */
            break;
        }

        /* Clear flag of receive buffer full. */
        r_qspi_smstr_sprff_clear(channel);
    }
    
    if (0 != trx_cnt)
    {
        /* ---- Check transmit buffer empty. ---- */
        trx_wait = QSPI_SMSTR_TX_WAIT;
        ret     = r_qspi_smstr_wait(spsr_addr, trx_wait, QSPI_SMSTR_MASK_SPTEF);
        if (QSPI_SMSTR_ERR_HARD == ret)
        {
            /* ---- Disable QSPI transmission and reception. ---- */
            r_qspi_smstr_trx_disable(channel);
            R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
            return ret;
        }

        /* Set data to transmit buffer. */
        cnt = trx_cnt;
        do
        {
            switch (p_qspi_smstr_info->op_mode)
            {
                case QSPI_SMSTR_SINGLE_SPI_WRITE:
                case QSPI_SMSTR_SINGLE_SPI_WRITEREAD:
                    /* Write transmit data in byte. */
                    r_qspi_smstr_data_set_byte(channel, *p_tx_data);

                    /* Update address of transmit data. */
                    p_tx_data++;
                break;
                case QSPI_SMSTR_SINGLE_SPI_READ:
                    /* Write dummy data in order to receive data in byte. */
                    r_qspi_smstr_data_set_byte(channel, QSPI_SMSTR_DUMMY_DATA_BYTE);
                break;
                default:
                    /* Do nothing. */
                break;
            }
            cnt--;
        }
        while (0 != cnt); /* WAIT_LOOP */
    }

    /* ---- Check QSSL negation. ---- */
    trx_wait = QSPI_SMSTR_QSSL_WAIT;
    ret     = r_qspi_smstr_wait(spsr_addr, trx_wait, QSPI_SMSTR_MASK_SPSSLF);
    if (QSPI_SMSTR_ERR_HARD == ret)
    {
        /* ---- Disable QSPI transmission and reception. ---- */
        r_qspi_smstr_trx_disable(channel);
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return ret;
    }

    if (0 != trx_cnt)
    {
        /* Store data to receive buffer. */
        do
        {
            switch (p_qspi_smstr_info->op_mode)
            {
                case QSPI_SMSTR_SINGLE_SPI_READ:
                case QSPI_SMSTR_SINGLE_SPI_WRITEREAD:
                    /* Read receive data in byte. */
                    *p_rx_data = r_qspi_smstr_data_get_byte(channel);

                    /* Update address of transmit data. */
                    p_rx_data++;
                break;
                case QSPI_SMSTR_SINGLE_SPI_WRITE:
                    /* Dummy read in byte */
                    uc_tmp = r_qspi_smstr_data_get_byte(channel);
                break;
                default:
                    /* Do nothing. */
                break;
            }
            /* Update count of receive data. */
            trx_cnt--;
        }
        while (0 != trx_cnt); /* WAIT_LOOP */
    }
    
    /* Clear flags of transmit buffer empty, receive buffer full and QSSL negation. */
    /* Disable QSPI transmission and reception. */
    r_qspi_smstr_trx_disable(channel);
    
    return QSPI_SMSTR_SUCCESS;
}


/*******************************************************************************
* Function Name: r_qspi_smstr_dualquad_write_software
* Description  : Transmits data, receives data and stores to the specified buffer in dual or quad mode using software.
* Arguments    : channel -
*                    Which channel to use
*                * p_qspi_smstr_info -
*                    QSPI information
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*                QSPI_SMSTR_ERR_HARD -
*                    Hardware error
*******************************************************************************/
qspi_smstr_status_t r_qspi_smstr_dualquad_write_software(uint8_t channel, qspi_smstr_info_t * p_qspi_smstr_info)
{
    qspi_smstr_status_t   ret = QSPI_SMSTR_SUCCESS;
    uint32_t            tx_wait;
    uint32_t            tx_cnt;
    uint32_t            tx_data[4];
    uint8_t           * p_tx_data;
    volatile uint8_t R_BSP_EVENACCESS_SFR * spsr_addr;
    
    /* Get address of status register for QSPI. */
    spsr_addr = r_qspi_smstr_spsr_addr(channel);
    
    /* ---- Get QSPI information. ---- */
    tx_cnt      = p_qspi_smstr_info->data_cnt;
    p_tx_data   = p_qspi_smstr_info->p_tx_data;
    
    /* Clear flags of transmit buffer empty and QSSL negation. */
    /* Enable QSPI transmission. */
    if (QSPI_SMSTR_DUAL_SPI == p_qspi_smstr_info->op_mode)
    {
        /* Enable QSPI transmission in Dual-SPI. */
        r_qspi_smstr_tx_enable_dual(channel, tx_cnt);
    }
    else
    {
        /* Enable QSPI transmission in Quad-SPI. */
        r_qspi_smstr_tx_enable_quad(channel, tx_cnt);
    }
    
    /* ==== Start QSPI transmission. ==== */
    /* Transmit of the data more than half of the transmit buffer size. */
    if (QSPI_FIFO_HALF_SIZE <= tx_cnt)
    {
        do
        {
            /* Exchange data by endian. */
            r_qspi_smstr_tx_exchg(channel, p_tx_data, &tx_data[0]);

            /* ---- Check transmit buffer empty. ---- */
            /* NOTE: Do not execute wait processing anymore when the flag is set.
                     Because the wait processing takes long time. */
            if (0 == (QSPI_SMSTR_MASK_SPTEF & (*spsr_addr)))
            {
                tx_wait = QSPI_SMSTR_TX_WAIT;
                ret     = r_qspi_smstr_wait(spsr_addr, tx_wait, QSPI_SMSTR_MASK_SPTEF);
                if (QSPI_SMSTR_ERR_HARD == ret)
                {
                    /* ---- Disable QSPI transmission. ---- */
                    r_qspi_smstr_tx_disable(channel);
                    R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
                    return ret;
                }
            }

            /* ---- Transfer data from RAM to QSPI Data Register. ---- */
            r_qspi_smstr_tx_software_trans(channel, &tx_data[0]);

            /* ---- Update count and address of transmit data. ---- */
            tx_cnt      -= QSPI_FIFO_HALF_SIZE;
            p_tx_data   += (uint8_t)QSPI_FIFO_HALF_SIZE;

            /* Clear flag of transmit buffer empty. */
            r_qspi_smstr_sptef_clear(channel);
        }
        while (QSPI_FIFO_HALF_SIZE <= tx_cnt); /* WAIT_LOOP */
    }

    /* Transmit the data which are smaller than half of the transmit buffer size. */
    if (0 != tx_cnt)
    {
        /* ---- Check transmit buffer empty. ---- */
        tx_wait = QSPI_SMSTR_TX_WAIT;
        ret     = r_qspi_smstr_wait(spsr_addr, tx_wait, QSPI_SMSTR_MASK_SPTEF);
        if (QSPI_SMSTR_ERR_HARD == ret)
        {
            /* ---- Disable QSPI transmission. ---- */
            r_qspi_smstr_tx_disable(channel);
            R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
            return ret;
        }

        do
        {
            /* Write transmit data in byte. */
            r_qspi_smstr_data_set_byte(channel, *p_tx_data);

            /* Update count and address of transmit data. */
            p_tx_data++;
            tx_cnt--;
        }
        while (0 != tx_cnt); /* WAIT_LOOP */
    }
    
    /* ---- Check QSSL negation. ---- */
    tx_wait = QSPI_SMSTR_QSSL_WAIT;
    ret     = r_qspi_smstr_wait(spsr_addr, tx_wait, QSPI_SMSTR_MASK_SPSSLF);
    if (QSPI_SMSTR_ERR_HARD == ret)
    {
        /* ---- Disable QSPI transmission. ---- */
        r_qspi_smstr_tx_disable(channel);
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return ret;
    }
    
    /* Clear flags of transmit buffer empty and QSSL negation. */
    /* Disable QSPI transmission. */
    r_qspi_smstr_tx_disable(channel);
    
    return QSPI_SMSTR_SUCCESS;
}


/*******************************************************************************
* Function Name: r_qspi_smstr_dualquad_read_software
* Description  : Receives data and stores to the specified buffer in dual or quad mode using software.
* Arguments    : channel -
*                    Which channel to use
*                * p_qspi_smstr_info -
*                    QSPI information
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*                QSPI_SMSTR_ERR_HARD -
*                    Hardware error
*******************************************************************************/
qspi_smstr_status_t r_qspi_smstr_dualquad_read_software(uint8_t channel, qspi_smstr_info_t * p_qspi_smstr_info)
{
    qspi_smstr_status_t   ret = QSPI_SMSTR_SUCCESS;
    uint32_t            rx_wait;
    uint32_t            rx_cnt;
    uint32_t            rx_data[4];
    uint8_t           * p_rx_data;
    volatile uint8_t R_BSP_EVENACCESS_SFR * spsr_addr;

    /* Get address of status register for QSPI. */
    spsr_addr = r_qspi_smstr_spsr_addr(channel);
    
    /* ---- Get QSPI information. ---- */
    rx_cnt      = p_qspi_smstr_info->data_cnt;
    p_rx_data   = p_qspi_smstr_info->p_rx_data;

    /* Clear flags of receive buffer full and QSSL negation. */
    /* Enable QSPI reception. */
    if (QSPI_SMSTR_DUAL_SPI == p_qspi_smstr_info->op_mode)
    {
        /* Enable QSPI reception in Dual-SPI. */
        r_qspi_smstr_rx_enable_dual(channel, rx_cnt);
    }
    else
    {
        /* Enable QSPI reception in Quad-SPI. */
        r_qspi_smstr_rx_enable_quad(channel, rx_cnt);
    }
    
    /* ==== Start QSPI reception. ==== */
    /* Receive of the data more than half of the receive buffer size. */
    if (QSPI_FIFO_HALF_SIZE <= rx_cnt)
    {
        do
        {
            /* ---- Check receive buffer full. ---- */
            /* NOTE: Do not execute wait processing anymore when the flag is set.
                     Because the wait processing takes long time. */
            if (0 == (QSPI_SMSTR_MASK_SPRFF & (*spsr_addr)))
            {
                rx_wait = QSPI_SMSTR_RX_WAIT;
                ret     = r_qspi_smstr_wait(spsr_addr, rx_wait, QSPI_SMSTR_MASK_SPRFF);
                if (QSPI_SMSTR_ERR_HARD == ret)
                {
                    /* ---- Disable QSPI reception. ---- */
                    r_qspi_smstr_rx_disable(channel);
                    R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
                    return ret;
                }
            }

            /* ---- Transfer data from QSPI Data Register to RAM. ---- */
            r_qspi_smstr_rx_software_trans(channel, &rx_data[0]);

            /* Exchange data by endian. */
            r_qspi_smstr_rx_exchg(channel, p_rx_data, &rx_data[0]);

            /* ---- Update count and address of receive data. ---- */
            rx_cnt      -= QSPI_FIFO_HALF_SIZE;
            p_rx_data   += (uint8_t)QSPI_FIFO_HALF_SIZE;

            /* ---- Clear flag of receive buffer full. ---- */
            r_qspi_smstr_sprff_clear(channel);
        }
        while (QSPI_FIFO_HALF_SIZE <= rx_cnt); /* WAIT_LOOP */
    }

    /* ---- Check QSSL negation. ---- */
    rx_wait = QSPI_SMSTR_QSSL_WAIT;
    ret     = r_qspi_smstr_wait(spsr_addr, rx_wait, QSPI_SMSTR_MASK_SPSSLF);
    if (QSPI_SMSTR_ERR_HARD == ret)
    {
        /* ---- Disable QSPI reception. ---- */
        r_qspi_smstr_rx_disable(channel);
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return ret;
    }
    
    /* Receive the data which are smaller than half of the receive buffer size. */
    if (0 != rx_cnt)
    {
        do
        {
            /* Read receive data in byte. */
            *p_rx_data = r_qspi_smstr_data_get_byte(channel);

            /* Update count and address of receive data. */
            p_rx_data++;
            rx_cnt--;
        }
        while (0 != rx_cnt); /* WAIT_LOOP */
    }
    
    /* Clear flags of receive buffer full and QSSL negation. */
    /* Disable QSPI reception. */
    r_qspi_smstr_rx_disable(channel);
    
    return QSPI_SMSTR_SUCCESS;
}


/*******************************************************************************
* Function Name: r_qspi_smstr_single_writeread_dmacdtc
* Description  : Transmits data, receives data and stores to the specified buffer in dual or quad mode using DMAC or DTC.
* Arguments    : channel -
*                    Which channel to use
*                * p_qspi_smstr_info -
*                    QSPI information
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*                QSPI_SMSTR_ERR_HARD -
*                    Hardware error
*******************************************************************************/
qspi_smstr_status_t r_qspi_smstr_single_writeread_dmacdtc(uint8_t channel, qspi_smstr_info_t * p_qspi_smstr_info)
{
    qspi_smstr_status_t   ret = QSPI_SMSTR_SUCCESS;
    uint32_t            tx_wait;
    volatile uint8_t R_BSP_EVENACCESS_SFR * spsr_addr;
    uint8_t * p_tx_data = NULL;
    uint8_t * p_rx_data = NULL;

    /* Get address of status register for QSPI. */
    spsr_addr   = r_qspi_smstr_spsr_addr(channel);

    /* ---- Beforehand exchange transmit data according to endian. ----*/
    if ((QSPI_SMSTR_SINGLE_SPI_WRITE     == p_qspi_smstr_info->op_mode) ||
        (QSPI_SMSTR_SINGLE_SPI_WRITEREAD == p_qspi_smstr_info->op_mode))
    {
        p_tx_data = p_qspi_smstr_info->p_tx_data;
        ret = r_qspi_smstr_exchg_dmacdtc(channel, p_tx_data, p_qspi_smstr_info->data_cnt);
        if (QSPI_SMSTR_SUCCESS != ret)
        {
            R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
            return ret;
        }
    }

    /* Set DMAC/DTC transfer end flag for SPTI and SPTI. */
    R_QSPI_SMstr_Int_Spti_Dmacdtc_Flag_Set(channel, QSPI_SET_TRANS_START);
    R_QSPI_SMstr_Int_Spri_Dmacdtc_Flag_Set(channel, QSPI_SET_TRANS_START);

    /* Initialize SPTI and SPRI interrupt registers. */
    r_qspi_smstr_int_spti_init(channel);
    r_qspi_smstr_int_spri_init(channel);

    /* Clear flags of transmit buffer empty, receive buffer full and QSSL negation. */
    /* Enable QSPI transmission and reception in Single-SPI. */
    r_qspi_smstr_trx_enable_single(channel, p_qspi_smstr_info->data_cnt);

    /* Set the ICU.IERm.IENj bit to 1. */
    r_qspi_smstr_int_spri_ier_set(channel);
    r_qspi_smstr_int_spti_ier_set(channel);

    /* **** Start QSPI transmission and reception. **** */

    /* ---- Wait for reception completion. ---- */
    ret = r_qspi_smstr_rx_dmacdtc_wait(channel, p_qspi_smstr_info->data_cnt);
    if (0 > ret)
    {
        /* ---- Disable QSPI transmission and reception. ---- */
        if ((QSPI_SMSTR_SINGLE_SPI_WRITE     == p_qspi_smstr_info->op_mode) ||
            (QSPI_SMSTR_SINGLE_SPI_WRITEREAD == p_qspi_smstr_info->op_mode))
        {
            p_tx_data = p_qspi_smstr_info->p_tx_data;
            r_qspi_smstr_exchg_dmacdtc(channel, p_tx_data, p_qspi_smstr_info->data_cnt);
        }
        R_QSPI_SMstr_Int_Spti_Ier_Clear(channel);
        R_QSPI_SMstr_Int_Spri_Ier_Clear(channel);
        R_QSPI_SMstr_Int_Spti_Dmacdtc_Flag_Set(channel, QSPI_SET_TRANS_STOP);
        R_QSPI_SMstr_Int_Spri_Dmacdtc_Flag_Set(channel, QSPI_SET_TRANS_STOP);
        r_qspi_smstr_trx_disable(channel);
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return ret;
    }

    /* Clear the ICU.IERm.IENj bit to 0 using DMAC or DTC. */
    R_QSPI_SMstr_Int_Spti_Ier_Clear(channel);
    R_QSPI_SMstr_Int_Spri_Ier_Clear(channel);
    R_QSPI_SMstr_Int_Spti_Dmacdtc_Flag_Set(channel, QSPI_SET_TRANS_STOP);
    R_QSPI_SMstr_Int_Spri_Dmacdtc_Flag_Set(channel, QSPI_SET_TRANS_STOP);

    /* ---- Check QSSL negation. ---- */
    tx_wait = QSPI_SMSTR_QSSL_WAIT;
    ret     = r_qspi_smstr_wait(spsr_addr, tx_wait, QSPI_SMSTR_MASK_SPSSLF);
    if (QSPI_SMSTR_ERR_HARD == ret)
    {
        /* ---- Disable QSPI transmission. ---- */
        if ((QSPI_SMSTR_SINGLE_SPI_WRITE     == p_qspi_smstr_info->op_mode) ||
            (QSPI_SMSTR_SINGLE_SPI_WRITEREAD == p_qspi_smstr_info->op_mode))
        {
            p_tx_data = p_qspi_smstr_info->p_tx_data;
            r_qspi_smstr_exchg_dmacdtc(channel, p_tx_data, p_qspi_smstr_info->data_cnt);
        }
        r_qspi_smstr_trx_disable(channel);
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return ret;
    }

    /* Clear flags of transmit buffer empty, receive buffer full and QSSL negation. */
    /* Disable QSPI transmission and reception. */
    r_qspi_smstr_trx_disable(channel);

    /* ---- Finally exchange receive data according to endian. ----*/
    if ((QSPI_SMSTR_SINGLE_SPI_READ      == p_qspi_smstr_info->op_mode) ||
        (QSPI_SMSTR_SINGLE_SPI_WRITEREAD == p_qspi_smstr_info->op_mode))
    {
        p_rx_data = p_qspi_smstr_info->p_rx_data;
        ret = r_qspi_smstr_exchg_dmacdtc(channel, p_rx_data, p_qspi_smstr_info->data_cnt);
        if (QSPI_SMSTR_SUCCESS != ret)
        {
            if (QSPI_SMSTR_SINGLE_SPI_WRITEREAD == p_qspi_smstr_info->op_mode)
            {
                p_tx_data = p_qspi_smstr_info->p_tx_data;
                r_qspi_smstr_exchg_dmacdtc(channel, p_tx_data, p_qspi_smstr_info->data_cnt);
            }
            R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
            return ret;
        }
    }

    /* ---- Restore to exchange transmit data according to endian. ----*/
    if ((QSPI_SMSTR_SINGLE_SPI_WRITE     == p_qspi_smstr_info->op_mode) ||
        (QSPI_SMSTR_SINGLE_SPI_WRITEREAD == p_qspi_smstr_info->op_mode))
    {
        p_tx_data = p_qspi_smstr_info->p_tx_data;
        ret = r_qspi_smstr_exchg_dmacdtc(channel, p_tx_data, p_qspi_smstr_info->data_cnt);
        if (QSPI_SMSTR_SUCCESS != ret)
        {
            R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
            return ret;
        }
    }

    return QSPI_SMSTR_SUCCESS;
}


/*******************************************************************************
* Function Name: r_qspi_smstr_dualquad_write_dmacdtc
* Description  : Transmits data in dual or quad mode using DMAC or DTC.
* Arguments    : channel -
*                    Which channel to use
*                * p_qspi_smstr_info -
*                    QSPI information
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*                QSPI_SMSTR_ERR_HARD -
*                    Hardware error
*******************************************************************************/
qspi_smstr_status_t r_qspi_smstr_dualquad_write_dmacdtc(uint8_t channel, qspi_smstr_info_t * p_qspi_smstr_info)
{
    qspi_smstr_status_t   ret = QSPI_SMSTR_SUCCESS;
    uint32_t            tx_wait;
    volatile uint8_t R_BSP_EVENACCESS_SFR * spsr_addr;
    uint8_t * p_tx_data = NULL;

    /* Get address of status register for QSPI. */
    spsr_addr   = r_qspi_smstr_spsr_addr(channel);

    /* ---- Beforehand exchange transmit data according to endian. ----*/
    p_tx_data = p_qspi_smstr_info->p_tx_data;
    ret = r_qspi_smstr_exchg_dmacdtc(channel, p_tx_data, p_qspi_smstr_info->data_cnt);
    if (QSPI_SMSTR_SUCCESS != ret)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return ret;
    }

    /* Set DMAC/DTC transfer end flag for SPTI.  */
    R_QSPI_SMstr_Int_Spti_Dmacdtc_Flag_Set(channel, QSPI_SET_TRANS_START);

    /* Initialize SPTI interrupt registers. */
    r_qspi_smstr_int_spti_init(channel);

    /* Clear flags of transmit buffer empty and QSSL negation. */
    /* Enable QSPI transmission. */
    if (QSPI_SMSTR_DUAL_SPI == p_qspi_smstr_info->op_mode)
    {
        /* Enable QSPI transmission in Dual-SPI. */
        r_qspi_smstr_tx_enable_dual(channel, p_qspi_smstr_info->data_cnt);
    }
    else
    {
        /* Enable QSPI transmission in Quad-SPI. */
        r_qspi_smstr_tx_enable_quad(channel, p_qspi_smstr_info->data_cnt);
    }

    /* Set the ICU.IERm.IENj bit to 1. */
    r_qspi_smstr_int_spti_ier_set(channel);

    /* **** Start QSPI transmission. **** */

    /* ---- Wait for transmission completion of DMAC or DTC. ---- */
    ret = r_qspi_smstr_tx_dmacdtc_wait(channel, p_qspi_smstr_info->data_cnt);
    if (0 > ret)
    {
        /* ---- Disable QSPI transmission. ---- */
        p_tx_data = p_qspi_smstr_info->p_tx_data;
        r_qspi_smstr_exchg_dmacdtc(channel, p_tx_data, p_qspi_smstr_info->data_cnt);
        R_QSPI_SMstr_Int_Spti_Ier_Clear(channel);
        R_QSPI_SMstr_Int_Spti_Dmacdtc_Flag_Set(channel, QSPI_SET_TRANS_STOP);
        r_qspi_smstr_tx_disable(channel);
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return ret;
    }

    /* Clear the ICU.IERm.IENj bit to 0 using DMAC or DTC. */
    R_QSPI_SMstr_Int_Spti_Ier_Clear(channel);
    R_QSPI_SMstr_Int_Spti_Dmacdtc_Flag_Set(channel, QSPI_SET_TRANS_STOP);

    /* ---- Check QSSL negation. ---- */
    tx_wait = QSPI_SMSTR_QSSL_WAIT;
    ret     = r_qspi_smstr_wait(spsr_addr, tx_wait, QSPI_SMSTR_MASK_SPSSLF);
    if (QSPI_SMSTR_ERR_HARD == ret)
    {
        /* ---- Disable QSPI transmission. ---- */
        p_tx_data = p_qspi_smstr_info->p_tx_data;
        r_qspi_smstr_exchg_dmacdtc(channel, p_tx_data, p_qspi_smstr_info->data_cnt);
        r_qspi_smstr_tx_disable(channel);
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return ret;
    }

    /* ---- Restore to exchange transmit data according to endian. ----*/
    p_tx_data = p_qspi_smstr_info->p_tx_data;
    ret = r_qspi_smstr_exchg_dmacdtc(channel, p_tx_data, p_qspi_smstr_info->data_cnt);
    if (QSPI_SMSTR_SUCCESS != ret)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return ret;
    }

    /* Clear flags of transmit buffer empty and QSSL negation. */
    /* Disable QSPI transmission. */
    r_qspi_smstr_tx_disable(channel);

    return QSPI_SMSTR_SUCCESS;
}


/*******************************************************************************
* Function Name: r_qspi_smstr_dualquad_read_dmacdtc
* Description  : Receives data and stores to the specified buffer in dual or quad mode using DMAC or DTC.
* Arguments    : channel -
*                    Which channel to use
*                * p_qspi_smstr_info -
*                    QSPI information
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*                QSPI_SMSTR_ERR_HARD -
*                    Hardware error
*******************************************************************************/
qspi_smstr_status_t r_qspi_smstr_dualquad_read_dmacdtc(uint8_t channel, qspi_smstr_info_t * p_qspi_smstr_info)
{
    qspi_smstr_status_t   ret = QSPI_SMSTR_SUCCESS;
    uint32_t            rx_wait;
    volatile uint8_t R_BSP_EVENACCESS_SFR * spsr_addr;
    uint8_t * p_rx_data = NULL;

    /* Get address of status register for QSPI. */
    spsr_addr   = r_qspi_smstr_spsr_addr(channel);

    /* Set DMAC/DTC transfer end flag for SPRI.  */
    R_QSPI_SMstr_Int_Spri_Dmacdtc_Flag_Set(channel, QSPI_SET_TRANS_START);

    /* Initialize SPRI interrupt registers. */
    r_qspi_smstr_int_spri_init(channel);

    /* Clear flags of receive buffer full and QSSL negation. */
    /* Enable QSPI reception. */
    if (QSPI_SMSTR_DUAL_SPI == p_qspi_smstr_info->op_mode)
    {
        /* Enable QSPI reception in Dual-SPI. */
        r_qspi_smstr_rx_enable_dual(channel, p_qspi_smstr_info->data_cnt);
    }
    else
    {
        /* Enable QSPI reception in Quad-SPI. */
        r_qspi_smstr_rx_enable_quad(channel, p_qspi_smstr_info->data_cnt);
    }

    /* Set the ICU.IERm.IENj bit to 1. */
    r_qspi_smstr_int_spri_ier_set(channel);

    /* **** Start QSPI reception. **** */

    /* ---- Wait for reception completion of DMAC or DTC. ---- */
    ret = r_qspi_smstr_rx_dmacdtc_wait(channel, p_qspi_smstr_info->data_cnt);
    if (0 > ret)
    {
        /* ---- Disable QSPI reception. ---- */
        R_QSPI_SMstr_Int_Spri_Ier_Clear(channel);
        R_QSPI_SMstr_Int_Spri_Dmacdtc_Flag_Set(channel, QSPI_SET_TRANS_STOP);
        r_qspi_smstr_rx_disable(channel);
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return ret;
    }

    /* Clear the ICU.IERm.IENj bit to 0 using DMAC or DTC. */
    R_QSPI_SMstr_Int_Spri_Ier_Clear(channel);
    R_QSPI_SMstr_Int_Spri_Dmacdtc_Flag_Set(channel, QSPI_SET_TRANS_STOP);

    /* ---- Check QSSL negation. ---- */
    rx_wait = QSPI_SMSTR_QSSL_WAIT;
    ret     = r_qspi_smstr_wait(spsr_addr, rx_wait, QSPI_SMSTR_MASK_SPSSLF);
    if (QSPI_SMSTR_ERR_HARD == ret)
    {
        /* ---- Disable QSPI reception. ---- */
        r_qspi_smstr_rx_disable(channel);
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return ret;
    }

    /* Clear flags of receive buffer full and QSSL negation. */
    /* Disable QSPI transmission. */
    r_qspi_smstr_rx_disable(channel);

    /* ---- Finally exchange receive data according to endian. ----*/
    p_rx_data = p_qspi_smstr_info->p_rx_data;
    ret = r_qspi_smstr_exchg_dmacdtc(channel, p_rx_data, p_qspi_smstr_info->data_cnt);
    if (QSPI_SMSTR_SUCCESS != ret)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return ret;
    }

    return QSPI_SMSTR_SUCCESS;
}


/*******************************************************************************
* Function Name: r_qspi_smstr_tx_exchg
* Description  : Exchanges transmit data according to endian.
* Arguments    : channel -
*                    Which channel to use
*              : * p_data -
*                    Pointer to transmit data
*              : * p_dataadr -
*                    Pointer to exchanged data
* Return Value : none
*******************************************************************************/
void r_qspi_smstr_tx_exchg(uint8_t channel, uint8_t * p_data, uint32_t * p_dataadr)
{
#if (QSPI_SMSTR_LITTLE_ENDIAN)
    *p_dataadr++ = R_BSP_REVL(*(uint32_t *)p_data);
    *p_dataadr++ = R_BSP_REVL(*(uint32_t *)(p_data+QSPI_SMSTR_TRAN_SIZE));
    *p_dataadr++ = R_BSP_REVL(*(uint32_t *)(p_data+(QSPI_SMSTR_TRAN_SIZE*2)));
    *p_dataadr   = R_BSP_REVL(*(uint32_t *)(p_data+(QSPI_SMSTR_TRAN_SIZE*3)));
#else
    *p_dataadr++ = *(uint32_t *)p_data;
    *p_dataadr++ = *(uint32_t *)(p_data+QSPI_SMSTR_TRAN_SIZE);
    *p_dataadr++ = *(uint32_t *)(p_data+(QSPI_SMSTR_TRAN_SIZE*2));
    *p_dataadr   = *(uint32_t *)(p_data+(QSPI_SMSTR_TRAN_SIZE*3));
#endif
}


/*******************************************************************************
* Function Name: r_qspi_smstr_rx_exchg
* Description  : Exchanges receive data according to endian.
* Arguments    : channel -
*                    Which channel to use
*                * p_rx_data -
*                    Pointer to recive data
*              : * p_dataadr -
*                    Pointer to exchanged data
* Return Value : none
*******************************************************************************/
void r_qspi_smstr_rx_exchg(uint8_t channel, uint8_t * p_data, uint32_t * p_dataadr)
{
#if (QSPI_SMSTR_LITTLE_ENDIAN)
    *(uint32_t *)p_data                      = R_BSP_REVL(*p_dataadr++);
    *(uint32_t *)(p_data+QSPI_SMSTR_TRAN_SIZE)     = R_BSP_REVL(*p_dataadr++);
    *(uint32_t *)(p_data+(QSPI_SMSTR_TRAN_SIZE*2)) = R_BSP_REVL(*p_dataadr++);
    *(uint32_t *)(p_data+(QSPI_SMSTR_TRAN_SIZE*3)) = R_BSP_REVL(*p_dataadr);
#else
    *(uint32_t *)p_data                      = *p_dataadr++;
    *(uint32_t *)(p_data+QSPI_SMSTR_TRAN_SIZE)     = *p_dataadr++;
    *(uint32_t *)(p_data+(QSPI_SMSTR_TRAN_SIZE*2)) = *p_dataadr++;
    *(uint32_t *)(p_data+(QSPI_SMSTR_TRAN_SIZE*3)) = *p_dataadr;
#endif
}


/*******************************************************************************
* Function Name: r_qspi_smstr_exchg_dmacdtc
* Description  : Exchanges data according to endian using DMAC or DTC.
* Arguments    : channel -
*                    Which channel to use
*                * p_data -
*                    Pointer of data
*                size -
*                    Size of data
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*                QSPI_SMSTR_ERR_PARAM -
*                    Parameter error
*                QSPI_SMSTR_ERR_HARD -
*                    Hardware error
*******************************************************************************/
qspi_smstr_status_t r_qspi_smstr_exchg_dmacdtc(uint8_t channel, uint8_t * p_data, uint32_t size)
{
#if (QSPI_SMSTR_LITTLE_ENDIAN)
    uint32_t                * p_dataadr;

    p_dataadr   = (uint32_t *)p_data;
    size        = size - (size % 4);
    do
    {
        *p_dataadr = R_BSP_REVL(*p_dataadr);
        p_dataadr  += (QSPI_SMSTR_TRAN_SIZE/sizeof(uint32_t));
        size       -= QSPI_SMSTR_TRAN_SIZE;
    }
    while(0 != size); /* WAIT_LOOP */
#endif

    return QSPI_SMSTR_SUCCESS;
}


/*******************************************************************************
* Function Name: r_qspi_smstr_wait
* Description  : Waits for flag to be set.
*                If time out occurred, returns error.
* Arguments    : * flag -
*                    Register to check
*                wait -
*                    Waiting time
*                mask -
*                    Mask data to specify flag to be set
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*                QSPI_SMSTR_ERR_HARD -
*                    Time out has be detected.
*******************************************************************************/
qspi_smstr_status_t r_qspi_smstr_wait(volatile uint8_t R_BSP_EVENACCESS_SFR * flag, uint32_t wait, uint8_t mask)
{
    /* Wait for flag to be set to 1. */
    /* WAIT_LOOP */
    while (QSPI_SMSTR_FLAG_CLR == ((*flag) & mask))
    {
        /* ---- Check of time out. ---- */
        wait--;
        if (0 == wait)
        {
            return QSPI_SMSTR_ERR_HARD;
        }
        
        r_qspi_smstr_wait_lp(QSPI_SMSTR_T_QSPI_WAIT);
    }
    
    return QSPI_SMSTR_SUCCESS;
}


/*******************************************************************************
* Function Name: r_qspi_smstr_wait_lp
* Description  : Loop timer processing
* Arguments    : time -
*                    timer value
* Return Value : none
*******************************************************************************/
void r_qspi_smstr_wait_lp(volatile uint32_t time)
{
    do
    {
        --time;
    }
    while (0 != time); /* WAIT_LOOP */
}


/*******************************************************************************
* Function Name: r_qspi_smstr_tx_software_trans
* Description  : Transfers data of 16 bytes from RAM to QSPI Data Register using software.
* Arguments    : channel -
*                    Which channel to use
*              : * p_dataadr -
*                    Pointer to transmit data
* Return Value : none
*******************************************************************************/
void r_qspi_smstr_tx_software_trans(uint8_t channel, uint32_t * p_dataadr)
{
    /* Transmit data in long word. */
    r_qspi_smstr_data_set_long(channel, *p_dataadr++);
    r_qspi_smstr_data_set_long(channel, *p_dataadr++);
    r_qspi_smstr_data_set_long(channel, *p_dataadr++);
    r_qspi_smstr_data_set_long(channel, *p_dataadr++);
}


/*******************************************************************************
* Function Name: r_qspi_smstr_rx_software_trans
* Description  : Receives data of 16 bytes from QSPI Data Register and stores to RAM using software.
* Arguments    : channel -
*                    Which channel to use
*              : * p_dataadr -
*                    Pointer to buffer to store data
* Return Value : none
*******************************************************************************/
void r_qspi_smstr_rx_software_trans(uint8_t channel, uint32_t * p_dataadr)
{
    /* Read receive data in long word. */
    *p_dataadr++ = r_qspi_smstr_data_get_long(channel);
    *p_dataadr++ = r_qspi_smstr_data_get_long(channel);
    *p_dataadr++ = r_qspi_smstr_data_get_long(channel);
    *p_dataadr++ = r_qspi_smstr_data_get_long(channel);
}


/*******************************************************************************
* Function Name: r_qspi_smstr_tx_software_trans_dummy
* Description  : Transfers dummy data of 16 bytes from RAM to QSPI Data Register using software.
* Arguments    : channel -
*                    Which channel to use
* Return Value : none
*******************************************************************************/
void r_qspi_smstr_tx_software_trans_dummy(uint8_t channel)
{
    /* Write dummy data of 16 bytes in order to receive data in long word. */
    r_qspi_smstr_data_set_long(channel, QSPI_SMSTR_DUMMY_DATA_LONG);
    r_qspi_smstr_data_set_long(channel, QSPI_SMSTR_DUMMY_DATA_LONG);
    r_qspi_smstr_data_set_long(channel, QSPI_SMSTR_DUMMY_DATA_LONG);
    r_qspi_smstr_data_set_long(channel, QSPI_SMSTR_DUMMY_DATA_LONG);
}


/*******************************************************************************
* Function Name: r_qspi_smstr_rx_software_trans_dummy
* Description  : Transfers dummy data of 16 bytes from QSPI Data Register using software.
* Arguments    : channel -
*                    Which channel to use
* Return Value : none
*******************************************************************************/
void r_qspi_smstr_rx_software_trans_dummy(uint8_t channel)
{
    volatile uint32_t   ul_tmp;

    /* Read data of 16 bytes in long word only. Do not store the data to RAM. */
    ul_tmp = r_qspi_smstr_data_get_long(channel);
    ul_tmp = r_qspi_smstr_data_get_long(channel);
    ul_tmp = r_qspi_smstr_data_get_long(channel);
    ul_tmp = r_qspi_smstr_data_get_long(channel);
}


/*******************************************************************************
* Function Name: R_QSPI_SMstr_Get_BuffRegAddress
* Description  : Gets address of QSPI data register (SPDR).
*              : Use the address of QSPI data register to set the transfer source
*              : register or transfer destination register in DMAC or DTC.
* Arguments    : channel -
*                    Which channel to use
*                p_spdr_adr -
*                    Address of QSPI data register (SPDR)
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*                QSPI_SMSTR_ERR_PARAM -
*                    Parameter error
*******************************************************************************/
qspi_smstr_status_t R_QSPI_SMstr_Get_BuffRegAddress(uint8_t channel, uint32_t *p_spdr_adr)
{
    qspi_smstr_status_t ret = QSPI_SMSTR_SUCCESS;
    
    /* ---- Check argument. ---- */
    ret = r_qspi_smstr_ch_check(channel);
    if (QSPI_SMSTR_SUCCESS != ret)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }

    if (0 == p_spdr_adr)
    {
        R_QSPI_SMSTR_LOG_FUNC(QSPI_SMSTR_DEBUG_ERR_ID, (uint32_t)QSPI_SMSTR, __LINE__);
        return QSPI_SMSTR_ERR_PARAM;
    }

    r_qspi_smstr_get_buffregaddress(channel, p_spdr_adr);

    return QSPI_SMSTR_SUCCESS;
}


/*****************************************************************************
* Function Name: R_QSPI_SMstr_GetVersion
* Description  : Returns the version of QSPI single master driver.
*                The version number is encoded such that the top two bytes are
*                the major version number and the bottom two bytes are the minor
*                version number.
* Arguments    : none
* Return Value : version number
******************************************************************************/
uint32_t R_QSPI_SMstr_GetVersion(void)
{
    uint32_t const version = (QSPI_SMSTR_VERSION_MAJOR << 16) | QSPI_SMSTR_VERSION_MINOR;
    
    return version;
}


#ifdef QSPI_SMSTR_CFG_LONGQ_ENABLE
/*******************************************************************************
* Function Name: R_QSPI_SMstr_Set_LogHdlAddress
* Description  : Sets handler Address.
* Arguments    : user_long_que -
*                    Handler Address
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*******************************************************************************/
qspi_smstr_status_t R_QSPI_SMstr_Set_LogHdlAddress(uint32_t user_long_que)
{
    p_qspi_smstr_long_que = (longq_hdl_t)user_long_que;
    return QSPI_SMSTR_SUCCESS;
}


/*******************************************************************************
* Function Name: r_qspi_smstr_log
* Description  : Stores error information to LONGQ buffer.
* Arguments    : flg -
*                    Breakpoint processing
*                fid -
*                    QSPI driver file No.
*                line -
*                    QSPI driver line number
* Return Value : 0 -
*                    Successful operation
*                1 -
*                    Error
*******************************************************************************/
uint32_t r_qspi_smstr_log(uint32_t flg, uint32_t fid, uint32_t line)
{
    longq_err_t err;
    uint32_t    ul_tmp;

    /* Long to Byte */
    ul_tmp = 0;                                         /* smstr_log   Reserved               */
    ul_tmp = (ul_tmp | (line << 8));                    /* smstr_log   LINE                   */
    ul_tmp = (ul_tmp | (fid  << 21));                   /* smstr_log   FID FILE No.           */
    ul_tmp = (ul_tmp | (QSPI_SMSTR_DRIVER_ID << 27));     /* smstr_log   FID DRIVER No.         */
    ul_tmp = (ul_tmp | (flg  << 31));                   /* smstr_log   Breakpoint processing  */

    err = R_LONGQ_Put(p_qspi_smstr_long_que, ul_tmp);
    if (err != LONGQ_SUCCESS)
    {
        return 1;
    }

    /* Breakpoint processing */
    if (0x80000000 == (ul_tmp & 0x80000000))
    {
        return 1;
    }
    return 0;
}
#else
/*******************************************************************************
* Function Name: R_QSPI_SMstr_Set_LogHdlAddress
* Description  : Sets handler Address.
* Arguments    : user_long_que -
*                    Handler Address
* Return Value : QSPI_SMSTR_SUCCESS -
*                    Successful operation
*******************************************************************************/
qspi_smstr_status_t R_QSPI_SMstr_Set_LogHdlAddress(uint32_t user_long_que)
{
    return QSPI_SMSTR_SUCCESS;
}
#endif  /* QSPI_SMSTR_CFG_LONGQ_ENABLE */


/*******************************************************************************
* Function Name: R_QSPI_SMstr_Log
* Description  : Stores error information to LONGQ buffer.
* Arguments    : flg -
*                    Breakpoint processing
*                fid -
*                    QSPI driver file No.
*                line -
*                    QSPI driver line number
* Return Value : 0 -
*                    Successful operation
*                1 -
*                    Error
*******************************************************************************/
uint32_t R_QSPI_SMstr_Log(uint32_t flg, uint32_t fid, uint32_t line)
{
    R_QSPI_SMSTR_LOG_FUNC(flg, fid, line);
    return 0;
}


/* End of File */

