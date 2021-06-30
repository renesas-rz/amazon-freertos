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
* Copyright (C) 2019 Renesas Electronics Corporation. All rights reserved.
*******************************************************************************/ 
/*******************************************************************************
* Rev: 3.00
* Description : IO bitmask header
*******************************************************************************/

#ifndef CPG_IOBITMASK_H
#define CPG_IOBITMASK_H


/* ==== Mask values for IO registers ==== */

#define CPG_FRQCR_PFC                                                          (0x0003u)
#define CPG_FRQCR_PFC_SHIFT                                                    (0u)
#define CPG_FRQCR_BFC                                                          (0x0030u)
#define CPG_FRQCR_BFC_SHIFT                                                    (4u)
#define CPG_FRQCR_IFC                                                          (0x0300u)
#define CPG_FRQCR_IFC_SHIFT                                                    (8u)
#define CPG_FRQCR_CKOEN                                                        (0x3000u)
#define CPG_FRQCR_CKOEN_SHIFT                                                  (12u)
#define CPG_FRQCR_CKOEN2                                                       (0x4000u)
#define CPG_FRQCR_CKOEN2_SHIFT                                                 (14u)
#define CPG_CPUSTS_ISBUSY                                                      (0x10u)
#define CPG_CPUSTS_ISBUSY_SHIFT                                                (4u)
#define CPG_STBCR1_DEEP                                                        (0x40u)
#define CPG_STBCR1_DEEP_SHIFT                                                  (6u)
#define CPG_STBCR1_STBY                                                        (0x80u)
#define CPG_STBCR1_STBY_SHIFT                                                  (7u)
#define CPG_STBCR2_MSTP20                                                      (0x01u)
#define CPG_STBCR2_MSTP20_SHIFT                                                (0u)
#define CPG_STBCR2_HIZ                                                         (0x80u)
#define CPG_STBCR2_HIZ_SHIFT                                                   (7u)
#define CPG_STBREQ1_STBRQ10                                                    (0x01u)
#define CPG_STBREQ1_STBRQ10_SHIFT                                              (0u)
#define CPG_STBREQ1_STBRQ11                                                    (0x02u)
#define CPG_STBREQ1_STBRQ11_SHIFT                                              (1u)
#define CPG_STBREQ1_STBRQ12                                                    (0x04u)
#define CPG_STBREQ1_STBRQ12_SHIFT                                              (2u)
#define CPG_STBREQ1_STBRQ13                                                    (0x08u)
#define CPG_STBREQ1_STBRQ13_SHIFT                                              (3u)
#define CPG_STBREQ1_STBRQ15                                                    (0x20u)
#define CPG_STBREQ1_STBRQ15_SHIFT                                              (5u)
#define CPG_STBREQ2_STBRQ20                                                    (0x01u)
#define CPG_STBREQ2_STBRQ20_SHIFT                                              (0u)
#define CPG_STBREQ2_STBRQ21                                                    (0x02u)
#define CPG_STBREQ2_STBRQ21_SHIFT                                              (1u)
#define CPG_STBREQ2_STBRQ22                                                    (0x04u)
#define CPG_STBREQ2_STBRQ22_SHIFT                                              (2u)
#define CPG_STBREQ2_STBRQ23                                                    (0x08u)
#define CPG_STBREQ2_STBRQ23_SHIFT                                              (3u)
#define CPG_STBREQ2_STBRQ24                                                    (0x10u)
#define CPG_STBREQ2_STBRQ24_SHIFT                                              (4u)
#define CPG_STBREQ2_STBRQ25                                                    (0x20u)
#define CPG_STBREQ2_STBRQ25_SHIFT                                              (5u)
#define CPG_STBREQ2_STBRQ26                                                    (0x40u)
#define CPG_STBREQ2_STBRQ26_SHIFT                                              (6u)
#define CPG_STBREQ2_STBRQ27                                                    (0x80u)
#define CPG_STBREQ2_STBRQ27_SHIFT                                              (7u)
#define CPG_STBREQ3_STBRQ30                                                    (0x01u)
#define CPG_STBREQ3_STBRQ30_SHIFT                                              (0u)
#define CPG_STBREQ3_STBRQ31                                                    (0x02u)
#define CPG_STBREQ3_STBRQ31_SHIFT                                              (1u)
#define CPG_STBREQ3_STBRQ32                                                    (0x04u)
#define CPG_STBREQ3_STBRQ32_SHIFT                                              (2u)
#define CPG_STBREQ3_STBRQ33                                                    (0x08u)
#define CPG_STBREQ3_STBRQ33_SHIFT                                              (3u)
#define CPG_STBACK1_STBAK10                                                    (0x01u)
#define CPG_STBACK1_STBAK10_SHIFT                                              (0u)
#define CPG_STBACK1_STBAK11                                                    (0x02u)
#define CPG_STBACK1_STBAK11_SHIFT                                              (1u)
#define CPG_STBACK1_STBAK12                                                    (0x04u)
#define CPG_STBACK1_STBAK12_SHIFT                                              (2u)
#define CPG_STBACK1_STBAK13                                                    (0x08u)
#define CPG_STBACK1_STBAK13_SHIFT                                              (3u)
#define CPG_STBACK1_STBAK15                                                    (0x20u)
#define CPG_STBACK1_STBAK15_SHIFT                                              (5u)
#define CPG_STBACK2_STBAK20                                                    (0x01u)
#define CPG_STBACK2_STBAK20_SHIFT                                              (0u)
#define CPG_STBACK2_STBAK21                                                    (0x02u)
#define CPG_STBACK2_STBAK21_SHIFT                                              (1u)
#define CPG_STBACK2_STBAK22                                                    (0x04u)
#define CPG_STBACK2_STBAK22_SHIFT                                              (2u)
#define CPG_STBACK2_STBAK23                                                    (0x08u)
#define CPG_STBACK2_STBAK23_SHIFT                                              (3u)
#define CPG_STBACK2_STBAK24                                                    (0x10u)
#define CPG_STBACK2_STBAK24_SHIFT                                              (4u)
#define CPG_STBACK2_STBAK25                                                    (0x20u)
#define CPG_STBACK2_STBAK25_SHIFT                                              (5u)
#define CPG_STBACK2_STBAK26                                                    (0x40u)
#define CPG_STBACK2_STBAK26_SHIFT                                              (6u)
#define CPG_STBACK2_STBAK27                                                    (0x80u)
#define CPG_STBACK2_STBAK27_SHIFT                                              (7u)
#define CPG_STBACK3_STBAK30                                                    (0x01u)
#define CPG_STBACK3_STBAK30_SHIFT                                              (0u)
#define CPG_STBACK3_STBAK31                                                    (0x02u)
#define CPG_STBACK3_STBAK31_SHIFT                                              (1u)
#define CPG_STBACK3_STBAK32                                                    (0x04u)
#define CPG_STBACK3_STBAK32_SHIFT                                              (2u)
#define CPG_STBACK3_STBAK33                                                    (0x08u)
#define CPG_STBACK3_STBAK33_SHIFT                                              (3u)
#define CPG_CKIOSEL_CKIOSEL                                                    (0x0003u)
#define CPG_CKIOSEL_CKIOSEL_SHIFT                                              (0u)
#define CPG_SCLKSEL_SPICR                                                      (0x0003u)
#define CPG_SCLKSEL_SPICR_SHIFT                                                (0u)
#define CPG_SCLKSEL_HYMCR                                                      (0x0030u)
#define CPG_SCLKSEL_HYMCR_SHIFT                                                (4u)
#define CPG_SCLKSEL_OCTCR                                                      (0x0300u)
#define CPG_SCLKSEL_OCTCR_SHIFT                                                (8u)
#define CPG_SYSCR1_VRAME0                                                      (0x01u)
#define CPG_SYSCR1_VRAME0_SHIFT                                                (0u)
#define CPG_SYSCR1_VRAME1                                                      (0x02u)
#define CPG_SYSCR1_VRAME1_SHIFT                                                (1u)
#define CPG_SYSCR1_VRAME2                                                      (0x04u)
#define CPG_SYSCR1_VRAME2_SHIFT                                                (2u)
#define CPG_SYSCR1_VRAME3                                                      (0x08u)
#define CPG_SYSCR1_VRAME3_SHIFT                                                (3u)
#define CPG_SYSCR1_VRAME4                                                      (0x10u)
#define CPG_SYSCR1_VRAME4_SHIFT                                                (4u)
#define CPG_SYSCR2_VRAMWE0                                                     (0x01u)
#define CPG_SYSCR2_VRAMWE0_SHIFT                                               (0u)
#define CPG_SYSCR2_VRAMWE1                                                     (0x02u)
#define CPG_SYSCR2_VRAMWE1_SHIFT                                               (1u)
#define CPG_SYSCR2_VRAMWE2                                                     (0x04u)
#define CPG_SYSCR2_VRAMWE2_SHIFT                                               (2u)
#define CPG_SYSCR2_VRAMWE3                                                     (0x08u)
#define CPG_SYSCR2_VRAMWE3_SHIFT                                               (3u)
#define CPG_SYSCR2_VRAMWE4                                                     (0x10u)
#define CPG_SYSCR2_VRAMWE4_SHIFT                                               (4u)
#define CPG_SYSCR3_RRAMWE0                                                     (0x01u)
#define CPG_SYSCR3_RRAMWE0_SHIFT                                               (0u)
#define CPG_SYSCR3_RRAMWE1                                                     (0x02u)
#define CPG_SYSCR3_RRAMWE1_SHIFT                                               (1u)
#define CPG_SYSCR3_RRAMWE2                                                     (0x04u)
#define CPG_SYSCR3_RRAMWE2_SHIFT                                               (2u)
#define CPG_SYSCR3_RRAMWE3                                                     (0x08u)
#define CPG_SYSCR3_RRAMWE3_SHIFT                                               (3u)
#define CPG_STBCR3_MSTP30                                                      (0x01u)
#define CPG_STBCR3_MSTP30_SHIFT                                                (0u)
#define CPG_STBCR3_MSTP32                                                      (0x04u)
#define CPG_STBCR3_MSTP32_SHIFT                                                (2u)
#define CPG_STBCR3_MSTP33                                                      (0x08u)
#define CPG_STBCR3_MSTP33_SHIFT                                                (3u)
#define CPG_STBCR3_MSTP34                                                      (0x10u)
#define CPG_STBCR3_MSTP34_SHIFT                                                (4u)
#define CPG_STBCR3_MSTP35                                                      (0x20u)
#define CPG_STBCR3_MSTP35_SHIFT                                                (5u)
#define CPG_STBCR3_MSTP36                                                      (0x40u)
#define CPG_STBCR3_MSTP36_SHIFT                                                (6u)
#define CPG_STBCR4_MSTP40                                                      (0x01u)
#define CPG_STBCR4_MSTP40_SHIFT                                                (0u)
#define CPG_STBCR4_MSTP41                                                      (0x02u)
#define CPG_STBCR4_MSTP41_SHIFT                                                (1u)
#define CPG_STBCR4_MSTP42                                                      (0x04u)
#define CPG_STBCR4_MSTP42_SHIFT                                                (2u)
#define CPG_STBCR4_MSTP43                                                      (0x08u)
#define CPG_STBCR4_MSTP43_SHIFT                                                (3u)
#define CPG_STBCR4_MSTP44                                                      (0x10u)
#define CPG_STBCR4_MSTP44_SHIFT                                                (4u)
#define CPG_STBCR4_MSTP45                                                      (0x20u)
#define CPG_STBCR4_MSTP45_SHIFT                                                (5u)
#define CPG_STBCR4_MSTP46                                                      (0x40u)
#define CPG_STBCR4_MSTP46_SHIFT                                                (6u)
#define CPG_STBCR4_MSTP47                                                      (0x80u)
#define CPG_STBCR4_MSTP47_SHIFT                                                (7u)
#define CPG_STBCR5_MSTP51                                                      (0x02u)
#define CPG_STBCR5_MSTP51_SHIFT                                                (1u)
#define CPG_STBCR5_MSTP52                                                      (0x04u)
#define CPG_STBCR5_MSTP52_SHIFT                                                (2u)
#define CPG_STBCR5_MSTP53                                                      (0x08u)
#define CPG_STBCR5_MSTP53_SHIFT                                                (3u)
#define CPG_STBCR5_MSTP56                                                      (0x40u)
#define CPG_STBCR5_MSTP56_SHIFT                                                (6u)
#define CPG_STBCR5_MSTP57                                                      (0x80u)
#define CPG_STBCR5_MSTP57_SHIFT                                                (7u)
#define CPG_STBCR6_MSTP60                                                      (0x01u)
#define CPG_STBCR6_MSTP60_SHIFT                                                (0u)
#define CPG_STBCR6_MSTP61                                                      (0x02u)
#define CPG_STBCR6_MSTP61_SHIFT                                                (1u)
#define CPG_STBCR6_MSTP62                                                      (0x04u)
#define CPG_STBCR6_MSTP62_SHIFT                                                (2u)
#define CPG_STBCR6_MSTP63                                                      (0x08u)
#define CPG_STBCR6_MSTP63_SHIFT                                                (3u)
#define CPG_STBCR6_MSTP64                                                      (0x10u)
#define CPG_STBCR6_MSTP64_SHIFT                                                (4u)
#define CPG_STBCR6_MSTP65                                                      (0x20u)
#define CPG_STBCR6_MSTP65_SHIFT                                                (5u)
#define CPG_STBCR6_MSTP66                                                      (0x40u)
#define CPG_STBCR6_MSTP66_SHIFT                                                (6u)
#define CPG_STBCR7_MSTP70                                                      (0x01u)
#define CPG_STBCR7_MSTP70_SHIFT                                                (0u)
#define CPG_STBCR7_MSTP71                                                      (0x02u)
#define CPG_STBCR7_MSTP71_SHIFT                                                (1u)
#define CPG_STBCR7_MSTP72                                                      (0x04u)
#define CPG_STBCR7_MSTP72_SHIFT                                                (2u)
#define CPG_STBCR7_MSTP73                                                      (0x08u)
#define CPG_STBCR7_MSTP73_SHIFT                                                (3u)
#define CPG_STBCR7_MSTP75                                                      (0x20u)
#define CPG_STBCR7_MSTP75_SHIFT                                                (5u)
#define CPG_STBCR7_MSTP76                                                      (0x40u)
#define CPG_STBCR7_MSTP76_SHIFT                                                (6u)
#define CPG_STBCR7_MSTP77                                                      (0x80u)
#define CPG_STBCR7_MSTP77_SHIFT                                                (7u)
#define CPG_STBCR8_MSTP81                                                      (0x02u)
#define CPG_STBCR8_MSTP81_SHIFT                                                (1u)
#define CPG_STBCR8_MSTP83                                                      (0x08u)
#define CPG_STBCR8_MSTP83_SHIFT                                                (3u)
#define CPG_STBCR8_MSTP84                                                      (0x10u)
#define CPG_STBCR8_MSTP84_SHIFT                                                (4u)
#define CPG_STBCR8_MSTP85                                                      (0x20u)
#define CPG_STBCR8_MSTP85_SHIFT                                                (5u)
#define CPG_STBCR8_MSTP86                                                      (0x40u)
#define CPG_STBCR8_MSTP86_SHIFT                                                (6u)
#define CPG_STBCR8_MSTP87                                                      (0x80u)
#define CPG_STBCR8_MSTP87_SHIFT                                                (7u)
#define CPG_STBCR9_MSTP90                                                      (0x01u)
#define CPG_STBCR9_MSTP90_SHIFT                                                (0u)
#define CPG_STBCR9_MSTP91                                                      (0x02u)
#define CPG_STBCR9_MSTP91_SHIFT                                                (1u)
#define CPG_STBCR9_MSTP92                                                      (0x04u)
#define CPG_STBCR9_MSTP92_SHIFT                                                (2u)
#define CPG_STBCR9_MSTP93                                                      (0x08u)
#define CPG_STBCR9_MSTP93_SHIFT                                                (3u)
#define CPG_STBCR9_MSTP95                                                      (0x20u)
#define CPG_STBCR9_MSTP95_SHIFT                                                (5u)
#define CPG_STBCR9_MSTP96                                                      (0x40u)
#define CPG_STBCR9_MSTP96_SHIFT                                                (6u)
#define CPG_STBCR9_MSTP97                                                      (0x80u)
#define CPG_STBCR9_MSTP97_SHIFT                                                (7u)
#define CPG_STBCR10_MSTP100                                                    (0x01u)
#define CPG_STBCR10_MSTP100_SHIFT                                              (0u)
#define CPG_STBCR10_MSTP101                                                    (0x02u)
#define CPG_STBCR10_MSTP101_SHIFT                                              (1u)
#define CPG_STBCR10_MSTP102                                                    (0x04u)
#define CPG_STBCR10_MSTP102_SHIFT                                              (2u)
#define CPG_STBCR10_MSTP103                                                    (0x08u)
#define CPG_STBCR10_MSTP103_SHIFT                                              (3u)
#define CPG_STBCR10_MSTP104                                                    (0x10u)
#define CPG_STBCR10_MSTP104_SHIFT                                              (4u)
#define CPG_STBCR10_MSTP107                                                    (0x80u)
#define CPG_STBCR10_MSTP107_SHIFT                                              (7u)
#define CPG_SWRSTCR1_SRST10                                                    (0x01u)
#define CPG_SWRSTCR1_SRST10_SHIFT                                              (0u)
#define CPG_SWRSTCR1_SRST11                                                    (0x02u)
#define CPG_SWRSTCR1_SRST11_SHIFT                                              (1u)
#define CPG_SWRSTCR1_SRST12                                                    (0x04u)
#define CPG_SWRSTCR1_SRST12_SHIFT                                              (2u)
#define CPG_SWRSTCR1_SRST13                                                    (0x08u)
#define CPG_SWRSTCR1_SRST13_SHIFT                                              (3u)
#define CPG_SWRSTCR1_AXTALE                                                    (0x80u)
#define CPG_SWRSTCR1_AXTALE_SHIFT                                              (7u)
#define CPG_SWRSTCR2_SRST21                                                    (0x02u)
#define CPG_SWRSTCR2_SRST21_SHIFT                                              (1u)
#define CPG_SWRSTCR2_SRST22                                                    (0x04u)
#define CPG_SWRSTCR2_SRST22_SHIFT                                              (2u)
#define CPG_SWRSTCR2_SRST23                                                    (0x08u)
#define CPG_SWRSTCR2_SRST23_SHIFT                                              (3u)
#define CPG_SWRSTCR2_SRST24                                                    (0x10u)
#define CPG_SWRSTCR2_SRST24_SHIFT                                              (4u)
#define CPG_SWRSTCR2_SRST25                                                    (0x20u)
#define CPG_SWRSTCR2_SRST25_SHIFT                                              (5u)
#define CPG_SWRSTCR2_SRST26                                                    (0x40u)
#define CPG_SWRSTCR2_SRST26_SHIFT                                              (6u)

#endif
