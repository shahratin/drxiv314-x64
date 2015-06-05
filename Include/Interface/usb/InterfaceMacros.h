/* 
* InterfaceMacros.h
*
*Copyright (C) 2010 Beceem Communications, Inc.
*
*This program is free software: you can redistribute it and/or modify 
*it under the terms of the GNU General Public License version 2 as
*published by the Free Software Foundation. 
*
*This program is distributed in the hope that it will be useful,but 
*WITHOUT ANY WARRANTY; without even the implied warranty of
*MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
*See the GNU General Public License for more details.
*
*You should have received a copy of the GNU General Public License
*along with this program. If not, write to the Free Software Foundation, Inc.,
*51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*
*/


#ifndef _INTERFACE_MACROS_H
#define _INTERFACE_MACROS_H

#define BCM_USB_MAX_READ_LENGTH 2048

#define MAXIMUM_USB_TCB      128
#define MAXIMUM_USB_RCB 	 128

#define MAX_BUFFERS_PER_QUEUE   256

#define MAX_DATA_BUFFER_SIZE    2048

//Num of Asynchronous reads pending
#define NUM_RX_DESC 64

#define SYS_CFG 0x0F000C00
#define SYS_CFG1 0x0F000C44
#define MAX_TRY_RESTORE_SYS_CFG 50

#define SYS_CFG_WRITE_SIG		0x8000



#define BCS35X_MIPS_CONFIG_REGISTER	0xAF006050
#define BCS35X_SYS_CFG_LATCH        0x0F000C3C

/*
*  Symphony Sys CFG Init_mode values:
*  00 -  No CIS Init. Both CPU1 and CPU2 Boot From Serial Flash together.
*  01 -  No CIS Init. Both CPU1 and CPU2 Boot From eMMC Flash together.
*  02 -  No CIS Init. Both CPU1 and CPU2 Boot From MMC Flash Card together.
*  03 -  No CIS Init. Both CPU1 and CPU2 Boot From Serial Flash together. CPU2 boots at 1MB offset from the default boot location.
*  04 -  No CIS Init. CPU1 Boots From Serial Flash First with RC_CLK (if PMU_CFG is 6) or EXT_CLK (if PMU_CFG is 0). CPU2 boots with CPU1/ Host Assistance.
*  05 -  No CIS Init. CPU1 Boots From eMMC Flash First with RC_CLK (if PMU_CFG is 6) or EXT_CLK (if PMU_CFG is 0). CPU2 boots with CPU1/ Host Assistance.
*  06 -  No CIS Init. CPU2 Boots From MMC Flash Card First. CPU1 boots with CPU2/ Host Assistance.
*  07 -  No CIS Init. CPU1 Boots From Serial Flash First. CPU2 boots with CPU1/ Host Assistance.
*  08 -  No CIS Init. Both CPUs Boot with Host Assistance
*  09 -  No CIS Init. CPU2 Boots From Serial Flash First at 1MB Offset from the default boot location. CPU1 boots with CPU2/ Host Assistance.
*  10 -  No CIS Init. CPU1 Boots From MMC Flash Card First. CPU2 boots with CPU1/ Host Assistance.
*  11 -  No CIS Init. CPU2 Boots From Serial Flash First at default boot location. CPU1 boots with CPU2/ Host Assistance.
*  12 -  No CIS Init. CPU2 Boots From eMMC Flash First. CPU1 boots with CPU2/ Host Assistance.
*  13 -  No CIS Init. CPU1 Boots From eMMC Flash First. CPU2 boots with CPU1/ Host Assistance.
*  14 -  CIS Init from I2C EEPROM or ROM if signature not found in EEPROM. Both CPUs Boot with EEPROM/ Host Assistance
*  15 -  CIS Init from SPI EEPROM, or ROM if signature not found in EEPROM. Both CPUs Boot with EEPROM/ Host Assistance
*
*/

#define BCS35X_HOST_ASST_BOOT_MODE	8
#define BCS35X_I2C_EEPROM_MODE		14
#define BCS35X_SPI_EEPROM_BOOT		15

/* Handshake patterns between the host driver and the SCSI firmware
 * Host first writes the host pattern and device on detecting the
 * host pattern writes its own pattern and goes into an idle loop.
 */
#define HOST_HANDSHAKE_PATTERN		0xA0A0A0A0
#define SCSI_HANDSHAKE_PATTERN		0x1A1A1A1A
#define HOST_SCSI_HANDSHAKE_LOC		0x0FF03FE0




#endif
