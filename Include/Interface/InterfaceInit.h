/* 
* InterfaceInit.h
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


#ifndef _INTERFACE_INIT_H
#define _INTERFACE_INIT_H

#define BCM_USB_VENDOR_ID_T3 	0x198f
#define BCM_USB_PRODUCT_ID_T3 	0x0300
#define BCM_USB_PRODUCT_ID_T3B 	0x0210
#define BCM_USB_PRODUCT_ID_T3L 	0x0220
#define BCM_USB_PRODUCT_ID_SYM  0x15E
#define BCM_USB_PRODUCT_ID_351  0x015F
#define BCM_USB_PRODUCT_ID_352  0x0160

#define BCM_USB_MINOR_BASE 		192

#define BCM_MAX_DEVICE_SUPPORTED 1


INT InterfaceInitialize(void);

INT InterfaceExit(void);

#ifndef BCM_SHM_INTERFACE
INT InterfaceAdapterInit(PS_INTERFACE_ADAPTER Adapter);

INT usbbcm_worker_thread(PS_INTERFACE_ADAPTER psIntfAdapter);

VOID InterfaceAdapterFree(PS_INTERFACE_ADAPTER psIntfAdapter);

#else
INT InterfaceAdapterInit(PMINI_ADAPTER Adapter);
#endif


#if 0

B_UINT32 InterfaceClaimAdapter(PMINI_ADAPTER Adapter);

VOID InterfaceDDRControllerInit(PMINI_ADAPTER Adapter);

B_UINT32 InterfaceReset(PMINI_ADAPTER Adapter);

B_UINT32 InterfaceRegisterResources(PMINI_ADAPTER Adapter);

VOID InterfaceUnRegisterResources(PMINI_ADAPTER Adapter);

B_UINT32 InterfaceFirmwareDownload(PMINI_ADAPTER Adapter);

#endif

#endif

