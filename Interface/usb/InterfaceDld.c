/* 
* InterfaceDld.c
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


#include <headers.h>

#ifndef BCM_SHM_INTERFACE

int InterfaceFileDownload( PVOID arg,
                        struct file *flp,
                        unsigned int on_chip_loc)
{
    char            *buff=NULL;
   // unsigned int    reg=0;
    mm_segment_t    oldfs={0};
    int             errno=0, len=0 /*,is_config_file = 0*/;
    loff_t          pos=0;
	PS_INTERFACE_ADAPTER psIntfAdapter = (PS_INTERFACE_ADAPTER)arg;
	//PMINI_ADAPTER Adapter = psIntfAdapter->psAdapter;

    buff=(PCHAR)kmalloc(MAX_TRANSFER_CTRL_BYTE_USB, GFP_KERNEL);
    if(!buff)
    {
        return -ENOMEM;
    }
    while(1)
    {
        oldfs=get_fs(); set_fs(get_ds());
        len=vfs_read(flp, buff, MAX_TRANSFER_CTRL_BYTE_USB, &pos);
        set_fs(oldfs);
        if(len<=0)
        {
            if(len<0)
            {
                BCM_DEBUG_PRINT(psIntfAdapter->psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "len < 0");
                errno=len;
            }
            else
            {
                errno = 0;
                BCM_DEBUG_PRINT(psIntfAdapter->psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Got end of file!");
            }
            break;
        }
        //BCM_DEBUG_PRINT_BUFFER(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, buff, MAX_TRANSFER_CTRL_BYTE_USB);
        errno = InterfaceWRM(psIntfAdapter, on_chip_loc, buff, len) ;
		if(errno)
		{
            BCM_DEBUG_PRINT(psIntfAdapter->psAdapter,DBG_TYPE_PRINTK, 0, 0, "WRM Failed! status: %d", errno);
			break;
			
		}
        on_chip_loc+=MAX_TRANSFER_CTRL_BYTE_USB;
	}/* End of for(;;)*/

	bcm_kfree(buff);
    return errno;
}

int InterfaceFileReadbackFromChip( PVOID arg,
                        struct file *flp,
                        unsigned int on_chip_loc)
{
    char            *buff=NULL, *buff_readback=NULL;
    unsigned int    reg=0;
    mm_segment_t    oldfs={0};
    int             errno=0, len=0, is_config_file = 0;
    loff_t          pos=0;
    static int fw_down = 0;
	INT				Status = STATUS_SUCCESS;
	PS_INTERFACE_ADAPTER psIntfAdapter = (PS_INTERFACE_ADAPTER)arg;

    buff=(PCHAR)kmalloc(MAX_TRANSFER_CTRL_BYTE_USB, GFP_DMA);
    buff_readback=(PCHAR)kmalloc(MAX_TRANSFER_CTRL_BYTE_USB , GFP_DMA);
    if(!buff || !buff_readback)
    {
        bcm_kfree(buff);
        bcm_kfree(buff_readback);
        
        return -ENOMEM;
    }
	
	is_config_file = (on_chip_loc == CONFIG_BEGIN_ADDR)? 1:0;
	
	memset(buff_readback, 0, MAX_TRANSFER_CTRL_BYTE_USB);
	memset(buff, 0, MAX_TRANSFER_CTRL_BYTE_USB);
    while(1)
    {
        oldfs=get_fs(); set_fs(get_ds());
        len=vfs_read(flp, buff, MAX_TRANSFER_CTRL_BYTE_USB, &pos);
        set_fs(oldfs);
        fw_down++;
        if(len<=0)
        {
            if(len<0)
            {
                BCM_DEBUG_PRINT(psIntfAdapter->psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "len < 0");
                errno=len;
            }
            else
            {
                errno = 0;
                BCM_DEBUG_PRINT(psIntfAdapter->psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Got end of file!");
            }
            break;
        }
		
		
		Status = InterfaceRDM(psIntfAdapter, on_chip_loc, buff_readback, len);
		if(Status)
		{
            BCM_DEBUG_PRINT(psIntfAdapter->psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "RDM of len %d Failed! %d", len, reg);
			goto exit;
		}
		reg++;
        if((len-sizeof(unsigned int))<4)
        {
            if(memcmp(buff_readback, buff, len))
            {
                BCM_DEBUG_PRINT(psIntfAdapter->psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Firmware Download is not proper %d", fw_down);
				BCM_DEBUG_PRINT(psIntfAdapter->psAdapter,DBG_TYPE_INITEXIT, MP_INIT,DBG_LVL_ALL,"Length is: %d",len);
				Status = -EIO;
				goto exit;
            }
        }
        else
        {
            len-=4;
            while(len)
            {
                if(*(unsigned int*)&buff_readback[len] != *(unsigned int *)&buff[len])
                {
                    BCM_DEBUG_PRINT(psIntfAdapter->psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Firmware Download is not proper %d", fw_down);
                    BCM_DEBUG_PRINT(psIntfAdapter->psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Val from Binary %x, Val From Read Back %x ", *(unsigned int *)&buff[len], *(unsigned int*)&buff_readback[len]);
                    BCM_DEBUG_PRINT(psIntfAdapter->psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "len =%x!!!", len);
					Status = -EIO;
					goto exit;
                }
                len-=4;
            }
        }
        on_chip_loc+=MAX_TRANSFER_CTRL_BYTE_USB;
    }/* End of while(1)*/
exit:
    bcm_kfree(buff);
    bcm_kfree(buff_readback);
	return Status;
}

static int bcm_download_config_file(PMINI_ADAPTER Adapter, 
								FIRMWARE_INFO *psFwInfo)
{
	int retval = STATUS_SUCCESS;
	B_UINT32 value = 0;
	unsigned char *kbuf = NULL;
	
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "FW length = %u", psFwInfo->u32FirmwareLength);
	if(psFwInfo->u32FirmwareLength < sizeof(STARGETPARAMS)) {
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Target Length Mismatch\n");
		return -EIO;
	}

	if(Adapter->pstargetparams == NULL) {
        if((Adapter->pstargetparams =
            kmalloc(sizeof(STARGETPARAMS), GFP_KERNEL)) == NULL)
        {
            return -ENOMEM;
        }
    }

	if ((kbuf = kmalloc(psFwInfo->u32FirmwareLength, GFP_KERNEL)) == NULL) {
			bcm_kfree (Adapter->pstargetparams);
			return -ENOMEM;
	}
	retval = copy_from_user (kbuf,psFwInfo->pvMappedFirmwareAddress, psFwInfo->u32FirmwareLength);
	if (retval) {
		bcm_kfree (kbuf);
		bcm_kfree (Adapter->pstargetparams);
		return retval;
	}
	/*   
     * Now 'kbuf' contains the "usual" first 144 bytes of binary configuration data;
     * and if cfgfil_sz > 144 , then it also now contains the new "flexi-config"
     * appended data (ACP - Appended Configuration Parameters).
     */ 
	if (psFwInfo->u32FirmwareLength > sizeof(STARGETPARAMS)) {
		BCM_DEBUG_PRINT (Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "## Flexi-Config ACP (Additional Configuration Parameters) detected ##");
		if (capture_and_merge_acp (Adapter, kbuf, psFwInfo->u32FirmwareLength)) {
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "***WARNING *** Function %s failed. ACP processing aborted...\n", 
                "capture_and_merge_acp");
        }
    }    

    /* Check for autolink in config params */
    /*   
     * Values in Adapter->pstargetparams are in network byte order
     */
	memcpy(Adapter->pstargetparams, kbuf, sizeof(STARGETPARAMS));
	bcm_kfree (kbuf);

	/* Parse the structure and then Download the Firmware */
	beceem_parse_target_struct(Adapter);

	//Initializing the NVM. 
	BcmInitNVM(Adapter);			

	retval = InitLedSettings (Adapter);			

	if(retval)
	{
		BCM_DEBUG_PRINT (Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "INIT LED Failed\n");
		return retval; 
	}

	if(Adapter->LEDInfo.led_thread_running & BCM_LED_THREAD_RUNNING_ACTIVELY)
	{
		Adapter->LEDInfo.bLedInitDone = FALSE;
		Adapter->DriverState = DRIVER_INIT;
		wake_up(&Adapter->LEDInfo.notify_led_event);
	}

	if(Adapter->LEDInfo.led_thread_running & BCM_LED_THREAD_RUNNING_ACTIVELY)
	{
		Adapter->DriverState = FW_DOWNLOAD;
		wake_up(&Adapter->LEDInfo.notify_led_event);
	}

	/* Initialize the DDR Controller */
	retval = ddr_init(Adapter);
	if(retval)
	{
		BCM_DEBUG_PRINT (Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "DDR Init Failed\n");
		return retval; 
	}

	value = 0;
	wrmalt(Adapter, EEPROM_CAL_DATA_INTERNAL_LOC - 4, &value, sizeof(value));
	wrmalt(Adapter, EEPROM_CAL_DATA_INTERNAL_LOC - 8, &value, sizeof(value));
	
	if(Adapter->eNVMType == NVM_FLASH)
	{
		retval = PropagateCalParamsFromFlashToMemory(Adapter);
		if(retval)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"propagaion of cal param failed with status :%d", retval);
			return retval;
		}
	}


	retval =buffDnldVerify(Adapter,(PUCHAR)Adapter->pstargetparams,sizeof(STARGETPARAMS),CONFIG_BEGIN_ADDR);

	if(retval)
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "configuration file not downloaded properly");
	}
	else	
		Adapter->bCfgDownloaded = TRUE;
		

	return retval;
}

int bcm_ioctl_fw_download(PMINI_ADAPTER Adapter, FIRMWARE_INFO *psFwInfo)
{
	int retval = STATUS_SUCCESS;
	PUCHAR buff = NULL;
	
	/*  Config File is needed for the Driver to download the Config file and 
		Firmware. Check for the Config file to be first to be sent from the 
		Application
	*/
	atomic_set (&Adapter->uiMBupdate, FALSE);
	if(!Adapter->bCfgDownloaded && 
		psFwInfo->u32StartingAddress != CONFIG_BEGIN_ADDR)
	{
		/*Can't Download Firmware.*/
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"Download the config File first\n");
		return -EINVAL;
	}
	
	/* If Config File, Finish the DDR Settings and then Download CFG File */
    if(psFwInfo->u32StartingAddress == CONFIG_BEGIN_ADDR)
    {
		retval = bcm_download_config_file (Adapter, psFwInfo);
	}
	else
	{

		buff = (PUCHAR)kzalloc(psFwInfo->u32FirmwareLength,GFP_KERNEL);
		if(buff==NULL)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"Failed in allocation memory");
			return -ENOMEM; 
		}
		retval = copy_from_user(buff,(PUCHAR)psFwInfo->pvMappedFirmwareAddress, psFwInfo->u32FirmwareLength);
		if(retval != STATUS_SUCCESS)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "copying buffer from user space failed");
			goto error ;
		}

		#if 0
		retval = bcm_download_buffer(Adapter, 
				(unsigned char *)psFwInfo->pvMappedFirmwareAddress,
				psFwInfo->u32FirmwareLength, psFwInfo->u32StartingAddress);
		if(retval != STATUS_SUCCESS)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "User space buffer download fails....");
		}
		retval = bcm_buffer_readback (Adapter, 
				(unsigned char *)psFwInfo->pvMappedFirmwareAddress,
				psFwInfo->u32FirmwareLength, psFwInfo->u32StartingAddress);
		
		if(retval != STATUS_SUCCESS)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "read back verifier failed ....");
		}
		#endif
		retval = buffDnldVerify(Adapter,
					buff,
					psFwInfo->u32FirmwareLength,
					psFwInfo->u32StartingAddress);
		if(retval != STATUS_SUCCESS)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"f/w download failed status :%d", retval);
			goto error;
		}
	}
error:
	bcm_kfree(buff);
	return retval;
}


#endif

