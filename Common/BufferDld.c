/* 
* BufferDld.c
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


static inline struct file *open_firmware_file(PMINI_ADAPTER Adapter, char *path)
{
    struct file             *flp=NULL;
    mm_segment_t        oldfs;
    oldfs=get_fs(); 
	set_fs(get_ds());
    flp=filp_open(path, O_RDONLY, S_IRWXU);
    set_fs(oldfs);
    if(IS_ERR(flp))
    {
        BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Unable To Open File %s, err  %lx",
				path, PTR_ERR(flp));
		flp = NULL;
    }
    else
    {
        BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Got file descriptor pointer of %s!", 
			path);
    }
	if(Adapter->device_removed)
	{
		flp = NULL;
	}

    return flp;
}


int BcmFileDownload(PMINI_ADAPTER Adapter,/**< Logical Adapter */
                        char *path,     /**< path to image file */
                        unsigned int loc    /**< Download Address on the chip*/
                        )
{
    int             errorno=0;
    struct file     *flp=NULL;
    mm_segment_t    oldfs;
    struct timeval tv={0};

    flp=open_firmware_file(Adapter, path);
    if(!flp)
    {
        errorno = -ENOENT;
        BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Unable to Open %s\n", path);
        goto exit_download;
    }
    BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Opened file is = %s and length =0x%lx to be downloaded at =0x%x", path,(unsigned long)flp->f_dentry->d_inode->i_size, loc);
    do_gettimeofday(&tv);
    
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "download start %lx", ((tv.tv_sec * 1000) +
                            (tv.tv_usec/1000)));
    if(Adapter->bcm_file_download(Adapter->pvInterfaceAdapter, flp, loc))
    {
        BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Failed to download the firmware with error\
		 %x!!!", -EIO);
        errorno=-EIO;
        goto exit_download;
    }
    oldfs=get_fs();set_fs(get_ds());
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    vfs_llseek(flp, 0, 0);
#endif
    set_fs(oldfs);
    if(Adapter->bcm_file_readback_from_chip(Adapter->pvInterfaceAdapter, 
										flp, loc))
    {
        BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Failed to read back firmware!");
        errorno=-EIO;
        goto exit_download;
    }

exit_download:
    oldfs=get_fs();set_fs(get_ds());
	if(flp && !(IS_ERR(flp)))
    	filp_close(flp, current->files);
    set_fs(oldfs);
    do_gettimeofday(&tv);
    BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "file download done at %lx", ((tv.tv_sec * 1000) +
                            (tv.tv_usec/1000)));
    return errorno;
}


/*
 * ACP : Appended Configuration Parameters
 * Capture them from the buffer and merge.
 */
int capture_and_merge_acp(PMINI_ADAPTER Adapter, unsigned char *ptr, int size)
{
	fw_typeval_rec_t *sp_fwrec;
	int j, k, recsz = sizeof (fw_typeval_rec_t);
	B_UINT32 type, val;
	B_UINT32 VID=0, PID=0;
	B_UINT32 DevVID=0, DevPID=0;

	ptr += CFGFIL_SZ_MIN;	// seek ahead 144 bytes

	rdmalt(Adapter, 0x0f011810, &DevVID, sizeof(B_UINT32));
	rdmalt(Adapter, 0x0f011814, &DevPID, sizeof(B_UINT32));
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "DevVID 0x%08x : DevPID = 0x%08x", DevVID, DevPID);
	printk( "DevVID 0x%08x : DevPID = 0x%08x\n", DevVID, DevPID);



	//--- Process each 'new ACP record' (of Type/Value pairs of (4+4=) 8 bytes each)...
	for (j=0, k=0; j < ((size-CFGFIL_SZ_MIN)/recsz); j++, k++) {
		// Map the read-in memory bytes to the structure
		sp_fwrec = (fw_typeval_rec_t *)ptr+k;
		type = ntohl (sp_fwrec->type);
		val  = ntohl (sp_fwrec->value);

		/* The very first Type/Value pair MUST be VID_PID , meaning type MUST be zero. */
		if (unlikely(((0 == j) && type))) {	// first pair
			printk (KERN_WARNING "\n\n*** WARNING ***\n\
INVALID TYPE [0x%x]. For First ACP, Type MUST be zero. Please Fix the config file %s first.\n\
Only then can ACP entries be processed.\n", type, CFG_FILE);
			return -1;
		}

		if (type == BCM_ACP_TYPE_NEW) {
			VID = (val & 0xffff0000) >> 16;
			PID = val & 0x0000ffff;
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "NEW ACP Section [VID.PID = %04x.%04x] follows:", 
				VID, PID);
		}
		
		/* The whole idea is that the 'new' appended (ACP) data overwrites the 
		 * previous 'usual' 0-143 bytes data if it exists.
		 * So, we know the Type n => the structure field n.
		 * (See the HLD Design Doc).
		 * Therefore, just overwrite location (ptr+(n*4)) in the buffer with the corr. value! 
		 * This will correspond to the structure member to be updated, as the user uses this 
		 * very same Type field to specify that (s)he wants this member updated.
		 */
		if ((VID == DevVID) && (PID == DevPID) && type) {
			if (unlikely(type > BCM_ACP_TYPE_MAX)) {
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "INVALID ACP TYPE [0x%x]!!  Aborting this record...", type);
				continue;
			}
			*(B_UINT32 *)((ptr-CFGFIL_SZ_MIN)+((type - 1)*sizeof (B_UINT32))) = ntohl (val);
		}
	}	// for

#if (BCM_DBG_SHOW_CFG_MEMBUF == 1)
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0, "\n");
	/**
 120 * print_hex_dump - print a text hex dump to syslog for a binary blob of data
 121 * @level: kernel log level (e.g. KERN_DEBUG)
 122 * @prefix_str: string to prefix each line with;
 123 *  caller supplies trailing spaces for alignment if desired
 124 * @prefix_type: controls whether prefix of an offset, address, or none
 125 *  is printed (%DUMP_PREFIX_OFFSET, %DUMP_PREFIX_ADDRESS, %DUMP_PREFIX_NONE)
 126 * @rowsize: number of bytes to print per line; must be 16 or 32
 127 * @groupsize: number of bytes to print at a time (1, 2, 4, 8; default = 1)
 128 * @buf: data blob to dump
 129 * @len: number of bytes in the @buf
 130 * @ascii: include ASCII after the hex output
	**/
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0, "\nMemory Dump of Config Data:\n\
<offset>  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n\n");
	print_hex_dump (KERN_ALERT, "", DUMP_PREFIX_ADDRESS, 16, 1, ptr-CFGFIL_SZ_MIN, size, 0);
#endif
	return 0;
}


int bcm_parse_target_params(PMINI_ADAPTER Adapter)
{
#ifdef BCM_SHM_INTERFACE	
	extern void read_cfg_file(PMINI_ADAPTER Adapter);
#endif
	struct file 	*flp=NULL;
	mm_segment_t 	oldfs={0};
	unsigned char *buff = NULL;
	int len = 0;
	loff_t	pos = 0;
	loff_t cfgfil_sz=0;

	if((Adapter->pstargetparams = 
		kmalloc(sizeof(STARGETPARAMS), GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	flp=open_firmware_file(Adapter, CFG_FILE);
	if(!flp) {
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "NOT ABLE TO OPEN THE %s FILE \n", CFG_FILE);
		bcm_kfree(Adapter->pstargetparams);
		return -ENOENT;
	}
	oldfs=get_fs();	set_fs(get_ds());

	cfgfil_sz = flp->f_dentry->d_inode->i_size;
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Config file %s size = %ld bytes", CFG_FILE,(long int)cfgfil_sz);

	if( (cfgfil_sz < CFGFIL_SZ_MIN) || (cfgfil_sz > CFGFIL_SZ_MAX)){
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Firmware Config file %s size invalid (too small/large)!\n", CFG_FILE);
		bcm_kfree(Adapter->pstargetparams);
		filp_close(flp, current->files);
		set_fs(oldfs);
		return -EINVAL;	// ?
	}
	
	buff=(PCHAR)kmalloc (cfgfil_sz, GFP_KERNEL);
	if (!buff) {
		bcm_kfree(Adapter->pstargetparams);
		filp_close(flp, current->files);
		set_fs(oldfs);
		return -ENOMEM;
	}

	flp->f_pos = 0;
	len=vfs_read(flp, buff, cfgfil_sz, &pos);
	if ((len < CFGFIL_SZ_MIN) ||(cfgfil_sz > CFGFIL_SZ_MAX)){
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"Mismatch in Target Param Structure!\n");
		bcm_kfree(buff);
		bcm_kfree(Adapter->pstargetparams);
		filp_close(flp, current->files);
		set_fs(oldfs);
		return -ENOENT;
	}
	filp_close(flp, current->files);
	set_fs(oldfs);

	/* 
	 * Now 'buff' contains the "usual" first 144 bytes of binary configuration data;
	 * and if cfgfil_sz > 144 , then it also now contains the new "flexi-config"
	 * appended data (ACP - Appended Configuration Parameters).
	 */ 
	if (cfgfil_sz > CFGFIL_SZ_MIN) {
		BCM_DEBUG_PRINT (Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "## Flexi-Config ACP (Additional Configuration Parameters) detected ##");
		if (capture_and_merge_acp (Adapter, buff, cfgfil_sz)) {
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "***WARNING *** Function %s failed. ACP processing aborted...\n", 
				"capture_and_merge_acp");
		}
	}

	/* Check for autolink in config params */
	/* 
	 * Values in Adapter->pstargetparams are in network byte order
	 */
	memcpy(Adapter->pstargetparams, buff, sizeof(STARGETPARAMS));
	bcm_kfree (buff);
	beceem_parse_target_struct(Adapter);
#ifdef BCM_SHM_INTERFACE
	read_cfg_file(Adapter);

#endif
	return STATUS_SUCCESS;
}


void beceem_parse_target_struct(PMINI_ADAPTER Adapter)
{
	UINT uiHostDrvrCfg6 =0, uiEEPROMFlag = 0;
	UINT       uiHarqEnable = 0;

	if(ntohl(Adapter->pstargetparams->m_u32PhyParameter2) & AUTO_SYNC_DISABLE)
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "AutoSyncup is Disabled\n");
		Adapter->AutoSyncup = FALSE;
	}
	else
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "AutoSyncup is Enabled\n");
		Adapter->AutoSyncup	= TRUE;
	}
	if(ntohl(Adapter->pstargetparams->HostDrvrConfig6) & AUTO_LINKUP_ENABLE)
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Enabling autolink up");
		Adapter->AutoLinkUp = TRUE;
	}
	else 
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Disabling autolink up");
		Adapter->AutoLinkUp = FALSE;
	}
	// Setting the DDR Setting..
	Adapter->DDRSetting = 
			(ntohl(Adapter->pstargetparams->HostDrvrConfig6) >>8)&0x0F;

	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "DDR Setting: %x\n", Adapter->DDRSetting);

	uiHostDrvrCfg6 = ntohl(Adapter->pstargetparams->HostDrvrConfig6);

	if(uiHostDrvrCfg6 & AUTO_FIRM_DOWNLOAD)
    {
        BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Enabling Auto Firmware Download\n");
        Adapter->AutoFirmDld = TRUE;
    }
    else 
    {
        BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Disabling Auto Firmware Download\n");
        Adapter->AutoFirmDld = FALSE;
    }

	uiHarqEnable = ntohl(Adapter->pstargetparams->m_u32HarqEnable);
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"HarqCat5Enable   : 0x%X\n", uiHarqEnable);
	Adapter->bHarqCat5Enable = ( uiHarqEnable >> 16 ) & 0xFF;
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"HarqCat5Enable   : 0x%X\n",Adapter->bHarqCat5Enable);
	
	
	Adapter->bMipsConfig = (uiHostDrvrCfg6>>20)&0x01;
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"MIPSConfig   : 0x%X\n",Adapter->bMipsConfig);	
	//used for backward compatibility.	
	Adapter->bDPLLConfig = (uiHostDrvrCfg6>>19)&0x01;

	Adapter->PmuMode= (uiHostDrvrCfg6 >> 24 ) & 0x03;
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "PMU MODE: %x", Adapter->PmuMode);

	Adapter->bDisableFastFlashWrite = (uiHostDrvrCfg6>>29)&0x1;
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "bDisableFastFlashWrite:%d",Adapter->bDisableFastFlashWrite);  

    if((uiHostDrvrCfg6 >> HOST_BUS_SUSPEND_BIT ) & (0x01))
    {
        Adapter->bDoSuspend = TRUE;
        BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Making DoSuspend TRUE as per configFile");    
    }
	
	uiEEPROMFlag = ntohl(Adapter->pstargetparams->m_u32EEPROMFlag);
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "uiEEPROMFlag  : 0x%X\n",uiEEPROMFlag); 
	Adapter->eNVMType = (NVM_TYPE)((uiEEPROMFlag>>4)&0x3); 
	

	Adapter->bStatusWrite = (uiEEPROMFlag>>6)&0x1;	
	//printk(("bStatusWrite   : 0x%X\n", Adapter->bStatusWrite));			

	Adapter->uiSectorSizeInCFG = 1024*(0xFFFF & ntohl(Adapter->pstargetparams->HostDrvrConfig4));
	//printk(("uiSectorSize   : 0x%X\n", Adapter->uiSectorSizeInCFG));

	Adapter->bSectorSizeOverride =(bool) ((ntohl(Adapter->pstargetparams->HostDrvrConfig4))>>16)&0x1;
	//printk(MP_INIT,("bSectorSizeOverride   : 0x%X\n",Adapter->bSectorSizeOverride));

	Adapter->ulPowerSaveMode = ((uiHostDrvrCfg6)>>12)&0x0F;

	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT,DBG_LVL_ALL, "Power Save Mode: %x\n", 
							Adapter->ulPowerSaveMode);
	/*
	**Incase of SHM_DRIVER: 
	**Calling doPowerAutoCorrection... Irrespective of ulPowerSaveMode value is DEVICE_POWERSAVE_MODE_AS_PROTOCOL_IDLE_MODE
	** to support the Hybrid Idle Mode...
	*/
	if(ntohl(Adapter->pstargetparams->m_u32PowerSavingModeOptions) & 0x01)
	{
#ifdef BCM_SHM_INTERFACE
		doPowerAutoCorrection(Adapter);
#endif
		Adapter->ulPowerSaveMode = DEVICE_POWERSAVE_MODE_AS_PROTOCOL_IDLE_MODE;
	}
	else
		doPowerAutoCorrection(Adapter);

	Adapter->ucDsxLinkUpCfg = ((uiHostDrvrCfg6>>21)&0x03)?((uiHostDrvrCfg6>>21)&0x03): CONNECT_ON_DL_UL;	
	BCM_DEBUG_PRINT (Adapter, DBG_TYPE_PRINTK, 0, 0, "LinkUp Config   : 0x%X\n",Adapter->ucDsxLinkUpCfg);

}

VOID doPowerAutoCorrection(PMINI_ADAPTER psAdapter)
{
	UINT reporting_mode = 0;
	
	reporting_mode = ntohl(psAdapter->pstargetparams->m_u32PowerSavingModeOptions) &0x02 ;
	psAdapter->bIsAutoCorrectEnabled = !((char)(psAdapter->ulPowerSaveMode >> 3) & 0x1);

	if(reporting_mode == TRUE)
	{
		BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"can't do suspen/resume as reporting mode is enable");
		psAdapter->bDoSuspend = FALSE;
	}
	
	if (psAdapter->bIsAutoCorrectEnabled && (psAdapter->chip_id >= T3LPB))
	{
#ifdef BCM_SHM_INTERFACE
		psAdapter->ulPowerSaveMode = DEVICE_POWERSAVE_MODE_AS_PMU_SHUTDOWN;
		psAdapter->bDoSuspend =FALSE;
		BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"PMU selected ...."); 
#else
		//If reporting mode is enable, switch PMU to PMC 
		if(reporting_mode == FALSE)
		{
			psAdapter->ulPowerSaveMode = DEVICE_POWERSAVE_MODE_AS_PMU_SHUTDOWN;
			psAdapter->bDoSuspend = TRUE;
			BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"PMU selected ....");	
		}
		else
		{
			psAdapter->ulPowerSaveMode = DEVICE_POWERSAVE_MODE_AS_PMU_CLOCK_GATING;
			psAdapter->bDoSuspend =FALSE;
			BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"PMC selected..");		
		}
#endif
		//clearing space bit[15..12]
		psAdapter->pstargetparams->HostDrvrConfig6 &= ~(htonl((0xF << 12)));
		//placing the power save mode option
		psAdapter->pstargetparams->HostDrvrConfig6 |= htonl((psAdapter->ulPowerSaveMode << 12));
	} 
	else if (psAdapter->bIsAutoCorrectEnabled == FALSE)
	{

		// remove the autocorrect disable bit set before dumping.
		psAdapter->ulPowerSaveMode &= ~(1 << 3);
		psAdapter->pstargetparams->HostDrvrConfig6 &= ~(htonl(1 << 15));
		BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"Using Forced User Choice: %x\n", psAdapter->ulPowerSaveMode);		
	}
}

static int bcm_compare_buff_contents(unsigned char *readbackbuff, 
	unsigned char *buff,unsigned int len)
{
	int retval = STATUS_SUCCESS;
    PMINI_ADAPTER Adapter = GET_BCM_ADAPTER(gblpnetdev);
    if((len-sizeof(unsigned int))<4)
	{
		if(memcmp(readbackbuff , buff, len))
		{
			retval=-EINVAL;
		}
	}
	else
	{
		len-=4;
		while(len)
		{
			if(*(unsigned int*)&readbackbuff[len] != 
					*(unsigned int *)&buff[len])
			{
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Firmware Download is not proper");
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Val from Binary %x, Val From Read Back %x ", *(unsigned int *)&buff[len], *(unsigned int*)&readbackbuff[len]);
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "len =%x!!!", len);
				retval=-EINVAL;
				break;
			}
			len-=4;
		}
	}
	return retval;
}

static INT buffDnld(PMINI_ADAPTER Adapter, PUCHAR mappedbuffer, UINT u32FirmwareLength, 
		B_UINT32 u32StartingAddress)
{

	unsigned int	len = 0;
	int retval = STATUS_SUCCESS;
	len = u32FirmwareLength;
		
	while(u32FirmwareLength)
	{
		len = MIN_VAL (u32FirmwareLength, MAX_TRANSFER_CTRL_BYTE_USB);
		retval = wrm (Adapter, u32StartingAddress, mappedbuffer, len);
		if(retval)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "wrm failed with status :%d", retval);
			break;
		}
		u32StartingAddress	+= len;
		u32FirmwareLength	-= len;
		mappedbuffer		+=len;
	}
	return retval;
	
}

static INT buffRdbkVerify(PMINI_ADAPTER Adapter, 
			PUCHAR mappedbuffer, UINT u32FirmwareLength, 
			B_UINT32 u32StartingAddress)
{
	PUCHAR readbackbuff = NULL;
	UINT len = u32FirmwareLength;
	INT retval = STATUS_SUCCESS;

	readbackbuff = (PUCHAR)kzalloc(MAX_TRANSFER_CTRL_BYTE_USB,GFP_KERNEL);
	if(NULL == readbackbuff)
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "MEMORY ALLOCATION FAILED");
		return -ENOMEM;
	}
	while (u32FirmwareLength && !retval)
	{

		len = MIN_VAL (u32FirmwareLength, MAX_TRANSFER_CTRL_BYTE_USB);
		
		retval = rdm (Adapter, u32StartingAddress, readbackbuff, len);
		if(retval)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "rdm failed with status %d" ,retval);
			break;
		}
		
		if (STATUS_SUCCESS != (retval = bcm_compare_buff_contents (readbackbuff, mappedbuffer, len)))
		{
			break;
		}
		u32StartingAddress 	+= len;
		u32FirmwareLength  	-= len;
		mappedbuffer	   	+=len;
	}/* end of while (u32FirmwareLength && !retval) */
	bcm_kfree(readbackbuff);
	return retval;
}

INT buffDnldVerify(PMINI_ADAPTER Adapter, unsigned char *mappedbuffer, unsigned int u32FirmwareLength, 
		unsigned long u32StartingAddress)
{
	INT status = STATUS_SUCCESS;
	
	status = buffDnld(Adapter,mappedbuffer,u32FirmwareLength,u32StartingAddress);
	if(status != STATUS_SUCCESS)
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"Buffer download failed");
		goto error;
	}
		
	status= buffRdbkVerify(Adapter,mappedbuffer,u32FirmwareLength,u32StartingAddress);
	if(status != STATUS_SUCCESS)
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"Buffer readback verifier failed");
		goto error;
	}
error:
	return status;
}



int bcm_ioctl_cfg_download(PMINI_ADAPTER Adapter, PFIRMWARE_INFO psFwInfo)
{
	int retval = STATUS_SUCCESS;
	unsigned char *kbuf = NULL;

	
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, OSAL_DBG, DBG_LVL_ALL, "FW length = %u", psFwInfo->u32FirmwareLength);
	if(psFwInfo->u32FirmwareLength < sizeof(STARGETPARAMS)) {
		BCM_DEBUG_PRINT(Adapter, DBG_TYPE_PRINTK, 0, 0, "Target Length Mismatch\n");
		return -EIO;
	}

	if(Adapter->pstargetparams == NULL) {
        if((Adapter->pstargetparams =
            kmalloc(sizeof(STARGETPARAMS), GFP_KERNEL)) == NULL)
        {
        	BCM_DEBUG_PRINT(Adapter, DBG_TYPE_PRINTK, 0, 0, "Malloc failed for pstargetparams \n");
            return -ENOMEM;
        }
    }

	if ((kbuf = kmalloc(psFwInfo->u32FirmwareLength, GFP_KERNEL)) == NULL) {
			bcm_kfree (Adapter->pstargetparams);
			BCM_DEBUG_PRINT(Adapter, DBG_TYPE_PRINTK, 0, 0, "Malloc failed for u32FirmwareLength \n");
			return -ENOMEM;
	}
	retval = copy_from_user (kbuf,psFwInfo->pvMappedFirmwareAddress, psFwInfo->u32FirmwareLength);
	if (retval) {
		bcm_kfree (kbuf);
		bcm_kfree (Adapter->pstargetparams);
		BCM_DEBUG_PRINT(Adapter, DBG_TYPE_PRINTK, 0, 0, "copy_from_user failed !!\n");
		return retval;
	}
		
	/*	 
	 * Now 'kbuf' contains the "usual" first 144 bytes of binary configuration data;
	 * and if cfgfil_sz > 144 , then it also now contains the new "flexi-config"
	 * appended data (ACP - Appended Configuration Parameters).
	 */ 
	if (psFwInfo->u32FirmwareLength > sizeof(STARGETPARAMS)) {
		BCM_DEBUG_PRINT (Adapter,DBG_TYPE_OTHERS, OSAL_DBG, DBG_LVL_ALL, "## Flexi-Config ACP (Additional Configuration Parameters) detected ##");
		if (capture_and_merge_acp (Adapter, kbuf, psFwInfo->u32FirmwareLength)) {
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0, "***WARNING *** Function %s failed. ACP processing aborted...\n", 
				"capture_and_merge_acp");
		}
	}	 

	/* Check for autolink in config params */
	/*	 
	 * Values in Adapter->pstargetparams are in network byte order
	 */
	memcpy(Adapter->pstargetparams, kbuf, sizeof(STARGETPARAMS));
	bcm_kfree (kbuf);

	beceem_parse_target_struct(Adapter);

	retval =buffDnldVerify(Adapter,(PUCHAR)Adapter->pstargetparams,sizeof(STARGETPARAMS),CONFIG_BEGIN_ADDR);

	if(retval)
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0, "configuration file not downloaded properly");
	}
	else
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0, "configuration file downloaded successfully!!");
	
	}

	return retval;
}


