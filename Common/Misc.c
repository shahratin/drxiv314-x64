/* 
* Misc.c
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


#include<headers.h>

#ifndef BCM_SHM_INTERFACE
extern int DeviceInsertedCount;
#endif
static VOID default_wimax_protocol_initialize(PMINI_ADAPTER Adapter)
{

	UINT    uiLoopIndex;

    for(uiLoopIndex=0; uiLoopIndex < NO_OF_QUEUES-1; uiLoopIndex++)
    {
    	Adapter->PackInfo[uiLoopIndex].uiThreshold=TX_PACKET_THRESHOLD;
        Adapter->PackInfo[uiLoopIndex].uiMaxAllowedRate=MAX_ALLOWED_RATE;
        Adapter->PackInfo[uiLoopIndex].uiMaxBucketSize=20*1024*1024;
    }

    Adapter->BEBucketSize=BE_BUCKET_SIZE;
    Adapter->rtPSBucketSize=rtPS_BUCKET_SIZE;
    Adapter->LinkStatus=SYNC_UP_REQUEST;
    Adapter->TransferMode=IP_PACKET_ONLY_MODE;
    Adapter->usBestEffortQueueIndex=-1;
    return;
}


INT
InitAdapter(PMINI_ADAPTER psAdapter)
{
    int i = 0;
	INT Status = STATUS_SUCCESS ;
	BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT,  DBG_LVL_ALL,  "Initialising Adapter = 0x%lx",(ULONG) psAdapter);

	if(psAdapter == NULL)
	{
		BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT,  DBG_LVL_ALL, "Adapter is NULL");
		return -EINVAL;
	}

	sema_init(&psAdapter->NVMRdmWrmLock,1);
//	psAdapter->ulFlashCalStart = FLASH_AUTO_INIT_BASE_ADDR;

	sema_init(&psAdapter->rdmwrmsync, 1);
	sema_init(&psAdapter->rdmWrmDevAccLock, 1);	
	spin_lock_init(&psAdapter->control_queue_lock);
	spin_lock_init(&psAdapter->txtransmitlock);
    sema_init(&psAdapter->RxAppControlQueuelock, 1);
//    sema_init(&psAdapter->data_packet_queue_lock, 1);
    sema_init(&psAdapter->fw_download_sema, 1);
  	sema_init(&psAdapter->LowPowerModeSync,1);
  	sema_init(&psAdapter->PatternWriteLock,1);

  // spin_lock_init(&psAdapter->sleeper_lock);
    for(i=0;i<NO_OF_QUEUES; i++)
        spin_lock_init(&psAdapter->PackInfo[i].SFQueueLock);
    i=0;

    init_waitqueue_head(&psAdapter->process_rx_cntrlpkt);
    init_waitqueue_head(&psAdapter->tx_packet_wait_queue);
    init_waitqueue_head(&psAdapter->process_read_wait_queue);
    init_waitqueue_head(&psAdapter->ioctl_fw_dnld_wait_queue);
    init_waitqueue_head(&psAdapter->lowpower_mode_wait_queue);
	psAdapter->waiting_to_fw_download_done = TRUE;
    //init_waitqueue_head(&psAdapter->device_wake_queue);
    psAdapter->fw_download_done=FALSE;

    psAdapter->pvOsDepData = (PLINUX_DEP_DATA) kmalloc(sizeof(LINUX_DEP_DATA),
                 GFP_KERNEL);

    if(psAdapter->pvOsDepData == NULL)
	{
        BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Linux Specific Data allocation failed");
        return -ENOMEM;
    }
    memset(psAdapter->pvOsDepData, 0, sizeof(LINUX_DEP_DATA));

	default_wimax_protocol_initialize(psAdapter);
	for (i=0;i<MAX_CNTRL_PKTS;i++)
	{
		psAdapter->txctlpacket[i] = (char *)kmalloc(MAX_CNTL_PKT_SIZE, 
												GFP_KERNEL);
		if(!psAdapter->txctlpacket[i])
		{
			BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "No More Cntl pkts got, max got is %d", i);
			return -ENOMEM;
		}
	}
	if(AllocAdapterDsxBuffer(psAdapter))
	{
		BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Failed to allocate DSX buffers");
		return -EINVAL;
	}

	//Initialize PHS interface
	if(phs_init(&psAdapter->stBCMPhsContext,psAdapter)!=0)
	{
		BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"%s:%s:%d:Error PHS Init Failed=====>\n", __FILE__, __FUNCTION__, __LINE__);
		return -ENOMEM;
	}
	
	Status = BcmAllocFlashCSStructure(psAdapter);
	if(Status)
	{
		BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"Memory Allocation for Flash structure failed");
		return Status ;
	}

	Status = vendorextnInit(psAdapter);

	if(STATUS_SUCCESS != Status)
	{
		BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"Vendor Init Failed");
		return Status ;
	}

	BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,  "Adapter initialised");


	return STATUS_SUCCESS;
}

VOID AdapterFree(PMINI_ADAPTER Adapter)
{
	INT count = 0;

	//Driver supports only one device...
	//In case of probe not success this function got called...
    // Making  DeviceInsertedCount value as zero: so other device can be inserted.
    
#ifndef BCM_SHM_INTERFACE
	DeviceInsertedCount = 0;
#endif
	beceem_protocol_reset(Adapter);

	vendorextnExit(Adapter);
	
	if(Adapter->control_packet_handler && !IS_ERR(Adapter->control_packet_handler))
	  	kthread_stop (Adapter->control_packet_handler);
	if(Adapter->transmit_packet_thread && !IS_ERR(Adapter->transmit_packet_thread))
    	kthread_stop (Adapter->transmit_packet_thread);
    wake_up(&Adapter->process_read_wait_queue);
	if(Adapter->LEDInfo.led_thread_running & (BCM_LED_THREAD_RUNNING_ACTIVELY | BCM_LED_THREAD_RUNNING_INACTIVELY))
		kthread_stop (Adapter->LEDInfo.led_cntrl_threadid);
	bcm_unregister_networkdev(Adapter);
	while(atomic_read(&Adapter->ApplicationRunning))
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Waiting for Application to close.. %d\n",atomic_read(&Adapter->ApplicationRunning));
		msleep(100);
	}
	unregister_control_device_interface(Adapter);
	if(Adapter->dev && !IS_ERR(Adapter->dev))
		free_netdev(Adapter->dev);
	if(Adapter->pstargetparams != NULL)
	{
		bcm_kfree(Adapter->pstargetparams);
	}
	for (count =0;count < MAX_CNTRL_PKTS;count++)
	{
		if(Adapter->txctlpacket[count])
			bcm_kfree(Adapter->txctlpacket[count]);
	}
	FreeAdapterDsxBuffer(Adapter);
	if(Adapter->pvOsDepData)
		bcm_kfree (Adapter->pvOsDepData);
	if(Adapter->pvInterfaceAdapter)
		bcm_kfree(Adapter->pvInterfaceAdapter);

	//Free the PHS Interface
	PhsCleanup(&Adapter->stBCMPhsContext);

#ifndef BCM_SHM_INTERFACE
	BcmDeAllocFlashCSStructure(Adapter);
#endif

	bcm_kfree (Adapter);
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "<========\n");
}


int create_worker_threads(PMINI_ADAPTER psAdapter)
{
	BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Init Threads...");
	// Rx Control Packets Processing
	psAdapter->control_packet_handler = kthread_run((int (*)(void *))
			control_packet_handler, psAdapter, "CtrlPktHdlr");
	if(IS_ERR(psAdapter->control_packet_handler))
	{
		BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "No Kernel Thread, but still returning success\n");
		return PTR_ERR(psAdapter->control_packet_handler);
	}
	// Tx Thread
	psAdapter->transmit_packet_thread = kthread_run((int (*)(void *))
		tx_pkt_handler, psAdapter, "TxPktThread");
	if(IS_ERR (psAdapter->transmit_packet_thread))
	{
		BCM_DEBUG_PRINT(psAdapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "No Kernel Thread, but still returning success");
		kthread_stop(psAdapter->control_packet_handler);
		return PTR_ERR(psAdapter->transmit_packet_thread);
	}
	return 0;
}


void bcm_kfree_skb(struct sk_buff *skb)
{
	if(skb)
    {
    	kfree_skb(skb);
    }
	skb = NULL ;
}

VOID bcm_kfree(VOID *ptr)
{
	if(ptr)
	{
		kfree(ptr);
	}
	ptr = NULL ;
}

/**
@ingroup ctrl_pkt_functions
This function copies the contents of given buffer
to the control packet and queues it for transmission.
@note Do not acquire the spinock, as it it already acquired.
@return  SUCCESS/FAILURE.
*/
INT CopyBufferToControlPacket(PMINI_ADAPTER Adapter,/**<Logical Adapter*/
									  PVOID ioBuffer/**<Control Packet Buffer*/
									  )
{
	PLEADER				pLeader=NULL;
	INT					Status=0;
	unsigned char		*ctrl_buff=NULL;
	UINT				pktlen=0;
	PLINK_REQUEST		pLinkReq 	= NULL;
	PUCHAR				pucAddIndication = NULL;

	BCM_DEBUG_PRINT( Adapter,DBG_TYPE_TX, TX_CONTROL, DBG_LVL_ALL, "======>");
	if(!ioBuffer)
	{
		BCM_DEBUG_PRINT( Adapter,DBG_TYPE_TX, TX_CONTROL,DBG_LVL_ALL, "Got Null Buffer\n");
		return -EINVAL;
	}

	pLinkReq = (PLINK_REQUEST)ioBuffer;
	pLeader=(PLEADER)ioBuffer; //ioBuffer Contains sw_Status and Payload
	
	if(Adapter->bShutStatus == TRUE &&
		pLinkReq->szData[0] == LINK_DOWN_REQ_PAYLOAD &&
		pLinkReq->szData[1] == LINK_SYNC_UP_SUBTYPE)
	{
		//Got sync down in SHUTDOWN..we could not process this.
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL,DBG_LVL_ALL, "SYNC DOWN Request in Shut Down Mode..\n");
		return STATUS_FAILURE;		
	}

	if((pLeader->Status == LINK_UP_CONTROL_REQ) &&
		((pLinkReq->szData[0] == LINK_UP_REQ_PAYLOAD &&
		 (pLinkReq->szData[1] == LINK_SYNC_UP_SUBTYPE)) ||//Sync Up Command
		 pLinkReq->szData[0] == NETWORK_ENTRY_REQ_PAYLOAD)) //Net Entry Command
	{
		if(Adapter->LinkStatus > PHY_SYNC_ACHIVED)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL,DBG_LVL_ALL,"LinkStatus is Greater than PHY_SYN_ACHIEVED");	
			return STATUS_FAILURE;
		}
		if(TRUE == Adapter->bShutStatus)
		{		
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL,DBG_LVL_ALL, "SYNC UP IN SHUTDOWN..Device WakeUp\n");
			if(Adapter->bTriedToWakeUpFromlowPowerMode == FALSE)
			{
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL,DBG_LVL_ALL, "Waking up for the First Time..\n");
				Adapter->usIdleModePattern = ABORT_SHUTDOWN_MODE; // change it to 1 for current support.
				Adapter->bWakeUpDevice = TRUE;
				wake_up(&Adapter->process_rx_cntrlpkt);	

				Status = wait_event_interruptible_timeout(Adapter->lowpower_mode_wait_queue,
					!Adapter->bShutStatus, (5 * HZ));
				
				if(Status == -ERESTARTSYS)
					return Status;

				if(Adapter->bShutStatus)
				{
					BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL,DBG_LVL_ALL, "Shutdown Mode Wake up Failed - No Wake Up Received\n");
					return STATUS_FAILURE;
				}
			}
			else
			{
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL,DBG_LVL_ALL, "Wakeup has been tried already...\n");
			}
		} 
		
	}
	if(TRUE == Adapter->IdleMode)
	{
		//BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Device is in Idle mode ... hence \n");
		if(pLeader->Status == LINK_UP_CONTROL_REQ || pLeader->Status == 0x80 ||
			pLeader->Status == CM_CONTROL_NEWDSX_MULTICLASSIFIER_REQ )
			
		{
			if((pLeader->Status == LINK_UP_CONTROL_REQ) && (pLinkReq->szData[0]==LINK_DOWN_REQ_PAYLOAD)) 
			{
				if(pLinkReq->szData[1] == LINK_SYNC_DOWN_SUBTYPE)
				{
					BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL,DBG_LVL_ALL, "Link Down Sent in Idle Mode\n");
					Adapter->usIdleModePattern = ABORT_IDLE_SYNCDOWN;//LINK DOWN sent in Idle Mode
				}
				else if(pLinkReq->szData[1] == SYNC_DOWN_NO_DREG_REQ)
				{
					Adapter->usIdleModePattern = ABORT_IDLE_SYNCDOWN_NO_DREG;
					down(&Adapter->PatternWriteLock);
					Adapter->uiHiPriorityPattern = ABORT_IDLE_SYNCDOWN_NO_DREG;

					if(Adapter->bPatternWritten)
					{
						BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL, DBG_LVL_ALL, "Writing Updated pattern<%d> to SW_ABORT_IDLEMODE_LOC\n", Adapter->uiHiPriorityPattern);
						Status = wrmalt(Adapter,SW_ABORT_IDLEMODE_LOC, &Adapter->uiHiPriorityPattern, sizeof(Adapter->uiHiPriorityPattern));
						if(Status)
						{
							BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"WRM to Register SW_ABORT_IDLEMODE_LOC failed.. still continuing");
						}	
					}
					up(&Adapter->PatternWriteLock);
				}
				else
				{
					BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL,DBG_LVL_ALL,"ABORT_IDLE_MODE pattern is being written\n");
					Adapter->usIdleModePattern = ABORT_IDLE_REG;
				}
			}
			else
			{
					BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL,DBG_LVL_ALL,"ABORT_IDLE_MODE pattern is being written\n");
					Adapter->usIdleModePattern = ABORT_IDLE_MODE;
			}

			/*Setting bIdleMode_tx_from_host to TRUE to indicate LED control thread to represent 
			  the wake up from idlemode is from host*/
			//Adapter->LEDInfo.bIdleMode_tx_from_host = TRUE;
#if 0
			if(STATUS_SUCCESS != InterfaceIdleModeWakeup(Adapter))
			{
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, NEXT_SEND, DBG_LVL_ALL, "Idle Mode Wake up Failed\n");
				return STATUS_FAILURE;
			}
#endif			
			Adapter->bWakeUpDevice = TRUE;
			wake_up(&Adapter->process_rx_cntrlpkt);

			

			if((LINK_DOWN_REQ_PAYLOAD == pLinkReq->szData[0]) &&
				(SYNC_DOWN_NO_DREG_REQ != pLinkReq->szData[1]) )
			{
				// We should not send DREG message down while in idlemode.	
				return STATUS_SUCCESS;
			}

			Status = wait_event_interruptible_timeout(Adapter->lowpower_mode_wait_queue,
				!Adapter->IdleMode, (5 * HZ));
			
			if(Status == -ERESTARTSYS)
				return Status;

			if(Adapter->IdleMode)
			{
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL,DBG_LVL_ALL, "Idle Mode Wake up Failed - No Wake Up Received\n");
				return STATUS_FAILURE;
			}
		}
		else
			return STATUS_SUCCESS;
	}
	//The Driver has to send control messages with a particular VCID
	pLeader->Vcid = VCID_CONTROL_PACKET;//VCID for control packet.

	/* Allocate skb for Control Packet */
	pktlen = pLeader->PLength;
	if(pLeader)
	{
		if((pLeader->Status == 0x80) || 
			(pLeader->Status == CM_CONTROL_NEWDSX_MULTICLASSIFIER_REQ))
		{
			/*
			//Restructure the DSX message to handle Multiple classifier Support
			// Write the Service Flow param Structures directly to the target
			//and embed the pointers in the DSX messages sent to target.
			*/
			//Lets store the current length of the control packet we are transmitting
			pucAddIndication = (PUCHAR)ioBuffer + LEADER_SIZE;
			pktlen = pLeader->PLength;
			Status = StoreCmControlResponseMessage(Adapter,pucAddIndication, &pktlen);
			if(Status != 1)
			{
				ClearTargetDSXBuffer(Adapter,((stLocalSFAddIndicationAlt *)pucAddIndication)->u16TID, FALSE);
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL, DBG_LVL_ALL, " Error Restoring The DSX Control Packet. Dsx Buffers on Target may not be Setup Properly ");
				return STATUS_FAILURE;
			}
			/*
			//update the leader to use the new length 
			//The length of the control packet is length of message being sent + Leader length			
			*/
			pLeader->PLength = pktlen;
		}
	}
	
	/*Update the statistics counters */
	spin_lock_bh(&Adapter->PackInfo[HiPriority].SFQueueLock);

	ctrl_buff = (char *)Adapter->txctlpacket[atomic_read(&Adapter->index_wr_txcntrlpkt)%MAX_CNTRL_PKTS];

	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL,DBG_LVL_ALL, "Control packet to be taken =%d and address is =%pincoming address is =%p and packet len=%x", atomic_read(&Adapter->index_wr_txcntrlpkt), ctrl_buff, ioBuffer, pktlen);
	if(ctrl_buff)
	{
		memset(ctrl_buff, 0, pktlen+LEADER_SIZE);
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL, DBG_LVL_ALL, "Copying the Control Packet Buffer with length=%d\n", pLeader->PLength);	
		*(PLEADER)ctrl_buff=*pLeader;
		memcpy(ctrl_buff + LEADER_SIZE, ((PUCHAR)ioBuffer + LEADER_SIZE), pLeader->PLength);
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL, DBG_LVL_ALL, "Enqueuing the Control Packet");	
		
		Adapter->PackInfo[HiPriority].uiCurrentBytesOnHost+=pLeader->PLength;
		Adapter->PackInfo[HiPriority].uiCurrentPacketsOnHost++;
		atomic_inc(&Adapter->TotalPacketCount);

		Adapter->PackInfo[HiPriority].bValid = TRUE;
			
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, TX_CONTROL, DBG_LVL_ALL, "CurrBytesOnHost: %x bValid: %x",
			Adapter->PackInfo[HiPriority].uiCurrentBytesOnHost,
			Adapter->PackInfo[HiPriority].bValid);
		Status=STATUS_SUCCESS;
		/*Queue the packet for transmission */
		atomic_inc(&Adapter->index_wr_txcntrlpkt);
		BCM_DEBUG_PRINT( Adapter,DBG_TYPE_TX, TX_CONTROL,DBG_LVL_ALL, "Calling transmit_packets");
		atomic_set(&Adapter->TxPktAvail, 1);
#ifdef BCM_SHM_INTERFACE
		virtual_mail_box_interrupt();
#endif
		wake_up(&Adapter->tx_packet_wait_queue);
	}
	else
	{
		Status=-ENOMEM;
		BCM_DEBUG_PRINT( Adapter,DBG_TYPE_TX, TX_CONTROL, DBG_LVL_ALL, "mem allocation Failed");
    }
	spin_unlock_bh(&Adapter->PackInfo[HiPriority].SFQueueLock);
	BCM_DEBUG_PRINT( Adapter,DBG_TYPE_TX, TX_CONTROL, DBG_LVL_ALL, "<====");
	return Status;
}

/*****************************************************************
* Function    - SendStatisticsPointerRequest()
* 
* Description - This function builds and forwards the Statistics
*				Pointer Request control Packet. 
* 
* Parameters  - Adapter					: Pointer to Adapter structure.
* 			  - pstStatisticsPtrRequest : Pointer to link request.
*
* Returns     - None.
*****************************************************************/
VOID SendStatisticsPointerRequest(PMINI_ADAPTER Adapter,
								PLINK_REQUEST	pstStatisticsPtrRequest)
{
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_RX, RX_DPC, DBG_LVL_ALL, "======>");
	pstStatisticsPtrRequest->Leader.Status = STATS_POINTER_REQ_STATUS;
	pstStatisticsPtrRequest->Leader.PLength = sizeof(B_UINT32);//minimum 4 bytes
	pstStatisticsPtrRequest->szData[0] = STATISTICS_POINTER_REQ;

	CopyBufferToControlPacket(Adapter,pstStatisticsPtrRequest);
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_RX, RX_DPC, DBG_LVL_ALL, "<=====");
	return;
}



void SendLinkDown(PMINI_ADAPTER Adapter)
{
	LINK_REQUEST	stLinkDownRequest;
	memset(&stLinkDownRequest, 0, sizeof(LINK_REQUEST));
	stLinkDownRequest.Leader.Status=LINK_UP_CONTROL_REQ;
	stLinkDownRequest.Leader.PLength=sizeof(B_UINT32);//minimum 4 bytes
	stLinkDownRequest.szData[0]=LINK_DOWN_REQ_PAYLOAD;
	Adapter->bLinkDownRequested = TRUE;

	CopyBufferToControlPacket(Adapter,&stLinkDownRequest);
}

/******************************************************************
* Function    - LinkMessage()
* 
* Description - This function builds the Sync-up and Link-up request
*				packet messages depending on the device Link status.
*				 
* Parameters  - Adapter:	Pointer to the Adapter structure.
*
* Returns     - None.
*******************************************************************/
__inline VOID LinkMessage(PMINI_ADAPTER Adapter)
{
	PLINK_REQUEST	pstLinkRequest=NULL;
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, LINK_UP_MSG, DBG_LVL_ALL, "=====>");	
	if(Adapter->LinkStatus == SYNC_UP_REQUEST && Adapter->AutoSyncup)
	{
		pstLinkRequest=kmalloc(sizeof(LINK_REQUEST), GFP_ATOMIC);
		if(!pstLinkRequest)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, LINK_UP_MSG, DBG_LVL_ALL, "Can not allocate memory for Link request!");
			return;
		}
		memset(pstLinkRequest,0,sizeof(LINK_REQUEST));
		//sync up request...
		Adapter->LinkStatus = WAIT_FOR_SYNC;// current link status
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, LINK_UP_MSG, DBG_LVL_ALL, "Requesting For SyncUp...");
		pstLinkRequest->szData[0]=LINK_UP_REQ_PAYLOAD;
		pstLinkRequest->szData[1]=LINK_SYNC_UP_SUBTYPE;
		pstLinkRequest->Leader.Status=LINK_UP_CONTROL_REQ;
		pstLinkRequest->Leader.PLength=sizeof(B_UINT32);
		Adapter->bSyncUpRequestSent = TRUE;
	}
	else if(Adapter->LinkStatus == PHY_SYNC_ACHIVED && Adapter->AutoLinkUp)
	{
		pstLinkRequest=kmalloc(sizeof(LINK_REQUEST), GFP_ATOMIC);
		if(!pstLinkRequest)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, LINK_UP_MSG, DBG_LVL_ALL, "Can not allocate memory for Link request!");
			return;
		}
		memset(pstLinkRequest,0,sizeof(LINK_REQUEST));
		//LINK_UP_REQUEST
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, LINK_UP_MSG, DBG_LVL_ALL, "Requesting For LinkUp...");
		pstLinkRequest->szData[0]=LINK_UP_REQ_PAYLOAD;
		pstLinkRequest->szData[1]=LINK_NET_ENTRY;
		pstLinkRequest->Leader.Status=LINK_UP_CONTROL_REQ;
		pstLinkRequest->Leader.PLength=sizeof(B_UINT32);
	}
	if(pstLinkRequest)
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, LINK_UP_MSG, DBG_LVL_ALL, "Calling CopyBufferToControlPacket");
		CopyBufferToControlPacket(Adapter, pstLinkRequest);
		bcm_kfree(pstLinkRequest);
	}
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, LINK_UP_MSG, DBG_LVL_ALL, "LinkMessage <=====");	
	return;
}


/**********************************************************************
* Function    - StatisticsResponse()
* 
* Description - This function handles the Statistics response packet. 
* 
* Parameters  - Adapter	: Pointer to the Adapter structure.
* 			  - pvBuffer: Starting address of Statistic response data.
*
* Returns     - None.
************************************************************************/
VOID StatisticsResponse(PMINI_ADAPTER Adapter,PVOID pvBuffer)
{
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "%s====>",__FUNCTION__);
	Adapter->StatisticsPointer = ntohl(*(PULONG)pvBuffer);
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "Stats at %x", Adapter->StatisticsPointer);
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "%s <====",__FUNCTION__);
	return;
}


/**********************************************************************
* Function    - LinkControlResponseMessage()
* 
* Description - This function handles the Link response packets. 
* 
* Parameters  - Adapter	 : Pointer to the Adapter structure.
* 			  - pucBuffer: Starting address of Link response data.
*
* Returns     - None.
***********************************************************************/
VOID LinkControlResponseMessage(PMINI_ADAPTER Adapter,PUCHAR pucBuffer)
{
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_RX, RX_DPC, DBG_LVL_ALL, "=====>");
	
	if(*pucBuffer==LINK_UP_ACK)
	{
		switch(*(pucBuffer+1))
		{
			case PHY_SYNC_ACHIVED: //SYNCed UP
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0, "PHY_SYNC_ACHIVED");
				
				if(Adapter->LinkStatus == LINKUP_DONE)
			   	{
					beceem_protocol_reset(Adapter);
				}

				Adapter->usBestEffortQueueIndex=INVALID_QUEUE_INDEX ;
				Adapter->LinkStatus=PHY_SYNC_ACHIVED;
				
				if(Adapter->LEDInfo.led_thread_running & BCM_LED_THREAD_RUNNING_ACTIVELY)
				{
					Adapter->DriverState = NO_NETWORK_ENTRY;
					wake_up(&Adapter->LEDInfo.notify_led_event);
				}
				
				LinkMessage(Adapter);
				break;

			case LINKUP_DONE:
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_RX, RX_DPC, DBG_LVL_ALL, "LINKUP_DONE");
				Adapter->LinkStatus=LINKUP_DONE;
				Adapter->bPHSEnabled = *(pucBuffer+3);
               	Adapter->bETHCSEnabled = *(pucBuffer+4) & ETH_CS_MASK;
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0, "PHS Support Status Recieved In LinkUp Ack : %x \n",Adapter->bPHSEnabled);
				if((FALSE == Adapter->bShutStatus)&& 
					(FALSE == Adapter->IdleMode))
				{
					if(Adapter->LEDInfo.led_thread_running & BCM_LED_THREAD_RUNNING_ACTIVELY)
					{	
						Adapter->DriverState = NORMAL_OPERATION;
						wake_up(&Adapter->LEDInfo.notify_led_event);
					}
				}
				LinkMessage(Adapter);
				break;
			case WAIT_FOR_SYNC:
			
				/* 
				 * Driver to ignore the DREG_RECEIVED
				 * WiMAX Application should handle this Message
				 */
				//Adapter->liTimeSinceLastNetEntry = 0; 
				
				if(NULL != Adapter->dev)
				{
					netif_carrier_off(Adapter->dev);
					netif_stop_queue(Adapter->dev);
					
				}	
				Adapter->ucDsxConnBitMap = FALSE;
				Adapter->LinkUpStatus = FALSE;
				// Intentionally Continued to OUT_OF_COVERAGE
			case OUT_OF_COVERAGE:
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Link down or Wait for Sync received 0x%X\n",*(pucBuffer+2));
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Performing a context cleanup - dreg\n");
				
				Adapter->LinkStatus = 0;
				Adapter->usBestEffortQueueIndex=INVALID_QUEUE_INDEX ;
				Adapter->bTriedToWakeUpFromlowPowerMode = FALSE;
				Adapter->IdleMode = FALSE;

				if(Adapter->LEDInfo.led_thread_running & BCM_LED_THREAD_RUNNING_ACTIVELY)
				{
					Adapter->DriverState = NO_NETWORK_ENTRY;
					wake_up(&Adapter->LEDInfo.notify_led_event);
				}
				beceem_reset_queues(Adapter);
				break;
				
			case LINK_SHUTDOWN_REQ_FROM_FIRMWARE:
			case SHUTDOWN_REQ_FRM_FW_STANDBY_TIMER :
			case SHUTDOWN_REQ_FRM_FW_HIBERNATION_BUTTON_PRESS :	
			case COMPLETE_WAKE_UP_NOTIFICATION_FRM_FW:
			case HIBERNATION_WAKEUP:
			{
				HandleShutDownModeRequest(Adapter, pucBuffer);
			}
				break;
			default:
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0, "default case:LinkResponse %x",*(pucBuffer+1));
				break;
		}
	}
	else if(SET_MAC_ADDRESS_RESPONSE==*pucBuffer)
	{
		PUCHAR puMacAddr = (pucBuffer + 1);
		Adapter->LinkStatus=SYNC_UP_REQUEST;
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_RX, RX_DPC, DBG_LVL_ALL, "MAC address response, sending SYNC_UP");
		LinkMessage(Adapter);
		memcpy(Adapter->dev->dev_addr, puMacAddr, MAC_ADDRESS_SIZE);
	}

#ifndef BCM_SHM_INTERFACE
	else if(*pucBuffer == TYPE_FLASH_ACCESS &&
	       (*(pucBuffer+1) == SUBTYPE_GET_FLASH_SHM_INFO))
	{
		GetFlashShmInfo(Adapter,(PVOID) (pucBuffer+FLASH_SHM_PAYLOAD_START_OFFSET));
	}
#endif
	
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_RX, RX_DPC, DBG_LVL_ALL, "%s <=====",__FUNCTION__);
	return;
}

void SendIdleModeResponse(PMINI_ADAPTER Adapter)
{
	INT status = 0, NVMAccess = 0,lowPwrAbortMsg = 0;
	struct timeval tv;
	CONTROL_MESSAGE		stIdleResponse = {{0}};
	memset(&tv, 0, sizeof(tv));
	stIdleResponse.Leader.Status  = IDLE_MESSAGE;
	stIdleResponse.Leader.PLength = IDLE_MODE_PAYLOAD_LENGTH;
	stIdleResponse.szData[0] = GO_TO_IDLE_MODE_PAYLOAD;
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_RX, RX_DPC, DBG_LVL_ALL," ============>");

	/*********************************
	**down_trylock -
	** if [ semaphore is available ]
	**		 acquire semaphone and return value 0 ;
	**   else		
	**		 return non-zero value ;
	**
	***********************************/

	NVMAccess = down_trylock(&Adapter->NVMRdmWrmLock);

	lowPwrAbortMsg= down_trylock(&Adapter->LowPowerModeSync);

	
	if((NVMAccess || lowPwrAbortMsg || atomic_read(&Adapter->TotalPacketCount)) &&
		(Adapter->ulPowerSaveMode != DEVICE_POWERSAVE_MODE_AS_PROTOCOL_IDLE_MODE)  )
	{
		if(!NVMAccess)
			up(&Adapter->NVMRdmWrmLock);

		if(!lowPwrAbortMsg)
			up(&Adapter->LowPowerModeSync);

		stIdleResponse.szData[1] = TARGET_CAN_NOT_GO_TO_IDLE_MODE;//NACK- device access is going on.
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_RX, RX_DPC, DBG_LVL_ALL, "HOST IS NACKING Idle mode To F/W!!!!!!!!");
		Adapter->bPreparingForLowPowerMode = FALSE;
	}
	else
	{
		stIdleResponse.szData[1] = TARGET_CAN_GO_TO_IDLE_MODE; //2;//Idle ACK
		Adapter->StatisticsPointer = 0;
		
		/* Wait for the LED to TURN OFF before sending ACK response */
		if(Adapter->LEDInfo.led_thread_running & BCM_LED_THREAD_RUNNING_ACTIVELY)
		{
			INT iRetVal = 0;
			
			/* Wake the LED Thread with IDLEMODE_ENTER State */
			Adapter->DriverState = LOWPOWER_MODE_ENTER;
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_RX, RX_DPC, DBG_LVL_ALL,"LED Thread is Running..Hence Setting LED Event as IDLEMODE_ENTER jiffies:%ld",jiffies);;
			wake_up(&Adapter->LEDInfo.notify_led_event);

			/* Wait for 1 SEC for LED to OFF */
			iRetVal = wait_event_timeout(Adapter->LEDInfo.idleModeSyncEvent, \
				Adapter->LEDInfo.bIdle_led_off, msecs_to_jiffies(1000));
			
			
			/* If Timed Out to Sync IDLE MODE Enter, do IDLE mode Exit and Send NACK to device */
			if(iRetVal <= 0) 
			{
				stIdleResponse.szData[1] = TARGET_CAN_NOT_GO_TO_IDLE_MODE;//NACK- device access is going on.
				Adapter->DriverState = NORMAL_OPERATION;
				wake_up(&Adapter->LEDInfo.notify_led_event);
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_RX, RX_DPC, DBG_LVL_ALL, "NACKING Idle mode as time out happen from LED side!!!!!!!!");
			}
		}
		if(stIdleResponse.szData[1] == TARGET_CAN_GO_TO_IDLE_MODE)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_RX, RX_DPC, DBG_LVL_ALL,"ACKING IDLE MODE !!!!!!!!!");
			down(&Adapter->rdmwrmsync);  
			Adapter->bPreparingForLowPowerMode = TRUE;
			up(&Adapter->rdmwrmsync); 
#ifndef BCM_SHM_INTERFACE
			//Killing all URBS.
			if(Adapter->bDoSuspend == TRUE)
				Bcm_kill_all_URBs((PS_INTERFACE_ADAPTER)(Adapter->pvInterfaceAdapter));

#endif
		}
		else
		{
			Adapter->bPreparingForLowPowerMode = FALSE;
		}

		if(!NVMAccess)
			up(&Adapter->NVMRdmWrmLock);
		
		if(!lowPwrAbortMsg)
			up(&Adapter->LowPowerModeSync);

	}
	status = CopyBufferToControlPacket(Adapter,&stIdleResponse);
	if((status != STATUS_SUCCESS))
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"fail to send the Idle mode Request \n");
		Adapter->bPreparingForLowPowerMode = FALSE;
#ifndef BCM_SHM_INTERFACE
		StartInterruptUrb((PS_INTERFACE_ADAPTER)(Adapter->pvInterfaceAdapter));
#endif
	}
	do_gettimeofday(&tv);
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_RX, RX_DPC, DBG_LVL_ALL, "IdleMode Msg submitter to Q :%ld ms", tv.tv_sec *1000 + tv.tv_usec /1000);
			
}

/******************************************************************
* Function    - DumpPackInfo()
* 
* Description - This function dumps the all Queue(PackInfo[]) details. 
* 
* Parameters  - Adapter: Pointer to the Adapter structure.
*
* Returns     - None.
*******************************************************************/
VOID DumpPackInfo(PMINI_ADAPTER Adapter)
{
    UINT uiLoopIndex = 0;
	UINT uiIndex = 0;
	UINT uiClsfrIndex = 0;
	S_CLASSIFIER_RULE *pstClassifierEntry = NULL;

	BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"Total Packets at host: %x\n",atomic_read(&Adapter->TotalPacketCount));
	BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"Read Counter for Control Packet: %x\n",atomic_read(&Adapter->index_rd_txcntrlpkt));
	BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"Write Counter for Control Packet: %x\n",atomic_read(&Adapter->index_wr_txcntrlpkt));

	for(uiLoopIndex=0;uiLoopIndex<NO_OF_QUEUES;uiLoopIndex++)
	{
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"*********** Showing Details Of Queue %d***** ******",uiLoopIndex);
		if(FALSE == Adapter->PackInfo[uiLoopIndex].bValid)
		{
			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"bValid is FALSE for %X index\n",uiLoopIndex);
			continue;
		}

		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"	Dumping	SF Rule Entry For SFID %X \n",Adapter->PackInfo[uiLoopIndex].ulSFID);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"	ucDirection %X \n",Adapter->PackInfo[uiLoopIndex].ucDirection);
		if(Adapter->PackInfo[uiLoopIndex].ucIpVersion == IPV6)
		{
			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"Ipv6 Service Flow \n");
		}
		else
		{
			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"Ipv4 Service Flow \n");
		}
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"	SF Traffic Priority %X \n",Adapter->PackInfo[uiLoopIndex].u8TrafficPriority);

		for(uiClsfrIndex=0;uiClsfrIndex<MAX_CLASSIFIERS;uiClsfrIndex++)
		{
			pstClassifierEntry = &Adapter->astClassifierTable[uiClsfrIndex];
			if(!pstClassifierEntry->bUsed)
				continue;

			if(pstClassifierEntry->ulSFID != Adapter->PackInfo[uiLoopIndex].ulSFID)
				continue;

			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tDumping Classifier Rule Entry For Index: %X Classifier Rule ID : %X\n",uiClsfrIndex,pstClassifierEntry->uiClassifierRuleIndex);
			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tDumping Classifier Rule Entry For Index: %X usVCID_Value : %X\n",uiClsfrIndex,pstClassifierEntry->usVCID_Value);
			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tDumping Classifier Rule Entry For Index: %X bProtocolValid : %X\n",uiClsfrIndex,pstClassifierEntry->bProtocolValid);
			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tDumping	Classifier Rule Entry For Index: %X bTOSValid : %X\n",uiClsfrIndex,pstClassifierEntry->bTOSValid);
			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tDumping	Classifier Rule Entry For Index: %X bDestIpValid : %X\n",uiClsfrIndex,pstClassifierEntry->bDestIpValid);
			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tDumping	Classifier Rule Entry For Index: %X bSrcIpValid : %X\n",uiClsfrIndex,pstClassifierEntry->bSrcIpValid);

			 
			for(uiIndex=0;uiIndex<MAX_PORT_RANGE;uiIndex++)
			{
				BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tusSrcPortRangeLo:%X\n",pstClassifierEntry->usSrcPortRangeLo[uiIndex]);
				BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tusSrcPortRangeHi:%X\n",pstClassifierEntry->usSrcPortRangeHi[uiIndex]);
				BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tusDestPortRangeLo:%X\n",pstClassifierEntry->usDestPortRangeLo[uiIndex]);
				BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tusDestPortRangeHi:%X\n",pstClassifierEntry->usDestPortRangeHi[uiIndex]);
			}

			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL," \tucIPSourceAddressLength : 0x%x\n",pstClassifierEntry->ucIPSourceAddressLength);
			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tucIPDestinationAddressLength : 0x%x\n",pstClassifierEntry->ucIPDestinationAddressLength);
			for(uiIndex=0;uiIndex<pstClassifierEntry->ucIPSourceAddressLength;uiIndex++)
			{
				if(Adapter->PackInfo[uiLoopIndex].ucIpVersion == IPV6)
				{
					BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tIpv6 ulSrcIpAddr :\n");
					DumpIpv6Address(pstClassifierEntry->stSrcIpAddress.ulIpv6Addr);
					BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tIpv6 ulSrcIpMask :\n");
					DumpIpv6Address(pstClassifierEntry->stSrcIpAddress.ulIpv6Mask);
				}
				else
				{
				BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tulSrcIpAddr:%X\n",pstClassifierEntry->stSrcIpAddress.ulIpv4Addr[uiIndex]);
				BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tulSrcIpMask:%X\n",pstClassifierEntry->stSrcIpAddress.ulIpv4Mask[uiIndex]);
				}
			}
			for(uiIndex=0;uiIndex<pstClassifierEntry->ucIPDestinationAddressLength;uiIndex++)
			{
				if(Adapter->PackInfo[uiLoopIndex].ucIpVersion == IPV6)
				{
					BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tIpv6 ulDestIpAddr :\n");
					DumpIpv6Address(pstClassifierEntry->stDestIpAddress.ulIpv6Addr);
					BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tIpv6 ulDestIpMask :\n");
					DumpIpv6Address(pstClassifierEntry->stDestIpAddress.ulIpv6Mask);

				}
				else
				{
					BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tulDestIpAddr:%X\n",pstClassifierEntry->stDestIpAddress.ulIpv4Addr[uiIndex]);
					BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tulDestIpMask:%X\n",pstClassifierEntry->stDestIpAddress.ulIpv4Mask[uiIndex]);
				}
			}
			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tucProtocol:0x%X\n",pstClassifierEntry->ucProtocol[0]);
			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"\tu8ClassifierRulePriority:%X\n",pstClassifierEntry->u8ClassifierRulePriority);

			
		}
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"ulSFID:%X\n",Adapter->PackInfo[uiLoopIndex].ulSFID);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"usVCID_Value:%X\n",Adapter->PackInfo[uiLoopIndex].usVCID_Value);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"PhsEnabled: 0x%X\n",Adapter->PackInfo[uiLoopIndex].bHeaderSuppressionEnabled);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"uiThreshold:%X\n",Adapter->PackInfo[uiLoopIndex].uiThreshold);


		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"bValid:%X\n",Adapter->PackInfo[uiLoopIndex].bValid);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"bActive:%X\n",Adapter->PackInfo[uiLoopIndex].bActive);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"ActivateReqSent: %x", Adapter->PackInfo[uiLoopIndex].bActivateRequestSent);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"u8QueueType:%X\n",Adapter->PackInfo[uiLoopIndex].u8QueueType);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"uiMaxBucketSize:%X\n",Adapter->PackInfo[uiLoopIndex].uiMaxBucketSize);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"uiPerSFTxResourceCount:%X\n",atomic_read(&Adapter->PackInfo[uiLoopIndex].uiPerSFTxResourceCount));
		//DumpDebug(DUMP_INFO,("				bCSSupport:%X\n",Adapter->PackInfo[uiLoopIndex].bCSSupport));
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"CurrQueueDepthOnTarget: %x\n", Adapter->PackInfo[uiLoopIndex].uiCurrentQueueDepthOnTarget);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"uiCurrentBytesOnHost:%X\n",Adapter->PackInfo[uiLoopIndex].uiCurrentBytesOnHost);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"uiCurrentPacketsOnHost:%X\n",Adapter->PackInfo[uiLoopIndex].uiCurrentPacketsOnHost);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"uiDroppedCountBytes:%X\n",Adapter->PackInfo[uiLoopIndex].uiDroppedCountBytes);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"uiDroppedCountPackets:%X\n",Adapter->PackInfo[uiLoopIndex].uiDroppedCountPackets);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"uiSentBytes:%X\n",Adapter->PackInfo[uiLoopIndex].uiSentBytes);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"uiSentPackets:%X\n",Adapter->PackInfo[uiLoopIndex].uiSentPackets);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"uiCurrentDrainRate:%X\n",Adapter->PackInfo[uiLoopIndex].uiCurrentDrainRate);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"uiThisPeriodSentBytes:%X\n",Adapter->PackInfo[uiLoopIndex].uiThisPeriodSentBytes);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"liDrainCalculated:%llX\n",Adapter->PackInfo[uiLoopIndex].liDrainCalculated);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"uiCurrentTokenCount:%X\n",Adapter->PackInfo[uiLoopIndex].uiCurrentTokenCount);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"liLastUpdateTokenAt:%llX\n",Adapter->PackInfo[uiLoopIndex].liLastUpdateTokenAt);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"uiMaxAllowedRate:%X\n",Adapter->PackInfo[uiLoopIndex].uiMaxAllowedRate);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"uiPendedLast:%X\n",Adapter->PackInfo[uiLoopIndex].uiPendedLast);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"NumOfPacketsSent:%X\n",Adapter->PackInfo[uiLoopIndex].NumOfPacketsSent);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "Direction: %x\n", Adapter->PackInfo[uiLoopIndex].ucDirection);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "CID: %x\n", Adapter->PackInfo[uiLoopIndex].usCID);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "ProtocolValid: %x\n", Adapter->PackInfo[uiLoopIndex].bProtocolValid);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "TOSValid: %x\n", Adapter->PackInfo[uiLoopIndex].bTOSValid);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "DestIpValid: %x\n", Adapter->PackInfo[uiLoopIndex].bDestIpValid);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "SrcIpValid: %x\n", Adapter->PackInfo[uiLoopIndex].bSrcIpValid);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "ActiveSet: %x\n", Adapter->PackInfo[uiLoopIndex].bActiveSet);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "AdmittedSet: %x\n", Adapter->PackInfo[uiLoopIndex].bAdmittedSet);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "AuthzSet: %x\n", Adapter->PackInfo[uiLoopIndex].bAuthorizedSet);
		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "ClassifyPrority: %x\n", Adapter->PackInfo[uiLoopIndex].bClassifierPriority);
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "uiMaxLatency: %x\n",Adapter->PackInfo[uiLoopIndex].uiMaxLatency);
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "ServiceClassName: %x %x %x %x\n",Adapter->PackInfo[uiLoopIndex].ucServiceClassName[0],Adapter->PackInfo[uiLoopIndex].ucServiceClassName[1],Adapter->PackInfo[uiLoopIndex].ucServiceClassName[2],Adapter->PackInfo[uiLoopIndex].ucServiceClassName[3]);
//	BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "bHeaderSuppressionEnabled :%X\n", Adapter->PackInfo[uiLoopIndex].bHeaderSuppressionEnabled);
//		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "uiTotalTxBytes:%X\n", Adapter->PackInfo[uiLoopIndex].uiTotalTxBytes);
//		BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL, "uiTotalRxBytes:%X\n", Adapter->PackInfo[uiLoopIndex].uiTotalRxBytes);
//		DumpDebug(DUMP_INFO,("				uiRanOutOfResCount:%X\n",Adapter->PackInfo[uiLoopIndex].uiRanOutOfResCount));
	}
	
	for(uiLoopIndex = 0 ; uiLoopIndex < MIBS_MAX_HIST_ENTRIES ; uiLoopIndex++)
			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"Adapter->aRxPktSizeHist[%x] = %x\n",uiLoopIndex,Adapter->aRxPktSizeHist[uiLoopIndex]);
		
	for(uiLoopIndex = 0 ; uiLoopIndex < MIBS_MAX_HIST_ENTRIES ; uiLoopIndex++)
			BCM_DEBUG_PRINT (Adapter, DBG_TYPE_OTHERS, DUMP_INFO, DBG_LVL_ALL,"Adapter->aTxPktSizeHist[%x] = %x\n",uiLoopIndex,Adapter->aTxPktSizeHist[uiLoopIndex]);



	return;

	
}

#ifndef BCM_SHM_INTERFACE

INT updateWriteProtectedRegister(PMINI_ADAPTER ps_adapter, UINT Reg, UINT value)
{
	INT count = 0, retval = STATUS_SUCCESS;
	UINT CurrValue;
	UINT ToWriteVal = 0;
	
	do
	{
		retval = rdmalt(ps_adapter,Reg,&CurrValue,sizeof(CurrValue));
		if( retval < 0) 
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"Read Reg: 0%x failed with status :%d",Reg, retval);
			goto err_exit;
		}

		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"Value read from Reg: 0x%x is 0x%x\n ",Reg, CurrValue);

		if(value == CurrValue )
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"Register 0x%x restored successfully, with value 0x%x !!\n",Reg, CurrValue );
			break;
		}
		

		retval = rdmalt(ps_adapter,Reg, &CurrValue, 4);
		if( retval < 0) 
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"Read Reg: 0%x failed with status :%d",Reg, retval);
			goto err_exit;
		}
		
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"Value to be written to Reg: 0x%x is 0x%x \n",Reg, value);

		ToWriteVal = value;
		
		retval = wrmalt(ps_adapter,Reg,&ToWriteVal, sizeof(ToWriteVal));
		if( retval < 0) 
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"Write Reg: 0x%x failed with status :%d",Reg, retval);
			goto err_exit;
		}
		
		count++;
	}	while( count < MAX_TRY_RESTORE_SYS_CFG );

err_exit:
	
	BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"Tried to restore Reg: 0x%x, %d times\n ",Reg, count);

	if(count >= MAX_TRY_RESTORE_SYS_CFG)
		return STATUS_FAILURE;
	
	return retval;
}

#endif
//-----------------------------------------------------------------------------
// Procedure:	LowPowerModeWakeup
//
// Description: weak up device from Idle/Shut-Down
//
// Arguments:
//		Adapter      - ptr to Adapter object instance
//		AbortReason - reason of abort, which decide which pattern to write...
//
// Returns:
//		OSAL_STATUS_SUCCESS - if Wake-up successful.
//		<FAILURE>			- if failed.
//-----------------------------------------------------------------------------

INT LowPowerModeWakeup(PMINI_ADAPTER ps_adapter, UINT AbortReason)
{
	INT retval = STATUS_SUCCESS;

	down(&ps_adapter->LowPowerModeSync);
	
	//check idle mode and shutdown condition in case of Request...
	if(!( (ps_adapter->IdleMode == TRUE) || 
		(ps_adapter->bShutStatus == TRUE) ||
		(ps_adapter->bPreparingForLowPowerMode == TRUE)) )
	{
		BCM_DEBUG_PRINT (ps_adapter, DBG_TYPE_OTHERS, OSAL_DBG, DBG_LVL_ALL,"Device in not in low power mode... returning\n");
		up(&ps_adapter->LowPowerModeSync);
		retval = STATUS_SUCCESS;
		goto err_exit;
	}
	
	retval = wait_event_interruptible_timeout(ps_adapter->lowpower_mode_wait_queue,
											!ps_adapter->bPreparingForLowPowerMode, 
											(1 * HZ));
	if(retval == -ERESTARTSYS)
	{
		up(&ps_adapter->LowPowerModeSync);
		goto err_exit;
	}
	
	if(ps_adapter->bPreparingForLowPowerMode)
	{
		BCM_DEBUG_PRINT (ps_adapter, DBG_TYPE_PRINTK, 0, 0, "Preparing Idle Mode is still True - Hence Rejecting control message\n");
		up(&ps_adapter->LowPowerModeSync);
		retval = STATUS_FAILURE ;
		goto err_exit;
	}

	up(&ps_adapter->LowPowerModeSync);
	
	if(ps_adapter->bShutStatus == TRUE || ps_adapter->IdleMode == TRUE)
	{		
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK,0,0, "Device WakeUp............\n");
		if(ps_adapter->bPreparingForLowPowerMode == FALSE)
		{
			if(ps_adapter->bShutStatus == TRUE)
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK,0,0, "Shutdown Mode !!\n");
				ps_adapter->usIdleModePattern = ABORT_SHUTDOWN_MODE; 
			}
			
			else if(ps_adapter->IdleMode == TRUE)
			{
				if(AbortReason == ABORT_CHIP_RESET)
					ps_adapter->usIdleModePattern = ABORT_IDLE_SYNCDOWN;
				
				else if(AbortReason == ABORT_NVM_ACCESS)
					ps_adapter->usIdleModePattern = ABORT_IDLE_MODE;
				
				else
					ps_adapter->usIdleModePattern = ABORT_IDLE_MODE;

				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK,0,0, "Aborting Idle Mode with pattern %x!!\n", ps_adapter->usIdleModePattern);

			}
			else
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK,0,0, "Invalid Mode !!\n");
				retval = STATUS_FAILURE;
				goto err_exit;
			}
			
			ps_adapter->bWakeUpDevice = TRUE;
			wake_up(&ps_adapter->process_rx_cntrlpkt); 
		}

		retval = wait_event_interruptible_timeout(ps_adapter->lowpower_mode_wait_queue,
												!(ps_adapter->bShutStatus || ps_adapter->IdleMode), (5 * HZ));
		 
		if(retval == -ERESTARTSYS)
		{
			goto err_exit;
		}
		if(ps_adapter->bShutStatus || ps_adapter->IdleMode)
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0, "Wake up Failed From Low Power Mode - No Wake Up Received\n");
			retval = STATUS_FAILURE;
			goto err_exit;
		}

		retval = STATUS_SUCCESS;
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0, "wake up successfully .....\n");
	}

err_exit:
	return retval;
}

#ifndef BCM_SHM_INTERFACE

VOID support_gpio(PMINI_ADAPTER ps_adapter )
{
	INT gpio	= SUPERCAP_PWR_GPIO_NUM;
	INT retval 	= 0;
	INT value 	= 0;
	if( (BCSM352_2AB == ps_adapter->chip_id)||
		(BCSM352_2BC == ps_adapter->chip_id))
	{
		/* Set the SUPERCAP_PWR_GPIO_NUM */
		if(gpio >= 32) 
		{
			gpio -= 32;
			value = (1<<gpio);
			retval = wrmalt(ps_adapter, GPIO_OUTPUT2_CLEAR_REG, &value, 4);
			if( retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"wrm Reg: GPIO_OUTPUT2_CLEAR_REG failed with status :%d",retval);
				goto exit;
			}
			
			retval = rdmalt(ps_adapter,GPIO_MODE2_REG, &value, sizeof(value));
			if( retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"rdm Reg: GPIO_MODE2_REG failed with status :%d",retval);
				goto exit;
			}

			value |= (1<<gpio);
			retval = wrmalt(ps_adapter, GPIO_MODE2_REG, &value, 4);
			if( retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"wrm Reg: GPIO_MODE2_REG failed with status :%d",retval);
				goto exit;
			}

			value = (1<<gpio);
			retval = wrmalt(ps_adapter, GPIO_OUTPUT2_SET_REG, &value, 4);
			if( retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"wrm Reg: GPIO_OUTPUT2_SET_REG failed with status :%d",retval);
				goto exit;
			}
		} 
		else 
		{
			value = 1<<gpio;
			retval = wrmalt(ps_adapter, BCM_GPIO_OUTPUT_CLR_REG, &value, 4);
			if( retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"wrm Reg: BCM_GPIO_OUTPUT_CLR_REG failed with status :%d",retval);
				goto exit;
			}

			retval = rdmalt(ps_adapter,GPIO_MODE_REGISTER, &value, sizeof(value));
			if( retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"rdm Reg: GPIO_MODE_REGISTER failed with status :%d",retval);
				goto exit;
			}

			value |= (1<<gpio);
			retval = wrmalt(ps_adapter, GPIO_MODE_REGISTER, &value, 4);
			if( retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"wrm Reg: GPIO_MODE_REGISTER failed with status :%d",retval);
				goto exit;
			}

			value = 1<<gpio;
			retval = wrmalt(ps_adapter,BCM_GPIO_OUTPUT_SET_REG, &value, 4);
			if( retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"wrm Reg: GPIO_OUTPUT2_SET_REG failed with status :%d",retval);
				goto exit;
			}
			
		}		
	   
	}
exit: 
	return ;
}

int do_scsi_handshake(int iterations, PMINI_ADAPTER ps_adapter )
{
	int value = 0;
	int count = 0;
	int retval = STATUS_SUCCESS;

	retval = rdmalt(ps_adapter, HOST_SCSI_HANDSHAKE_LOC, &value, sizeof(value));
	if(retval < 0) 
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"read HOST_SCSI_HANDSHAKE_LOC failed with status :%d",retval);
		goto err_exit;
	}
	BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"InterfaceReset() : Wrote Host pattern!! initial pattern value %x\n",value);

	value = HOST_HANDSHAKE_PATTERN;
	retval = wrmalt(ps_adapter, HOST_SCSI_HANDSHAKE_LOC, &value, sizeof(value));
	if(retval < 0) 
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"write HOST_SCSI_HANDSHAKE_LOC failed with status :%d",retval);
		goto err_exit;
	}
	
	BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"InterfaceReset() : Sleeping for SCSI to clear!!\n");
	
	value = 0;
	do
	{
		retval = rdmalt(ps_adapter, HOST_SCSI_HANDSHAKE_LOC, &value, sizeof(value));
		if(retval < 0) 
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"read HOST_SCSI_HANDSHAKE_LOC failed with status :%d",retval);
			goto err_exit;
		}
		msleep(1);
		count++;	
	}
	while(value != SCSI_HANDSHAKE_PATTERN && count < iterations);
	
	BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"Polled the SCSI handshake location for %d msecs\n",count);
	
	if ( value == SCSI_HANDSHAKE_PATTERN )
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"InterfaceReset() : SCSI handshake successful!!!\n");
				
	} 
	else 
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"InterfaceReset() : SCSI handshake failed. Old bootloader perhaps or interface reset after miniport initialize, going ahead nevertheless to halt MIPS!!\n");
	}
err_exit:
	value = 0;
	retval = wrmalt(ps_adapter, HOST_SCSI_HANDSHAKE_LOC, &value, sizeof(value)); //reset the location
	if(retval < 0) 
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"write HOST_SCSI_HANDSHAKE_LOC failed with status :%d",retval);
	}
	return retval;
}
#endif

__inline int reset_card_proc(PMINI_ADAPTER ps_adapter)
{
	int retval = STATUS_SUCCESS;

#ifndef BCM_SHM_INTERFACE
	PS_INTERFACE_ADAPTER psIntfAdapter = NULL;
	unsigned int value = 0, uiResetValue = 0 ;
	psIntfAdapter = ((PS_INTERFACE_ADAPTER)(ps_adapter->pvInterfaceAdapter)) ;
#endif

	if((ps_adapter->bShutStatus == TRUE || ps_adapter->IdleMode == TRUE) 
			&& (ps_adapter->device_removed == FALSE) )
	{		
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK,0,0, "Device WakeUp............\n");
		if(ps_adapter->bTriedToWakeUpFromlowPowerMode == FALSE)
		{
			if(ps_adapter->bShutStatus == TRUE)
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK,0,0, "Shutdown Mode !!\n");
				ps_adapter->usIdleModePattern = ABORT_SHUTDOWN_MODE; 
			}
			else if(ps_adapter->IdleMode== TRUE)
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK,0,0, "Idle Mode !!\n");
				ps_adapter->usIdleModePattern = ABORT_IDLE_SYNCDOWN;
			}
			else
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK,0,0, "Invalid Mode !!\n");
				retval = STATUS_FAILURE;
				goto err_exit;
			}
			
			ps_adapter->bWakeUpDevice = TRUE;
			wake_up(&ps_adapter->process_rx_cntrlpkt); 
		}

		retval = wait_event_interruptible_timeout(ps_adapter->lowpower_mode_wait_queue,
												!(ps_adapter->bShutStatus || ps_adapter->IdleMode), (5 * HZ));
		 
		if(retval == -ERESTARTSYS)
		{
			goto err_exit;
		}
		if(ps_adapter->bShutStatus || ps_adapter->IdleMode)
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0, "Wake up Failed From Low Power Mode - No Wake Up Received\n");
			retval = STATUS_FAILURE;
			goto err_exit;
		}

		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0, "wake up successfully .....\n");
	}

#ifndef BCM_SHM_INTERFACE

	ps_adapter->bDDRInitDone = FALSE;

	if((ps_adapter->bFlashBoot == FALSE) && 
		((ps_adapter->chip_id >= T3LPB) && (ps_adapter->chip_id < BCS350)))
	{
		//SYS_CFG register is write protected hence for modifying this reg value, it should be read twice before
		retval = rdmalt(ps_adapter,SYS_CFG, &value, sizeof(value)); 
		if( retval < 0) 
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"read SYS_CFG failed with status :%d ",retval);
			goto err_exit;
		}
		
		//making bit[6...5] same as was before f/w download. this setting force the h/w to 
		//re-populated the SP RAM area with the string descriptor . 
		value |= (ps_adapter->syscfgBefFwDld & 0x00000060);
		retval = updateWriteProtectedRegister(ps_adapter,SYS_CFG, value);
		if( retval) 
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"write SYS_CFG failed with status :%d",retval);
			goto err_exit;
		}
	}
	
	if( ps_adapter->bFlashBoot &&
		ps_adapter->chip_id >= BCS350)
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"To support the scsi suspend change, in some cases expected to give error\n");
		do_scsi_handshake(50, ps_adapter); // to ensure that SCSI doesn't runs while SYS_CFG is updated. 

		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0, "InterfaceReset() : Restoring SYS_CFG \n");
		retval = rdmalt(ps_adapter,SYS_CFG1,&value,4);
		if( retval < 0) 
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"read SYS_CFG1 failed with status :%d \n",retval);
			goto err_exit;
		}
		
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"Value read from SYS_CFG1 %x \n",value);
		value |= SYS_CFG_WRITE_SIG;
		retval = updateWriteProtectedRegister(ps_adapter,SYS_CFG, value);
		if(retval)
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"write SYS_CFG failed with status :%d",retval);
			goto err_exit;
		}
	}
	psIntfAdapter->psAdapter->StopAllXaction = TRUE ;
	//killing all submitted URBs.
	Bcm_kill_all_URBs(psIntfAdapter);

	/* Reset the UMA-B Device */
	if(ps_adapter->chip_id >= T3LPB)
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0, "Reseting UMA-B \n");
		
		retval = usb_reset_device(psIntfAdapter->udev);
		if(retval != STATUS_SUCCESS)
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0, "Reset failed with ret value :%d", retval);
			goto err_exit;
		}

		psIntfAdapter->psAdapter->StopAllXaction = FALSE ;
		
		if (ps_adapter->chip_id == BCS220_2 || 
			ps_adapter->chip_id == BCS220_2BC ||
			ps_adapter->chip_id == BCS250_BC ||
			ps_adapter->chip_id == BCS220_3) 
		{
			retval = rdmalt(ps_adapter,HPM_CONFIG_LDO145, &value, sizeof(value));
			if( retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"read HPM_CONFIG_LDO145 failed with status :%d",retval);
				goto err_exit;
			}
			//setting 0th bit
			value |= (1<<0);
			retval = wrmalt(ps_adapter, HPM_CONFIG_LDO145, &value, sizeof(value));
			if( retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"write HPM_CONFIG_LDO145 failed with status :%d",retval);
				goto err_exit;
			}
		}
		
	}
	else 
	{	
		retval = rdmalt(ps_adapter,0x0f007018, &value, sizeof(value));
		if( retval < 0) {
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"read failed with status :%d",retval);
			goto err_exit;
		}
		value&=(~(1<<16));
		retval= wrmalt(ps_adapter, 0x0f007018, &value, sizeof(value)) ;
		if( retval < 0) {
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"write failed with status :%d",retval);
			goto err_exit;
		}
	
		// Toggling the GPIO 8, 9
		value = 0;
		retval = wrmalt(ps_adapter, GPIO_OUTPUT_REGISTER, &value, sizeof(value));
		if(retval < 0) {
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"write failed with status :%d",retval);
			goto err_exit;
		}
		value = 0x300;
		retval = wrmalt(ps_adapter, GPIO_MODE_REGISTER, &value, sizeof(value)) ;
		if(retval < 0) {
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"write failed with status :%d",retval);
			goto err_exit;
		}
		mdelay(50);
	}
	
	ps_adapter->fpFlashBulkRead  = BeceemFlashBulkRead;
	ps_adapter->fpFlashBulkWrite = BeceemFlashBulkWrite;
	ps_adapter->bFlashSHMEnabled = FALSE;
	
	//ps_adapter->uiFirstInterrupt = false;
		
	if(ps_adapter->bFlashBoot)
	{

		do_scsi_handshake(750,ps_adapter);
	
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"Issue Device Processor Halt\n");
		if(ps_adapter->chip_id >= BCS350)
		{
		//Halt the MIPS.
			retval = rdmalt(ps_adapter,BCS35X_MIPS_CONFIG_REGISTER,&uiResetValue, sizeof(uiResetValue));
			if(retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"read BCS35X_MIPS_CONFIG_REGISTER failed with status :%d",retval);
				goto err_exit;
			}
			retval = rdmalt(ps_adapter,BCS35X_MIPS_CONFIG_REGISTER,&uiResetValue, sizeof(uiResetValue));
			if(retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"read BCS35X_MIPS_CONFIG_REGISTER failed with status :%d",retval);
				goto err_exit;
			}
			uiResetValue |= (0x1<<8)| (0x1<<15);
			retval = wrmalt(ps_adapter,BCS35X_MIPS_CONFIG_REGISTER,&uiResetValue, sizeof(uiResetValue));
			if(retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"write BCS35X_MIPS_CONFIG_REGISTER failed with status :%d",retval);
				goto err_exit;
			}
		}
		else
		{
			//In flash boot mode MIPS state register has reverse polarity.
			// So just or with setting bit 30.
			//Make the MIPS in Reset state.
			retval = rdmalt(ps_adapter, CLOCK_RESET_CNTRL_REG_1, &uiResetValue, sizeof(uiResetValue));
			if(retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"read CLOCK_RESET_CNTRL_REG_1 failed with status :%d",retval);
				goto err_exit;
			}
			uiResetValue |=(1<<30);
			retval = wrmalt(ps_adapter, CLOCK_RESET_CNTRL_REG_1, &uiResetValue, sizeof(uiResetValue));
			if(retval < 0) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"write CLOCK_RESET_CNTRL_REG_1 failed with status :%d",retval);
				goto err_exit;
			}
		}
	}

	if(ps_adapter->chip_id == T3LPB)
	{
		uiResetValue = 0;
		//
		// WA for SYSConfig Issue.
		// Read SYSCFG Twice to make it writable.
		//
		retval = rdmalt(ps_adapter, SYS_CFG, &uiResetValue, sizeof(uiResetValue));
		if(retval < 0) 
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"read SYS_CFG failed with status :%d",retval);
			goto err_exit;
		}
		if(uiResetValue & (1<<4))
		{			
			uiResetValue &= (~(1<<4));
			
			retval = updateWriteProtectedRegister(ps_adapter,SYS_CFG, uiResetValue);
			if(retval) 
			{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"write SYS_CFG failed with status :%d",retval);
				goto err_exit;
			}
		}
			
	}	
	uiResetValue = 0;	
	retval = wrmalt(ps_adapter, 0x0f01186c, &uiResetValue, sizeof(uiResetValue));
	if(retval < 0) 
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"write failed with status :%d",retval);
		goto err_exit;
	}
	
	support_gpio(ps_adapter);
	
#endif
err_exit :
	ps_adapter->StopAllXaction = FALSE ;
	return retval;
}

#ifndef BCM_SHM_INTERFACE
__inline int run_card_proc(PMINI_ADAPTER ps_adapter )
{
	unsigned int value=0;
	int retval = STATUS_SUCCESS;

	if(ps_adapter->chip_id >= BCS350)
	{
		retval = rdmalt(ps_adapter, BCS35X_MIPS_CONFIG_REGISTER, &value, sizeof(value));
		if(retval < 0) 
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"read BCS35X_MIPS_CONFIG_REGISTER failed with status :%d",retval);
			return STATUS_FAILURE;
		}
		
		value = value & 0xFFFF7EFF;
		retval = updateWriteProtectedRegister(ps_adapter,BCS35X_MIPS_CONFIG_REGISTER, value);
		if(retval) 
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"write BCS35X_MIPS_CONFIG_REGISTER failed with status :%d",retval);
			return STATUS_FAILURE;
		}
		
	}
	else
	{

		if(rdmalt(ps_adapter, CLOCK_RESET_CNTRL_REG_1, &value, sizeof(value)) < 0) {
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"%s:%d\n", __FUNCTION__, __LINE__);
			return STATUS_FAILURE;
		}

		if(ps_adapter->bFlashBoot)
		{
				
			value&=(~(1<<30));
		}
		else
		{
			value |=(1<<30);
		}	

		if(wrmalt(ps_adapter, CLOCK_RESET_CNTRL_REG_1, &value, sizeof(value)) < 0) {
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL,"%s:%d\n", __FUNCTION__, __LINE__);
			return STATUS_FAILURE;
		}
	}	
	return STATUS_SUCCESS;
}
#endif

int InitCardAndDownloadFirmware(PMINI_ADAPTER ps_adapter)
{

	UINT status	= STATUS_SUCCESS;
	UINT value	= 0;
#ifndef BCM_SHM_INTERFACE
	INT retval = 0;
#endif

#ifdef BCM_SHM_INTERFACE
	unsigned char *pConfigFileAddr = (unsigned char *)CPE_MACXVI_CFG_ADDR;
#endif
	/* 
 	 * Create the threads first and then download the 
 	 * Firm/DDR Settings.. 
 	 */

	if((status = create_worker_threads(ps_adapter))<0)
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Cannot create thread");
		return status;
	}
	/*
 	 * For Downloading the Firm, parse the cfg file first. 
 	 */
	status = bcm_parse_target_params (ps_adapter);
	if(status){
		return status;	
	}
	
#ifndef BCM_SHM_INTERFACE
	if(ps_adapter->chip_id >= BCS350)
	{
		 rdmalt(ps_adapter,BCS35X_SYS_CFG_LATCH, &value, sizeof(value));
		//
		// check the init_mode (Bits8:5) and see if it is flash boot.
		//
		if( ((value>>5) & 0xF) == BCS35X_HOST_ASST_BOOT_MODE ||
			((value>>5) & 0xF) == BCS35X_I2C_EEPROM_MODE	  ||
			((value>>5) & 0xF) == BCS35X_SPI_EEPROM_BOOT )
		{
			ps_adapter->bFlashBoot = FALSE;
			BCM_DEBUG_PRINT (ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "It's NOT flash boot\n");
		}
		else
		{
			BCM_DEBUG_PRINT (ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "It's flash boot\n");
			ps_adapter->bFlashBoot = TRUE;
		}
	}
	else if(ps_adapter->chip_id >= T3LPB)
	{

		rdmalt(ps_adapter, SYS_CFG, &value, sizeof (value));
	
		ps_adapter->syscfgBefFwDld = value ;
		if((value & 0x60)== 0)
		{
			ps_adapter->bFlashBoot = TRUE;
		}

	}


	reset_card_proc(ps_adapter);

	//Initializing the NVM. 
	BcmInitNVM(ps_adapter);
	status = ddr_init(ps_adapter);
	if(status)
	{
		BCM_DEBUG_PRINT (ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "ddr_init Failed\n");
		return status;
	}
	
	/* Download cfg file */
	status = buffDnldVerify(ps_adapter, 
							 (PUCHAR)ps_adapter->pstargetparams, 
							 sizeof(STARGETPARAMS),
							 CONFIG_BEGIN_ADDR);
	if(status)
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Error downloading CFG file");
		goto OUT;
	}
	BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "CFG file downloaded");

	if(register_networkdev(ps_adapter))
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Register Netdevice failed. Cleanup needs to be performed.");
		return -EIO;
	}

	if(FALSE == ps_adapter->AutoFirmDld)
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "AutoFirmDld Disabled in CFG File..\n");
		//If Auto f/w download is disable, register the control interface, 
		//register the control interface after the mailbox. 
		if(register_control_device_interface(ps_adapter) < 0)
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Register Control Device failed. Cleanup needs to be performed.");
			return -EIO;
		}

		return STATUS_SUCCESS;
	}

	/*
     * Do the LED Settings here. It will be used by the Firmware Download 
     * Thread.
     */
	
	/*  
     * 1. If the LED Settings fails, do not stop and do the Firmware download.
     * 2. This init would happend only if the cfg file is present, else
     *    call from the ioctl context. 
     */

	status = InitLedSettings (ps_adapter);

	if(status)
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"INIT LED FAILED\n");
		return status;
	}
	if(ps_adapter->LEDInfo.led_thread_running & BCM_LED_THREAD_RUNNING_ACTIVELY)
	{
		ps_adapter->DriverState = DRIVER_INIT;
		wake_up(&ps_adapter->LEDInfo.notify_led_event);
	}

	if(ps_adapter->LEDInfo.led_thread_running & BCM_LED_THREAD_RUNNING_ACTIVELY)
	{
		ps_adapter->DriverState = FW_DOWNLOAD;
		wake_up(&ps_adapter->LEDInfo.notify_led_event);
	}

	value = 0;
	wrmalt(ps_adapter, EEPROM_CAL_DATA_INTERNAL_LOC - 4, &value, sizeof(value));
	wrmalt(ps_adapter, EEPROM_CAL_DATA_INTERNAL_LOC - 8, &value, sizeof(value));
	
	if(ps_adapter->eNVMType == NVM_FLASH)
	{
		status = PropagateCalParamsFromFlashToMemory(ps_adapter);
		if(status)
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL," Propogation of Cal param failed .." );
			goto OUT;
		}
	}
#if 0	
	else if(psAdapter->eNVMType == NVM_EEPROM)
	{
		PropagateCalParamsFromEEPROMToMemory();
	}
#endif	
/*
	 * Override SYS_CFG register in flashboot mode
	 * and chipid is >= 350. 
	 * This is to enable the fw to access the flash
	 * using GSPI in flashboot mode.
	 */ 
	if( ps_adapter->bFlashBoot	 &&
		ps_adapter->bDisableFastFlashWrite == FALSE &&
		ps_adapter->chip_id >= BCS350)
	{
		rdmalt(ps_adapter,SYS_CFG, &value, sizeof(value));
		value &= ~(1<<7);	
		value |= SYS_CFG_WRITE_SIG;	
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Overriding SYS_CFG: 0x%x\n",value);
		retval = updateWriteProtectedRegister(ps_adapter,SYS_CFG, value);
		if(retval) 
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"write SYS_CFG failed with status :%d",retval);
			return retval;
		}
	}

	/* Download Firmare */
	if ((status = BcmFileDownload( ps_adapter, BIN_350_FILE, FIRMWARE_BEGIN_ADDR)))
	{
		if(ps_adapter->chip_id >= BCS350)
		{
				BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Firmware File not found for 35XX\n");
				goto OUT;
		}
		else
		{
				if ((status = BcmFileDownload( ps_adapter, BIN_FILE, FIRMWARE_BEGIN_ADDR))) {
					BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "No Firmware File is present... \n");
					goto OUT;
				}
		}
	}
	
	BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "BIN file downloaded");
	status = run_card_proc(ps_adapter);
	if(status)
	{
		BCM_DEBUG_PRINT (ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "run_card_proc Failed\n");
		goto OUT;
	}

	
	ps_adapter->fw_download_done = TRUE;
	mdelay(10);

OUT:
	if(ps_adapter->LEDInfo.led_thread_running & BCM_LED_THREAD_RUNNING_ACTIVELY)
	{
		ps_adapter->DriverState = FW_DOWNLOAD_DONE;
		wake_up(&ps_adapter->LEDInfo.notify_led_event);
	}

#else

	ps_adapter->bDDRInitDone = TRUE;
	//Initializing the NVM. 
	BcmInitNVM(ps_adapter);

	//Propagating the cal param from Flash to DDR
	value = 0;
	wrmalt(ps_adapter, EEPROM_CAL_DATA_INTERNAL_LOC - 4, &value, sizeof(value));
	wrmalt(ps_adapter, EEPROM_CAL_DATA_INTERNAL_LOC - 8, &value, sizeof(value));
	
	if(ps_adapter->eNVMType == NVM_FLASH)
	{
		status = PropagateCalParamsFromFlashToMemory(ps_adapter);
		if(status)
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"\nPropogation of Cal param from flash to DDR failed ..\n");	
		}
	}
	

	if(register_networkdev(ps_adapter))
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Register Netdevice failed. Cleanup needs to be performed.");
		return -EIO;
	}
		
	if(FALSE == ps_adapter->AutoFirmDld)
	{
		ps_adapter->fw_download_done = FALSE;
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"\nAutofirware download is disabled .. hence not downloading config file\n");	
	}
	else
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"\nAutofirware download is enabled ..\n");	
		//Copy config file param to DDR.
		ps_adapter->waiting_to_fw_download_done = FALSE;
		memcpy(pConfigFileAddr,ps_adapter->pstargetparams, sizeof(STARGETPARAMS));

		status = wait_event_interruptible_timeout(ps_adapter->ioctl_fw_dnld_wait_queue, 
			ps_adapter->waiting_to_fw_download_done, msecs_to_jiffies(2000));
	
		if(status == -ERESTARTSYS)
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"\n Asking to exit ..\n");	
		}
		if(status == 0 || ps_adapter->waiting_to_fw_download_done == FALSE )
		{
			BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"\n Time out happens or flag is false ..\n");	
		}
						
		
		ps_adapter->fw_download_done = TRUE;
		
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"\nConfig file downloaded ...\n");	
	}
	
	

	status = InitLedSettings (ps_adapter);
	if(status)
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_PRINTK, 0, 0,"INIT LED FAILED\n");
		return status;
	}
	
	
	if(register_control_device_interface(ps_adapter) < 0)
	{
		BCM_DEBUG_PRINT(ps_adapter,DBG_TYPE_INITEXIT, MP_INIT, DBG_LVL_ALL, "Register Control Device failed. Cleanup needs to be performed.");
		return -EIO;
	}
	
	
#endif
	return status;
}

unsigned char *ReadMacAddrEEPROM(PMINI_ADAPTER Adapter, B_UINT32 dwAddress)
{
	unsigned char *pucmacaddr = NULL;
	int status = 0, i=0;
	unsigned int temp =0;


	pucmacaddr = (unsigned char *)kmalloc(MAC_ADDRESS_SIZE, GFP_KERNEL);
	if(!pucmacaddr)
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0, "No Buffers to Read the EEPROM Address\n");
		return NULL;
	}
	
	dwAddress |= 0x5b000000;
	status = wrmalt(Adapter, EEPROM_COMMAND_Q_REG, 
						(PUINT)&dwAddress, sizeof(UINT));
	if(status != STATUS_SUCCESS)
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0, "wrm Failed..\n");
		bcm_kfree(pucmacaddr);
		pucmacaddr = NULL;
		goto OUT;
	}
	for(i=0;i<MAC_ADDRESS_SIZE;i++)
	{
		status = rdmalt(Adapter, EEPROM_READ_DATA_Q_REG, &temp,sizeof(temp));
		if(status != STATUS_SUCCESS)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0, "rdm Failed..\n");
			bcm_kfree(pucmacaddr);
			pucmacaddr = NULL;
			goto OUT;
		}
		pucmacaddr[i] = temp & 0xff;
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_INITEXIT, DRV_ENTRY, DBG_LVL_ALL,"%x \n", pucmacaddr[i]);
	}
OUT:
	return pucmacaddr;
}

#if 0
INT ReadMacAddressFromEEPROM(PMINI_ADAPTER Adapter)
{
	unsigned char *puMacAddr = NULL;
	int i =0;

	puMacAddr = ReadMacAddrEEPROM(Adapter,0x200);
	if(!puMacAddr)
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, NEXT_SEND, DBG_LVL_ALL, "Couldn't retrieve the Mac Address\n");
		return STATUS_FAILURE;	
	}
	else
	{
		if((puMacAddr[0] == 0x0  && puMacAddr[1] == 0x0  &&
			puMacAddr[2] == 0x0  && puMacAddr[3] == 0x0  && 
			puMacAddr[4] == 0x0  && puMacAddr[5] == 0x0) || 
		   (puMacAddr[0] == 0xFF && puMacAddr[1] == 0xFF &&
			puMacAddr[2] == 0xFF && puMacAddr[3] == 0xFF && 
			puMacAddr[4] == 0xFF && puMacAddr[5] == 0xFF))
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, NEXT_SEND, DBG_LVL_ALL, "Invalid Mac Address\n");
			bcm_kfree(puMacAddr);
			return STATUS_FAILURE;	
		}
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_TX, NEXT_SEND, DBG_LVL_ALL, "The Mac Address received is: \n");
		memcpy(Adapter->dev->dev_addr, puMacAddr, MAC_ADDRESS_SIZE);
        for(i=0;i<MAC_ADDRESS_SIZE;i++)
        {
            BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"%02x ", Adapter->dev->dev_addr[i]);
        }
        BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"\n");
		bcm_kfree(puMacAddr);
	}
	return STATUS_SUCCESS;
}
#endif

void convertEndian(B_UINT8 rwFlag, PUINT puiBuffer, UINT uiByteCount)
{
	UINT uiIndex = 0;
	
	if(RWM_WRITE == rwFlag) {
		for(uiIndex =0; uiIndex < (uiByteCount/sizeof(UINT)); uiIndex++) {
			puiBuffer[uiIndex] = htonl(puiBuffer[uiIndex]);
		}
	} else {
		for(uiIndex =0; uiIndex < (uiByteCount/sizeof(UINT)); uiIndex++) {
			puiBuffer[uiIndex] = ntohl(puiBuffer[uiIndex]);
		}
	}
}

#define CACHE_ADDRESS_MASK	0x80000000
#define UNCACHE_ADDRESS_MASK	0xa0000000

int rdm(PMINI_ADAPTER Adapter, UINT uiAddress, PCHAR pucBuff, size_t sSize)
{
	INT uiRetVal =0;
	
#ifndef BCM_SHM_INTERFACE
	uiRetVal = Adapter->interface_rdm(Adapter->pvInterfaceAdapter, 
			uiAddress, pucBuff, sSize);

	if(uiRetVal < 0)
		return uiRetVal;
	
#else
	int indx;
	uiRetVal = STATUS_SUCCESS;
	if(uiAddress & 0x10000000) {
			// DDR Memory Access
		uiAddress |= CACHE_ADDRESS_MASK;
		memcpy(pucBuff,(unsigned char *)uiAddress ,sSize);
	}
	else {
		// Register, SPRAM, Flash
		uiAddress |= UNCACHE_ADDRESS_MASK;
    if ((uiAddress & FLASH_ADDR_MASK) == (FLASH_CONTIGIOUS_START_ADDR_BCS350 & FLASH_ADDR_MASK))
	{
		#if defined(FLASH_DIRECT_ACCESS)
        	memcpy(pucBuff,(unsigned char *)uiAddress ,sSize);
		#else
			printk("\nInvalid GSPI ACCESS :Addr :%#X", uiAddress);
			uiRetVal = STATUS_FAILURE;
		#endif
	}	
    else if(((unsigned int )uiAddress & 0x3) || 
			((unsigned int )pucBuff & 0x3) || 
			((unsigned int )sSize & 0x3)) {
		  	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"rdmalt :unalligned register access uiAddress =  %x,pucBuff = %x  size = %x\n",(unsigned int )uiAddress,(unsigned int )pucBuff,(unsigned int )sSize);
			 uiRetVal = STATUS_FAILURE;
		}
		else {
		 	for (indx=0;indx<sSize;indx+=4){
		   		*(PUINT)(pucBuff + indx) = *(PUINT)(uiAddress + indx);
		  	}
		}
	}
#endif
	return uiRetVal;
}
int wrm(PMINI_ADAPTER Adapter, UINT uiAddress, PCHAR pucBuff, size_t sSize)
{
	int iRetVal;

#ifndef BCM_SHM_INTERFACE
	iRetVal = Adapter->interface_wrm(Adapter->pvInterfaceAdapter, 
			uiAddress, pucBuff, sSize);

#else
	int indx;
	if(uiAddress & 0x10000000) {
		// DDR Memory Access
		uiAddress |= CACHE_ADDRESS_MASK;
		memcpy((unsigned char *)(uiAddress),pucBuff,sSize);
	}
	else {
		// Register, SPRAM, Flash
		uiAddress |= UNCACHE_ADDRESS_MASK;
		
		if(((unsigned int )uiAddress & 0x3) || 
			((unsigned int )pucBuff & 0x3) || 
			((unsigned int )sSize & 0x3)) {
		  		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"wrmalt: unalligned register access uiAddress =  %x,pucBuff = %x  size = %x\n",(unsigned int )uiAddress,(unsigned int )pucBuff,(unsigned int )sSize);
			 iRetVal = STATUS_FAILURE;
		}
		else {
		 	for (indx=0;indx<sSize;indx+=4) {
		  		*(PUINT)(uiAddress + indx) = *(PUINT)(pucBuff + indx);
			}
		}
	}
	iRetVal = STATUS_SUCCESS;
#endif

	return iRetVal;
}

int wrmalt (PMINI_ADAPTER Adapter, UINT uiAddress, PUINT pucBuff, size_t size)
{
	convertEndian(RWM_WRITE, pucBuff, size);
	return wrm(Adapter, uiAddress, (PUCHAR)pucBuff, size);
}

int rdmalt (PMINI_ADAPTER Adapter, UINT uiAddress, PUINT pucBuff, size_t size)
{
	INT uiRetVal =0;

	uiRetVal = rdm(Adapter,uiAddress,(PUCHAR)pucBuff,size);
	convertEndian(RWM_READ, (PUINT)pucBuff, size);

	return uiRetVal;
}

int rdmWithLock(PMINI_ADAPTER Adapter, UINT uiAddress, PCHAR pucBuff, size_t sSize)
{
	
	INT status = STATUS_SUCCESS ;
	down(&Adapter->rdmwrmsync);
	
	if((Adapter->IdleMode == TRUE) || 
		(Adapter->bShutStatus ==TRUE) || 
		(Adapter->bPreparingForLowPowerMode ==TRUE))
	{
		status = -EACCES;
		goto exit;
	}

	status = rdm(Adapter, uiAddress, pucBuff, sSize);

exit:	
	up(&Adapter->rdmwrmsync);
	return status ;
}
int wrmWithLock(PMINI_ADAPTER Adapter, UINT uiAddress, PCHAR pucBuff, size_t sSize)
{
	INT status = STATUS_SUCCESS ;
	down(&Adapter->rdmwrmsync);
	
	if((Adapter->IdleMode == TRUE) || 
		(Adapter->bShutStatus ==TRUE) || 
		(Adapter->bPreparingForLowPowerMode ==TRUE))
	{
		status = -EACCES;
		goto exit;
	}

	status =wrm(Adapter, uiAddress, pucBuff, sSize);

exit:	
	up(&Adapter->rdmwrmsync);
	return status ;
}

int wrmaltWithLock (PMINI_ADAPTER Adapter, UINT uiAddress, PUINT pucBuff, size_t size)
{
	int iRetVal = STATUS_SUCCESS;

	down(&Adapter->rdmwrmsync);
	
	if((Adapter->IdleMode == TRUE) || 
		(Adapter->bShutStatus ==TRUE) || 
		(Adapter->bPreparingForLowPowerMode ==TRUE))
	{
		iRetVal = -EACCES;
		goto exit;
	}

	iRetVal = wrmalt(Adapter,uiAddress,pucBuff,size);

exit:
	up(&Adapter->rdmwrmsync);
	return iRetVal;
}

int rdmaltWithLock (PMINI_ADAPTER Adapter, UINT uiAddress, PUINT pucBuff, size_t size)
{
	INT uiRetVal =STATUS_SUCCESS;

	down(&Adapter->rdmwrmsync);
	
	if((Adapter->IdleMode == TRUE) || 
		(Adapter->bShutStatus ==TRUE) || 
		(Adapter->bPreparingForLowPowerMode ==TRUE))
	{
		uiRetVal = -EACCES;
		goto exit;
	}

	uiRetVal = rdmalt(Adapter,uiAddress, pucBuff, size);

exit:
	up(&Adapter->rdmwrmsync);
	return uiRetVal;
}


VOID HandleShutDownModeWakeup(PMINI_ADAPTER Adapter)
{
	int clear_abort_pattern = 0,Status = 0;
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, MP_SHUTDOWN, DBG_LVL_ALL, "====>\n");
	//target has woken up From Shut Down
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, MP_SHUTDOWN, DBG_LVL_ALL, "Clearing Shut Down Software abort pattern\n");
	Status = wrmalt(Adapter,SW_ABORT_IDLEMODE_LOC, (PUINT)&clear_abort_pattern, sizeof(clear_abort_pattern));
	if(Status)
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, MP_SHUTDOWN, DBG_LVL_ALL,"WRM to SW_ABORT_IDLEMODE_LOC failed with err:%d", Status);
		return;
	}
	if(Adapter->ulPowerSaveMode != DEVICE_POWERSAVE_MODE_AS_PROTOCOL_IDLE_MODE)
	{
		msleep(100);
		InterfaceHandleShutdownModeWakeup(Adapter);
		msleep(100);
	}
	if(Adapter->LEDInfo.led_thread_running & BCM_LED_THREAD_RUNNING_ACTIVELY)
	{
		Adapter->DriverState = NO_NETWORK_ENTRY;
		wake_up(&Adapter->LEDInfo.notify_led_event);
	}
	
	Adapter->bTriedToWakeUpFromlowPowerMode = FALSE;
	Adapter->bShutStatus = FALSE;
	wake_up(&Adapter->lowpower_mode_wait_queue);
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, MP_SHUTDOWN, DBG_LVL_ALL, "<====\n");
}

VOID SendShutModeResponse(PMINI_ADAPTER Adapter)
{
	CONTROL_MESSAGE		stShutdownResponse;
	UINT NVMAccess = 0,lowPwrAbortMsg = 0;
	UINT Status = 0;
	
	memset (&stShutdownResponse, 0, sizeof(CONTROL_MESSAGE));	
	stShutdownResponse.Leader.Status  = LINK_UP_CONTROL_REQ;
	stShutdownResponse.Leader.PLength = 8;//8 bytes;
	stShutdownResponse.szData[0] = LINK_UP_ACK; 
	stShutdownResponse.szData[1] = LINK_SHUTDOWN_REQ_FROM_FIRMWARE; 

	/*********************************
	**down_trylock -
	** if [ semaphore is available ]
	**		 acquire semaphone and return value 0 ;
	**   else		
	**		 return non-zero value ;
	**
	***********************************/
	

	if(Adapter->link_shutdown_req_type == SHUTDOWN_REQ_FRM_FW_HIBERNATION_BUTTON_PRESS)
	{
				down(&Adapter->NVMRdmWrmLock);
				down(&Adapter->LowPowerModeSync);
				NVMAccess = 0;
				lowPwrAbortMsg =0;
				
	}
	else
	{
		NVMAccess = down_trylock(&Adapter->NVMRdmWrmLock);
		lowPwrAbortMsg= down_trylock(&Adapter->LowPowerModeSync);
	}
	
	if(
		(NVMAccess || lowPwrAbortMsg|| atomic_read(&Adapter->TotalPacketCount))	
							&&
		(Adapter->link_shutdown_req_type != SHUTDOWN_REQ_FRM_FW_HIBERNATION_BUTTON_PRESS)			
	   )	
	{
		if(!NVMAccess)
			up(&Adapter->NVMRdmWrmLock);

		if(!lowPwrAbortMsg)
			up(&Adapter->LowPowerModeSync);

		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, MP_SHUTDOWN, DBG_LVL_ALL, "Device Access is going on NACK the Shut Down MODE\n");
		stShutdownResponse.szData[2] = SHUTDOWN_NACK_FROM_DRIVER;//NACK- device access is going on.
		Adapter->bPreparingForLowPowerMode = FALSE;
	}
	else
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, MP_SHUTDOWN, DBG_LVL_ALL, "Sending SHUTDOWN MODE ACK\n");
		stShutdownResponse.szData[2] = SHUTDOWN_ACK_FROM_DRIVER;//ShutDown ACK

		/* Wait for the LED to TURN OFF before sending ACK response */
		if(Adapter->LEDInfo.led_thread_running & BCM_LED_THREAD_RUNNING_ACTIVELY)
		{
			INT iRetVal = 0;

			/* Wake the LED Thread with LOWPOWER_MODE_ENTER State */
			Adapter->DriverState = LOWPOWER_MODE_ENTER;
			wake_up(&Adapter->LEDInfo.notify_led_event);

			/* Wait for 1 SEC for LED to OFF */
			iRetVal = wait_event_timeout(Adapter->LEDInfo.idleModeSyncEvent,\
				Adapter->LEDInfo.bIdle_led_off, msecs_to_jiffies(1000));

			/* If Timed Out to Sync IDLE MODE Enter, do IDLE mode Exit and Send NACK to device */
			if(iRetVal <= 0) 
			{
				stShutdownResponse.szData[1] = SHUTDOWN_NACK_FROM_DRIVER;//NACK- device access is going on.
			
				Adapter->DriverState = NO_NETWORK_ENTRY;
				wake_up(&Adapter->LEDInfo.notify_led_event);
			}
		}	

		if(stShutdownResponse.szData[2] == SHUTDOWN_ACK_FROM_DRIVER)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, MP_SHUTDOWN, DBG_LVL_ALL,"ACKING SHUTDOWN MODE !!!!!!!!!");
			down(&Adapter->rdmwrmsync); 
			Adapter->bPreparingForLowPowerMode = TRUE;
			up(&Adapter->rdmwrmsync);
			//Killing all URBS.
#ifndef BCM_SHM_INTERFACE			
			if(Adapter->bDoSuspend == TRUE)
				Bcm_kill_all_URBs((PS_INTERFACE_ADAPTER)(Adapter->pvInterfaceAdapter));
#endif		
		}
		else
		{
			Adapter->bPreparingForLowPowerMode = FALSE;
		}

		if(!NVMAccess)
			up(&Adapter->NVMRdmWrmLock);	
		
		if(!lowPwrAbortMsg)
			up(&Adapter->LowPowerModeSync);
	}
	Status = CopyBufferToControlPacket(Adapter,&stShutdownResponse);
	if((Status != STATUS_SUCCESS))
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, MP_SHUTDOWN, DBG_LVL_ALL,"fail to send the Idle mode Request \n");
		Adapter->bPreparingForLowPowerMode = FALSE;

#ifndef BCM_SHM_INTERFACE
		StartInterruptUrb((PS_INTERFACE_ADAPTER)(Adapter->pvInterfaceAdapter));
#endif
	}
}


void HandleShutDownModeRequest(PMINI_ADAPTER Adapter,PUCHAR pucBuffer)
{
	B_UINT32 uiResetValue = 0;
	
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, MP_SHUTDOWN, DBG_LVL_ALL, "====>\n");
	
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"ShutdownRequest  = 0x%x \n",*(pucBuffer+1) );
	if((*(pucBuffer+1) ==  COMPLETE_WAKE_UP_NOTIFICATION_FRM_FW)
	   || (*(pucBuffer+1) ==  HIBERNATION_WAKEUP))
	{
		HandleShutDownModeWakeup(Adapter);
#ifdef BCM_SHM_INTERFACE		
		if((Adapter->CPUId == NP_CPU_ID) && Adapter->shmsig_intr != SHM_SIGNATURE_INTERRUPT_OFF)
		{
			BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, MP_SHUTDOWN, DBG_LVL_ALL,"Interrupt NP enable \n");
			*(volatile UINT *)MIPS_BRIDGE_INT_MASK_REGISTER = *(volatile UINT *)MIPS_BRIDGE_INT_MASK_REGISTER & ~(0x1);
		}
#endif
	}
	
	else if(
		    *(pucBuffer+1) ==  LINK_SHUTDOWN_REQ_FROM_FIRMWARE 
							||
			*(pucBuffer+1)  ==	SHUTDOWN_REQ_FRM_FW_STANDBY_TIMER
							 ||
            *(pucBuffer+1) ==  SHUTDOWN_REQ_FRM_FW_HIBERNATION_BUTTON_PRESS
		)
	{
		Adapter->link_shutdown_req_type = *(pucBuffer+1);
		
		//Target wants to go to Shut Down Mode
		//InterfacePrepareForShutdown(Adapter);
		if(Adapter->chip_id == BCS220_2 || 
		   Adapter->chip_id == BCS220_2BC || 	
		   Adapter->chip_id == BCS250_BC ||
		   Adapter->chip_id == BCS220_3) 
		{	
			rdmalt(Adapter,HPM_CONFIG_MSW, &uiResetValue, 4);
			uiResetValue |= (1<<17);
			wrmalt(Adapter, HPM_CONFIG_MSW, &uiResetValue, 4);		
		}
		
		SendShutModeResponse(Adapter);
		BCM_DEBUG_PRINT (Adapter,DBG_TYPE_OTHERS, MP_SHUTDOWN, DBG_LVL_ALL,"ShutDownModeResponse:Notification received: Sending the response(Ack/Nack)\n");
	}
	
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_OTHERS, MP_SHUTDOWN, DBG_LVL_ALL, "<====\n");
	return;

}

VOID ResetCounters(PMINI_ADAPTER Adapter)
{

   	beceem_protocol_reset(Adapter);

	Adapter->CurrNumRecvDescs = 0;
    Adapter->PrevNumRecvDescs = 0;
    Adapter->LinkUpStatus = 0;
	Adapter->LinkStatus = 0;
  //  atomic_set(&Adapter->cntrlpktCnt,0);
  //  atomic_set (&Adapter->TotalPacketCount,0);
    Adapter->fw_download_done=FALSE;
	Adapter->LinkStatus = 0;
    Adapter->AutoLinkUp = FALSE;
	Adapter->IdleMode = FALSE;
	Adapter->bShutStatus = FALSE;

}
S_CLASSIFIER_RULE *GetFragIPClsEntry(PMINI_ADAPTER Adapter,USHORT usIpIdentification,B_UINT32 SrcIP)
{
	UINT uiIndex=0;
	for(uiIndex=0;uiIndex<MAX_FRAGMENTEDIP_CLASSIFICATION_ENTRIES;uiIndex++)
	{
		if((Adapter->astFragmentedPktClassifierTable[uiIndex].bUsed)&&
			(Adapter->astFragmentedPktClassifierTable[uiIndex].usIpIdentification == usIpIdentification)&&
			(Adapter->astFragmentedPktClassifierTable[uiIndex].ulSrcIpAddress== SrcIP)&&
			!Adapter->astFragmentedPktClassifierTable[uiIndex].bOutOfOrderFragment)
			return Adapter->astFragmentedPktClassifierTable[uiIndex].pstMatchedClassifierEntry;
	}
	return NULL;
}

void AddFragIPClsEntry(PMINI_ADAPTER Adapter,PS_FRAGMENTED_PACKET_INFO psFragPktInfo)
{
	UINT uiIndex=0;
	for(uiIndex=0;uiIndex<MAX_FRAGMENTEDIP_CLASSIFICATION_ENTRIES;uiIndex++)
	{
		if(!Adapter->astFragmentedPktClassifierTable[uiIndex].bUsed)
		{
			memcpy(&Adapter->astFragmentedPktClassifierTable[uiIndex],psFragPktInfo,sizeof(S_FRAGMENTED_PACKET_INFO));
			break;
		}
	}

}

void DelFragIPClsEntry(PMINI_ADAPTER Adapter,USHORT usIpIdentification,B_UINT32 SrcIp)
{
	UINT uiIndex=0;
	for(uiIndex=0;uiIndex<MAX_FRAGMENTEDIP_CLASSIFICATION_ENTRIES;uiIndex++)
	{
		if((Adapter->astFragmentedPktClassifierTable[uiIndex].bUsed)&&
			(Adapter->astFragmentedPktClassifierTable[uiIndex].usIpIdentification == usIpIdentification)&&
			(Adapter->astFragmentedPktClassifierTable[uiIndex].ulSrcIpAddress== SrcIp))
		memset(&Adapter->astFragmentedPktClassifierTable[uiIndex],0,sizeof(S_FRAGMENTED_PACKET_INFO));
	}
}

void update_per_cid_rx (PMINI_ADAPTER Adapter)
{
	UINT  qindex = 0;

	if((jiffies - Adapter->liDrainCalculated) < XSECONDS)
		return;	

	for(qindex = 0; qindex < HiPriority; qindex++)
	{
		if(Adapter->PackInfo[qindex].ucDirection == 0)
		{
			Adapter->PackInfo[qindex].uiCurrentRxRate =
				(Adapter->PackInfo[qindex].uiCurrentRxRate + 
				Adapter->PackInfo[qindex].uiThisPeriodRxBytes)/2;

			Adapter->PackInfo[qindex].uiThisPeriodRxBytes = 0;
		}
		else
		{
			Adapter->PackInfo[qindex].uiCurrentDrainRate =
				(Adapter->PackInfo[qindex].uiCurrentDrainRate + 
				Adapter->PackInfo[qindex].uiThisPeriodSentBytes)/2;

			Adapter->PackInfo[qindex].uiThisPeriodSentBytes=0;
		}
	}
	Adapter->liDrainCalculated=jiffies;
}
void update_per_sf_desc_cnts( PMINI_ADAPTER Adapter)
{
	INT iIndex = 0;
	u32 uibuff[MAX_TARGET_DSX_BUFFERS];

	if(!atomic_read (&Adapter->uiMBupdate))
		return;

#ifdef BCM_SHM_INTERFACE
	if(rdmalt(Adapter, TARGET_SFID_TXDESC_MAP_LOC, (PUINT)uibuff, sizeof(UINT) * MAX_TARGET_DSX_BUFFERS)<0)
#else	
	if(rdmaltWithLock(Adapter, TARGET_SFID_TXDESC_MAP_LOC, (PUINT)uibuff, sizeof(UINT) * MAX_TARGET_DSX_BUFFERS)<0)
#endif
	{
		BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0, "rdm failed\n");
		return;
	}
	for(iIndex = 0;iIndex < HiPriority; iIndex++)
	{
		if(Adapter->PackInfo[iIndex].bValid && Adapter->PackInfo[iIndex].ucDirection)
		{
			if(Adapter->PackInfo[iIndex].usVCID_Value < MAX_TARGET_DSX_BUFFERS)
			{
				atomic_set(&Adapter->PackInfo[iIndex].uiPerSFTxResourceCount, uibuff[Adapter->PackInfo[iIndex].usVCID_Value]);
			}
			else
			{
				BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0, "Invalid VCID : %x \n", 
					Adapter->PackInfo[iIndex].usVCID_Value);			
			}
		}
	}
	atomic_set (&Adapter->uiMBupdate, FALSE);
}

void flush_queue(PMINI_ADAPTER Adapter, UINT iQIndex)
{
	struct sk_buff* 			PacketToDrop=NULL;
	struct net_device_stats*		netstats=NULL;

	netstats = &((PLINUX_DEP_DATA)Adapter->pvOsDepData)->netstats;

	spin_lock_bh(&Adapter->PackInfo[iQIndex].SFQueueLock);	

	while(Adapter->PackInfo[iQIndex].FirstTxQueue && 
		atomic_read(&Adapter->TotalPacketCount))
	{
		PacketToDrop = Adapter->PackInfo[iQIndex].FirstTxQueue;
		if(PacketToDrop && PacketToDrop->len)
		{
			netstats->tx_dropped++;
			DEQUEUEPACKET(Adapter->PackInfo[iQIndex].FirstTxQueue, \
					Adapter->PackInfo[iQIndex].LastTxQueue);
			
			Adapter->PackInfo[iQIndex].uiCurrentPacketsOnHost--;
			Adapter->PackInfo[iQIndex].uiCurrentBytesOnHost -= PacketToDrop->len;

			//Adding dropped statistics
			Adapter->PackInfo[iQIndex].uiDroppedCountBytes += PacketToDrop->len;
			Adapter->PackInfo[iQIndex].uiDroppedCountPackets++;

			bcm_kfree_skb(PacketToDrop);
			atomic_dec(&Adapter->TotalPacketCount);
			atomic_inc(&Adapter->TxDroppedPacketCount);
			
		}
	}
	spin_unlock_bh(&Adapter->PackInfo[iQIndex].SFQueueLock);	
	
}

void beceem_protocol_reset (PMINI_ADAPTER Adapter)
{
		
	if(NULL != Adapter->dev)
	{
		netif_carrier_off(Adapter->dev);
		netif_stop_queue(Adapter->dev);
	}	

	Adapter->IdleMode = FALSE;
	Adapter->LinkUpStatus = FALSE;
	Adapter->ucDsxConnBitMap = FALSE;

	beceem_reset_queues (Adapter);

}




void beceem_reset_queues (PMINI_ADAPTER Adapter)
{
	int i =0;
	
	ClearTargetDSXBuffer(Adapter,0, TRUE);
	//Delete All Classifier Rules

	for(i = 0;i<HiPriority;i++)
	{
		DeleteAllClassifiersForSF(Adapter,i);
	}
	
	flush_all_queues(Adapter);
	
	if(Adapter->TimerActive == TRUE)
		Adapter->TimerActive = FALSE;

	memset(Adapter->astFragmentedPktClassifierTable, 0, 
			sizeof(S_FRAGMENTED_PACKET_INFO) * 
			MAX_FRAGMENTEDIP_CLASSIFICATION_ENTRIES);	

	for(i = 0;i<HiPriority;i++)
	{
		//resetting only the first size (S_MIBS_SERVICEFLOW_TABLE) for the SF.
		// It is same between MIBs and SF.
		memset((PVOID)&Adapter->PackInfo[i],0,sizeof(S_MIBS_SERVICEFLOW_TABLE));
	}
}

#ifdef BCM_SHM_INTERFACE


#define GET_GTB_DIFF(start, end)  \
( (start) < (end) )? ( (end) - (start) ) : ( ~0x0 - ( (start) - (end)) +1 )

void usdelay ( unsigned int a) {
	unsigned int start= *(unsigned int *)0xaf8051b4; 
	unsigned int end  = start+1;
	unsigned int diff = 0;

	while(1) {
		end = *(unsigned int *)0xaf8051b4;
		diff = (GET_GTB_DIFF(start,end))/80;
		if (diff >= a)
			break;
	}
}
void read_cfg_file(PMINI_ADAPTER Adapter) {


	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Config File Version = 0x%x \n",Adapter->pstargetparams->m_u32CfgVersion );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Center Frequency =  0x%x \n",Adapter->pstargetparams->m_u32CenterFrequency );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Band A Scan = 0x%x \n",Adapter->pstargetparams->m_u32BandAScan );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Band B Scan = 0x%x \n",Adapter->pstargetparams->m_u32BandBScan );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Band C Scan = 0x%x \n",Adapter->pstargetparams->m_u32BandCScan );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"ERTPS Options = 0x%x \n",Adapter->pstargetparams->m_u32ErtpsOptions );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"PHS Enable = 0x%x \n",Adapter->pstargetparams->m_u32PHSEnable );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Handoff Enable = 0x%x \n",Adapter->pstargetparams->m_u32HoEnable );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"HO Reserved1 = 0x%x \n",Adapter->pstargetparams->m_u32HoReserved1 );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"HO Reserved2 = 0x%x \n",Adapter->pstargetparams->m_u32HoReserved2 );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"MIMO Enable = 0x%x \n",Adapter->pstargetparams->m_u32MimoEnable );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"PKMv2 Enable = 0x%x \n",Adapter->pstargetparams->m_u32SecurityEnable );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Powersaving Modes Enable = 0x%x \n",Adapter->pstargetparams->m_u32PowerSavingModesEnable );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Power Saving Mode Options = 0x%x \n",Adapter->pstargetparams->m_u32PowerSavingModeOptions );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"ARQ Enable = 0x%x \n",Adapter->pstargetparams->m_u32ArqEnable );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Harq Enable = 0x%x \n",Adapter->pstargetparams->m_u32HarqEnable );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"EEPROM Flag = 0x%x \n",Adapter->pstargetparams->m_u32EEPROMFlag );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Customize = 0x%x \n",Adapter->pstargetparams->m_u32Customize );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Bandwidth = 0x%x \n",Adapter->pstargetparams->m_u32ConfigBW );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"ShutDown Timer Value = 0x%x \n",Adapter->pstargetparams->m_u32ShutDownInitThresholdTimer );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"RadioParameter = 0x%x \n",Adapter->pstargetparams->m_u32RadioParameter );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"PhyParameter1 = 0x%x \n",Adapter->pstargetparams->m_u32PhyParameter1 );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"PhyParameter2 = 0x%x \n",Adapter->pstargetparams->m_u32PhyParameter2 );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"PhyParameter3 = 0x%x \n",Adapter->pstargetparams->m_u32PhyParameter3 );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"m_u32TestOptions = 0x%x \n",Adapter->pstargetparams->m_u32TestOptions );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"MaxMACDataperDLFrame = 0x%x \n",Adapter->pstargetparams->m_u32MaxMACDataperDLFrame );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"MaxMACDataperULFrame = 0x%x \n",Adapter->pstargetparams->m_u32MaxMACDataperULFrame );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Corr2MacFlags = 0x%x \n",Adapter->pstargetparams->m_u32Corr2MacFlags );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"HostDrvrConfig1 = 0x%x \n",Adapter->pstargetparams->HostDrvrConfig1 );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"HostDrvrConfig2 = 0x%x \n",Adapter->pstargetparams->HostDrvrConfig2 );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"HostDrvrConfig3 = 0x%x \n",Adapter->pstargetparams->HostDrvrConfig3 );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"HostDrvrConfig4 = 0x%x \n",Adapter->pstargetparams->HostDrvrConfig4 );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"HostDrvrConfig5 = 0x%x \n",Adapter->pstargetparams->HostDrvrConfig5 );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"HostDrvrConfig6 = 0x%x \n",Adapter->pstargetparams->HostDrvrConfig6 );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"Segmented PUSC Enable = 0x%x \n",Adapter->pstargetparams->m_u32SegmentedPUSCenable );
	BCM_DEBUG_PRINT(Adapter,DBG_TYPE_PRINTK, 0, 0,"BamcEnable = 0x%x \n",Adapter->pstargetparams->m_u32BandAMCEnable );
}

#endif


