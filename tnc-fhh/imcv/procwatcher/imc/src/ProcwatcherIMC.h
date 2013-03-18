/* 
 * Copyright (C) 2006-2011 Fachhochschule Hannover
 * (University of Applied Sciences and Arts, Hannover)
 * Faculty IV, Dept. of Computer Science
 * Ricklinger Stadtweg 118, 30459 Hannover, Germany
 * 
 * Email: trust@f4-i.fh-hannover.de
 * Website: http://trust.inform.fh-hannover.de/
 * 
 * This file is part of tnc@fhh, an open source 
 * Trusted Network Connect implementation by the Trust@FHH
 * research group at the Fachhochschule Hannover.
 * 
 * tnc@fhh is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * tnc@fhh is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with tnc@fhh; if not, see <http://www.gnu.org/licenses/>
 */
 
#ifndef PROCWATCHERIMC_H_
#define PROCWATCHERIMC_H_

#include <imunit/imc/AbstractIMC.h>
#include "ProcwatcherIMCLibrary.h"
#include <vector>
#include <string.h>
#include <trousers/tss.h> 
#include <trousers/trousers.h>

using namespace std;

#define BLOCKSIZE 4096
#define SHA1_LENGTH 20
typedef unsigned char *TNC_BufferReference;
/**
 * ProcwatcherIMC.
 *
 * <h3>Changelog:</h3>
 * <ul>
 *   <li>19.08.2009 - create class (mbs)</li>
 * </ul>
 *
 * @date 19.08.2009
 * @author Mike Steinmetz (mbs)
 */
class ProcwatcherIMC : public tncfhh::iml::AbstractIMC
{
public:

	/**
	 * Ctor.
	 */
	ProcwatcherIMC(TNC_ConnectionID conID, ProcwatcherIMCLibrary *pProcwatcherIMCLibrary);

	/**
	 * Dtor.
	 */
	virtual ~ProcwatcherIMC();

	/**
	 * beginHandshake
	 */
    virtual TNC_Result beginHandshake();

    /**
     * receive Message
     */
    virtual TNC_Result receiveMessage(TNC_BufferReference message,
    		                          TNC_UInt32 messageLength,
    		                          TNC_MessageType messageType);

    /**
     * batchEnding
     */
    virtual TNC_Result batchEnding();

    /**
     * notifyConnectionChange
     */
    virtual TNC_Result notifyConnectionChange();

    void   read_policy();
    void   find_matched(std::stringstream &);

    int calculate_hash_by_fd(char * , unsigned char *);
private:
    unsigned char *nonce;
    char *buf;
    unsigned char buffer[BLOCKSIZE];
    
    //新增加的：
//    TNC_Buffer digest[20];
    int loadConfigFile(void);
    int processConfigLine(string configLine);
    void processCertificateLine(string configLine);
    void processAikKeyLine(string configLine);
    int loadX509Certificate(void);
    int loadAikBlob(void);
    int loadBlobToBuf(TNC_BufferReference *buf, const char *filename);
    string              certificateFile;
    string              aikBlobFile;
    int initTpmStuff(void);
    void cleanup1(void);
    void cleanup2(void);
    void cleanup3(void);
    void cleanup4(void);
    void cleanup5(void);
    bool                certificateSent;
    bool initialized;
    /*  place to store the x509 certificate */
    TNC_UInt32          certificateLength;
    TNC_BufferReference     certificate;

    /*  place to store the aik blob */
    TNC_UInt32          aikBlobLength;
    TNC_BufferReference     aikBlob;

    /*  context handle */
    TSS_HCONTEXT    hContext;
    /*  tpm handle */
    TSS_HTPM    hTPM;

    /*  srk handle */
    TSS_HKEY    hSRK;

    /*  srk policy handle */
    TSS_HPOLICY srkPolicy;

    /*  aik handle */
    TSS_HKEY    hAIK;

    class Policy{
        public:
            Policy(); 
            void init();
            void add(std::string);
            bool find(std::string);
        private:
            std::vector<std::string> paths;
    };

    Policy policy;

};

#endif /* PROCWATCHERIMC_H_ */
