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


/*  default includes */
#include "tcg/tnc/tncifimc.h"
#include "imunit/imv/AbstractIMV.h"
#include "ProcwatcherIMVPolicyManager.h"
#include "ProcwatcherIMVLibrary.h"

#include <vector>

/*  openssl includes */
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#define SHA1_LENGTH 20
#define MAX 2048
using namespace tncfhh::iml;
using namespace std;
/**
 * ProcwatcherIMV.
 *
 * <h3>Changelog:</h3>
 * <ul>
 *   <li>19.08.2009 - create class (mbs)</li>
 * </ul>
 *
 * @date 19.08.2009
 * @author Mike Steinmetz (mbs)
 */
class ProcwatcherIMV : public tncfhh::iml::AbstractIMV
{
public:
	/**
	 * Ctor.
	 */
	ProcwatcherIMV(TNC_ConnectionID conID, ProcwatcherIMVLibrary *pProcwatcherIMVLibrary,ProcwatcherIMVPolicyManager * pm);

	/**
	 * Dtor.
	 */
	virtual ~ProcwatcherIMV();

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

typedef std::pair<std::string,std::string> prop_type;

    std::vector<prop_type> readAllProperties(std::istream & );
    bool readLine(std::istream &in, char *buf, const int size);
    std::string trim(std::string const& source, char const* delims);

    ProcwatcherIMVPolicyManager *policyManager;
    
private:
    unsigned char * hashAll; //40位，被translate后的hash
    unsigned char * digest;//20位,hash(hashAll）
    unsigned char *nonceBuf ; 
    X509                *x509Cert;
    EVP_PKEY            *pKey; 
    RSA                 *rsa;
    bool firstMessage;
    bool nothingWrong;
    bool checkClientKnown();

    vector<FileEntry> entry;
    int processFirstMessage(TNC_BufferReference message, TNC_UInt32 length);
    int loadX509Cert(TNC_BufferReference message, TNC_UInt32 length);
    int loadPKey(void);
    int loadRSA(void);
    bool isASN1(TNC_BufferReference message, TNC_UInt32 length);
    int calculateHash(std::vector<FileEntry> &ent);
};

#endif /* PROCWATCHERIMV_H_ */
