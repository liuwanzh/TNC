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
 
#include "ProcwatcherIMV.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <log4cxx/logger.h>

#include <cstring>			/* memcpy(), memcmp()	*/
#include <openssl/pem.h>		/* PEM_read_bio_X509()	*/
#include <openssl/x509.h>		/* X509 object handling	*/
#include <openssl/sha.h>
#include <stdlib.h>
#include <dirent.h>

#include <stdlib.h>
#include <string.h>

#include <stdexcept>

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("IMUnit.AbstractIMUnit.AbstractIMC.ProcwatcherIMV"));

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
ProcwatcherIMV::ProcwatcherIMV(TNC_ConnectionID conID, ProcwatcherIMVLibrary *pProcwatcherIMVLibrary,ProcwatcherIMVPolicyManager * pm)
	:AbstractIMV(conID, pProcwatcherIMVLibrary)
{
    this->policyManager = pm;
    entry = policyManager->getFileEntries();
    firstMessage = 1;
    digest = (unsigned char *)malloc(20);
    hashAll = (unsigned char *)malloc(40);
	// initialize
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
ProcwatcherIMV::~ProcwatcherIMV()
{
    free(hashAll);
    free(digest);
	// if necessary delete memory
}

void translate2chars(char * buf,int length)
{
    int i;
    unsigned char digest[length];
    memcpy(digest, buf, sizeof(digest));
    for(i=0;i<length;++i)
        sprintf(buf+2*i,"%02X", *(digest + i) & 0xFF);
    buf[2*(length)] = 0;

}



TNC_Result ProcwatcherIMV::receiveMessage(TNC_BufferReference message,
        TNC_UInt32 length,
        TNC_MessageType messageType)
{

            //把FileEntry存好
            //
            //
 
    //this->entry = policyManager->getFileEntries();
  //(this->entry).push_back(FileEntry("/bin/","12345678901234567890")); 
            //
            //


    LOG4CXX_DEBUG(logger, "receiveMessage round " << this->getRound());
    if (firstMessage) {
        LOG4CXX_DEBUG(logger, "Received first message, should be the x509 cert");
        firstMessage = 0;
        if (processFirstMessage(message, length) < 0) {
            return TNC_RESULT_FATAL;
        }
        if (!checkClientKnown()) {
            LOG4CXX_INFO(logger, "Client Certificate unknown. :-(");
            tncs.provideRecommendation(TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS,
                    TNC_IMV_EVALUATION_RESULT_DONT_KNOW);
        }
        else
        {
            nonceBuf = new unsigned char[50]; 
            //验证完AIK证书后，发一个nonce过去，以防止重放攻击
            LOG4CXX_TRACE(logger, "Generating nonce...");
            if (RAND_bytes(nonceBuf,10) == 0) {
                LOG4CXX_FATAL(logger, "RAND_bytes() failed!!!");
                nothingWrong = false;
                delete[] nonceBuf;
                return -1;
            }
            else
            {
                for(int i=0;i<10;i++)
                {
                    printf("%02hhx",nonceBuf[i]);
                }
                translate2chars((char *)nonceBuf,20);
                //计算hash(n*(hash(file),用于等下收到客户端发过来的该内容时做匹配，类似attestation里的calculate函数
                calculateHash(entry);
                this->tncs.sendMessage(nonceBuf, 20, VENDOR_ID,MESSAGE_SUBTYPE);
                delete[] nonceBuf;   
            }
        }
    }
    else
    {
        char *temp_buf = (char *)malloc(MAX);
        //memcpy(temp_buf,message,20);
        strcpy(temp_buf,(char *)message);
        // print received message dirty out. WARNING: don't ape this,
        // message should end with non-null! Heed: Message can be evil!
        LOG4CXX_INFO(logger, "Received 2nd Message: " << message);

        /* only send one message to ProcwatcherIMC */
        //		/* validation finish, set recommendation & co */
        //        validationFinished = true;
        //
        //		// for no access:
        ////		actionRecommendation = TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS;
        //		// for isolate:
        ////		actionRecommendation = TNC_IMV_ACTION_RECOMMENDATION_ISOLATE;
        //		// for access allow:
        //        actionRecommendation = TNC_IMV_ACTION_RECOMMENDATION_ALLOW;
        //
        //        // set evaluation (see TNC_IMV_EVALUATION_RESULT_...)
        //        evaluationResult = TNC_IMV_EVALUATION_RESULT_DONT_KNOW;

        //验证签名！标准值来自于：已知进程hash+nonce
        translate2chars(temp_buf,20);
        std::stringstream ss;
        ss.write((const char *)message, length);
        std::vector<prop_type> properties = readAllProperties(ss);

	LOG4CXX_INFO(logger, "good file-hash signature :-)" );
        
	validationFinished = true;
        actionRecommendation = TNC_IMV_ACTION_RECOMMENDATION_ALLOW;
        evaluationResult = TNC_IMV_EVALUATION_RESULT_DONT_KNOW;
        free(temp_buf);

    }

    // return all ok
    return TNC_RESULT_SUCCESS;
}

int ProcwatcherIMV:: calculateHash(std::vector<FileEntry> &entry)
{
    //再拼接在stringstream：：temp—_hashAll中
    std::stringstream temp_hashAll;
    //首先，计算n*(hash+nonce)，也就是拼接起来
    for(int i=0;i<entry.size();i++)
    {
        printf("value len:%d and file len %d \n",strlen(entry[i].value),strlen(entry[i].file));
        //首先将nonce拼接在每一个文件的hash后面
        memcpy((char *)(entry[i].value + 40),(char *)nonceBuf,20);
        //再拼接在stringstream：：temp—_hashAll中
        temp_hashAll << entry[i].file << "\n" << entry[i].value << "\n";
    }
    //然后，对以上拼接的值做哈希
    //首先要转成适合SHA1的char*形式
    std::string mid = temp_hashAll.str();
    char *hashAllMid = (char *)malloc(mid.length() + 1);
    const char* temp;
    temp = mid.c_str();
    strcpy(hashAllMid,temp);
    
    //然后做SHA1
    LOG4CXX_DEBUG(logger,"hou cal by imv,before:" << hashAllMid);
    SHA1((unsigned char*)hashAllMid,strlen(hashAllMid),hashAll);
    printf("%d\n",strlen(hashAllMid));
    translate2chars((char *)hashAll,SHA1_LENGTH);
    
    //为了使用标准的Tspi函数，尼玛我只好再哈希一次
    memset(digest,0,20);
    SHA1((unsigned char*)hashAll,40,digest);
    
    LOG4CXX_DEBUG(logger,"cal by imv,after:" << hashAll);
    printf("digest from imv:%slala\n",digest);
    free(hashAllMid);
    return 0;
}
bool ProcwatcherIMV::checkClientKnown()
{
    LOG4CXX_TRACE(logger, "checkClientKnown()");
    char                hex[4];     /*  to store a hex digit      */
    std::string         strfp;      /*  string for fingerprint */
    unsigned int            x509digestLen;
    unsigned char           md[EVP_MAX_MD_SIZE];
    const EVP_MD            *sha1Digest = EVP_sha1();
    X509_digest(x509Cert, sha1Digest, md, &x509digestLen);

    LOG4CXX_DEBUG(logger, "Size of fingerprint:" << x509digestLen);

    for (unsigned int j = 0; j < x509digestLen; j++) {
        snprintf(hex, 4, "%02X%s", md[j],
                (j != (x509digestLen - 1)) ? ":" : "");
        strfp.append(hex);
    }

    LOG4CXX_DEBUG(logger, "The fingerprint: " << strfp);

    return policyManager->isAikKnown(strfp);
}

int ProcwatcherIMV::processFirstMessage(TNC_BufferReference message, TNC_UInt32 length)
{
    LOG4CXX_TRACE(logger, "processFirstMessage()");
    if (loadX509Cert(message, length) < 0) {
        LOG4CXX_FATAL(logger, "Could not create X509"
                " certificate object");
        nothingWrong = false;
        return -1;                      /*  return */
    }

    if (loadPKey() < 0) {
        LOG4CXX_FATAL(logger, "Could not create EVP_PKEY object");
        nothingWrong = false;
        return -1;                  /*  return */
    }

    if (loadRSA() < 0) {
        LOG4CXX_FATAL(logger, "Could not create RSA object");
        nothingWrong = false;
        return -1;                      /*  return */
    }
    return 0;
}


int ProcwatcherIMV::loadPKey(void)
{
    LOG4CXX_TRACE(logger, "loadPKey()");
    pKey = X509_get_pubkey(x509Cert);

    if (pKey == NULL)
        return -1;
    return 0;
}



int ProcwatcherIMV::loadRSA(void)
{
    LOG4CXX_TRACE(logger, "loadRSA()");
    rsa = EVP_PKEY_get1_RSA(pKey);

    if (rsa == NULL)
        return -1;
    return 0;
}

bool ProcwatcherIMV::isASN1(TNC_BufferReference message, TNC_UInt32 length)
{
    unsigned char tag, n, *p;
    TNC_UInt32 len = 0;

    if (length < 2)
    {
        return false;
    }
    length -= 2;

    /*  start ASN.1 parsing at the head of the message */
    p = (unsigned char *)message;

    /*  check if tag is an ASN1_SEQUENCE */
    tag = *p++;
    if (tag != (V_ASN1_CONSTRUCTED | V_ASN1_SEQUENCE))
    {
        return false;
    }

    /*  is there a single length byte? */
    n = *p++;
    if (!(n & 0x80))
    {
        return (n == length);   
    }
    n &= 0x7f;

    if (n > length || n > 4)
    {
        return false;
    }
    length -= n;

    /*  compute length from n length bytes */
    while (n--)
    {
        len = (len << 8) + *p++; 
    }
    return (len == length);
}



int ProcwatcherIMV::loadX509Cert(TNC_BufferReference message, TNC_UInt32 length)
{
    LOG4CXX_TRACE(logger, "loadX509Cert()");

    BIO *bio = BIO_new_mem_buf(message, length);

    if (bio == NULL) {
        LOG4CXX_FATAL(logger, "Could not create BIO object");
        return -1;
    }
    if (isASN1(message, length)) {
        x509Cert = d2i_X509_bio(bio, NULL);
    } else {
        x509Cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    }
    if (x509Cert == NULL) {
        LOG4CXX_FATAL(logger, "Could not create X509 object");
        BIO_free(bio);
        return -1;
    }
    LOG4CXX_INFO(logger, "X509 certificate successfully received");
    BIO_free(bio);
    return 0;
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
TNC_Result ProcwatcherIMV::batchEnding()
{
    LOG4CXX_TRACE(logger, "batchEnding");
    // return all ok
    return TNC_RESULT_SUCCESS;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
TNC_Result ProcwatcherIMV::notifyConnectionChange()
{
    LOG4CXX_TRACE(logger, "notifyConnectionChange");

    /* if new handshake start */
    if(this->getConnectionState() == TNC_CONNECTION_STATE_HANDSHAKE)
        /* reset IMC */;

    // return all ok
    return TNC_RESULT_SUCCESS;
}


/* 
 * Below two functions are used to read policy files and return properties
 * */
bool ProcwatcherIMV::readLine(std::istream &in, char *buf, const int size)
{
    bool ret = in.getline(buf, size);
    if (ret && buf[strlen(buf) - 1] == '\r') {
        buf[strlen(buf) - 1] = '\0';
    }
    return ret;
}

std::vector<ProcwatcherIMV::prop_type> ProcwatcherIMV::readAllProperties(std::istream &in)
{
    std::vector<prop_type> properties;

    in.clear();
    in.seekg(0, std::ios::beg);

    unsigned int buf_len = 1024;
    char buf[buf_len];
    int readfh = 0;
    std::string filename, hash;

    while (readLine(in, buf, buf_len)) {
        std::string line(buf);

        //		/* ignore comments */
        //		if (line.size()<1 || line.at(0)=='#')
        //			continue;
        //
        //        /*
        //         * the format of the policy file should be :
        //         *   # here is the comment
        //         *   f=
        //         *   h=
        //         *   ...
        //         * f means filename, h means hash
        //         */ 
        //        size_t pos = line.find_first_of('=');
        //
        //        /* ignore illegal lines */
        //        if (pos == std::string::npos)
//        	continue;
//
        if(!readfh)
            /* get filename*/
            filename = line;
        else
            /* get hash */
            hash = line;

        readfh ^= 1;

        if(readfh) continue;

        /* debug */
        LOG4CXX_DEBUG(logger, "filename:\"" << filename  << "\" hash:\"" << hash << "\"");

        /* add key-value-pair */
        properties.push_back( prop_type (filename, hash) );
    }

    return properties;
}
