 /* (University of Applied Sciences and Arts, Hannover)
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
#include "ProcwatcherIMC.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <log4cxx/logger.h>
#include <set>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/sha.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#define PROCWATCHERIMC_X509_CERT        "x509_certificate_file"
#define PROCWATCHERIMC_AIK_KEY          "aik_key_file"

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("IMUnit.AbstractIMUnit.AbstractIMC.ProcwatcherIMC"));

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*  macro which returns -1 if a is not TSS_RESULT
 *   * c represents the cleanup function to be called
 *    * before returning
 *     */

#define CHECK_TSS_RETURN(a, b, c)                       \
    do {                                    \
        if (a != TSS_SUCCESS) {                     \
            if (b != NULL)                      \
            LOG4CXX_FATAL(logger, b);           \
            LOG4CXX_FATAL(logger, Trspi_Error_String(a));       \
            c();                            \
            return -1;                      \
        }                               \
    } while (0);


static void noop()
{
    return;
}
void ProcwatcherIMC::cleanup1(void) {
        Tspi_Context_Close(hContext);
}

void ProcwatcherIMC::cleanup2(void) {
        Tspi_Context_CloseObject(hContext, hSRK);
            cleanup1();
}

void ProcwatcherIMC::cleanup3(void) {
        Tspi_Context_CloseObject(hContext, srkPolicy);
            cleanup2();
}

void ProcwatcherIMC::cleanup4(void) {
        Tspi_Context_CloseObject(hContext, hAIK);
            cleanup3();
}

void ProcwatcherIMC::cleanup5(void) {
        Tspi_Context_CloseObject(hContext, hTPM);
            cleanup4();
}

    ProcwatcherIMC::ProcwatcherIMC(TNC_ConnectionID conID, ProcwatcherIMCLibrary *pProcwatcherIMCLibrary)
:AbstractIMC(conID, pProcwatcherIMCLibrary)
{
    buf = new char[500];

    certificate = NULL;
    aikBlob = NULL;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
ProcwatcherIMC::~ProcwatcherIMC()
{
	// if necessary delete memory
    LOG4CXX_TRACE(logger, "Destructor");
    delete[] buf;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
TNC_Result ProcwatcherIMC::beginHandshake()
{
    LOG4CXX_TRACE(logger, "beginHandshake()");

    // this message should be send to ProcwatcherIMV
    //	std::string sendMessage("Procwatcher message from ProcwatcherIMC");

    if (loadConfigFile() < 0) {
        LOG4CXX_FATAL(logger, "BAD loadConfigFile()");
        return TNC_RESULT_FATAL;
    }

    if (loadX509Certificate() < 0) {
        LOG4CXX_FATAL(logger, "BAD loadX509Certificate()");
        return TNC_RESULT_FATAL;
    }
    if (loadAikBlob() < 0) {
        LOG4CXX_FATAL(logger, "BAD loadAikBlob()");
        return TNC_RESULT_FATAL;
    }

    if (initTpmStuff() < 0) {
        LOG4CXX_FATAL(logger, "Could not init TPM stuff");
        cleanup5();
        return TNC_RESULT_FATAL;
    }
    initialized = true;
    LOG4CXX_TRACE(logger, "Send certificate: " << certificate);
    // send message
    //this->tncc.sendMessage((unsigned char*)sendMessage.c_str(), sendMessage.size()+1/*for'\0'*/, VENDOR_ID, MESSAGE_SUBTYPE);
    this->tncc.sendMessage(certificate, certificateLength,VENDOR_ID,MESSAGE_SUBTYPE);
    // return all ok
    certificateSent = true;
    return TNC_RESULT_SUCCESS;
}

int ProcwatcherIMC::initTpmStuff() {

    TSS_UUID srkUuid = TSS_UUID_SRK;
    BYTE wks[] = TSS_WELL_KNOWN_SECRET;
    TSS_RESULT res;
    res = Tspi_Context_Create(&hContext);
    printf("liuwanzh1\n");
    CHECK_TSS_RETURN(res, "Context_Create", noop);
    res = Tspi_Context_Connect(hContext, NULL);
    printf("liuwanzh1\n");
    CHECK_TSS_RETURN(res, "Context_Connect", cleanup1);
    res = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
            srkUuid, &hSRK);
    printf("liuwanzh1\n");
    CHECK_TSS_RETURN(res, "Load_SRK", cleanup1);
    res = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkPolicy);
    printf("liuwanzh1\n");
    CHECK_TSS_RETURN(res, "Get_SRK_Policy", cleanup2);
    res = Tspi_Policy_SetSecret(srkPolicy, TSS_SECRET_MODE_SHA1, 20, wks);
    printf("liuwanzh1\n");
    CHECK_TSS_RETURN(res, "Set_SRK_Secret", cleanup2);
    res = Tspi_Context_LoadKeyByBlob(hContext, hSRK, aikBlobLength, aikBlob, &hAIK);
    printf("liuwanzh2\n");
    CHECK_TSS_RETURN(res, "Load aik blob", cleanup3);
    printf("liuwanzh1\n");
    res = Tspi_Context_GetTpmObject(hContext, &hTPM);
    CHECK_TSS_RETURN(res, "Get_TPM_Object", cleanup4);

    return 0;
}

int ProcwatcherIMC::loadX509Certificate(void)
{
    if (certificate != NULL) {
        delete[] certificate;

        certificate = NULL;
    }
    certificateLength = loadBlobToBuf(&certificate, certificateFile.c_str());
    if (certificateLength < 0) {
        LOG4CXX_FATAL(logger, "Failed to load certifciate!");
    }
    return certificateLength;
}

int ProcwatcherIMC::loadAikBlob()
{
    if (aikBlob != NULL) {
        delete[] aikBlob;
    }
    aikBlobLength = loadBlobToBuf(&aikBlob, aikBlobFile.c_str());
    if (aikBlobLength < 0) {
        LOG4CXX_FATAL(logger, "Failed to load AIK blob!");
    }
    return aikBlobLength;
}


/*
 *  * Read a file into buffer... Allocating as much memory as needed.
 *   */
int ProcwatcherIMC::loadBlobToBuf(TNC_BufferReference *buf, const char *filename)
{
    int len;
    LOG4CXX_TRACE(logger, "open file: " << filename);
    ifstream file(filename, ios::binary);

    if (file.is_open()) {
        file.seekg(0, ios::end);
        len = file.tellg();
        file.seekg(0, ios::beg);
        LOG4CXX_TRACE(logger, "Requesting " << len << " bytes buffer");
        *buf = new TNC_Buffer[len];
        file.read((char *)(*buf), len);
        file.close();
    } else {
        LOG4CXX_FATAL(logger, "Could not open file " << filename);
        len = -1;
    }
    return len;
}

/*function:loadConfigFile(),获得AIK证书存储目录*/
int ProcwatcherIMC::loadConfigFile()
{
    LOG4CXX_TRACE(logger, "loadConfigFile()");
    ifstream cfgfile("/etc/tnc/procwatcherimc.file");
    string line;

    if (cfgfile.is_open()) {
        while (!cfgfile.eof()) {
            getline(cfgfile, line);
            processConfigLine(line);
        }
    } else {
        LOG4CXX_FATAL(logger, "Could not open " << "/etc/tnc/procwatcherimc.file");
        return -1;
    }

    LOG4CXX_TRACE(logger, "Certificate File = " << certificateFile);
    LOG4CXX_TRACE(logger, "AikBlob File     = " << aikBlobFile);

    if (certificateFile.length() == 0 || aikBlobFile.length() == 0) {
        LOG4CXX_FATAL(logger, "Failed parsing config file!");
        return -1;
    }

    return 0;
}

/* function:processConfigLine(),读配置文件/etc/tnc/procwatcherimc.file
 * 里的每一行，得到AIK证书outcert，及AIK公钥outkey
 */
int ProcwatcherIMC::processConfigLine(string configLine)
{    LOG4CXX_TRACE(logger, "processConfigLine()");

    if (!(configLine.length() > 0)) {
        LOG4CXX_DEBUG(logger, "Found empty line");

    } else if (configLine.at(0) == '#') {
        LOG4CXX_DEBUG(logger, "Found comment line");

    } else if (!configLine.compare(0, strlen(PROCWATCHERIMC_X509_CERT),
             PROCWATCHERIMC_X509_CERT)) {
        LOG4CXX_DEBUG(logger, "process certificate entry");
        processCertificateLine(configLine);

    } else if (!configLine.compare(0, strlen(PROCWATCHERIMC_AIK_KEY),
                PROCWATCHERIMC_AIK_KEY)) {
        LOG4CXX_DEBUG(logger, "process aik key entry");
        processAikKeyLine(configLine);

    } else {
        LOG4CXX_WARN(logger, "Found unknown entry in config");
    }

    return 0;
}

/* processCertificateLine(),读AIK证书 */
void ProcwatcherIMC::processCertificateLine(string line)
{
    unsigned int i;
    if ((i = line.find_first_of(' ')) != std::string::npos) {
        certificateFile = line.substr(i+1, line.length() - (i + 1));
        LOG4CXX_INFO(logger, "Certificate File = " << certificateFile);
    }
}

void ProcwatcherIMC::processAikKeyLine(string line)
{
    unsigned int i;
    if ((i = line.find_first_of(' ')) != std::string::npos) {
        aikBlobFile = line.substr(i+1, line.length() - (i + 1));
        LOG4CXX_INFO(logger, "AikBlob File = " << aikBlobFile);
    }
}
/* 
 * functions for Policy class
 */
ProcwatcherIMC::Policy::Policy(){paths.clear();}
void ProcwatcherIMC::Policy::init(){paths.clear();}
void ProcwatcherIMC::Policy::add(std::string path){paths.push_back(path);}
bool ProcwatcherIMC::Policy::find(std::string cmd){ for (int i=0;i<paths.size();++i) if(cmd.find(paths[i]) == 0) return true;  return false; }

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  read_policy
 *  Description:  
 * =====================================================================================
 */
    void 
ProcwatcherIMC::read_policy (  )
{
    //FIX:这里可以加上策略选择，让服务器发过来需要度量的目录列表。在此简化，默认只看/bin
    const char * protectdir[] = {"/bin"};
    int i;

    policy.init();

    for(i=0;i<sizeof(protectdir)/sizeof(protectdir[0]);i++){
        policy.add(protectdir[i]);
    }
}		/* -----  end of function read_policy  ----- */


void translate2chars(char * buf,int length)
{
    int i;
    unsigned char digest[length];
    memcpy(digest, buf, sizeof(digest));
    for(i=0;i<length;++i)
        sprintf(buf+2*i,"%02X", *(digest + i) & 0xFF);
    buf[2*(length)] = 0;

}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  find_matched
 *  Description:  
            * =====================================================================================
 */
    void
ProcwatcherIMC::find_matched ( std::stringstream &ss)
{
    dirent *entry;
    DIR *dir;
    char path[256];
    int MAX=1024;
    char temp_buf[MAX];
    char *temp_buffer2 = (char *)malloc(61);

    std::set<std::string> procset;

    /*  open '/proc' directory */
    if( (dir = opendir("/proc")) == NULL ) {
        LOG4CXX_DEBUG(logger, "Unable to open '/proc' ");
        return;
    }

    while ( (entry = readdir(dir)) != NULL) {

        memset(temp_buffer2,0,60);
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {

            /*  every number or dir-name in the /proc directory is the identity of a process */
            /*  cmdline shows what makes the startup of the process */
            sprintf( path,"/proc/%s/exe", entry->d_name);
            memset(temp_buf,0,MAX);
            readlink(path,temp_buf,MAX);
            strcpy(path,temp_buf);
            if( policy.find( path ) && procset.find(path) == procset.end() ){
                procset.insert(path);
                calculate_hash_by_fd(path, (unsigned char*) temp_buf);
                memcpy(temp_buffer2,(char *)temp_buf, SHA1_LENGTH);
                translate2chars(temp_buffer2,SHA1_LENGTH);
                //拼接nonce
                memcpy((char *)(temp_buffer2+ 2 *SHA1_LENGTH),(char *)nonce, 20);
                temp_buffer2[60]=0;
                printf("len value %d and len file %d\n",strlen(temp_buffer2),strlen(path));
                //translate2chars(temp_buf,SHA1_LENGTH+20);
                ss << path << "\n" << temp_buffer2 <<"\n";
            }
        }
    }
    free(temp_buffer2); 
}
/* -----  end of function find_matched  ----- */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
TNC_Result ProcwatcherIMC::receiveMessage(TNC_BufferReference message,
		                          TNC_UInt32 messageLength,
		                          TNC_MessageType messageType)
{
    //收到服务器发来的nonce后，拼接到hash（文件）的后面，签名后再发过去
	LOG4CXX_DEBUG(logger, "receiveMessage round " << this->getRound());

	// print received message dirty out. WARNING: don't ape this,
	// message should end with non-null! Heed: Message can be evil!
    LOG4CXX_INFO(logger, "imcReceived Message: " << message);

	// this message should be send to ProcwatcherIMV
	//std::string sendMessage("Another example message from ProcwatcherIMC.");

//    std::string filename = "/bin/ls\n";
//	std::string sendMessage = "filename="+ filename;
//
//	LOG4CXX_INFO(logger, "Send Message: " << sendMessage);
//
//    std::string hash = "0\n";
//	sendMessage += "hash="+ hash;
//
//	LOG4CXX_INFO(logger, "Send Message: " << sendMessage);
//	// send message
//	this->tncc.sendMessage((unsigned char*)sendMessage.c_str(), sendMessage.size()+1/*for'\0'*/, VENDOR_ID, MESSAGE_SUBTYPE);
    nonce=new unsigned char[20];
    memcpy(nonce,message,20);
    TNC_Buffer *digest = new unsigned char[20];
    read_policy();
    std::stringstream ss;
    find_matched(ss);
    

    //将ss转换成char *形式
    std::string sendString = ss.str();
    char *hashFile = (char *)malloc(sendString.length()+ 1);
    const char *temp;
    temp=sendString.c_str();
    strcpy(hashFile,temp);
    //hashFile=(char *)sendString.c_str();


    //对sendString做哈希
    //将收到的nonce附加在sendString的后面
    //用AIK私钥做签名，再发过去。
    LOG4CXX_DEBUG(logger, "Send Message before hash: Length = " << sendString.size() << " Bytes.");
    SHA1((unsigned char*)hashFile,strlen(hashFile),digest);
    //memset(hashFile,0,1024);
    //strcpy(hashFile,(char *)digest);
    //translate2chars(hashFile,SHA1_LENGTH);
    char *temp_buffer=(char *)malloc(1024);
    strcpy(temp_buffer,(char *)digest);
    translate2chars(temp_buffer,SHA1_LENGTH);
    LOG4CXX_DEBUG(logger,"after hash,files turn to:"<<temp_buffer);
    memset(digest,0,20);
    SHA1((unsigned char*)temp_buffer,strlen(temp_buffer),digest);
    printf("digest from imc:%s\n",digest);

    TSS_HHASH hHash;
    BYTE *sig;
    UINT32 sigLen,digestLen = 20;

    Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_HASH,TSS_HASH_SHA1,&hHash);
    Tspi_Hash_SetHashValue(hHash,digestLen,(BYTE *)digest);
    Tspi_Hash_Sign(hHash,hAIK,&sigLen,&sig);
    /* 
       if(TSS_SUCCESS==Tspi_Hash_VerifySignature(hHash,hAIK,sigLen,sig))
       {
       printf("yeah!\n");
       }

    int length;
    if (1 != RSA_verify(NID_sha1, sig, 20, digest, length, rsa)) {
        LOG4CXX_FATAL(logger, "Bad signature :-(");
        nothingWrong = false;
        tncs.provideRecommendation(TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS,
                TNC_IMV_EVALUATION_RESULT_COMPLIANT);
        return TNC_RESULT_SUCCESS;
    }
*/
    this->tncc.sendMessage(digest, SHA_DIGEST_LENGTH, VENDOR_ID, MESSAGE_SUBTYPE); 
    free(hashFile);
    free(temp_buffer);
    hashFile = NULL;
    delete[] digest;
    return TNC_RESULT_SUCCESS;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
TNC_Result ProcwatcherIMC::batchEnding()
{
    LOG4CXX_TRACE(logger, "batchEnding");
    // return all ok
    return TNC_RESULT_SUCCESS;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
TNC_Result ProcwatcherIMC::notifyConnectionChange()
{
    LOG4CXX_TRACE(logger, "notifyConnectionChange");

    /* if new handshake start */
    if(this->getConnectionState() == TNC_CONNECTION_STATE_HANDSHAKE)
        /* reset IMC */;

    // return all ok
    return TNC_RESULT_SUCCESS;
}


/* 
 * -filename is the filename of the file that would be hashed
 * -sha array is the SHA1 hash. unsigned char sha[SHA1_LENGTH];
 * */
    int 
ProcwatcherIMC::calculate_hash_by_fd(char *filename, unsigned char *sha)
{
    size_t n;
    int fd;

    fd = open(filename,O_RDONLY);


    memset(sha, 0, SHA1_LENGTH);
    while (1) {
        memset(buffer, 0, BLOCKSIZE);
        n = read(fd, buffer, BLOCKSIZE - SHA1_LENGTH);
        if ( n == -1 ) { 
            LOG4CXX_DEBUG(logger, "Read file error!");
            return -1;
        }

        if ( n == BLOCKSIZE - SHA1_LENGTH ) {
            memcpy(buffer + BLOCKSIZE - SHA1_LENGTH, sha, SHA1_LENGTH);
            SHA1( buffer, BLOCKSIZE, sha );
        } else {
            memcpy(buffer + n, sha, SHA1_LENGTH);
            SHA1( buffer, BLOCKSIZE, sha );
            break;
        }
    }
    //display_sha1_digest(sha);  
    close(fd);
    return 0;
}
