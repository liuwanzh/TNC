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
 
#include "ExampleIMC.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <log4cxx/logger.h>
#include <set>

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/sha.h>

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("IMUnit.AbstractIMUnit.AbstractIMC.ExampleIMC"));

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
ExampleIMC::ExampleIMC(TNC_ConnectionID conID, ExampleIMCLibrary *pExampleIMCLibrary)
	:AbstractIMC(conID, pExampleIMCLibrary)
{
	buf = new char[50];
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
ExampleIMC::~ExampleIMC()
{
	// if necessary delete memory
	LOG4CXX_TRACE(logger, "Destructor");
	delete[] buf;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
TNC_Result ExampleIMC::beginHandshake()
{
	LOG4CXX_TRACE(logger, "beginHandshake()");

	// this message should be send to ExampleIMV
	std::string sendMessage("Example message from ExampleIMC");

	LOG4CXX_TRACE(logger, "Send Message: " << sendMessage);
	// send message
	this->tncc.sendMessage((unsigned char*)sendMessage.c_str(), sendMessage.size()+1/*for'\0'*/, VENDOR_ID, MESSAGE_SUBTYPE);

	// return all ok
	return TNC_RESULT_SUCCESS;
}


/* 
 * functions for Policy class
 */
ExampleIMC::Policy::Policy(){paths.clear();}
void ExampleIMC::Policy::init(){paths.clear();}
void ExampleIMC::Policy::add(std::string path){paths.push_back(path);}
bool ExampleIMC::Policy::find(std::string cmd){ for (int i=0;i<paths.size();++i) if(cmd.find(paths[i]) == 0) return true;  return false; }

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  read_policy
 *  Description:  
 * =====================================================================================
 */
    void 
ExampleIMC::read_policy (  )
{
    const char * protectdir[] = {"/bin","/sbin","/usr/bin"};
    int i;

    policy.init();

    for(i=0;i<sizeof(protectdir)/sizeof(protectdir[0]);i++){
       policy.add(protectdir[i]);
    }
}		/* -----  end of function read_policy  ----- */


void translate2chars(char * buf)
{
    int i;
    unsigned char digest[SHA1_LENGTH];
    memcpy(digest, buf, sizeof(digest));
    for(i=0;i<SHA1_LENGTH;++i)
        sprintf(buf+2*i,"%02X", *(digest + i) & 0xFF);
    buf[2*SHA1_LENGTH] = 0;

}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  find_matched
 *  Description:  
 * =====================================================================================
 */
    void
ExampleIMC::find_matched ( std::stringstream &ss)
{
    dirent *entry;
    DIR *dir;
    char path[256];
    int MAX=1024;
    char buf[MAX];
    
    std::set<std::string> procset;

    /*  open '/proc' directory */
    if( (dir = opendir("/proc")) == NULL ) {
        LOG4CXX_DEBUG(logger, "Unable to open '/proc' ");
        return;
    }

    while ( (entry = readdir(dir)) != NULL) {

       if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {

             /*  every number or dir-name in the /proc directory is the identity of a process */
             /*  cmdline shows what makes the startup of the process */
             sprintf( path,"/proc/%s/exe", entry->d_name);
             
             memset(buf,0,MAX);
             readlink(path,buf,MAX);
             strcpy(path,buf);
             if( policy.find( path ) && procset.find(path) == procset.end() ){
                procset.insert(path);
                calculate_hash_by_fd(path, (unsigned char*) buf);
                translate2chars(buf);
                LOG4CXX_DEBUG(logger, "path=" << path << " buf=" << buf);

                ss << path << "\n" << buf <<"\n";
             }
       } 
    }

}		/* -----  end of function find_matched  ----- */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
TNC_Result ExampleIMC::receiveMessage(TNC_BufferReference message,
		                          TNC_UInt32 messageLength,
		                          TNC_MessageType messageType)
{
	LOG4CXX_DEBUG(logger, "receiveMessage round " << this->getRound());

	// print received message dirty out. WARNING: don't ape this,
	// message should end with non-null! Heed: Message can be evil!
	LOG4CXX_INFO(logger, "Received Message: " << message);

	// this message should be send to ExampleIMV
	//std::string sendMessage("Another example message from ExampleIMC.");

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


    read_policy();

    std::stringstream ss;
    find_matched(ss);
    
    std::string sendString = ss.str();
    LOG4CXX_DEBUG(logger, "Send Message: Length = " << sendString.size() << " Bytes.");

    this->tncc.sendMessage((unsigned char*)sendString.c_str(), sendString.size()+1, VENDOR_ID, MESSAGE_SUBTYPE); 

	return TNC_RESULT_SUCCESS;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
TNC_Result ExampleIMC::batchEnding()
{
	LOG4CXX_TRACE(logger, "batchEnding");
	// return all ok
	return TNC_RESULT_SUCCESS;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
TNC_Result ExampleIMC::notifyConnectionChange()
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
ExampleIMC::calculate_hash_by_fd(char *filename, unsigned char *sha)
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
