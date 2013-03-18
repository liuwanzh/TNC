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
 

#include "ProcwatcherIMVPolicyManager.h"

/* log4cxx includes */
#include "log4cxx/logger.h"
using namespace log4cxx;
using namespace std;

/* our logger */
static LoggerPtr
logger(Logger::getLogger("ProcwatcherIMVPolicyManager"));

#include <sstream>
#include <iomanip>
#include <string.h>
#include <stdio.h>
#include <fstream>
#include <algorithm> // std::remove

#define min(a,b) (a>b ? b:a)

namespace tncfhh {

namespace iml {

PcrEntry::PcrEntry(unsigned int index, std::string valueAsString)
	:index(index), valueAsString(valueAsString)
{
	stringToByteArray(valueAsString);
}

FileEntry::FileEntry(char * a,char * b)
{
    memset(value,0,256);
    memset(file,0,50);
    memcpy(file,a,min(50, strlen(a)));
    memcpy(value,b,40);
}
FileEntry::FileEntry()
{

}
FileEntry::FileEntry(const FileEntry &b)
{
    memcpy(this->value, b.value, 256);
    memcpy(this->file, b.file, 50);
}
FileEntry::~FileEntry()
{

}
   
void PcrEntry::stringToByteArray(const std::string &valueAsString)
{
	unsigned int sha1SizeAsString = 40;
	// check if size matches SHA-1
	if(valueAsString.size() != sha1SizeAsString)
	{
		LOG4CXX_WARN(logger, "PcrEntry valueAsString must be 40 characters long, but length is " << valueAsString.size());
		memset(value, 0, sha1SizeAsString/2);
		index = 0;
		this->valueAsString = "0000000000000000000000000000000000000000";
	} else { // size is OK
		std::stringstream ss(valueAsString);
		// go through characters
		for (unsigned int i = 0; i < valueAsString.size()/2; i++) {
			char c1, c2;
			uint8_t d1, d2;

			// read two characters per loop
			ss >> c1 >> c2;
			// convert characters to uint8_t
			// code taken from http://www.codeguru.com/forum/showthread.php?t=316299
			if(isdigit(c1)) d1 = c1 - '0';
			else if(c1>='A' && c1<='F') d1 = c1 - 'A' + 10;
			else if(c1>='a' && c1<='f') d1 = c1 - 'a' + 10;
			if(isdigit(c2)) d2 = c2 - '0';
			else if(c2>='A' && c2<='F') d2 = c2 - 'A' + 10;
			else if(c2>='a' && c2<='f') d2 = c2 - 'a' + 10;

			// save value of two characters in one byte
			value[i] = d1*16 + d2;
		}
	}
}

PcrEntry::~PcrEntry()
{
	// intentionally left blank
}


ProcwatcherIMVPolicyManager::ProcwatcherIMVPolicyManager(const char *policyFile)
{
	LOG4CXX_TRACE(logger, "ProcwatcherIMVPolicyManager()");
    temp_line=(char *)malloc(1024);
	parsePolicy(policyFile);
}

ProcwatcherIMVPolicyManager::~ProcwatcherIMVPolicyManager()
{
    free (temp_line);
    
	LOG4CXX_TRACE(logger, "~ProcwatcherIMVPolicyManager");
}

void ProcwatcherIMVPolicyManager::parsePolicy(const char * policyFile)
{
	LOG4CXX_DEBUG(logger, "Parsing policy file " << policyFile);

	// clear old entries
	this->pcrEntries.clear();
	this->knownAiks.clear();
    this->fileEntries.clear();

	std::ifstream file(policyFile);
	std::string line;

	// read file
	if(file.is_open()){
		while (std::getline(file, line)) {
			parsePolicyLine(line);
		}
//        LOG4CXX_DEBUG(logger,"file0:" << fileEntries[0].file << "hash:" << fileEntries[0].value);
	} else {
		LOG4CXX_WARN(logger, "Could not open file!");
	}
	file.close();

    for(unsigned int i=0;i<this->fileEntries.size();++i) {
        LOG4CXX_DEBUG(logger,"file" << fileEntries[i].file << " hash" << fileEntries[i].value);
    }
	for (unsigned int i = 0; i < this->knownAiks.size(); ++i) {
		LOG4CXX_TRACE(logger, "AIK " << i << " " << knownAiks[i]);
	}

	for (unsigned int i = 0; i < this->pcrEntries.size(); ++i) {
		LOG4CXX_DEBUG(logger, "pcr" << (unsigned int) pcrEntries[i].index << " " << pcrEntries[i].valueAsString);
	}

	LOG4CXX_TRACE(logger, "quoteType = " << (quoteType == single ? "single" : "complete"));
}

void ProcwatcherIMVPolicyManager::parsePolicyLine(std::string &line)
{
	// remove any spaces
	line.erase(std::remove(line.begin(), line.end(), ' '), line.end());

	// skip empty lines
	if (line.length() == 0)
		return;
	// skip comments
	if (line[0] == '#')
		return;

	// in this version, there are three possible valid entries
	// pcr, aik, quoteType
    std::string sfile("/");
	std::string saik("aik");
	std::string spcr("pcr");
	std::string squoteType("quoteType");

    if(!line.compare(0, saik.size(), saik.c_str())) {
        // an aik line
        parsePolicyLineAik(line);
    } else if(!line.compare(0, spcr.size(), spcr.c_str())) {
        // an pcr line
        parsePolicyLinePcr(line);
    } else if (!line.compare(0, squoteType.size(), squoteType.c_str())) {
        // an quoteType line
        parsePolicyLineQuoteType(line);
    }
    else if (!line.compare(0,sfile.size(),sfile.c_str()))   {
        //an file hash line
        parsePolicyLineFile(line);
    }
    else {
        // an invalid line
        LOG4CXX_WARN(logger, "Invalid policy line: " << line);
    }
}

void ProcwatcherIMVPolicyManager::parsePolicyLineFile(std::string &line)
{
    int pos = line.find_first_of('=');
    this->temp_line=(char *)line.c_str();
     
    char temp_file[256];
    memcpy(temp_file,temp_line,pos);
    temp_file[pos]=0;
    char temp_hash[40];
    memset(temp_hash,0,40);
    memcpy(temp_hash,temp_line+pos+1,40);
    (this->fileEntries).push_back(FileEntry(temp_file,temp_hash));
    
}
void ProcwatcherIMVPolicyManager::parsePolicyLineAik(std::string &line)
{
    // format: aik=DC:30:E6:EA:F1:97:5D:90:E6:AE:D0:A3:C8:62:5C:61:93:9B:96:4B
    int pos = line.find_first_of('=');
    this->knownAiks.push_back(line.substr(pos+1));
}

void ProcwatcherIMVPolicyManager::parsePolicyLinePcr(std::string &line)
{
    unsigned int index;
    std::stringstream hashValue;
    int pos;
    std::stringstream ss;

    // format: pcrX=<20 byte SHA-1 hash as 40 characters ASCII string>
    pos = line.find_first_of('=');
    // get pcr index
    ss << line.substr(3, pos - 3);
    LOG4CXX_DEBUG(logger, "ss = " << ss.str());
    ss >> index;

    // get hash value
    hashValue << line.substr(pos+1);

    // save pcr entry
    this->pcrEntries.push_back(PcrEntry(index, hashValue.str()));

}

void ProcwatcherIMVPolicyManager::parsePolicyLineQuoteType(std::string &line)
{
    int pos;
    std::stringstream ss;

    // format: quoteType=complete
    //         quoteType=single
    pos = line.find_first_of('=');
    ss << line.substr(pos+1);
    if(!ss.str().compare("single")){
        quoteType = single;
    } else if (!ss.str().compare("complete")){
        quoteType = complete;
    } else {
        LOG4CXX_WARN(logger, "Invalid quoteType. Using 'complete' as default.");
        quoteType = complete;
    }
}


bool ProcwatcherIMVPolicyManager::isAikKnown(std::string fingerprint)
{
    LOG4CXX_TRACE(logger, "isAikKnown()lll");
    std::vector<std::string>::iterator it;
    it = find(this->knownAiks.begin(), this->knownAiks.end(), fingerprint);
    return it == this->knownAiks.end() ? false : true;
}

QuoteType ProcwatcherIMVPolicyManager::getQuoteType()
{
    LOG4CXX_TRACE(logger, "getQuoteType()");
    return this->quoteType;
}

std::vector<PcrEntry> ProcwatcherIMVPolicyManager::getPcrEntries()
{
    LOG4CXX_TRACE(logger, "getPcrEntries()");
    return this->pcrEntries;
}

std::vector<FileEntry> ProcwatcherIMVPolicyManager::getFileEntries()
{
	LOG4CXX_TRACE(logger, "getFileEntries()");
	return this->fileEntries;
}


} // namespace iml

} // namespace tncfhh

