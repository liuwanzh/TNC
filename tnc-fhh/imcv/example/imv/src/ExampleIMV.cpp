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
 
#include "ExampleIMV.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <log4cxx/logger.h>

#include <stdlib.h>
#include <string.h>

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("IMUnit.AbstractIMUnit.AbstractIMC.ExampleIMV"));

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
ExampleIMV::ExampleIMV(TNC_ConnectionID conID, ExampleIMVLibrary *pExampleIMVLibrary)
	:AbstractIMV(conID, pExampleIMVLibrary)
{
	// initialize
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
ExampleIMV::~ExampleIMV()
{
	// if necessary delete memory
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
TNC_Result ExampleIMV::receiveMessage(TNC_BufferReference message,
		                          TNC_UInt32 messageLength,
		                          TNC_MessageType messageType)
{
	LOG4CXX_DEBUG(logger, "receiveMessage round " << this->getRound());

	// print received message dirty out. WARNING: don't ape this,
	// message should end with non-null! Heed: Message can be evil!
	LOG4CXX_INFO(logger, "Received Message: " << message);

	/* only send one message to ExampleIMC */
	if (this->getRound() < 1) {
		// this message should be send to ExampleIMC
		std::string sendMessage("Example message from ExampleIMV");

		LOG4CXX_INFO(logger, "Send Message: " << sendMessage);
		// send message
		this->tncs.sendMessage((unsigned char*)sendMessage.c_str(), sendMessage.size()+1/*for'\0'*/, VENDOR_ID, MESSAGE_SUBTYPE);
	} else {
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

        std::stringstream ss;
        ss.write((const char *)message, messageLength);
        std::vector<prop_type> properties = readAllProperties(ss);
        
         

        validationFinished = true;
        actionRecommendation = TNC_IMV_ACTION_RECOMMENDATION_ALLOW;
        evaluationResult = TNC_IMV_EVALUATION_RESULT_DONT_KNOW;
	}

	// return all ok
	return TNC_RESULT_SUCCESS;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
TNC_Result ExampleIMV::batchEnding()
{
	LOG4CXX_TRACE(logger, "batchEnding");
	// return all ok
	return TNC_RESULT_SUCCESS;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
TNC_Result ExampleIMV::notifyConnectionChange()
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
bool ExampleIMV::readLine(std::istream &in, char *buf, const int size)
{
    bool ret = in.getline(buf, size);
    if (ret && buf[strlen(buf) - 1] == '\r') {
        buf[strlen(buf) - 1] = '\0';
    }
    return ret;
}

std::vector<ExampleIMV::prop_type> ExampleIMV::readAllProperties(std::istream &in)
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
