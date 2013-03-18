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
 
/**
 * The tncsim program. It is primarily designed to test IMC/V pairs locally on
 * one endpoint. In its default configuration, tncsim uses libtnc as
 * TNCC and TNC@FHH as TNCS.
 * 
 * <h3>Changelog:</h3>
 * <ul>
 *   <li>16.07.2009 - first implementation (mbs)</li>
 *   <li>16.03.2010 - integrated tncsim from branches to tncfhh (ib)</li>
 *   <li>17.03.2010 - support for arbitrary tnc_config files (ib)</li>
 * </ul>
 *
 * @date 16.03.2010
 * @author Mike Steinmetz (mbs)
 * @author Ingo Bente (ib)
 */

#include <tncfhhConfig.h> // generated by cmake
#include <tncsimConfig.h> // generated by cmake

#include "server/AbstractTNCS.h"
#include "client/AbstractTNCC.h"

#include <iostream>
#include <iomanip>
#include <string>

using namespace tncsim;

namespace tncsim {

namespace server {
server::AbstractTNCS * getServer(std::string &tncConfig);
}


namespace client {
client::AbstractTNCC * getClient(std::string &tncConfig);
}

}

void printBinaryOut(const unsigned char * const packet, unsigned long packetLength, std::string text = "", std::ostream &cout = std::cout)
{
	std::string ascii;
	unsigned int i;

	cout << std::endl;
	cout << "###############################################################################" << std::endl;
	cout << std::endl << text << "(" << std::dec << packetLength << "):";
	for (i = 0; i < packetLength; ++i) {
		if (i%16 == 0) {
			cout << "   " << ascii << std::endl
			     << " " << std::setw(4) << std::setfill('0') << std::hex << i << "   ";
			ascii = "";
		} else if (i%8 == 0) {
			ascii += ' ';
			cout << " ";
		}

		cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(packet[i]) << " ";
		if (packet[i]>=' ' && packet[i] <= 'z')
			ascii += static_cast<char>(packet[i]);
		else
			ascii += '.';
	}
	while (i%16) {
		if (i%8 == 0) {
			cout << " ";
		}
		cout << "   ";
		i++;
	}
	cout << "   " << ascii << std::endl;
}


void printSeperate(const char * out) {
	std::cout << std::endl <<
	"###############################################################################" << std::endl <<
	"# " << out << std::endl <<
	"###############################################################################" << std::endl <<
	std::endl;
}

void printSeperateRound(const char * out, unsigned int r) {
	std::cout << std::endl <<
	"###############################################################################" << std::endl <<
	"# (" << r << ") " << out << std::endl <<
	"###############################################################################" << std::endl <<
	std::endl;
}

void printSeperateFinished(const char * out, TNC_IMV_Action_Recommendation r) {
	std::cout << std::endl <<
	"###############################################################################" << std::endl <<
	"# " << out << r << std::endl <<
	"###############################################################################" << std::endl <<
	std::endl;
}

int main(int argc, char **argv) {

	unsigned int round = 0;
	unsigned int maxRounds = 20;
	std::string tncConfig;

    // parse command line
    if(argc < 2){
            std::cout << "using " << TNCSIM_CONFIG << " as configuration file" << std::endl;
            tncConfig = TNCSIM_CONFIG;
    } else if (argc == 2){
            tncConfig = argv[1];
    } else {
            std::cout << "invalid arguments. usage: " << argv[0] << " <path-to-tnc_config>" << std::endl;
            return -1;
    }

    // version information
	std::cout << "tncsim version " << TNCFHH_VERSION_MAJOR << "." << TNCFHH_VERSION_MINOR << "." << TNCFHH_VERSION_PATCH << std::endl;

	printSeperate("init server");
	// init server
	server::AbstractTNCS * server = tncsim::server::getServer(tncConfig);

	printSeperate("init client");
	// init client
	client::AbstractTNCC * client = tncsim::client::getClient(tncConfig);

	printSeperate("create connection server");
	// create connection server
	server->createConnection(0);

	printSeperate("create connection client");
	// create connection client
	client->createConnection(0);

	printSeperateRound("begin handshake client", round);
	// begin handshake client
	TNCCSData data = client->beginHandshake();

//	data.getData()[0] = '>';

	while(round < maxRounds) {
		round++;
		try {
			printBinaryOut(data.getData(), data.getLength(), "Client --> Server");
			(std::cout << std::endl).write((const char *)data.getData(), data.getLength());
			printSeperateRound("receive TNCCSData server", round);
			data = server->receiveTNCCSData(data);
		} catch (server::Finished & e) {
			data = e.lastData;

			printBinaryOut(data.getData(), data.getLength(), "Last message Server --> Client");
			(std::cout << std::endl).write((const char *)data.getData(), data.getLength());
			printSeperateRound("receive last TNCCSData client", round);
			// client receive data
			client->receiveTNCCSData(data);

			printSeperateFinished("handshake finished, recommendation: ", e.rec);
			break;
		}

		printBinaryOut(data.getData(), data.getLength(), "Server --> Client");
		(std::cout << std::endl).write((const char *)data.getData(), data.getLength());
		printSeperateRound("receive TNCCSData client", round);
		// client receive data
		data = client->receiveTNCCSData(data);
	}

	if(round == maxRounds)
		std::cout << std::dec << "!!! WARNING !!!: maximum number of rounds ( " << maxRounds << " ) reached. stopping tncsim." << std::endl;

	printSeperate("delete server");
	delete server;

	printSeperate("delete client");
	delete client;

	printSeperate("exit program");
}
