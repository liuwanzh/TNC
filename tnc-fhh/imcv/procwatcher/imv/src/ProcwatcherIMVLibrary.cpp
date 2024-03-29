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
 
#include "ProcwatcherIMVLibrary.h"
#include "ProcwatcherIMV.h"

#include <log4cxx/logger.h>

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("IMUnit.IMUnitLibrary.IMCLibrary.ProcwatcherIMVLibrary"));

// TNC@FHH IMCLibrary Initialization +
// implement IF-IMC c-functions
TNCFHH_IMVLIBRARY_INITIALIZE(ProcwatcherIMVLibrary) ;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
ProcwatcherIMVLibrary::ProcwatcherIMVLibrary()
{
	LOG4CXX_INFO(logger, "Load ProcwatcherIMV library ");

	/* set all attributes inherited from tncfhh::iml::IMCLibrary */
	// the library name for logging
	this->imUnitLibraryName = "ProcwatcherIMV";
	// add an messageType comprise Vendor ID (IANA PEN) and MessageSubtype
	this->addMessageType(VENDOR_ID, MESSAGE_SUBTYPE);
    this->policyManager = new ProcwatcherIMVPolicyManager("/etc/tnc/procwatcherimv.policy");
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
tncfhh::iml::AbstractIMV *ProcwatcherIMVLibrary::createNewImvInstance(TNC_ConnectionID conID)
{
	LOG4CXX_TRACE(logger, "createNewImvInstance( " << conID << ")");

	// just return a new instance of ProcwatcherIMV
	return new ProcwatcherIMV(conID, this,policyManager);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
ProcwatcherIMVLibrary::~ProcwatcherIMVLibrary()
{

	// if necessary delete memory
}
