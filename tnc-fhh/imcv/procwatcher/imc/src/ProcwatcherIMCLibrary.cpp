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
 
#include "ProcwatcherIMCLibrary.h"
#include "ProcwatcherIMC.h"

#include <log4cxx/logger.h>

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("IMUnit.IMUnitLibrary.IMCLibrary.ProcwatcherIMCLibrary"));

// TNC@FHH IMCLibrary Initialization +
// implement IF-IMC c-functions
TNCFHH_IMCLIBRARY_INITIALIZE(ProcwatcherIMCLibrary) ;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
ProcwatcherIMCLibrary::ProcwatcherIMCLibrary()
{
	LOG4CXX_INFO(logger, "Load ProcwatcherIMC library ");

	/* set all attributes inherited from tncfhh::iml::IMCLibrary */
	// the library name for logging
	this->imUnitLibraryName = "ProcwatcherIMC";
	// add an messageType comprise Vendor ID (IANA PEN) and MessageSubtype
	this->addMessageType(VENDOR_ID, MESSAGE_SUBTYPE);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
tncfhh::iml::AbstractIMC *ProcwatcherIMCLibrary::createNewImcInstance(TNC_ConnectionID conID)
{
	LOG4CXX_TRACE(logger, "createNewImcInstance( " << conID << ")");

	// just return a new instance of ProcwatcherIMC
	return new ProcwatcherIMC(conID, this);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
ProcwatcherIMCLibrary::~ProcwatcherIMCLibrary()
{
	// if necessary delete memory
}
