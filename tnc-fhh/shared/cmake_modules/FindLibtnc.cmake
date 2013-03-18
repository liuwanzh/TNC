# - Try to find libtnc
# Once done this will define
#
#  LIBTNC_FOUND - System has libtnc
#  LIBTNC_INCLUDE_DIR - The Libtnc include directory
#  LIBTNC_LIBRARIES - The libraries needed to use Libtnc

# Copyright (c) 2010, Ingo Bente, <ingo.bente@fh-hannover.de>
# This cmake script is based upon FindLibxml2.cmake.
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

IF (LIBTNC_INCLUDE_DIR AND LIBTNC_LIBRARIES)
   # in cache already
   SET(LibTnc_FIND_QUIETLY TRUE)
ENDIF (LIBTNC_INCLUDE_DIR AND LIBTNC_LIBRARIES)

IF(LIBTNC_USE_STATIC)
  SET( LIBTNC_ORIG_CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
     IF(WIN32)
        SET(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
     ELSE(WIN32)
        SET(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
  ENDIF(WIN32)
ENDIF(LIBTNC_USE_STATIC)

FIND_PATH(LIBTNC_INCLUDE_DIR libtnc.h)

FIND_LIBRARY(LIBTNC_LIBRARIES NAMES tnc)

# handle the QUIETLY and REQUIRED arguments and set LIBTNC_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibTnc DEFAULT_MSG LIBTNC_LIBRARIES LIBTNC_INCLUDE_DIR)

IF(LIBTNC_USE_STATIC)
  SET( CMAKE_FIND_LIBRARY_SUFFIXES ${LIBTNC_ORIG_CMAKE_FIND_LIBRARY_SUFFIXES})
ENDIF(LIBTNC_USE_STATIC)


MESSAGE(STATUS "=====================")
MESSAGE(STATUS "CMAKE_INCLUDE_PATH = ${CMAKE_INCLUDE_PATH}")
MESSAGE(STATUS "LIBTNC_INCLUDE_DIR = ${LIBTNC_INCLUDE_DIR}")
MESSAGE(STATUS "LIBTNC_LIBRARIES = ${LIBTNC_LIBRARIES}")
MESSAGE(STATUS "LIBTNC_USE_STATIC = ${LIBTNC_USE_STATIC}")
MESSAGE(STATUS "=====================")
