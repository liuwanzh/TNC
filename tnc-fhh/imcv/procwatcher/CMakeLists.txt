project(procwatcher)

TARGET_LINK_LIBRARIES(/usr/lib/libssl.so)
IF(TNCFHH_BUILD_IMCS)
	add_subdirectory(imc)
ENDIF()

IF(TNCFHH_BUILD_IMVS)
	add_subdirectory(imv)
ENDIF()
