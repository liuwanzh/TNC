# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 2.8

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canoncical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/liuwanzh/tnc/TNC/tnc-fhh

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/liuwanzh/tnc/TNC/tnc-fhh/build

# Include any dependencies generated for this target.
include tncsim/CMakeFiles/tncsim.dir/depend.make

# Include the progress variables for this target.
include tncsim/CMakeFiles/tncsim.dir/progress.make

# Include the compile flags for this target's objects.
include tncsim/CMakeFiles/tncsim.dir/flags.make

tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o: tncsim/CMakeFiles/tncsim.dir/flags.make
tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o: ../tncsim/src/server/libtnc/LibtncTNCS.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/liuwanzh/tnc/TNC/tnc-fhh/build/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o -c /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/server/libtnc/LibtncTNCS.cpp

tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.i"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/server/libtnc/LibtncTNCS.cpp > CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.i

tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.s"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/server/libtnc/LibtncTNCS.cpp -o CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.s

tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o.requires:
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o.requires

tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o.provides: tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o.requires
	$(MAKE) -f tncsim/CMakeFiles/tncsim.dir/build.make tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o.provides.build
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o.provides

tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o.provides.build: tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o.provides.build

tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o: tncsim/CMakeFiles/tncsim.dir/flags.make
tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o: ../tncsim/src/client/libtnc/LibtncTNCC.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/liuwanzh/tnc/TNC/tnc-fhh/build/CMakeFiles $(CMAKE_PROGRESS_2)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o -c /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/client/libtnc/LibtncTNCC.cpp

tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.i"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/client/libtnc/LibtncTNCC.cpp > CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.i

tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.s"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/client/libtnc/LibtncTNCC.cpp -o CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.s

tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o.requires:
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o.requires

tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o.provides: tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o.requires
	$(MAKE) -f tncsim/CMakeFiles/tncsim.dir/build.make tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o.provides.build
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o.provides

tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o.provides.build: tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o.provides.build

tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o: tncsim/CMakeFiles/tncsim.dir/flags.make
tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o: ../tncsim/src/client/AbstractTNCC.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/liuwanzh/tnc/TNC/tnc-fhh/build/CMakeFiles $(CMAKE_PROGRESS_3)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o -c /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/client/AbstractTNCC.cpp

tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.i"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/client/AbstractTNCC.cpp > CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.i

tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.s"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/client/AbstractTNCC.cpp -o CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.s

tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o.requires:
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o.requires

tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o.provides: tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o.requires
	$(MAKE) -f tncsim/CMakeFiles/tncsim.dir/build.make tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o.provides.build
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o.provides

tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o.provides.build: tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o.provides.build

tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o: tncsim/CMakeFiles/tncsim.dir/flags.make
tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o: ../tncsim/src/server/AbstractTNCS.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/liuwanzh/tnc/TNC/tnc-fhh/build/CMakeFiles $(CMAKE_PROGRESS_4)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o -c /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/server/AbstractTNCS.cpp

tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.i"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/server/AbstractTNCS.cpp > CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.i

tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.s"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/server/AbstractTNCS.cpp -o CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.s

tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o.requires:
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o.requires

tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o.provides: tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o.requires
	$(MAKE) -f tncsim/CMakeFiles/tncsim.dir/build.make tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o.provides.build
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o.provides

tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o.provides.build: tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o.provides.build

tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.o: tncsim/CMakeFiles/tncsim.dir/flags.make
tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.o: ../tncsim/src/server/Finished.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/liuwanzh/tnc/TNC/tnc-fhh/build/CMakeFiles $(CMAKE_PROGRESS_5)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.o"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/tncsim.dir/src/server/Finished.cpp.o -c /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/server/Finished.cpp

tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tncsim.dir/src/server/Finished.cpp.i"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/server/Finished.cpp > CMakeFiles/tncsim.dir/src/server/Finished.cpp.i

tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tncsim.dir/src/server/Finished.cpp.s"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/server/Finished.cpp -o CMakeFiles/tncsim.dir/src/server/Finished.cpp.s

tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.o.requires:
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.o.requires

tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.o.provides: tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.o.requires
	$(MAKE) -f tncsim/CMakeFiles/tncsim.dir/build.make tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.o.provides.build
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.o.provides

tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.o.provides.build: tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.o
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.o.provides.build

tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o: tncsim/CMakeFiles/tncsim.dir/flags.make
tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o: ../tncsim/src/TNCCSData.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/liuwanzh/tnc/TNC/tnc-fhh/build/CMakeFiles $(CMAKE_PROGRESS_6)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o -c /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/TNCCSData.cpp

tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tncsim.dir/src/TNCCSData.cpp.i"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/TNCCSData.cpp > CMakeFiles/tncsim.dir/src/TNCCSData.cpp.i

tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tncsim.dir/src/TNCCSData.cpp.s"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/TNCCSData.cpp -o CMakeFiles/tncsim.dir/src/TNCCSData.cpp.s

tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o.requires:
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o.requires

tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o.provides: tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o.requires
	$(MAKE) -f tncsim/CMakeFiles/tncsim.dir/build.make tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o.provides.build
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o.provides

tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o.provides.build: tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o.provides.build

tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.o: tncsim/CMakeFiles/tncsim.dir/flags.make
tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.o: ../tncsim/src/tncsim.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/liuwanzh/tnc/TNC/tnc-fhh/build/CMakeFiles $(CMAKE_PROGRESS_7)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.o"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/tncsim.dir/src/tncsim.cpp.o -c /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/tncsim.cpp

tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tncsim.dir/src/tncsim.cpp.i"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/tncsim.cpp > CMakeFiles/tncsim.dir/src/tncsim.cpp.i

tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tncsim.dir/src/tncsim.cpp.s"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim/src/tncsim.cpp -o CMakeFiles/tncsim.dir/src/tncsim.cpp.s

tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.o.requires:
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.o.requires

tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.o.provides: tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.o.requires
	$(MAKE) -f tncsim/CMakeFiles/tncsim.dir/build.make tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.o.provides.build
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.o.provides

tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.o.provides.build: tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.o
.PHONY : tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.o.provides.build

# Object files for target tncsim
tncsim_OBJECTS = \
"CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o" \
"CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o" \
"CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o" \
"CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o" \
"CMakeFiles/tncsim.dir/src/server/Finished.cpp.o" \
"CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o" \
"CMakeFiles/tncsim.dir/src/tncsim.cpp.o"

# External object files for target tncsim
tncsim_EXTERNAL_OBJECTS =

tncsim/tncsim: tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o
tncsim/tncsim: tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o
tncsim/tncsim: tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o
tncsim/tncsim: tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o
tncsim/tncsim: tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.o
tncsim/tncsim: tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o
tncsim/tncsim: tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.o
tncsim/tncsim: /usr/lib/libxml2.so
tncsim/tncsim: /usr/local/lib/libtnc.a
tncsim/tncsim: tncsim/CMakeFiles/tncsim.dir/build.make
tncsim/tncsim: tncsim/CMakeFiles/tncsim.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking CXX executable tncsim"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/tncsim.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tncsim/CMakeFiles/tncsim.dir/build: tncsim/tncsim
.PHONY : tncsim/CMakeFiles/tncsim.dir/build

tncsim/CMakeFiles/tncsim.dir/requires: tncsim/CMakeFiles/tncsim.dir/src/server/libtnc/LibtncTNCS.cpp.o.requires
tncsim/CMakeFiles/tncsim.dir/requires: tncsim/CMakeFiles/tncsim.dir/src/client/libtnc/LibtncTNCC.cpp.o.requires
tncsim/CMakeFiles/tncsim.dir/requires: tncsim/CMakeFiles/tncsim.dir/src/client/AbstractTNCC.cpp.o.requires
tncsim/CMakeFiles/tncsim.dir/requires: tncsim/CMakeFiles/tncsim.dir/src/server/AbstractTNCS.cpp.o.requires
tncsim/CMakeFiles/tncsim.dir/requires: tncsim/CMakeFiles/tncsim.dir/src/server/Finished.cpp.o.requires
tncsim/CMakeFiles/tncsim.dir/requires: tncsim/CMakeFiles/tncsim.dir/src/TNCCSData.cpp.o.requires
tncsim/CMakeFiles/tncsim.dir/requires: tncsim/CMakeFiles/tncsim.dir/src/tncsim.cpp.o.requires
.PHONY : tncsim/CMakeFiles/tncsim.dir/requires

tncsim/CMakeFiles/tncsim.dir/clean:
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim && $(CMAKE_COMMAND) -P CMakeFiles/tncsim.dir/cmake_clean.cmake
.PHONY : tncsim/CMakeFiles/tncsim.dir/clean

tncsim/CMakeFiles/tncsim.dir/depend:
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/liuwanzh/tnc/TNC/tnc-fhh /home/liuwanzh/tnc/TNC/tnc-fhh/tncsim /home/liuwanzh/tnc/TNC/tnc-fhh/build /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncsim/CMakeFiles/tncsim.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tncsim/CMakeFiles/tncsim.dir/depend

