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
include tncutil/CMakeFiles/tncutil.dir/depend.make

# Include the progress variables for this target.
include tncutil/CMakeFiles/tncutil.dir/progress.make

# Include the compile flags for this target's objects.
include tncutil/CMakeFiles/tncutil.dir/flags.make

tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o: tncutil/CMakeFiles/tncutil.dir/flags.make
tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o: ../tncutil/src/tncutil/Configuration.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/liuwanzh/tnc/TNC/tnc-fhh/build/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncutil && /usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o -c /home/liuwanzh/tnc/TNC/tnc-fhh/tncutil/src/tncutil/Configuration.cpp

tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.i"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncutil && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/liuwanzh/tnc/TNC/tnc-fhh/tncutil/src/tncutil/Configuration.cpp > CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.i

tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.s"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncutil && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/liuwanzh/tnc/TNC/tnc-fhh/tncutil/src/tncutil/Configuration.cpp -o CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.s

tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o.requires:
.PHONY : tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o.requires

tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o.provides: tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o.requires
	$(MAKE) -f tncutil/CMakeFiles/tncutil.dir/build.make tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o.provides.build
.PHONY : tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o.provides

tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o.provides.build: tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o
.PHONY : tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o.provides.build

tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o: tncutil/CMakeFiles/tncutil.dir/flags.make
tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o: ../tncutil/src/tncutil/ConfigurationService.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/liuwanzh/tnc/TNC/tnc-fhh/build/CMakeFiles $(CMAKE_PROGRESS_2)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncutil && /usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o -c /home/liuwanzh/tnc/TNC/tnc-fhh/tncutil/src/tncutil/ConfigurationService.cpp

tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.i"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncutil && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/liuwanzh/tnc/TNC/tnc-fhh/tncutil/src/tncutil/ConfigurationService.cpp > CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.i

tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.s"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncutil && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/liuwanzh/tnc/TNC/tnc-fhh/tncutil/src/tncutil/ConfigurationService.cpp -o CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.s

tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o.requires:
.PHONY : tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o.requires

tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o.provides: tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o.requires
	$(MAKE) -f tncutil/CMakeFiles/tncutil.dir/build.make tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o.provides.build
.PHONY : tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o.provides

tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o.provides.build: tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o
.PHONY : tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o.provides.build

tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o: tncutil/CMakeFiles/tncutil.dir/flags.make
tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o: ../tncutil/src/tncutil/XercesString.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/liuwanzh/tnc/TNC/tnc-fhh/build/CMakeFiles $(CMAKE_PROGRESS_3)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncutil && /usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o -c /home/liuwanzh/tnc/TNC/tnc-fhh/tncutil/src/tncutil/XercesString.cpp

tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.i"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncutil && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/liuwanzh/tnc/TNC/tnc-fhh/tncutil/src/tncutil/XercesString.cpp > CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.i

tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.s"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncutil && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/liuwanzh/tnc/TNC/tnc-fhh/tncutil/src/tncutil/XercesString.cpp -o CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.s

tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o.requires:
.PHONY : tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o.requires

tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o.provides: tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o.requires
	$(MAKE) -f tncutil/CMakeFiles/tncutil.dir/build.make tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o.provides.build
.PHONY : tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o.provides

tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o.provides.build: tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o
.PHONY : tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o.provides.build

# Object files for target tncutil
tncutil_OBJECTS = \
"CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o" \
"CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o" \
"CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o"

# External object files for target tncutil
tncutil_EXTERNAL_OBJECTS =

tncutil/libtncutil.so.0.8.4: tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o
tncutil/libtncutil.so.0.8.4: tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o
tncutil/libtncutil.so.0.8.4: tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o
tncutil/libtncutil.so.0.8.4: /usr/lib/liblog4cxx.so
tncutil/libtncutil.so.0.8.4: /usr/lib/libxerces-c.so
tncutil/libtncutil.so.0.8.4: tncutil/CMakeFiles/tncutil.dir/build.make
tncutil/libtncutil.so.0.8.4: tncutil/CMakeFiles/tncutil.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking CXX shared library libtncutil.so"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncutil && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/tncutil.dir/link.txt --verbose=$(VERBOSE)
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncutil && $(CMAKE_COMMAND) -E cmake_symlink_library libtncutil.so.0.8.4 libtncutil.so.0 libtncutil.so

tncutil/libtncutil.so.0: tncutil/libtncutil.so.0.8.4

tncutil/libtncutil.so: tncutil/libtncutil.so.0.8.4

# Rule to build all files generated by this target.
tncutil/CMakeFiles/tncutil.dir/build: tncutil/libtncutil.so
.PHONY : tncutil/CMakeFiles/tncutil.dir/build

tncutil/CMakeFiles/tncutil.dir/requires: tncutil/CMakeFiles/tncutil.dir/src/tncutil/Configuration.cpp.o.requires
tncutil/CMakeFiles/tncutil.dir/requires: tncutil/CMakeFiles/tncutil.dir/src/tncutil/ConfigurationService.cpp.o.requires
tncutil/CMakeFiles/tncutil.dir/requires: tncutil/CMakeFiles/tncutil.dir/src/tncutil/XercesString.cpp.o.requires
.PHONY : tncutil/CMakeFiles/tncutil.dir/requires

tncutil/CMakeFiles/tncutil.dir/clean:
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncutil && $(CMAKE_COMMAND) -P CMakeFiles/tncutil.dir/cmake_clean.cmake
.PHONY : tncutil/CMakeFiles/tncutil.dir/clean

tncutil/CMakeFiles/tncutil.dir/depend:
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/liuwanzh/tnc/TNC/tnc-fhh /home/liuwanzh/tnc/TNC/tnc-fhh/tncutil /home/liuwanzh/tnc/TNC/tnc-fhh/build /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncutil /home/liuwanzh/tnc/TNC/tnc-fhh/build/tncutil/CMakeFiles/tncutil.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tncutil/CMakeFiles/tncutil.dir/depend

