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
include imcv/example/imc/CMakeFiles/exampleimc.dir/depend.make

# Include the progress variables for this target.
include imcv/example/imc/CMakeFiles/exampleimc.dir/progress.make

# Include the compile flags for this target's objects.
include imcv/example/imc/CMakeFiles/exampleimc.dir/flags.make

imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o: imcv/example/imc/CMakeFiles/exampleimc.dir/flags.make
imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o: ../imcv/example/imc/src/ExampleIMCLibrary.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/liuwanzh/tnc/TNC/tnc-fhh/build/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/imcv/example/imc && /usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o -c /home/liuwanzh/tnc/TNC/tnc-fhh/imcv/example/imc/src/ExampleIMCLibrary.cpp

imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.i"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/imcv/example/imc && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/liuwanzh/tnc/TNC/tnc-fhh/imcv/example/imc/src/ExampleIMCLibrary.cpp > CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.i

imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.s"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/imcv/example/imc && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/liuwanzh/tnc/TNC/tnc-fhh/imcv/example/imc/src/ExampleIMCLibrary.cpp -o CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.s

imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o.requires:
.PHONY : imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o.requires

imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o.provides: imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o.requires
	$(MAKE) -f imcv/example/imc/CMakeFiles/exampleimc.dir/build.make imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o.provides.build
.PHONY : imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o.provides

imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o.provides.build: imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o
.PHONY : imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o.provides.build

imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o: imcv/example/imc/CMakeFiles/exampleimc.dir/flags.make
imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o: ../imcv/example/imc/src/ExampleIMC.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/liuwanzh/tnc/TNC/tnc-fhh/build/CMakeFiles $(CMAKE_PROGRESS_2)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/imcv/example/imc && /usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o -c /home/liuwanzh/tnc/TNC/tnc-fhh/imcv/example/imc/src/ExampleIMC.cpp

imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.i"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/imcv/example/imc && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/liuwanzh/tnc/TNC/tnc-fhh/imcv/example/imc/src/ExampleIMC.cpp > CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.i

imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.s"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/imcv/example/imc && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/liuwanzh/tnc/TNC/tnc-fhh/imcv/example/imc/src/ExampleIMC.cpp -o CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.s

imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o.requires:
.PHONY : imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o.requires

imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o.provides: imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o.requires
	$(MAKE) -f imcv/example/imc/CMakeFiles/exampleimc.dir/build.make imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o.provides.build
.PHONY : imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o.provides

imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o.provides.build: imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o
.PHONY : imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o.provides.build

# Object files for target exampleimc
exampleimc_OBJECTS = \
"CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o" \
"CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o"

# External object files for target exampleimc
exampleimc_EXTERNAL_OBJECTS =

imcv/example/imc/libexampleimc.so.0.8.4: imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o
imcv/example/imc/libexampleimc.so.0.8.4: imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o
imcv/example/imc/libexampleimc.so.0.8.4: imunit/libimunit.so.0.8.4
imcv/example/imc/libexampleimc.so.0.8.4: /usr/lib/liblog4cxx.so
imcv/example/imc/libexampleimc.so.0.8.4: imcv/example/imc/CMakeFiles/exampleimc.dir/build.make
imcv/example/imc/libexampleimc.so.0.8.4: imcv/example/imc/CMakeFiles/exampleimc.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking CXX shared module libexampleimc.so"
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/imcv/example/imc && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/exampleimc.dir/link.txt --verbose=$(VERBOSE)
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/imcv/example/imc && $(CMAKE_COMMAND) -E cmake_symlink_library libexampleimc.so.0.8.4 libexampleimc.so.0 libexampleimc.so

imcv/example/imc/libexampleimc.so.0: imcv/example/imc/libexampleimc.so.0.8.4

imcv/example/imc/libexampleimc.so: imcv/example/imc/libexampleimc.so.0.8.4

# Rule to build all files generated by this target.
imcv/example/imc/CMakeFiles/exampleimc.dir/build: imcv/example/imc/libexampleimc.so
.PHONY : imcv/example/imc/CMakeFiles/exampleimc.dir/build

imcv/example/imc/CMakeFiles/exampleimc.dir/requires: imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMCLibrary.cpp.o.requires
imcv/example/imc/CMakeFiles/exampleimc.dir/requires: imcv/example/imc/CMakeFiles/exampleimc.dir/src/ExampleIMC.cpp.o.requires
.PHONY : imcv/example/imc/CMakeFiles/exampleimc.dir/requires

imcv/example/imc/CMakeFiles/exampleimc.dir/clean:
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build/imcv/example/imc && $(CMAKE_COMMAND) -P CMakeFiles/exampleimc.dir/cmake_clean.cmake
.PHONY : imcv/example/imc/CMakeFiles/exampleimc.dir/clean

imcv/example/imc/CMakeFiles/exampleimc.dir/depend:
	cd /home/liuwanzh/tnc/TNC/tnc-fhh/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/liuwanzh/tnc/TNC/tnc-fhh /home/liuwanzh/tnc/TNC/tnc-fhh/imcv/example/imc /home/liuwanzh/tnc/TNC/tnc-fhh/build /home/liuwanzh/tnc/TNC/tnc-fhh/build/imcv/example/imc /home/liuwanzh/tnc/TNC/tnc-fhh/build/imcv/example/imc/CMakeFiles/exampleimc.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : imcv/example/imc/CMakeFiles/exampleimc.dir/depend
