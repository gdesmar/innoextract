
macro(use_static_libs ID)
	if(${ID}_USE_STATIC_LIBS)
		set(_UseStaticLibs_ORIG_CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
		if(WIN32)
			set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
		else()
			set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
		endif()
	endif()
endmacro()

macro(use_static_libs_restore)
	if(${ID}_USE_STATIC_LIBS)
		set(CMAKE_FIND_LIBRARY_SUFFIXES ${_UseStaticLibs_ORIG_CMAKE_FIND_LIBRARY_SUFFIXES})
	endif()
endmacro()