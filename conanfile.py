from conan import ConanFile
from conan.tools.cmake import cmake_layout, CMakeToolchain, CMake


class NetlearnConan(ConanFile):
    name = "netlearn"
    version = "0.1.0"
    description = "Network packet analysis tool with C++23"
    author = "Your Name <your.email@example.com>"
    license = "MIT"
    url = "https://github.com/yourusername/netlearn"
    
    # Binary configuration
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
    }
    
    # Build requirements for Conan 2.0
    tool_requires = []
    
    # Runtime dependencies
    requires = (
        "cli11/2.6.0",
        "libpcap/1.10.5",
        "spdlog/1.17.0",
    )
    
    # Build/Test dependencies
    test_requires = (
        "gtest/1.17.0",
        "benchmark/1.8.4",
    )
    
    # Generators for CMake integration
    generators = "CMakeDeps"
    
    def config_options(self):
        """Configure options based on OS"""
        if self.settings.os == "Windows":
            del self.options.fPIC
    
    def configure(self):
        """Configure build settings"""
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")
    
    def layout(self):
        """Define folder layout"""
        cmake_layout(self)
        bt = str(self.settings.build_type).lower()
        self.folders.build      = f"cmake-build-{bt}"
        self.folders.generators = f"cmake-build-{bt}"
    def generate(self):
        """Generate build files"""
        tc = CMakeToolchain(self)
        
        # C++23 configuration
        tc.variables["CMAKE_CXX_STANDARD"] = "23"
        tc.variables["CMAKE_CXX_STANDARD_REQUIRED"] = "ON"
        tc.variables["CMAKE_CXX_EXTENSIONS"] = "OFF"
        
        # Optimization flags for Release builds
        if self.settings.build_type == "Release":
            tc.variables["CMAKE_CXX_FLAGS_RELEASE"] = "-O3 -DNDEBUG"
        
        # Enable testing support
        tc.variables["ENABLE_TESTING"] = "ON"
        
        tc.generate()

def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()