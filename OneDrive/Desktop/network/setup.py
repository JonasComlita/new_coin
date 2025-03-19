#!/usr/bin/env python3
"""
Setup script for enhanced blockchain implementation.
Handles installation of Python package and C++ acceleration libraries.
"""

import os
import sys
import platform
import subprocess
from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext

if sys.version_info < (3, 8):
    sys.exit('Python >= 3.8 is required')

VERSION = '1.0.0'
DESCRIPTION = 'Enhanced blockchain implementation with PostgreSQL, msgpack, and C++ acceleration'
LONG_DESCRIPTION = '''
Enhanced blockchain implementation featuring:
- C++ acceleration for compute-intensive operations
- GPU mining support with CUDA
- PostgreSQL storage for high scalability
- MessagePack serialization for efficiency
- Multiprocessing for mining operations
'''

REQUIRES = [
    'asyncio>=3.4.3',
    'asyncpg>=0.27.0',
    'msgpack>=1.0.4',
    'pybind11>=2.10.0',
    'ecdsa>=0.18.0',
    'cryptography>=39.0.0',
    'aiohttp>=3.8.0',
    'uvloop>=0.17.0; platform_system != "Windows"',
    'psutil>=5.9.0',
]

EXTRAS_REQUIRE = {
    'dev': ['pytest>=7.0.0', 'pytest-asyncio>=0.20.0', 'pytest-cov>=4.0.0', 'black>=23.0.0', 'isort>=5.12.0', 'mypy>=1.0.0'],
    'gpu': ['cuda-python>=12.0.0; platform_system=="Linux" or platform_system=="Windows"'],
}

class CMakeExtension(Extension):
    def __init__(self, name, sourcedir=''):
        Extension.__init__(self, name, sources=[])
        self.sourcedir = os.path.abspath(sourcedir)

class CMakeBuild(build_ext):
    def run(self):
        try:
            subprocess.check_output(['cmake', '--version'])
        except OSError:
            raise RuntimeError("CMake must be installed to build the C++ extensions")
        
        for ext in self.extensions:
            self.build_extension(ext)
    
    def build_extension(self, ext):
        extdir = os.path.abspath(os.path.dirname(self.get_ext_fullpath(ext.name)))
        
        # Use absolute path to the project root
        ext.sourcedir = os.path.abspath(os.path.dirname(__file__))
        
        cfg = 'Debug' if self.debug else 'Release'
        
        try:
            import pybind11
            pybind11_path = pybind11.get_cmake_dir()
        except ImportError:
            raise RuntimeError("pybind11 must be installed to build the C++ extensions")
        
        cmake_args = [
            f'-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={extdir}',
            f'-DPYTHON_EXECUTABLE={sys.executable}',
            f'-DCMAKE_PREFIX_PATH={pybind11_path}',
        ]
        
        if platform.system() == "Windows":
            cmake_args += [f'-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_{cfg.upper()}={extdir}']
            if sys.maxsize > 2**32:
                cmake_args += ['-A', 'x64']
            build_args = ['--config', cfg, '--', '/m']
        else:
            cmake_args += [f'-DCMAKE_BUILD_TYPE={cfg}']
            build_args = ['--', '-j4']
        
        try:
            subprocess.check_output(['nvcc', '--version'])
            cmake_args.append('-DWITH_CUDA=ON')
            print("CUDA detected, enabling GPU support")
        except Exception:
            print("CUDA not found, building without GPU support")
        
        os.makedirs(self.build_temp, exist_ok=True)
        
        try:
            subprocess.check_call(['cmake', ext.sourcedir] + cmake_args, cwd=self.build_temp)
        except subprocess.CalledProcessError as e:
            print(f"CMake configuration failed with exit code {e.returncode}")
            print(f"Command: {' '.join(e.cmd)}")
            print(f"Output: {e.output.decode() if e.output else 'No output'}")
            raise
        
        try:
            subprocess.check_call(['cmake', '--build', '.'] + build_args, cwd=self.build_temp)
        except subprocess.CalledProcessError as e:
            print(f"CMake build failed with exit code {e.returncode}")
            print(f"Command: {' '.join(e.cmd)}")
            print(f"Output: {e.output.decode() if e.output else 'No output'}")
            raise
        
        print()

setup(
    name='blockchain',
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    packages=find_packages(),
    install_requires=REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: C++',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Distributed Computing',
    ],
    ext_modules=[
        CMakeExtension('blockchain_cpp'),
        CMakeExtension('utxo_cpp')  # Added utxo_cpp extension
    ],
    cmdclass={'build_ext': CMakeBuild},
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'blockchain-node=enhanced_blockchain.main:main',
        ],
    },
)

# Existing setup.py, but add this to ensure extensions are properly built and placed
def copy_extensions():
    """Copy built extensions to the correct package directory"""
    import glob
    import shutil
    import os

    # Find built .pyd files
    extension_files = glob.glob('build/**/*.pyd', recursive=True)
    
    # Destination directory
    dest_dir = os.path.join('blockchain')
    
    # Create destination directory if it doesn't exist
    os.makedirs(dest_dir, exist_ok=True)
    
    # Copy each extension
    for ext_file in extension_files:
        dest_file = os.path.join(dest_dir, os.path.basename(ext_file))
        shutil.copy(ext_file, dest_file)
        print(f"Copied {ext_file} to {dest_file}")

# Add this to your setup function or post-install script
copy_extensions()